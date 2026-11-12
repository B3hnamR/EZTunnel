//! Real direct UDP delivery and authenticated channel replacement with stable targets.
use anyhow::{Result,ensure,Context};
use eztunnel::{config::Config,gaming::Hub};
use serde_json::json;
use std::{net::{UdpSocket as StdUdp,TcpListener},time::Duration};
use tokio::{net::UdpSocket,time::{timeout,sleep}};

fn udp_port()->u16 {StdUdp::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()}
fn tcp_port()->u16 {TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()}
fn config(value:serde_json::Value)->Result<(tempfile::TempDir,Config)> {
    let directory=tempfile::tempdir()?;let path=directory.path().join("config.json");
    std::fs::write(&path,serde_json::to_vec(&value)?)?;
    #[cfg(unix)] {use std::os::unix::fs::PermissionsExt;std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o600))?;}
    let config=Config::load(&path)?;Ok((directory,config))
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn reply_only_traffic_keeps_target_socket_active_and_flow_close_is_terminal()->Result<()> {
    timeout(Duration::from_secs(15),async {
        let control=tcp_port();let su=udp_port();let cu=udp_port();
        let target_socket=UdpSocket::bind("127.0.0.1:0").await?;let target=target_socket.local_addr()?;
        let producer=tokio::spawn(async move {
            let mut bytes=[0;32];let(_,peer)=target_socket.recv_from(&mut bytes).await?;
            for index in 0..24u8 {target_socket.send_to(&[index],peer).await?;sleep(Duration::from_millis(250)).await;}
            // A later request must use the SAME socket after more than one idle
            // interval of response-only traffic.
            let(_,again)=target_socket.recv_from(&mut bytes).await?;ensure!(again==peer,"reply-only flow was recreated");target_socket.send_to(b"last",peer).await?;
            Ok::<_,anyhow::Error>(())
        });
        let key=eztunnel::tunnel_key::TunnelKey::generate()?.display();
        let(_sd,server)=config(json!({"mode":"server","tunnel_key":key,"listeners":[{"addr":"127.0.0.1:25550"}],
            "timeouts":{"udp_idle_sec":5},"gaming":{"control_address":format!("127.0.0.1:{control}"),"udp_bind":format!("127.0.0.1:{su}")}}))?;
        let(_cd,client)=config(json!({"mode":"client","tunnel_key":key,"paths":[{"addr":"127.0.0.1:25550"}],"allowed_targets":[target.to_string()],
            "timeouts":{"udp_idle_sec":5},"gaming":{"control_address":format!("127.0.0.1:{control}"),"udp_bind":format!("127.0.0.1:{cu}")}}))?;
        let origin=Hub::start(&server).await?;let _destination=Hub::start(&client).await?;let(flow,mut replies)=origin.register().await?;
        for _ in 0..100 {if origin.send(flow,&target.to_string(),b"start").await?{break;}sleep(Duration::from_millis(25)).await;}
        for index in 0..24u8 {ensure!(timeout(Duration::from_secs(2),replies.recv()).await?.as_deref()==Some([index].as_slice()),"reply-only packet missing");}
        ensure!(origin.send(flow,&target.to_string(),b"finish").await?,"path disappeared");
        ensure!(timeout(Duration::from_secs(2),replies.recv()).await?.as_deref()==Some(b"last"),"final reply");
        origin.unregister(flow).await;assert!(origin.send(flow,&target.to_string(),b"stale").await.is_err());producer.await??;
        Ok::<_,anyhow::Error>(())
    }).await??;Ok(())
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn direct_udp_migrates_keys_without_changing_the_target_socket()->Result<()> {
    let _=tracing_subscriber::fmt().with_env_filter("debug").with_test_writer().try_init();
    timeout(Duration::from_secs(25),async {
        let control=tcp_port();let server_udp=udp_port();let client_udp=udp_port();
        let echo=UdpSocket::bind("127.0.0.1:0").await?;let target=echo.local_addr()?;
        let echo_task=tokio::spawn(async move {
            let mut peer=None;let mut buffer=[0;65536];
            for _ in 0..24 {
                let(size,source)=echo.recv_from(&mut buffer).await?;
                if let Some(previous)=peer {ensure!(source==previous,"UDP migration replaced the target socket/NAT identity");}else{peer=Some(source);}
                echo.send_to(&buffer[..size],source).await?;
            }
            Ok::<_,anyhow::Error>(())
        });
        let key=eztunnel::tunnel_key::TunnelKey::generate()?.display();
        let (_s,server)=config(json!({"mode":"server","tunnel_key":key,"listeners":[{"addr":"127.0.0.1:25550","maps":[]}],
            "gaming":{"control_address":format!("127.0.0.1:{control}"),"udp_bind":format!("127.0.0.1:{server_udp}"),"renewal_sec":5}}))?;
        let (_c,client)=config(json!({"mode":"client","tunnel_key":key,"paths":[{"addr":"127.0.0.1:25550"}],"allowed_targets":[target.to_string()],
            "gaming":{"control_address":format!("127.0.0.1:{control}"),"udp_bind":format!("127.0.0.1:{client_udp}"),"renewal_sec":5}}))?;
        let origin=Hub::start(&server).await?;let _target=Hub::start(&client).await?;
        let(flow,mut replies)=origin.register().await?;
        for index in 0..24u8 {
            if index==12 {
                let rebound=origin.rebind("127.0.0.1:0".parse()?,None).await?;
                ensure!(rebound.port()!=server_udp,"migration did not change the UDP source port");
            }
            let payload=vec![index;match index%4 {0=>0,1=>500,2=>1301,_=>16_384}];
            for _ in 0..100 {if origin.send(flow,&target.to_string(),&payload).await?{break;}sleep(Duration::from_millis(25)).await;}
            ensure!(timeout(Duration::from_secs(2),replies.recv()).await.with_context(||format!("gaming reply index{index} size{}",payload.len()))?.as_deref()==Some(payload.as_slice()),"gaming reply mismatch at index{index}");
            sleep(Duration::from_millis(350)).await;
        }
        ensure!(eztunnel::transport_metrics::GAMING_MIGRATIONS.load(std::sync::atomic::Ordering::Relaxed)>0,"no target flow generation migrated");
        origin.unregister(flow).await;echo_task.await??;Ok::<_,anyhow::Error>(())
    }).await??;Ok(())
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn socks_udp_source_pin_and_header_survive_direct_channel_renewal()->Result<()> {
    use tokio::io::{AsyncReadExt,AsyncWriteExt};
    timeout(Duration::from_secs(20),async {
        let tunnel=tcp_port();let control=tcp_port();let socks=tcp_port();let su=udp_port();let cu=udp_port();
        let echo=UdpSocket::bind("127.0.0.1:0").await?;let target=echo.local_addr()?;
        let task=tokio::spawn(async move {let mut data=[0;2048];for _ in 0..20 {let(size,peer)=echo.recv_from(&mut data).await?;echo.send_to(&data[..size],peer).await?;}Ok::<_,anyhow::Error>(())});
        let key=eztunnel::tunnel_key::TunnelKey::generate()?.display();
        let(_sd,server)=config(json!({"mode":"server","tunnel_key":key,"socks5":format!("127.0.0.1:{socks}"),"listeners":[{"addr":format!("127.0.0.1:{tunnel}"),"maps":[]}],
            "gaming":{"control_address":format!("127.0.0.1:{control}"),"udp_bind":format!("127.0.0.1:{su}"),"renewal_sec":5}}))?;
        let(_cd,client)=config(json!({"mode":"client","tunnel_key":key,"paths":[{"addr":format!("127.0.0.1:{tunnel}")}],"allowed_targets":[target.to_string()],
            "gaming":{"control_address":format!("127.0.0.1:{control}"),"udp_bind":format!("127.0.0.1:{cu}"),"renewal_sec":5}}))?;
        struct Abort(tokio::task::JoinHandle<Result<()>>);impl Drop for Abort{fn drop(&mut self){self.0.abort();}}
        let _server=Abort(tokio::spawn(eztunnel::engine::run(server)));let _client=Abort(tokio::spawn(eztunnel::engine::run(client)));
        sleep(Duration::from_secs(1)).await;
        let mut tcp=tokio::net::TcpStream::connect(format!("127.0.0.1:{socks}")).await?;
        tcp.write_all(&[5,1,0]).await?;let mut greeting=[0;2];tcp.read_exact(&mut greeting).await?;ensure!(greeting==[5,0],"SOCKS greeting");
        tcp.write_all(&[5,3,0,1,0,0,0,0,0,0]).await?;let mut reply=[0;10];tcp.read_exact(&mut reply).await?;ensure!(reply[..4]==[5,0,0,1],"SOCKS associate");
        let relay=std::net::SocketAddr::from(([reply[4],reply[5],reply[6],reply[7]],u16::from_be_bytes(reply[8..10].try_into().unwrap())));
        let udp=UdpSocket::bind("127.0.0.1:0").await?;
        let mut header=vec![0,0,0,1,127,0,0,1];header.extend_from_slice(&target.port().to_be_bytes());
        for index in 0..20u8 {let mut packet=header.clone();packet.extend_from_slice(&[index;128]);udp.send_to(&packet,relay).await?;let mut received=[0;2048];let(size,_)=timeout(Duration::from_secs(2),udp.recv_from(&mut received)).await??;ensure!(&received[..size]==packet.as_slice(),"SOCKS datagram changed");sleep(Duration::from_millis(300)).await;}
        tcp.shutdown().await?;task.await??;Ok::<_,anyhow::Error>(())
    }).await??;Ok(())
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn ordinary_udp_map_survives_reliable_session_restart_with_direct_flow_identity()->Result<()> {
    timeout(Duration::from_secs(35),async {
        let tunnel=tcp_port();let control=tcp_port();let server_udp=udp_port();let client_udp=udp_port();let map=udp_port();
        let proxy=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let proxy_address=proxy.local_addr()?;
        let(cut,mut cuts)=tokio::sync::mpsc::channel::<()>(1);
        let connections=std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));let counted=connections.clone();
        let proxy_task=tokio::spawn(async move {
            let mut active=tokio::task::JoinSet::new();
            loop {tokio::select! {
                accepted=proxy.accept()=>{let(mut incoming,_)=accepted?;counted.fetch_add(1,std::sync::atomic::Ordering::Relaxed);active.spawn(async move {
                    let mut outgoing=tokio::net::TcpStream::connect(format!("127.0.0.1:{tunnel}")).await?;
                    tokio::io::copy_bidirectional(&mut incoming,&mut outgoing).await?;Ok::<_,std::io::Error>(())
                });}
                cut=cuts.recv()=>{if cut.is_none(){break;}active.abort_all();}
                _=active.join_next(),if !active.is_empty()=>{},
            }}
            Ok::<_,std::io::Error>(())
        });
        let echo=UdpSocket::bind("127.0.0.1:0").await?;let target=echo.local_addr()?;
        let echo_task=tokio::spawn(async move{
            let mut data=[0;2048];let mut first=None;
            for _ in 0..36 {
                let(size,peer)=echo.recv_from(&mut data).await?;
                if let Some(first)=first{ensure!(peer==first,"direct map changed target UDP port");}else{first=Some(peer);}
                echo.send_to(&data[..size],peer).await?;
            }
            Ok::<_,anyhow::Error>(())
        });
        let key=eztunnel::tunnel_key::TunnelKey::generate()?.display();
        let(_sd,server)=config(json!({"mode":"server","tunnel_key":key,"worker_threads":2,"heartbeat_sec":1,"dead_timeout_sec":3,
          "listeners":[{"addr":format!("127.0.0.1:{tunnel}"),"maps":[{"type":"udp","bind":format!("127.0.0.1:{map}"),"target":target.to_string()}]}],
          "gaming":{"control_address":format!("127.0.0.1:{control}"),"udp_bind":format!("127.0.0.1:{server_udp}"),"renewal_sec":5}}))?;
        let(_cd,client)=config(json!({"mode":"client","tunnel_key":key,"paths":[{"addr":proxy_address.to_string(),"retry_interval":1,"connection_pool":1}],"allowed_targets":[target.to_string()],
          "gaming":{"control_address":format!("127.0.0.1:{control}"),"udp_bind":format!("127.0.0.1:{client_udp}"),"renewal_sec":5}}))?;
        struct Abort(tokio::task::JoinHandle<()>);impl Drop for Abort{fn drop(&mut self){self.0.abort();}}
        let _server=Abort(tokio::spawn(async move{if let Err(error)=eztunnel::engine::run(server).await{eprintln!("server:{error:#}");}}));
        let _client=Abort(tokio::spawn(async move{if let Err(error)=eztunnel::engine::run(client).await{eprintln!("client:{error:#}");}}));
        let proxy_abort=proxy_task.abort_handle();
        struct ProxyAbort(tokio::task::AbortHandle);impl Drop for ProxyAbort{fn drop(&mut self){self.0.abort();}}
        let _proxy=ProxyAbort(proxy_abort);
        // Let mutually authenticated UDP path validation finish before opening map.
        sleep(Duration::from_secs(1)).await;
        let socket=UdpSocket::bind("127.0.0.1:0").await?;socket.connect(format!("127.0.0.1:{map}")).await?;
        for index in 0..36u8 {
            if index==12 {ensure!(connections.load(std::sync::atomic::Ordering::Relaxed)>0,"reliable session never established");cut.send(()).await?;}
            let payload=vec![index;400];socket.send(&payload).await?;let mut data=[0;2048];
            let size=timeout(Duration::from_secs(2),socket.recv(&mut data)).await??;
            ensure!(&data[..size]==payload.as_slice(),"map lost UDP payload");
            sleep(Duration::from_millis(250)).await;
        }
        ensure!(connections.load(std::sync::atomic::Ordering::Relaxed)>=2,"reliable session never reconnected after forced cut");
        echo_task.await??;Ok::<_,anyhow::Error>(())
    }).await??;Ok(())
}
