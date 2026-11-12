//! Real KCP/FEC streams with the optional scheduler, not merely formula tests.
use anyhow::{Result, ensure};
use eztunnel::{config::{ClientPath, Listener}, fec_carrier::{self, FecListener}};
use serde_json::json;
use std::time::Duration;
use tokio::{io::{AsyncReadExt, AsyncWriteExt}, time::timeout};

#[tokio::test(flavor="multi_thread", worker_threads=2)]
async fn adaptive_and_shared_allocation_transfer_multiple_conversations() -> Result<()> {
    timeout(Duration::from_secs(40), async {
        let adaptive=json!({"enabled":true,"shared_bandwidth":true,"min_rate":2_000_000,"max_rate":16_000_000});
        let settings:Listener=serde_json::from_value(json!({"addr":"127.0.0.1:0","transport":"fec-udp","maps":[],
            "fec":{"knock":false,"adaptive":adaptive}}))?;
        settings.fec.validate()?;
        let mut server=FecListener::bind(&settings).await?;
        let address=server.local_addr();
        let echo=tokio::spawn(async move {
            let mut tasks=Vec::new();
            for _ in 0..4 {
                let mut stream=server.accept().await?;
                tasks.push(tokio::spawn(async move {
                    let mut data=vec![0;262_144]; stream.read_exact(&mut data).await?;
                    stream.write_all(&data).await?; stream.flush().await?;
                    let mut done=[0;1]; stream.read_exact(&mut done).await?;
                    ensure!(done==[1],"missing final receipt");
                    Ok::<_,anyhow::Error>(())
                }));
            }
            for task in tasks {task.await??;}
            Ok::<_,anyhow::Error>(())
        });
        let mut clients=Vec::new();
        for index in 0..4 {
            let adaptive=adaptive.clone();
            clients.push(tokio::spawn(async move {
                let path:ClientPath=serde_json::from_value(json!({"addr":address.to_string(),"transport":"fec-udp",
                    "server_public_key":"00".repeat(32),"fec":{"knock":false,"adaptive":adaptive}}))?;
                let mut stream=fec_carrier::connect(&path).await?;
                let data=vec![index;262_144]; let mut received=vec![0;data.len()];
                stream.write_all(&data).await?; stream.flush().await?;
                stream.read_exact(&mut received).await?;
                ensure!(received==data,"adaptive stream changed payload");
                stream.write_all(&[1]).await?; stream.flush().await?;
                Ok::<_,anyhow::Error>(())
            }));
        }
        for client in clients {client.await??;}
        echo.await??;
        Ok::<_,anyhow::Error>(())
    }).await??;
    Ok(())
}

#[test]
fn conflicting_scheduler_owners_are_rejected_and_old_defaults_remain_off() -> Result<()> {
    let mut options=eztunnel::fec_carrier::FecOptions::default();
    assert!(!options.adaptive.enabled && !options.adaptive.shared_bandwidth);
    options.adaptive.enabled=true; options.pacer=true;
    assert!(options.validate().is_err()); options.pacer=false;
    options.tuner.mode=eztunnel::fec_carrier::FecTunerMode::Auto;
    assert!(options.validate().is_err());
    options.tuner.mode=eztunnel::fec_carrier::FecTunerMode::Off;
    options.congestion_control=Some(true); assert!(options.validate().is_err());
    options.congestion_control=Some(false); options.validate()?;
    Ok(())
}

#[tokio::test(flavor="multi_thread",worker_threads=2)]
async fn adaptive_stream_survives_deterministic_loss_duplicates_and_reordering()->Result<()> {
    use tokio::net::UdpSocket;
    use std::sync::Arc;
    timeout(Duration::from_secs(45),async {
        let settings:Listener=serde_json::from_value(json!({"addr":"127.0.0.1:0","transport":"fec-udp","maps":[],
            "fec":{"knock":false,"mtu":1200,"adaptive":{"enabled":true,"shared_bandwidth":true,"min_rate":500000,"max_rate":4000000}}}))?;
        let mut server=FecListener::bind(&settings).await?;
        let address=server.local_addr();
        let proxy=Arc::new(UdpSocket::bind("127.0.0.1:0").await?);let proxied=proxy.local_addr()?;
        let worker=tokio::spawn(async move {
            let mut bytes=[0;9216];let mut peer=None;let mut count=0u64;let mut delayed=None;
            loop {
                let(size,from)=proxy.recv_from(&mut bytes).await?;
                let destination=if from==address {let Some(peer)=peer else{continue;};peer}else{peer=Some(from);address};
                count+=1;
                // Loss applies to both data and ACKs, beyond FEC's one-loss case.
                if count%17==0 {continue;}
                if count%11==0 {delayed=Some((bytes[..size].to_vec(),destination));continue;}
                proxy.send_to(&bytes[..size],destination).await?;
                if count%23==0 {proxy.send_to(&bytes[..size],destination).await?;}
                if let Some((packet,target))=delayed.take(){proxy.send_to(&packet,target).await?;}
            }
            #[allow(unreachable_code)] Ok::<(),std::io::Error>(())
        });
        struct Abort(tokio::task::JoinHandle<Result<(),std::io::Error>>);impl Drop for Abort{fn drop(&mut self){self.0.abort();}}
        let _proxy=Abort(worker);
        let echo=tokio::spawn(async move {
            let mut stream=server.accept().await?;
            let(mut read,mut write)=tokio::io::split(&mut stream);
            tokio::io::copy(&mut read,&mut write).await?;
            Ok::<_,anyhow::Error>(())
        });
        let path:ClientPath=serde_json::from_value(json!({"addr":proxied.to_string(),"transport":"fec-udp","server_public_key":"00".repeat(32),
            "fec":{"knock":false,"mtu":1200,"adaptive":{"enabled":true,"shared_bandwidth":true,"min_rate":500000,"max_rate":4000000}}}))?;
        let stream=fec_carrier::connect(&path).await?;
        let(mut read,mut write)=tokio::io::split(stream);
        let payload=(0..1024*1024).map(|n|(n%251)as u8).collect::<Vec<_>>();let expected=payload.clone();
        let send=async {write.write_all(&payload).await?;write.flush().await?;Ok::<_,anyhow::Error>(())};
        let receive=async {let mut bytes=vec![0;expected.len()];read.read_exact(&mut bytes).await?;ensure!(bytes==expected,"loss recovery payload mismatch");Ok::<_,anyhow::Error>(())};
        tokio::try_join!(send,receive)?;echo.abort();Ok::<_,anyhow::Error>(())
    }).await??;Ok(())
}
