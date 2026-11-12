//! Shared explicit final action for saved tunnel setup, regardless of code type.
use super::{service,store::Store,ui};
use anyhow::{Result,ensure};

#[derive(Debug,Clone,Copy,PartialEq,Eq)]
pub(super) enum SaveAction{Start,SaveOnly}
fn action_at(system:bool,index:usize)->Option<SaveAction>{match(system,index){(true,0)=>Some(SaveAction::Start),(true,1)|(false,0)=>Some(SaveAction::SaveOnly),_=>None}}

pub(super) fn choose(store:&Store)->Result<Option<SaveAction>>{
    let rows=if store.system{vec!["Save and start  install the service and connect to the peer".into(),"Save only  start later from Manage tunnels".into(),"Back".into()]}
        else{vec!["Save only  systemd is unavailable; no service will be started".into(),"Back".into()]};
    Ok(ui::choose("Finish setup",&rows,0)?.and_then(|index|action_at(store.system,index)))
}

#[cfg(test)]mod tests{
    use super::*;
    #[test]fn default_action_starts_only_when_systemd_is_available(){
        assert_eq!(action_at(true,0),Some(SaveAction::Start));assert_eq!(action_at(true,1),Some(SaveAction::SaveOnly));
        assert_eq!(action_at(false,0),Some(SaveAction::SaveOnly));assert_eq!(action_at(false,1),None);assert_eq!(action_at(true,2),None);
    }
    #[test]fn save_only_never_starts_and_failures_are_not_reported_as_success(){
        assert!(!finish_start(SaveAction::SaveOnly,||panic!("must not start"),||panic!("must not watch")).unwrap());
        assert!(finish_start(SaveAction::Start,||anyhow::bail!("unit failure"),||panic!("do not watch failed startup")).unwrap_err().to_string().contains("Configuration saved"));
        assert!(finish_start(SaveAction::Start,||Ok(()),||false).is_err());
        assert!(finish_start(SaveAction::Start,||Ok(()),||true).unwrap());
    }
}
pub(super) fn save(store:&Store,name:&str,config:&serde_json::Value,action:SaveAction)->Result<()> {
    super::plan::check(config)?;
    ensure!(!store.exists(name),"a tunnel with this name already exists");
    store.save(name,config)?;
    ui::ok(&format!("Saved {}",store.path(name).display()));
    if finish_start(action,||service::start_saved(store,name),||service::watch_started(||service::state(store,name)==service::State::Running,std::thread::sleep))?{
        ui::ok("Service is running. Waiting for the other endpoint until Live status confirms an authenticated link.");
    }else{ui::note("Saved only. Start later through Manage tunnels.");}
    Ok(())
}
fn finish_start(action:SaveAction,start:impl FnOnce()->Result<()>,healthy:impl FnOnce()->bool)->Result<bool>{
    if action==SaveAction::SaveOnly{return Ok(false);}
    start().map_err(|error|anyhow::anyhow!("Configuration saved, but startup failed: {error:#}. Open Manage tunnels -> Live logs; do not recreate the tunnel."))?;
    ensure!(healthy(),"Configuration saved, but the service did not stay running. Open Manage tunnels -> Live logs for the startup error.");Ok(true)
}
