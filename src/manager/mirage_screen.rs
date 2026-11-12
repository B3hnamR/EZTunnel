//! Checker-style bounded viewport for Mirage progress and saved measurements.
use crate::{spoof_session::{self,Invitation,Report},spoof_test::Row};
use anyhow::Result;
use console::{Key,Term,style};
use std::{path::Path,process::{Child,ExitStatus},time::{Duration,Instant}};

struct Terminal{term:Term,#[cfg(unix)]original:Option<libc::termios>}
impl Terminal{
    fn open()->Self{
        let term=Term::stderr();
        #[cfg(unix)]let original=unsafe{
            let mut value=std::mem::MaybeUninit::<libc::termios>::uninit();
            if libc::tcgetattr(libc::STDIN_FILENO,value.as_mut_ptr())==0{
                let old=value.assume_init();let mut raw=old;
                raw.c_lflag&=!(libc::ICANON|libc::ECHO|libc::ISIG);raw.c_iflag&=!(libc::IXON|libc::ICRNL);
                raw.c_cc[libc::VMIN]=1;raw.c_cc[libc::VTIME]=0;
                if libc::tcsetattr(libc::STDIN_FILENO,libc::TCSANOW,&raw)==0{Some(old)}else{None}
            }else{None}
        };
        let _=term.write_str("\x1b[?1049h");let _=term.hide_cursor();Self{term,#[cfg(unix)]original}
    }
    fn draw(&self,lines:&[String]){let(rows,cols)=self.term.size();let width=usize::from(cols).saturating_sub(1).max(1);let _=self.term.clear_screen();
        for line in lines.iter().take(usize::from(rows).saturating_sub(1)){let _=self.term.write_line(&console::truncate_str(line,width,"…"));}}
    fn key(&self)->Result<Option<Key>>{
        #[cfg(unix)]{
            let mut fd=libc::pollfd{fd:libc::STDIN_FILENO,events:libc::POLLIN,revents:0};
            let ready=unsafe{libc::poll(&mut fd,1,200)};
            if ready<=0{return Ok(None);}
        }
        #[cfg(not(unix))]std::thread::sleep(Duration::from_millis(200));
        Ok(Some(self.term.read_key()?))
    }
}
impl Drop for Terminal{fn drop(&mut self){
    #[cfg(unix)]if let Some(original)=&self.original{unsafe{libc::tcsetattr(libc::STDIN_FILENO,libc::TCSANOW,original);}}
    let _=self.term.show_cursor();let _=self.term.write_str("\x1b[?1049l");}}

#[derive(Default)]
struct Screen{reverse:bool,selected:usize,working:bool,details:bool,log:bool,confirm:Option<Instant>}
fn rows(report:&Report,reverse:bool)->&[Row]{if reverse{&report.foreign_bound}else{&report.iran_bound}}
fn indices(report:&Report,state:&Screen)->Vec<usize>{let list=rows(report,state.reverse);Report::ranked(list).into_iter().filter(|index|!state.working||(list[*index].received>0&&list[*index].error.is_none())).collect()}
fn label(row:&Row)->(&'static str,console::Color){
    use console::Color;
    if row.error.is_some(){("Error",Color::Red)}else if row.stage!="authenticated-interface-admission"{("Received; awaiting RTT",Color::Yellow)}else if row.received==0{("No receipt",Color::Red)}else if row.received<usize::from(row.sent){("Lossy sample",Color::Yellow)}else if row.raw_reply_received<usize::from(row.sent){("Return lossy",Color::Yellow)}else{("Passed sample",Color::Green)}
}
fn lines(report:Option<&Report>,state:&mut Screen,size:(u16,u16),elapsed:u64,totals:(usize,usize),running:bool,logs:&[String])->Vec<String>{
    let mut out=vec![format!("  {}   {}   {}s",style("Mirage source tests").bold(),if running{style(if report.is_some(){"Running"}else{"Waiting for other server"}).cyan().to_string()}else if report.is_some_and(|r|r.finished){style("Finished sample").green().to_string()}else{style("Stopped / partial").yellow().to_string()},elapsed)];
    let observed=report.map_or(0,|r|r.iran_bound.len()+r.foreign_bound.len());let total=totals.0+totals.1;
    let final_rows=report.map_or(0,|r|r.iran_bound.iter().chain(&r.foreign_bound).filter(|row|row.stage=="authenticated-interface-admission").count());
    out.push(format!("  {observed}/{total} cases observed; {final_rows} final RTT reports. {}",if state.reverse{"Iran -> Foreign"}else{"Foreign -> Iran"}));
    out.push(format!("  {}",style("Source IP        Profile  Recv   Loss   Return  p95 RTT   Result").bold()));
    let room=usize::from(size.0).saturating_sub(if state.details||state.log{15}else{9}).clamp(1,20);
    if let Some(report)=report{
        let list=rows(report,state.reverse);let indices=indices(report,state);state.selected=state.selected.min(indices.len().saturating_sub(1));
        let first=state.selected.saturating_sub(room/2).min(indices.len().saturating_sub(room));
        for(position,index)in indices.iter().enumerate().skip(first).take(room){let row=&list[*index];let(status,color)=label(row);
            out.push(format!(" {} {:<15} {:<8} {:>2}/{:<2} {:>4.0}% {:>2}/{:<2} {:>8}  {}",if position==state.selected{style("›").cyan().bold().to_string()}else{" ".into()},row.source,format!("{:?}",row.profile).to_lowercase(),row.received,row.sent,row.loss_percent,row.raw_reply_received,row.sent,row.rtt_p95_ms.map(|n|format!("{n:.1}ms")).unwrap_or_else(||"-".into()),style(status).fg(color)));
        }
        if indices.is_empty(){out.push("  No rows in this direction/filter yet.".into());}
        out.push(format!("  Rows {}-{} / {}   Filter: {}",if indices.is_empty(){0}else{first+1},(first+room).min(indices.len()),indices.len(),if state.working{"received only"}else{"all results"}));
        if state.details&&let Some(index)=indices.get(state.selected){let row=&list[*index];out.push(format!("  Selected: {} {:?} / {}",row.source,row.profile,row.stage));out.push(format!("  One-way loss: {:.1}%; return loss: {:.1}%; median RTT: {}",row.loss_percent,row.raw_reply_loss_percent,row.rtt_median_ms.map(|n|format!("{n:.1}ms")).unwrap_or_else(||"not available".into())));if let Some(error)=&row.error{out.push(format!("  Error: {error}"));}}
        if let Some(error)=&report.error{out.push(format!("  {}",style(error).red()));}
    }else{out.push("  Keep this screen open; the peer must join with the invitation.".into());}
    if state.log{out.push("  Recent worker log (not a test success indicator):".into());out.extend(logs.iter().rev().take(4).collect::<Vec<_>>().into_iter().rev().map(|line|format!("  {}",style(line).dim())));}
    out.push(format!("  {}",style("A sample is not long-run stability or a verified forwarding tunnel.").dim()));
    out.push(if state.confirm.is_some(){"  Press q again within5s to stop; completed rows stay saved.".into()}else if running{"  [↑↓] select  [Tab] direction  [w] received filter  [d] details  [l] log  [q] stop".into()}else{"  [↑↓] select  [Tab] direction  [w] filter  [d] details  [Enter] result actions  [q] back".into()});
    out
}
fn log_tail(path:&Path)->Vec<String>{
    use std::io::{Read,Seek,SeekFrom};
    let Ok(mut file)=std::fs::File::open(path)else{return vec![];};let length=file.metadata().map_or(0,|m|m.len());let _=file.seek(SeekFrom::Start(length.saturating_sub(8192)));let mut text=String::new();let _=file.read_to_string(&mut text);
    text.lines().rev().take(4).map(str::to_string).collect::<Vec<_>>().into_iter().rev().collect()
}
pub(super) fn watch(child:&mut Child,path:&Path,log:&Path,invite:&Invitation,host:bool)->Result<ExitStatus>{
    let terminal=Terminal::open();let mut screen=Screen::default();let started=Instant::now();
    let totals=(invite.foreign_sources.len()*invite.profiles.len(),invite.iran_sources.len()*invite.profiles.len());
    loop{
        if let Some(status)=child.try_wait()?{return Ok(status);}
        if screen.confirm.is_some_and(|t|t.elapsed()>Duration::from_secs(5)){screen.confirm=None;}
        let report=spoof_session::read_private::<Report>(path).ok();
        let mut display=lines(report.as_ref(),&mut screen,terminal.term.size(),started.elapsed().as_secs(),totals,true,&log_tail(log));
        if host{display.insert(1,"  [i] Show invitation / Foreign joining instructions".into());}
        terminal.draw(&display);
        if let Some(key)=terminal.key()?{
            match key{
                Key::ArrowDown=>screen.selected=screen.selected.saturating_add(1),Key::ArrowUp=>screen.selected=screen.selected.saturating_sub(1),
                Key::Tab=>{screen.reverse=!screen.reverse;screen.selected=0;},Key::Char('w')=>{screen.working=!screen.working;screen.selected=0;},Key::Char('d')=>screen.details=!screen.details,Key::Char('l')=>screen.log=!screen.log,
                Key::Char('i') if host=>{
                    // Leave the alternate viewport so the whole copyable code
                    // remains in ordinary scrollback instead of being clipped
                    // to table width or overwritten on the next refresh.
                    terminal.term.write_str("\x1b[?1049l")?;
                    terminal.term.write_line("\nForeign: sudo eztunnel spooftest menu -> Join on Foreign")?;
                    match invite.encode(){
                        Ok(code)=>{
                            terminal.term.write_line("Secret test invitation (ten-minute, one-run joining window):")?;
                            terminal.term.write_line(&code)?;
                        }
                        Err(_)=>terminal.term.write_line("This invitation has expired. A peer already joined can finish; otherwise cancel and start a new test.")?,
                    }
                    terminal.term.write_line("Press Enter to return to the live table. The test worker continues; no second listener is started.")?;
                    terminal.term.flush()?;
                    let interaction=(||->Result<()>{loop{
                        if child.try_wait()?.is_some(){break;}
                        if let Some(key)=terminal.key()?{if matches!(key,Key::Enter|Key::Escape|Key::Char('i')|Key::Char('q')){break;}
                            if matches!(key,Key::CtrlC){
                                #[cfg(unix)]unsafe{libc::kill(child.id()as i32,libc::SIGINT);}
                                #[cfg(not(unix))]child.kill()?;
                                break;
                            }
                        }
                    }Ok(())})();
                    terminal.term.write_str("\x1b[?1049h")?;
                    interaction?;
                }
                Key::CtrlC|Key::Char('q')|Key::Escape=>{
                    if matches!(key,Key::CtrlC)||screen.confirm.is_some(){
                        #[cfg(unix)]unsafe{libc::kill(child.id()as i32,libc::SIGINT);}
                        #[cfg(not(unix))]child.kill()?;
                        let until=Instant::now()+Duration::from_secs(5);while Instant::now()<until{if let Some(status)=child.try_wait()?{return Ok(status);}std::thread::sleep(Duration::from_millis(50));}
                        child.kill()?;return Ok(child.wait()?);
                    }screen.confirm=Some(Instant::now());
                }
                _=>screen.confirm=None,
            }
        }
    }
}
/// Returns the original report-row index in the selected direction, not a
/// display/filter index, so actions cannot target the wrong source IP.
pub(super) fn select(report:&Report)->Result<Option<(bool,usize)>>{
    let terminal=Terminal::open();let mut state=Screen::default();let totals=(report.iran_bound.len(),report.foreign_bound.len());
    loop{terminal.draw(&lines(Some(report),&mut state,terminal.term.size(),0,totals,false,&[]));
        match terminal.key()?{
            Some(Key::ArrowDown)=>state.selected=state.selected.saturating_add(1),Some(Key::ArrowUp)=>state.selected=state.selected.saturating_sub(1),
            Some(Key::Tab)=>{state.reverse=!state.reverse;state.selected=0;},Some(Key::Char('w'))=>{state.working=!state.working;state.selected=0;},Some(Key::Char('d'))=>state.details=!state.details,
            Some(Key::Enter)=>{if let Some(index)=indices(report,&state).get(state.selected){return Ok(Some((state.reverse,*index)));}},
            Some(Key::Escape|Key::Char('q')|Key::CtrlC)=>return Ok(None),_=>{},
        }
    }
}

#[cfg(test)]mod tests{
    use super::*;
    #[test]fn provisional_rows_are_not_final_or_healthy(){
        let row=Row{source:"192.0.2.1".parse().unwrap(),profile:crate::raw_packet::RawProfile::Tcp,direction:"test".into(),sent:5,received:5,loss_percent:0.0,stage:"receiving-case-complete-awaiting-sender-report".into(),error:None,raw_reply_received:0,raw_reply_loss_percent:100.0,rtt_median_ms:None,rtt_p95_ms:None};
        assert_eq!(label(&row).0,"Received; awaiting RTT");
    }
    #[test]fn viewport_handles_tiny_terminals_without_unbounded_rows(){
        let mut screen=Screen::default();let rendered=lines(None,&mut screen,(8,30),12,(175,7),true,&[]);assert!(rendered.len()<=8);
    }
    #[test]fn filtering_keeps_original_indices_and_marks_partial_results(){
        let make=|received|Row{source:"192.0.2.1".parse().unwrap(),profile:crate::raw_packet::RawProfile::Udp,direction:"test".into(),sent:5,received,loss_percent:if received==0{100.0}else{0.0},stage:"authenticated-interface-admission".into(),error:None,raw_reply_received:received,raw_reply_loss_percent:if received==0{100.0}else{0.0},rtt_median_ms:Some(80.0),rtt_p95_ms:Some(85.0)};
        let report=Report{session:"a".repeat(24),created_at:0,finished:false,depth:crate::spoof_session::Depth::Quick,iran:"192.0.2.1".parse().unwrap(),foreign:"192.0.2.2".parse().unwrap(),raw_port:45670,iran_bound:vec![make(0),make(5)],foreign_bound:vec![],error:None};
        let mut screen=Screen{working:true,..Screen::default()};assert_eq!(indices(&report,&screen),vec![1]);
        let rendered=lines(Some(&report),&mut screen,(24,80),5,(2,0),false,&[]).join("\n");assert!(rendered.contains("Stopped / partial")&&rendered.contains("Passed sample"));
    }
}
