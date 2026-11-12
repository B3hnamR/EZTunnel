//! Terminal look and prompts for the manager: the banner, colours and small prompt helpers.
//! Everything is drawn on standard error, like the prompts themselves.
use anyhow::{Context,Result};
use console::{Style, Term, style};
use dialoguer::{Input, Select, theme::ColorfulTheme};
use std::cell::RefCell;

#[derive(Clone)]
enum Answer {
    Choice(Option<usize>),
    Text(String),
    Confirm(bool),
    Multi(Vec<usize>),
}
#[derive(Default)]
struct History {
    answers: Vec<(String, Answer)>,
    cursor: usize,
}
impl Drop for Answer {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Answer::Text(text) = self {
            text.zeroize();
        }
    }
}
thread_local! {static HISTORY:RefCell<Option<History>>=const{RefCell::new(None)};}

fn remembered(prompt: &str) -> Option<Answer> {
    HISTORY.with(|cell| {
        let mut value = cell.borrow_mut();
        let history = value.as_mut()?;
        if let Some((old, answer)) = history.answers.get(history.cursor)
            && old == prompt
        {
            let answer = answer.clone();
            history.cursor += 1;
            return Some(answer);
        }
        history.answers.truncate(history.cursor);
        None
    })
}
fn remember(prompt: &str, answer: Answer) {
    HISTORY.with(|cell| {
        if let Some(history) = cell.borrow_mut().as_mut() {
            history.answers.truncate(history.cursor);
            history.answers.push((prompt.into(), answer));
            history.cursor += 1;
        }
    });
}

/// Replay only pure question forms. Callers commit their draft after success;
/// networking, file writes and service starts must stay outside this boundary.
pub fn form<T>(mut body: impl FnMut() -> Result<T>) -> Result<T> {
    if HISTORY.with(|cell| cell.borrow().is_some()) {
        return body();
    }
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            HISTORY.with(|cell| *cell.borrow_mut() = None);
        }
    }
    HISTORY.with(|cell| *cell.borrow_mut() = Some(History::default()));
    let _reset = Reset;
    loop {
        HISTORY.with(|cell| cell.borrow_mut().as_mut().unwrap().cursor = 0);
        match body() {
            Err(error) if is_back(&error) => {
                let previous = HISTORY.with(|cell| {
                    let mut value = cell.borrow_mut();
                    let history = value.as_mut().unwrap();
                    if history.cursor == 0 {
                        return false;
                    }
                    history.answers.truncate(history.cursor - 1);
                    true
                });
                if !previous {
                    return Err(error);
                }
            }
            result => return result,
        }
    }
}

/// Suspend draft-answer replay around consent and capability checks. Accepting an
/// earlier form answer must never implicitly accept a later risk disclaimer.
pub fn without_history<T>(body: impl FnOnce() -> Result<T>) -> Result<T> {
    let saved = HISTORY.with(|cell| cell.borrow_mut().take());
    let result = body();
    HISTORY.with(|cell| *cell.borrow_mut() = saved);
    result
}
pub fn remembered_multi(prompt: &str) -> Option<Vec<usize>> {
    match remembered(prompt) {
        Some(Answer::Multi(ref mut values)) => Some(std::mem::take(values)),
        _ => None,
    }
}
pub fn remember_multi(prompt: &str, values: &[usize]) {
    remember(prompt, Answer::Multi(values.to_vec()));
}

#[derive(Debug)]
pub struct Back;
impl std::fmt::Display for Back {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Back")
    }
}
impl std::error::Error for Back {}
pub fn is_back(error: &anyhow::Error) -> bool {
    error.is::<Back>()
}

fn navigation_row(text: &str) -> bool {
    let text = console::strip_ansi_codes(text);
    let text = text.trim().trim_start_matches('←').trim();
    text.eq_ignore_ascii_case("back")
        || text.starts_with("Back ")
        || text.eq_ignore_ascii_case("exit")
        || text.eq_ignore_ascii_case("cancel")
}

fn choice_rows(items: &[String]) -> (Vec<String>, bool) {
    let added = !items.iter().any(|text| navigation_row(text));
    let mut rows = items.to_vec();
    if added {
        rows.push(dim("← Back"));
    }
    (rows, added)
}

const LETTERS: [[&str; 6]; 8] = [
    // E
    [
        "███████╗",
        "██╔════╝",
        "█████╗  ",
        "██╔══╝  ",
        "███████╗",
        "╚══════╝",
    ],
    // Z
    [
        "███████╗",
        "╚══███╔╝",
        "  ███╔╝ ",
        " ███╔╝  ",
        "███████╗",
        "╚══════╝",
    ],
    // T
    [
        "████████╗",
        "╚══██╔══╝",
        "   ██║   ",
        "   ██║   ",
        "   ██║   ",
        "   ╚═╝   ",
    ],
    // U
    [
        "██╗   ██╗",
        "██║   ██║",
        "██║   ██║",
        "██║   ██║",
        "╚██████╔╝",
        " ╚═════╝ ",
    ],
    // N
    [
        "███╗   ██╗",
        "████╗  ██║",
        "██╔██╗ ██║",
        "██║╚██╗██║",
        "██║ ╚████║",
        "╚═╝  ╚═══╝",
    ],
    // N
    [
        "███╗   ██╗",
        "████╗  ██║",
        "██╔██╗ ██║",
        "██║╚██╗██║",
        "██║ ╚████║",
        "╚═╝  ╚═══╝",
    ],
    // E
    [
        "███████╗",
        "██╔════╝",
        "█████╗  ",
        "██╔══╝  ",
        "███████╗",
        "╚══════╝",
    ],
    // L
    [
        "██╗     ",
        "██║     ",
        "██║     ",
        "██║     ",
        "███████╗",
        "╚══════╝",
    ],
];

/// Colours from cyan to violet, one per column band of the logo.
const GRADIENT: [u8; 8] = [51, 45, 39, 33, 63, 99, 135, 171];

pub fn term() -> Term {
    Term::stderr()
}

pub fn theme() -> ColorfulTheme {
    ColorfulTheme {
        prompt_prefix: style("?".to_string()).for_stderr().cyan().bold(),
        active_item_prefix: style("❯".to_string()).for_stderr().cyan().bold(),
        active_item_style: Style::new().for_stderr().cyan().bold(),
        values_style: Style::new().for_stderr().cyan(),
        ..ColorfulTheme::default()
    }
}

fn logo_width() -> usize {
    LETTERS.iter().map(|letter| letter[0].chars().count()).sum()
}

/// Clears the screen and draws the logo, the version and a one-line status.
pub fn banner(status: &str) {
    let term = term();
    let _ = term.clear_screen();
    let wide = term.size().1 as usize >= logo_width() + 4;
    eprintln!();
    if wide {
        for row in 0..6 {
            let mut line = String::from("  ");
            for (index, letter) in LETTERS.iter().enumerate() {
                line.push_str(
                    &style(letter[row])
                        .for_stderr()
                        .color256(GRADIENT[index])
                        .bold()
                        .to_string(),
                );
            }
            eprintln!("{line}");
        }
    } else {
        eprintln!("  {}", style("E Z T U N N E L").for_stderr().cyan().bold());
    }
    let version = format!("v{}", env!("CARGO_PKG_VERSION"));
    eprintln!(
        "  {}  {}  {}",
        style(version).for_stderr().black().on_cyan().bold(),
        style("Encrypted tunnels, made simple").for_stderr().white(),
        style(status).for_stderr().dim()
    );
    eprintln!(
        "  {}",
        style("made by B3hnamR · Telegram @B3hnamR")
            .for_stderr()
            .dim()
    );
    rule();
}

pub fn rule() {
    let width = (term().size().1 as usize).clamp(20, 74);
    eprintln!("{}", style("─".repeat(width)).for_stderr().dim());
}

/// A screen heading such as "New tunnel · step 2 of 6".
pub fn heading(title: &str, detail: &str) {
    eprintln!();
    if detail.is_empty() {
        eprintln!("  {}", style(title).for_stderr().cyan().bold());
    } else {
        eprintln!(
            "  {}  {}",
            style(title).for_stderr().cyan().bold(),
            style(detail).for_stderr().dim()
        );
    }
    eprintln!();
}

pub fn note(text: &str) {
    for line in text.lines() {
        eprintln!("  {}", style(line).for_stderr().dim());
    }
}

pub fn info(text: &str) {
    eprintln!("  {} {text}", style("›").for_stderr().cyan().bold());
}

pub fn ok(text: &str) {
    eprintln!("  {} {text}", style("✔").for_stderr().green().bold());
}

pub fn warn(text: &str) {
    eprintln!("  {} {text}", style("!").for_stderr().yellow().bold());
}

pub fn fail(text: &str) {
    eprintln!("  {} {text}", style("✘").for_stderr().red().bold());
}

/// A framed block that stands out, used for the tunnel key and summaries.
pub fn boxed(title: &str, lines: &[String]) {
    let width = lines
        .iter()
        .map(|line| console::measure_text_width(line))
        .chain([console::measure_text_width(title) + 2])
        .max()
        .unwrap_or(0)
        + 2;
    let edge = Style::new().for_stderr().cyan();
    let title_width = console::measure_text_width(title);
    eprintln!(
        "  {}{}{}",
        edge.apply_to("╭─ "),
        style(title).for_stderr().bold(),
        edge.apply_to(format!(
            " {}╮",
            "─".repeat(width.saturating_sub(title_width + 2))
        ))
    );
    for line in lines {
        let pad = width - console::measure_text_width(line) - 1;
        eprintln!(
            "  {} {line}{}{}",
            edge.apply_to("│"),
            " ".repeat(pad),
            edge.apply_to("│")
        );
    }
    eprintln!("  {}", edge.apply_to(format!("╰{}╯", "─".repeat(width))));
}

pub fn bold(text: &str) -> String {
    style(text).for_stderr().bold().to_string()
}

pub fn accent(text: &str) -> String {
    style(text).for_stderr().cyan().bold().to_string()
}

pub fn dim(text: &str) -> String {
    style(text).for_stderr().dim().to_string()
}

pub fn green(text: &str) -> String {
    style(text).for_stderr().green().to_string()
}

pub fn red(text: &str) -> String {
    style(text).for_stderr().red().to_string()
}

pub fn yellow(text: &str) -> String {
    style(text).for_stderr().yellow().to_string()
}

/// A list choice. Returns `None` when the user presses Esc or q to go back.
pub fn choose(prompt: &str, items: &[String], default: usize) -> Result<Option<usize>> {
    if let Some(Answer::Choice(choice)) = remembered(prompt) {
        return Ok(choice);
    }
    let (rows, added) = choice_rows(items);
    let choice = Select::with_theme(&theme())
        .with_prompt(prompt)
        .items(&rows)
        .default(default.min(items.len().saturating_sub(1)))
        .max_length((term().size().0 as usize).saturating_sub(14).clamp(6, 40))
        .report(false)
        .interact_opt()?;
    let choice = choice.filter(|index| !added || *index < items.len());
    if let Some(index) = choice {
        // Confirm with the short name only, not the explanation after it.
        let plain = console::strip_ansi_codes(&items[index]).into_owned();
        let short = plain.split("  ").next().unwrap_or(&plain).trim();
        eprintln!(
            "{} {} {} {}",
            style("✔").for_stderr().green().bold(),
            style(prompt).for_stderr().bold(),
            style("·").for_stderr().dim(),
            style(short).for_stderr().cyan()
        );
    }
    if choice.is_some_and(|i| !navigation_row(&items[i])) {
        remember(prompt, Answer::Choice(choice));
    }
    Ok(choice)
}

/// A required answer can propagate Back instead of trapping the user in a loop.
pub fn choose_required(prompt: &str, items: &[String], default: usize) -> Result<usize> {
    choose(prompt, items, default)?.ok_or_else(|| Back.into())
}

/// A line of text, checked by `check` before it is accepted.
pub fn ask<F>(prompt: &str, default: Option<&str>, mut check: F) -> Result<String>
where
    F: FnMut(&String) -> std::result::Result<(), String>,
{
    if let Some(Answer::Text(ref mut text)) = remembered(prompt) {
        return Ok(std::mem::take(text));
    }
    let theme = theme();
    let mut input = Input::<String>::with_theme(&theme)
        .with_prompt(format!("{prompt} (/back = previous page)"))
        .validate_with(move |text: &String| {
            if text.trim() == "/back" {
                Ok(())
            } else {
                check(text)
            }
        });
    if let Some(value) = default {
        input = input.default(value.to_string());
    }
    let text = input.interact_text()?.trim().to_string();
    if text == "/back" {
        return Err(Back.into());
    }
    remember(prompt, Answer::Text(text.clone()));
    Ok(text)
}

/// Typed and pasted text is always shown in full, wrapped over as many rows as
/// needed and redrawn in place. Nothing typed or pasted is ever hidden.
pub fn paste<F,S>(prompt:&str,mut check:F,summary:S)->Result<String>
where F:FnMut(&String)->std::result::Result<(),String>,S:Fn(&str)->String {
    paste_mode(prompt,&mut check,summary,"Paste the code, then press Enter. What you paste is shown below. /back returns.")
}
pub fn paste_sources<F,S>(prompt:&str,mut check:F,summary:S)->Result<String>
where F:FnMut(&String)->std::result::Result<(),String>,S:Fn(&str)->String {
    paste_mode(prompt,&mut check,summary,"Type or paste source IPs, then press Enter. What you type is shown below. /back returns.")
}
fn paste_mode<F,S>(prompt:&str,check:&mut F,summary:S,hint:&str)->Result<String>
where F:FnMut(&String)->std::result::Result<(),String>,S:Fn(&str)->String {
    if let Some(Answer::Text(ref mut text))=remembered(prompt){return Ok(std::mem::take(text));}
    note(hint);
    loop{
        term().write_line(&format!("{} {}:",style("?").for_stderr().cyan(),style(prompt).for_stderr().bold()))?;
        let Some(text)=read_paste_line()? else{return Err(Back.into());};
        let text=text.trim().to_string();
        if text=="/back"{return Err(Back.into());}
        match check(&text){
            Ok(())=>{
                eprintln!("{} {} {} {}",style("✔").for_stderr().green().bold(),style(prompt).for_stderr().bold(),style("·").for_stderr().dim(),style(summary(&text)).for_stderr().cyan());
                remember(prompt,Answer::Text(text.clone()));return Ok(text);
            }
            Err(error)=>fail(&error),
        }
    }
}

/// Read directly from the foreground terminal rather than mixing stdio's
/// canonical line buffer with dialoguer's per-key input. Never flush queued
/// bytes when opening the prompt: a fast paste may already be waiting.
#[cfg(unix)]
fn read_paste_line()->Result<Option<String>>{
    use std::os::fd::{AsRawFd,FromRawFd};
    let tty=if unsafe{libc::isatty(libc::STDIN_FILENO)}==1{None}else{
        let fd=unsafe{libc::open(c"/dev/tty".as_ptr(),libc::O_RDWR|libc::O_CLOEXEC|libc::O_NOCTTY)};
        if fd<0{return Err(std::io::Error::last_os_error()).context("Open an interactive terminal to paste input");}
        Some(unsafe{std::os::fd::OwnedFd::from_raw_fd(fd)})
    };
    let fd=tty.as_ref().map_or(libc::STDIN_FILENO,|fd|fd.as_raw_fd());
    let mut saved=std::mem::MaybeUninit::<libc::termios>::uninit();
    if unsafe{libc::tcgetattr(fd,saved.as_mut_ptr())}!=0{return Err(std::io::Error::last_os_error()).context("Read terminal input settings");}
    let saved=unsafe{saved.assume_init()};
    struct Restore{fd:libc::c_int,saved:libc::termios}
    impl Drop for Restore{fn drop(&mut self){unsafe{libc::tcsetattr(self.fd,libc::TCSANOW,&self.saved);}let _=term().write_str("\x1b[?2004l");}}
    let mut raw=saved;raw.c_lflag&=!(libc::ICANON|libc::ECHO|libc::ISIG);raw.c_iflag&=!(libc::IXON|libc::ICRNL|libc::INLCR);raw.c_cc[libc::VMIN]=1;raw.c_cc[libc::VTIME]=0;
    if unsafe{libc::tcsetattr(fd,libc::TCSANOW,&raw)}!=0{return Err(std::io::Error::last_os_error()).context("Enable terminal paste input");}
    let _restore=Restore{fd,saved};
    term().write_str("\x1b[?2004h")?;
    let mut state=PasteInput::default();
    let mut rows=0;
    draw_paste(&state.bytes,&mut rows,true)?;
    loop{
        let mut input=[0u8;1024];
        let count=unsafe{libc::read(fd,input.as_mut_ptr().cast(),input.len())};
        if count<0{let error=std::io::Error::last_os_error();if error.kind()==std::io::ErrorKind::Interrupted{continue;}return Err(error.into());}
        if count==0{return Err(anyhow::anyhow!("Terminal closed before input was submitted"));}
        for byte in &input[..count as usize]{
            match state.feed(*byte)?{PasteStep::More=>{},PasteStep::Cancel=>{
                draw_paste(&state.bytes,&mut rows,false)?;term().write_str("\r\n")?;return Ok(None);
            },PasteStep::Submit=>{
                draw_paste(&state.bytes,&mut rows,false)?;term().write_str("\r\n")?;
                return Ok(Some(String::from_utf8(state.bytes).context("Paste must be valid UTF-8")?));
            }}
        }
        draw_paste(&state.bytes,&mut rows,true)?;
    }
}
#[cfg(not(unix))]
fn read_paste_line()->Result<Option<String>>{Ok(Some(term().read_line()?))}

/// The whole input, hard-wrapped to `width` columns, then (while editing) a
/// status row with the character count.
fn paste_rows(bytes:&[u8],width:usize,status:bool)->Vec<String>{
    let text=String::from_utf8_lossy(bytes);
    let characters=std::iter::once('>').chain(std::iter::once(' ')).chain(text.chars().filter(|c|!c.is_control())).collect::<Vec<_>>();
    let mut rows=characters.chunks(width.max(1)).map(|row|row.iter().collect::<String>()).collect::<Vec<_>>();
    if status{rows.push(format!("  [{} chars] Enter submits",characters.len()-2));}
    rows
}
/// Redraws the input in place: back to its first row, clear below, write it again.
fn draw_paste(bytes:&[u8],drawn:&mut usize,status:bool)->Result<()>{
    let terminal=term();let (height,width)=terminal.size();
    let mut rows=paste_rows(bytes,usize::from(width).saturating_sub(1).max(10),status);
    // While editing, rows that would scroll off the top could not be redrawn;
    // keep what fits. The final submitted text is printed in full.
    let fit=usize::from(height).saturating_sub(3).max(2);
    if status&&rows.len()>fit{rows.drain(..rows.len()-fit);}
    let mut out=String::new();
    if *drawn>1{out.push_str(&format!("\x1b[{}A",*drawn-1));}
    out.push_str("\r\x1b[J");out.push_str(&rows.join("\r\n"));
    terminal.write_str(&out)?;terminal.flush()?;*drawn=rows.len();Ok(())
}

#[derive(Default)]
struct PasteInput{bytes:Vec<u8>,escape:Vec<u8>,bracketed:bool}
enum PasteStep{More,Submit,Cancel}
impl PasteInput{
    fn feed(&mut self,byte:u8)->Result<PasteStep>{
        if byte==3{return Ok(PasteStep::Cancel);}
        if byte==27||!self.escape.is_empty(){
            self.escape.push(byte);
            if self.escape==b"\x1b[200~"{self.bracketed=true;self.escape.clear();}
            else if self.escape==b"\x1b[201~"{self.bracketed=false;self.escape.clear();}
            else if self.escape.len()>16||(!b"\x1b[200~".starts_with(&self.escape)&&!b"\x1b[201~".starts_with(&self.escape)&&self.escape.len()>2){self.escape.clear();}
            return Ok(PasteStep::More);
        }
        match byte{
            b'\r'|b'\n' if !self.bracketed=>return Ok(PasteStep::Submit),
            4 if self.bytes.is_empty()=>return Ok(PasteStep::Cancel),
            8|127 if !self.bracketed=>{
                if !self.bytes.is_empty(){let mut start=self.bytes.len()-1;while start>0&&self.bytes[start]&0xc0==0x80{start-=1;}self.bytes.truncate(start);}
            },
            21 if !self.bracketed=>self.bytes.clear(),
            b'\r'|b'\n'|b'\t'=>{self.bytes.push(b' ');},
            0..=31=>{},
            _=>self.bytes.push(byte),
        }
        anyhow::ensure!(self.bytes.len()<=40000,"Paste is too long (maximum 40000 bytes). Input was not submitted.");
        Ok(PasteStep::More)
    }
}

/// Like `ask`, but an empty answer is allowed and returned as `None` (go back).
pub fn ask_or_back<F>(prompt: &str, default: Option<&str>, mut check: F) -> Result<Option<String>>
where
    F: FnMut(&String) -> std::result::Result<(), String>,
{
    if let Some(Answer::Text(ref mut text)) = remembered(prompt) {
        return Ok(Some(std::mem::take(text)));
    }
    let theme = theme();
    let mut input = Input::<String>::with_theme(&theme)
        .with_prompt(format!("{prompt} (empty or /back = previous page)"))
        .allow_empty(true)
        .validate_with(move |text: &String| {
            if text.trim().is_empty() || text.trim() == "/back" {
                Ok(())
            } else {
                check(text)
            }
        });
    if let Some(value) = default {
        input = input.default(value.to_string());
    }
    let text = input.interact_text()?.trim().to_string();
    if text.is_empty() || text == "/back" {
        return Ok(None);
    }
    remember(prompt, Answer::Text(text.clone()));
    Ok(Some(text))
}

pub fn confirm(prompt: &str, default: bool) -> Result<bool> {
    if let Some(Answer::Confirm(value)) = remembered(prompt) {
        return Ok(value);
    }
    let options = ["Yes", "No", "Back"];
    let value = Select::with_theme(&theme())
        .with_prompt(prompt)
        .items(options)
        .default(if default { 0 } else { 1 })
        .interact_opt()?;
    let value = match value {
        Some(0) => true,
        Some(1) => false,
        _ => return Err(Back.into()),
    };
    remember(prompt, Answer::Confirm(value));
    Ok(value)
}

pub fn pause() {
    eprintln!();
    eprint!("  {}", dim("Press Enter to continue"));
    let _ = term().read_line();
}

/// Makes Ctrl-C leave the menu cleanly: the cursor is shown again and the process exits.
pub fn exit_on_interrupt() {
    #[cfg(target_os = "linux")]
    {
        extern "C" fn leave(_: libc::c_int) {
            const SHOW_CURSOR: &[u8] = b"\x1b[?25h\n";
            // SAFETY: write and _exit are async-signal-safe; the buffer is a static constant.
            unsafe {
                libc::write(2, SHOW_CURSOR.as_ptr().cast(), SHOW_CURSOR.len());
                libc::_exit(130);
            }
        }
        // SAFETY: installs a handler that only calls async-signal-safe functions.
        unsafe {
            libc::signal(libc::SIGINT, leave as *const () as libc::sighandler_t);
        }
    }
}

/// Runs `body` while Ctrl-C only stops child programs (such as a log viewer), not the menu.
pub fn with_interrupt_for_children<T>(body: impl FnOnce() -> T) -> T {
    #[cfg(target_os = "linux")]
    {
        extern "C" fn ignore(_: libc::c_int) {}
        // SAFETY: the handler does nothing. A handler (unlike SIG_IGN) is reset to the default
        // in a started program, so the child still stops on Ctrl-C.
        unsafe {
            libc::signal(libc::SIGINT, ignore as *const () as libc::sighandler_t);
        }
        let result = body();
        exit_on_interrupt();
        result
    }
    #[cfg(not(target_os = "linux"))]
    body()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bracketed_multiline_paste_waits_for_explicit_enter_and_keeps_all_tokens(){
        let mut input=PasteInput::default();
        for byte in b"\x1b[200~198.51.100.1\r\n198.51.100.2\x1b[201~"{assert!(matches!(input.feed(*byte).unwrap(),PasteStep::More));}
        assert_eq!(String::from_utf8(input.bytes.clone()).unwrap(),"198.51.100.1  198.51.100.2");
        assert!(matches!(input.feed(b'\r').unwrap(),PasteStep::Submit));
    }
    #[test]
    fn paste_edits_cancellation_and_bounds_are_explicit(){
        let mut input=PasteInput::default();for byte in "abé".as_bytes(){input.feed(*byte).unwrap();}input.feed(127).unwrap();assert_eq!(input.bytes,b"ab");
        input.feed(21).unwrap();assert!(input.bytes.is_empty());assert!(matches!(input.feed(3).unwrap(),PasteStep::Cancel));
        input.bytes=vec![b'a';40000];assert!(input.feed(b'b').is_err());
    }
    #[test]
    fn paste_rows_show_every_character_typed(){
        let list=b"198.51.100.1,198.51.100.2";
        let short=paste_rows(list,100,true);assert_eq!(short[0],"> 198.51.100.1,198.51.100.2");assert!(short[1].contains(&format!("{} chars",list.len())));
        let code=format!("ezm-setup1-{}-END","x".repeat(500));
        let long=paste_rows(code.as_bytes(),80,false);
        assert!(long.iter().all(|row|row.chars().count()<=80));
        assert_eq!(long.concat(),format!("> {code}"));
    }
    #[test]
    fn back_is_visible_without_duplicate_rows_or_changed_existing_indices() {
        let items = vec!["One".into(), "Two".into()];
        let (rows, added) = choice_rows(&items);
        assert!(added);
        assert_eq!(&rows[..2], &items);
        assert!(navigation_row(rows.last().unwrap()));
        for terminal in ["← Back", "Back", "Exit", "Cancel"] {
            let items = vec!["One".into(), terminal.into()];
            let (rows, added) = choice_rows(&items);
            assert!(!added);
            assert_eq!(items, rows);
        }
    }
    #[test]
    fn form_replays_prior_answers_and_reopens_previous_question() {
        let mut attempts = 0;
        form(|| {
            attempts += 1;
            if attempts == 1 {
                remember("first", Answer::Text("kept".into()));
                remember("second", Answer::Text("old".into()));
                return Err(Back.into());
            }
            assert!(matches!(remembered("first"),Some(Answer::Text(ref text)) if text=="kept"));
            assert!(remembered("second").is_none());
            Ok(())
        })
        .unwrap();
        assert_eq!(attempts, 2);
        assert!(HISTORY.with(|cell| cell.borrow().is_none()));
        assert!(is_back(&form::<()>(|| Err(Back.into())).unwrap_err()));
    }
    #[test]
    fn sensitive_capability_checks_are_not_replayed_as_form_answers() {
        form(|| {
            remember("question", Answer::Text("draft".into()));
            without_history(|| {
                assert!(remembered("question").is_none());
                Ok(())
            })?;
            assert!(HISTORY.with(|cell| cell.borrow().as_ref().unwrap().answers.len() == 1));
            Ok(())
        })
        .unwrap();
    }
    #[test]
    fn logo_rows_line_up() {
        for letter in super::LETTERS {
            let width = letter[0].chars().count();
            assert!(letter.iter().all(|row| row.chars().count() == width));
        }
        assert!(super::logo_width() <= 76);
    }
}
