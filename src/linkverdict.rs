//! Turns a link-test report into a score, plain-language notes and advice on which carriers to try.
//!
//! The score is a rough guide to how usable the path looks for a tunnel; the thresholds below are
//! diagnostic rules of thumb, not tunnel settings. The advice only covers what the tester measures
//! (plain TCP and UDP on the tested ports): TLS, WebSocket and raw-packet carriers are not probed,
//! so a good verdict does not prove they pass.
use crate::linktest::{DatagramResult, LinkReport, MTU_SIZES};
use serde::Serialize;
use std::fmt::Write;

/// Scores at or above this are rated good, scores at or above `FAIR_FROM` fair, the rest poor.
pub const GOOD_FROM: u8 = 80;
pub const FAIR_FROM: u8 = 50;

/// Points taken off 100.
const TCP_FAILED: i32 = 30; // per direction
const UDP_NOTHING: i32 = 25; // per direction, when no datagram came back
const UDP_LOSS_CAP: i32 = 25; // per direction; loss of 1 % costs 2 points
const UDP_LOSS_PER_PERCENT: f64 = 2.;
const INTEGRITY: i32 = 30; // once, when any payload arrived changed
const HIGH_RTT: i32 = 10;
const SLOW_TRANSFER: i32 = 10; // per direction
const TRANSFER_FAILED: i32 = 20; // per direction: the transfer did not complete
const UDP_PROBE_ERROR: i32 = 10; // per direction: sending stopped on an error
const LOSS_ASYMMETRY: i32 = 5;
const SMALL_MTU: i32 = 5;
const EXTRA_PORT: i32 = 5; // per failing extra port, at most three counted

/// Thresholds for the rules above.
const HIGH_RTT_MS: f64 = 250.;
const SLOW_MBPS: f64 = 5.;
const ASYMMETRY_POINTS: f64 = 5.;
const BAD_LOSS_PERCENT: f64 = 10.;
const SOME_LOSS_PERCENT: f64 = 1.;
/// Path MTU below this is penalised; the sizes of the UDP carriers' defaults are quoted in advice.
const SMALL_PATH_MTU: usize = 1400;
const KCP_DEFAULT_MTU: usize = 1400;
const FEC_DEFAULT_MTU: usize = 1350;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Rating {
    Good,
    Fair,
    #[default]
    Poor,
}
impl Rating {
    fn of(score: i32) -> Self {
        if score >= i32::from(GOOD_FROM) {
            Self::Good
        } else if score >= i32::from(FAIR_FROM) {
            Self::Fair
        } else {
            Self::Poor
        }
    }
    fn label(self) -> &'static str {
        match self {
            Self::Good => "GOOD",
            Self::Fair => "FAIR",
            Self::Poor => "POOR",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Verdict {
    /// 0..=100.
    pub score: u8,
    pub rating: Rating,
    /// What was measured that is worth knowing.
    pub notes: Vec<String>,
    /// Which carriers and settings fit what was measured.
    pub advice: Vec<String>,
}

fn nothing_came_back(result: &DatagramResult) -> bool {
    result.received == 0
}

pub fn assess(report: &LinkReport) -> Verdict {
    let mut score = 100;
    let mut notes = Vec::new();
    let mut advice = Vec::new();

    // ---- TCP
    let tcp_out = report.tcp.ok;
    let tcp_in = report.reverse_tcp.ok;
    for (ok, error, what) in [
        (tcp_out, &report.tcp.error, "from here to the peer"),
        (tcp_in, &report.reverse_tcp.error, "from the peer to here"),
    ] {
        if !ok {
            score -= TCP_FAILED;
            notes.push(format!(
                "TCP does not connect {what}{}.",
                error
                    .as_deref()
                    .map(|e| format!(" ({e})"))
                    .unwrap_or_default()
            ));
        }
    }
    match (tcp_out, tcp_in) {
        (true, true) => advice.push(
            "TCP works both ways, so the tcp carrier can connect from either side. ws/wss, http/https and xhttp/xhttps ride on the same TCP path but were not tested here, and networks often treat them differently."
                .to_string(),
        ),
        (false, true) => advice.push(
            "TCP only works from the peer to here: let the peer be the side that dials (swap the tunnel direction)."
                .to_string(),
        ),
        (true, false) => advice.push(
            "TCP only works from here to the peer: let this machine be the side that dials (swap the tunnel direction). \
             If this machine's firewall blocks the test's local port, open it and test again: that makes the peer-to-here check fail too."
                .to_string(),
        ),
        (false, false) => advice.push(
            "TCP does not pass on this port in either direction: try another port (--extra-ports tests more of them). \
             If this machine's firewall blocks the test's local port, open it and test again."
                .to_string(),
        ),
    }

    // ---- UDP
    let mut losses = Vec::new();
    for (result, what) in [
        (&report.udp, "a round trip started here"),
        (&report.reverse_udp, "a round trip started by the peer"),
    ] {
        if nothing_came_back(result) {
            score -= UDP_NOTHING;
            notes.push(format!("No UDP datagram came back in {what}."));
        } else {
            let cost = (result.loss_percent * UDP_LOSS_PER_PERCENT).round() as i32;
            score -= cost.min(UDP_LOSS_CAP);
            if result.loss_percent > 0. {
                notes.push(format!(
                    "UDP lost {:.0} % of the datagrams in {what} ({} of {} came back).",
                    result.loss_percent, result.received, result.sent
                ));
            }
            losses.push(result.loss_percent);
        }
    }
    if let [a, b] = losses[..]
        && (a - b).abs() >= ASYMMETRY_POINTS
    {
        score -= LOSS_ASYMMETRY;
        notes.push(format!(
            "UDP loss differs a lot between the directions ({a:.0} % and {b:.0} %): the path treats them differently."
        ));
    }
    for (result, what) in [
        (&report.udp, "started here"),
        (&report.reverse_udp, "started by the peer"),
    ] {
        if let Some(error) = &result.error {
            score -= UDP_PROBE_ERROR;
            notes.push(format!(
                "The UDP probe {what} stopped on an error ({error}); its loss figure covers only the datagrams sent."
            ));
        }
    }
    let dead_here = nothing_came_back(&report.udp);
    let dead_there = nothing_came_back(&report.reverse_udp);
    let worst_loss = losses.iter().copied().fold(0., f64::max);
    if dead_here && dead_there {
        advice.push(
            "UDP does not get through on this port in either direction: kcp and fec-udp will not connect here, use a TCP-based carrier. \
             Another UDP port may behave differently (--extra-ports)."
                .to_string(),
        );
    } else if dead_here || dead_there {
        advice.push(
            "UDP gets through in one direction only; kcp and fec-udp need both, so use a TCP-based carrier on this path."
                .to_string(),
        );
    } else if worst_loss >= BAD_LOSS_PERCENT {
        advice.push(format!(
            "UDP loses up to {worst_loss:.0} %: kcp would be slow; fec-udp (it rebuilds lost packets) or a TCP-based carrier is the better choice."
        ));
    } else if worst_loss >= SOME_LOSS_PERCENT {
        advice.push(format!(
            "UDP loses up to {worst_loss:.0} %: kcp and fec-udp both work; fec-udp copes better with loss."
        ));
    } else {
        advice.push("UDP is clean: kcp and fec-udp are worth trying for speed.".to_string());
    }

    // ---- integrity
    let altered = (!report.udp.integrity && report.udp.received > 0)
        || (!report.reverse_udp.integrity && report.reverse_udp.received > 0)
        || (report.upload.bytes > 0 && !report.upload.integrity)
        || (report.download.bytes > 0 && !report.download.integrity);
    if altered {
        score -= INTEGRITY;
        notes.push(
            "Some test data arrived changed: something on the path rewrites traffic. Encrypted carriers detect that, but expect trouble."
                .to_string(),
        );
    }

    // ---- latency
    let rtt = [&report.udp, &report.reverse_udp]
        .into_iter()
        .filter(|r| r.received > 0)
        .map(|r| r.rtt_ms)
        .fold(None, |best: Option<f64>, v| {
            Some(best.map_or(v, |b| b.min(v)))
        })
        .or((report.tcp.ok).then_some(report.tcp.rtt_ms));
    if let Some(rtt) = rtt {
        notes.push(format!("Round trip time about {rtt:.0} ms."));
        if rtt > HIGH_RTT_MS {
            score -= HIGH_RTT;
            notes.push(
                "That is long: the UDP carriers' windows must cover bandwidth x round trip time (see \"Speed on long links\" in the configuration reference)."
                    .to_string(),
            );
        }
    }

    // ---- speed
    if report.quick {
        notes.push(
            "Speed was only sampled for a fraction of a second; run without --quick for a figure and a speed rating."
                .to_string(),
        );
    }
    for (result, what) in [
        (&report.upload, "Upload to the peer"),
        (&report.download, "Download from the peer"),
    ] {
        if result.bytes == 0 || result.error.is_some() {
            // Whatever the mode: a transfer that does not complete is a finding (a filter that
            // resets a connection after some data looks exactly like this).
            score -= TRANSFER_FAILED;
            notes.push(format!(
                "{what} did not complete{}.",
                result
                    .error
                    .as_deref()
                    .map(|e| format!(" ({e})"))
                    .unwrap_or_default()
            ));
        } else if !report.quick {
            notes.push(format!(
                "{what}: {:.1} Mbit/s over one TCP connection.",
                result.mbps
            ));
            if result.mbps < SLOW_MBPS {
                score -= SLOW_TRANSFER;
            }
        }
    }

    // ---- extra ports
    let mut failed_ports = 0;
    for port in &report.ports {
        if !(port.tcp.ok && port.udp.received == port.udp.sent && port.udp.sent > 0) {
            failed_ports += 1;
            notes.push(format!(
                "Port {}: TCP {}, UDP {} of {} came back.",
                port.port,
                if port.tcp.ok { "ok" } else { "failed" },
                port.udp.received,
                port.udp.sent
            ));
        }
    }
    score -= EXTRA_PORT * failed_ports.min(3);

    // ---- MTU
    if let Some(mtu) = &report.mtu {
        if let Some(error) = &mtu.error {
            notes.push(format!("The datagram size sweep failed: {error}."));
        } else if let Some(payload) = mtu.max_payload {
            let at_least = if mtu.at_ladder_top { "at least " } else { "" };
            notes.push(format!(
                "Largest UDP datagram that crosses the path in both directions: {at_least}{payload} bytes (path MTU {at_least}{}).",
                mtu.path_mtu.unwrap_or(payload + mtu.header_bytes)
            ));
            if let (Some(f), Some(r)) = (mtu.forward_max_payload, mtu.reverse_max_payload)
                && f != r
            {
                notes.push(format!(
                    "The two directions differ: {f} bytes from here, {r} bytes from the peer."
                ));
            }
            if !mtu.dont_fragment {
                notes.push(
                    "The don't-fragment bit could not be set on one of the machines, so the size may be too high."
                        .to_string(),
                );
            }
            if mtu.irregular {
                notes.push(
                    "A larger size got through after a smaller one failed (random loss or several paths with different limits); the figure stops at the first failure."
                        .to_string(),
                );
            }
            if !mtu.at_ladder_top && mtu.path_mtu.is_some_and(|path| path < SMALL_PATH_MTU) {
                score -= SMALL_MTU;
            }
            let mut too_big = Vec::new();
            if payload < KCP_DEFAULT_MTU {
                too_big.push(format!("kcp.mtu (default {KCP_DEFAULT_MTU})"));
            }
            if payload < FEC_DEFAULT_MTU {
                too_big.push(format!("fec.mtu (default {FEC_DEFAULT_MTU})"));
            }
            if too_big.is_empty() {
                advice.push(format!(
                    "The default packet sizes of the UDP carriers (kcp.mtu {KCP_DEFAULT_MTU}, fec.mtu {FEC_DEFAULT_MTU}) fit."
                ));
            } else {
                advice.push(format!(
                    "Set {} to {payload} or less on both servers: bigger packets do not cross this path.",
                    too_big.join(" and ")
                ));
            }
        } else if !(dead_here && dead_there) {
            notes.push(format!(
                "No datagram size of the sweep (smallest {} bytes) crossed the path in both directions.",
                MTU_SIZES[0]
            ));
        }
    }
    notes.push(
        "TLS, WebSocket and raw-packet carriers are not probed here; this verdict covers plain TCP and UDP only."
            .to_string(),
    );

    let score = score.clamp(0, 100);
    Verdict {
        score: score as u8,
        rating: Rating::of(score),
        notes,
        advice,
    }
}

/// Green/yellow/red, auto-disabled when stdout is not a terminal (piped, redirected, saved).
fn paint() -> console::Style {
    console::Style::new().for_stdout()
}

fn rating_style(rating: Rating) -> console::Style {
    match rating {
        Rating::Good => paint().green().bold(),
        Rating::Fair => paint().yellow().bold(),
        Rating::Poor => paint().red().bold(),
    }
}

fn rating_icon(rating: Rating) -> &'static str {
    match rating {
        Rating::Good => "✔",
        Rating::Fair => "~",
        Rating::Poor => "✘",
    }
}

/// TCP cell for the table: a colored icon plus the round trip time, or the error.
fn tcp_cell(check: &crate::linktest::CheckResult) -> String {
    if check.ok {
        format!(
            "{} {:.0} ms",
            paint().green().bold().apply_to("✔"),
            check.rtt_ms
        )
    } else {
        format!(
            "{} failed{}",
            paint().red().bold().apply_to("✘"),
            check
                .error
                .as_deref()
                .map(|e| format!(" ({e})"))
                .unwrap_or_default()
        )
    }
}

/// UDP cell for the table: a colored icon, the loss percentage, the round trip time.
fn udp_cell(result: &DatagramResult) -> String {
    if result.received == 0 {
        format!(
            "{} nothing came back (0/{}){}",
            paint().red().bold().apply_to("✘"),
            result.sent,
            result
                .error
                .as_deref()
                .map(|e| format!(" ({e})"))
                .unwrap_or_default()
        )
    } else {
        let clean = result.received == result.sent && result.integrity;
        let icon = if clean {
            paint().green().bold().apply_to("✔")
        } else {
            paint().yellow().bold().apply_to("~")
        };
        format!(
            "{icon} {}/{} ({:.0}% loss), {:.0} ms{}",
            result.received,
            result.sent,
            result.loss_percent,
            result.rtt_ms,
            if result.integrity {
                ""
            } else {
                " — data arrived changed!"
            }
        )
    }
}

/// The report as text for a person: the checks, the verdict, then notes and advice.
pub fn render(report: &LinkReport) -> String {
    let verdict = &report.verdict;
    let mut out = String::new();
    let _ = writeln!(
        out,
        "Link to {}   {} {}{}",
        paint().bold().apply_to(report.peer),
        rating_style(verdict.rating).apply_to(rating_icon(verdict.rating)),
        rating_style(verdict.rating).apply_to(format!(
            "{} ({}/100)",
            verdict.rating.label(),
            verdict.score
        )),
        if report.quick {
            format!("   {}", paint().dim().apply_to("[quick]"))
        } else {
            String::new()
        }
    );
    let _ = writeln!(
        out,
        "\n  TCP   started here: {:<34} started by the peer: {}",
        tcp_cell(&report.tcp),
        tcp_cell(&report.reverse_tcp)
    );
    let _ = writeln!(
        out,
        "  UDP   started here: {:<34} started by the peer: {}",
        udp_cell(&report.udp),
        udp_cell(&report.reverse_udp)
    );
    if !report.quick && report.upload.bytes > 0 && report.download.bytes > 0 {
        let _ = writeln!(
            out,
            "  Speed upload {:.1} Mbit/s, download {:.1} Mbit/s (one TCP connection)",
            report.upload.mbps, report.download.mbps
        );
    }
    if let Some(mtu) = &report.mtu
        && mtu.error.is_none()
    {
        let side = |value: Option<usize>| value.map_or("none".to_string(), |v| v.to_string());
        let at_least = if mtu.at_ladder_top { "at least " } else { "" };
        let path_mtu = mtu
            .path_mtu
            .map_or(String::new(), |v| format!("   path MTU {at_least}{v}"));
        let flags = [
            (!mtu.dont_fragment).then_some("don't-fragment not confirmed"),
            mtu.irregular.then_some("irregular"),
        ]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
        let flags = if flags.is_empty() {
            String::new()
        } else {
            format!(
                "   {}",
                paint().yellow().apply_to(format!("⚠ {}", flags.join(", ")))
            )
        };
        let _ = writeln!(
            out,
            "  Datagram size   from here: {}   from the peer: {}   (UDP payload, bytes){path_mtu}{flags}",
            side(mtu.forward_max_payload),
            side(mtu.reverse_max_payload)
        );
    }
    if !report.ports.is_empty() {
        let _ = writeln!(out);
        for port in &report.ports {
            let _ = writeln!(
                out,
                "  Port {}   TCP {}   UDP {}",
                port.port,
                tcp_cell(&port.tcp),
                udp_cell(&port.udp)
            );
        }
    }
    if !verdict.notes.is_empty() {
        let _ = writeln!(out, "\n{}", paint().bold().apply_to("What was measured:"));
        for note in &verdict.notes {
            let _ = writeln!(out, "  {} {note}", paint().cyan().apply_to("›"));
        }
    }
    if !verdict.advice.is_empty() {
        let _ = writeln!(out, "\n{}", paint().bold().apply_to("What to do:"));
        for line in &verdict.advice {
            let _ = writeln!(out, "  {} {line}", paint().cyan().bold().apply_to("→"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linktest::{CheckResult, MtuReport, PortResult, ThroughputResult};

    fn tcp(ok: bool) -> CheckResult {
        CheckResult {
            ok,
            round_trips: usize::from(ok),
            rtt_ms: if ok { 90. } else { 0. },
            error: (!ok).then(|| "timed out".to_string()),
        }
    }
    fn udp(received: usize) -> DatagramResult {
        DatagramResult {
            sent: 16,
            received,
            loss_percent: (16 - received) as f64 / 16. * 100.,
            integrity: true,
            rtt_ms: if received > 0 { 90. } else { 0. },
            error: None,
        }
    }
    fn speed(mbps: f64) -> ThroughputResult {
        ThroughputResult {
            bytes: 1_000_000,
            seconds: 1.,
            mbps,
            integrity: true,
            error: None,
        }
    }
    fn report() -> LinkReport {
        LinkReport {
            quick: false,
            peer: "192.0.2.1:47000".parse().unwrap(),
            reverse_listener: "192.0.2.2:47001".parse().unwrap(),
            tcp: tcp(true),
            udp: udp(16),
            reverse_tcp: tcp(true),
            reverse_udp: udp(16),
            upload: speed(100.),
            download: speed(100.),
            ports: Vec::new(),
            mtu: None,
            verdict: Verdict::default(),
        }
    }
    fn mtu(forward: usize, reverse: usize) -> MtuReport {
        let sizes = [548, 1000, 1200, 1280, 1350, 1400, 1452, 1472];
        let counts = |max: usize| -> Vec<(u16, bool)> {
            sizes
                .iter()
                .map(|s| (if *s <= max { 5 } else { 0 }, true))
                .collect()
        };
        MtuReport::from_counts(&sizes, 5, &counts(forward), &counts(reverse), true, true)
    }
    fn text(verdict: &Verdict) -> String {
        verdict
            .notes
            .iter()
            .chain(&verdict.advice)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn a_clean_path_scores_good_and_says_every_carrier_can_work() {
        let mut r = report();
        r.mtu = Some(mtu(1472, 1472));
        let v = assess(&r);
        assert_eq!(v.score, 100);
        assert_eq!(v.rating, Rating::Good);
        let t = text(&v);
        assert!(
            t.contains("TCP works both ways") && t.contains("UDP is clean"),
            "{t}"
        );
        assert!(t.contains("at least 1472"), "{t}");
        assert!(t.contains("fit"), "{t}");
    }

    #[test]
    fn blocked_udp_with_working_tcp_points_to_tcp_carriers() {
        let mut r = report();
        r.udp = udp(0);
        r.reverse_udp = udp(0);
        let v = assess(&r);
        assert_eq!(v.score, 50, "two UDP directions at 25 each");
        assert_eq!(v.rating, Rating::Fair);
        assert!(text(&v).contains("kcp and fec-udp will not connect here"));
    }

    #[test]
    fn one_blocked_tcp_direction_says_which_side_should_dial() {
        let mut r = report();
        r.tcp = tcp(false);
        let v = assess(&r);
        assert!(text(&v).contains("only works from the peer to here"));
        assert_eq!(v.score, 70);
        let mut r = report();
        r.reverse_tcp = tcp(false);
        assert!(text(&assess(&r)).contains("only works from here to the peer"));
    }

    #[test]
    fn nothing_working_is_poor_and_never_negative() {
        let mut r = report();
        r.tcp = tcp(false);
        r.reverse_tcp = tcp(false);
        r.udp = udp(0);
        r.reverse_udp = udp(0);
        let v = assess(&r);
        assert_eq!((v.score, v.rating), (0, Rating::Poor));
    }

    #[test]
    fn loss_costs_points_and_changes_the_udp_advice() {
        let mut r = report();
        r.udp = udp(15); // 6.25 % loss
        let v = assess(&r);
        assert_eq!(
            v.score,
            100 - 13 - 5,
            "6.25 % loss costs 13 points, plus the asymmetry"
        );
        assert!(text(&v).contains("fec-udp copes better"));
        r.udp = udp(8); // 50 % loss: capped at 25 points
        r.reverse_udp = udp(16);
        let v = assess(&r);
        assert_eq!(v.score, 100 - 25 - 5, "capped loss plus the asymmetry");
        assert!(text(&v).contains("kcp would be slow"));
    }

    #[test]
    fn a_small_datagram_limit_names_the_settings_to_lower() {
        let mut r = report();
        r.mtu = Some(mtu(1280, 1350));
        let v = assess(&r);
        let t = text(&v);
        assert!(
            t.contains("kcp.mtu (default 1400) and fec.mtu (default 1350) to 1280"),
            "{t}"
        );
        assert!(
            t.contains("1280 bytes from here, 1350 bytes from the peer") || t.contains("differ"),
            "{t}"
        );
        assert_eq!(v.score, 95);
    }

    #[test]
    fn a_transfer_that_did_not_complete_is_a_finding_even_in_quick_mode() {
        let mut r = report();
        r.upload.bytes = 0;
        r.upload.error = Some("connection reset".to_string());
        let v = assess(&r);
        assert_eq!(v.score, 100 - 20);
        assert!(text(&v).contains("Upload to the peer did not complete (connection reset)"));
        r.quick = true;
        assert_eq!(assess(&r).score, 100 - 20);
        r.download.bytes = 0;
        assert_eq!(assess(&r).score, 100 - 40);
    }

    #[test]
    fn a_udp_probe_that_stopped_on_an_error_is_reported() {
        let mut r = report();
        r.udp.error = Some("No buffer space available".to_string());
        let v = assess(&r);
        assert_eq!(v.score, 90);
        assert!(text(&v).contains("stopped on an error"));
    }

    #[test]
    fn the_mtu_penalty_looks_at_the_path_mtu_not_the_payload() {
        let counts = |sizes: &[usize], max: usize| -> Vec<(u16, bool)> {
            sizes
                .iter()
                .map(|s| (if *s <= max { 5 } else { 0 }, true))
                .collect()
        };
        // Payload 1392 is a path MTU of 1420: not below 1400, so no penalty.
        let sizes = [548, 1000, 1392, 1432];
        let mut r = report();
        r.mtu = Some(MtuReport::from_counts(
            &sizes,
            5,
            &counts(&sizes, 1392),
            &counts(&sizes, 1392),
            true,
            true,
        ));
        assert_eq!(assess(&r).score, 100);
        // Payload 1300 is a path MTU of 1328.
        let sizes = [548, 1000, 1300, 1432];
        r.mtu = Some(MtuReport::from_counts(
            &sizes,
            5,
            &counts(&sizes, 1300),
            &counts(&sizes, 1300),
            true,
            true,
        ));
        assert_eq!(assess(&r).score, 95);
    }

    #[test]
    fn quick_mode_does_not_judge_speed_and_slow_transfers_cost_points() {
        let mut r = report();
        r.upload = speed(1.);
        r.download = speed(2.);
        assert_eq!(assess(&r).score, 80);
        r.quick = true;
        let v = assess(&r);
        assert_eq!(v.score, 100);
        assert!(text(&v).contains("fraction of a second"));
    }

    #[test]
    fn failing_extra_ports_cost_points_up_to_three_of_them() {
        let mut r = report();
        for port in 1..=5u16 {
            r.ports.push(PortResult {
                port: 47000 + port,
                tcp: tcp(false),
                udp: udp(0),
            });
        }
        assert_eq!(assess(&r).score, 85);
    }

    #[test]
    fn altered_data_is_flagged_once() {
        let mut r = report();
        r.udp.integrity = false;
        r.download.integrity = false;
        let v = assess(&r);
        assert_eq!(v.score, 70);
        assert!(text(&v).contains("rewrites traffic"));
    }

    #[test]
    fn the_text_report_names_each_check() {
        let mut r = report();
        r.mtu = Some(mtu(1400, 1400));
        r.verdict = assess(&r);
        let out = render(&r);
        for needle in [
            "GOOD (",
            "/100)",
            "TCP   started here",
            "UDP   started here",
            "0% loss",
            "Speed upload",
            "Datagram size",
            "path MTU",
            "What to do:",
        ] {
            assert!(out.contains(needle), "{needle} missing in\n{out}");
        }
    }
}
