//! Figures computed from a tunnel's live status, shared by the terminal manager and the dashboard.

/// Heartbeat loss in percent from the heartbeats that were settled: answered, or unanswered for
/// a whole interval. A heartbeat still in flight is neither, so it cannot make the figure jump.
/// `None` until five have settled.
pub fn loss_percent(lost: u64, answered: u64) -> Option<f64> {
    let settled = lost + answered;
    (settled >= 5).then(|| lost as f64 * 100.0 / settled as f64)
}

/// Round-trip statistics from heartbeat samples: (average, lowest, highest, jitter) in ms.
pub fn rtt_figures(samples: &[f64]) -> Option<(f64, f64, f64, f64)> {
    if samples.is_empty() {
        return None;
    }
    let recent = &samples[samples.len().saturating_sub(20)..];
    let avg = recent.iter().sum::<f64>() / recent.len() as f64;
    let min = recent.iter().copied().fold(f64::MAX, f64::min);
    let max = recent.iter().copied().fold(0.0, f64::max);
    let jitter = if recent.len() > 1 {
        recent.windows(2).map(|w| (w[1] - w[0]).abs()).sum::<f64>() / (recent.len() - 1) as f64
    } else {
        0.0
    };
    Some((avg, min, max, jitter))
}
