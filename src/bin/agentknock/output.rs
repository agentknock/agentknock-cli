use std::{cell::Cell, fmt::Display, future::Future, time::Duration};

use agentknock::RequestProgress;
use tokio::time::{Instant, sleep};

const PROGRESS_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputMode {
    Normal,
    Quiet,
    Verbose,
}

impl OutputMode {
    pub fn from_flags(quiet: bool, verbose: bool) -> Self {
        if quiet {
            Self::Quiet
        } else if verbose {
            Self::Verbose
        } else {
            Self::Normal
        }
    }
}

pub struct Progress<M> {
    current: Cell<Option<RequestProgress>>,
    mode: OutputMode,
    prefixed: bool,
    message: M,
}

impl<M: Fn(RequestProgress) -> &'static str> Progress<M> {
    pub fn plain(message: M) -> Self {
        Self {
            prefixed: false,
            ..Self::for_command(OutputMode::Normal, message)
        }
    }

    pub fn for_command(mode: OutputMode, message: M) -> Self {
        Self {
            current: Cell::new(None),
            mode,
            prefixed: true,
            message,
        }
    }

    pub fn observe(&self, stage: RequestProgress) {
        let changed = self.current.replace(Some(stage)) != Some(stage);
        if changed && self.mode == OutputMode::Verbose {
            self.print((self.message)(stage));
        }
    }

    pub async fn monitor<F: Future>(&self, request: F) -> F::Output {
        tokio::pin!(request);
        let started = Instant::now();
        let heartbeat = sleep(PROGRESS_INTERVAL);
        tokio::pin!(heartbeat);
        loop {
            tokio::select! {
                biased;
                result = request.as_mut() => return result,
                _ = heartbeat.as_mut(), if self.mode != OutputMode::Quiet => {
                    if let Some(stage) = self.current.get() {
                        self.print(progress_report((self.message)(stage), started.elapsed()));
                    }
                    heartbeat.as_mut().reset(Instant::now() + PROGRESS_INTERVAL);
                }
            }
        }
    }

    fn print(&self, message: impl Display) {
        if self.prefixed {
            print_message(message);
        } else {
            eprintln!("{message}");
        }
    }
}

pub fn print_message(message: impl Display) {
    for line in message.to_string().lines() {
        eprintln!("AGENTKNOCK: {line}");
    }
}

fn progress_report(message: &str, elapsed: Duration) -> String {
    format!("{message} Elapsed time: {}.", format_elapsed_time(elapsed))
}

fn format_elapsed_time(elapsed: Duration) -> String {
    let total_seconds = elapsed.as_secs();
    let units = [
        ("day", total_seconds / 86_400),
        ("hour", total_seconds % 86_400 / 3_600),
        ("minute", total_seconds % 3_600 / 60),
        ("second", total_seconds % 60),
    ];
    let parts = units
        .into_iter()
        .filter(|(_, value)| *value != 0)
        .map(|(unit, value)| {
            let suffix = if value == 1 { "" } else { "s" };
            format!("{value} {unit}{suffix}")
        })
        .collect::<Vec<_>>();

    if parts.is_empty() {
        "0 seconds".into()
    } else {
        parts.join(" ")
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_elapsed_time_for_progress_reports() {
        use std::time::Duration;

        assert_eq!(format_elapsed_time(Duration::ZERO), "0 seconds");
        assert_eq!(format_elapsed_time(Duration::from_secs(30)), "30 seconds");
        assert_eq!(format_elapsed_time(Duration::from_secs(60)), "1 minute");
        assert_eq!(
            format_elapsed_time(Duration::from_secs(90)),
            "1 minute 30 seconds"
        );
        assert_eq!(
            format_elapsed_time(Duration::from_secs(3_661)),
            "1 hour 1 minute 1 second"
        );
        assert_eq!(
            format_elapsed_time(Duration::from_secs(90_061)),
            "1 day 1 hour 1 minute 1 second"
        );
        assert_eq!(
            progress_report("Waiting for the device.", Duration::from_secs(90)),
            "Waiting for the device. Elapsed time: 1 minute 30 seconds."
        );
    }
}
