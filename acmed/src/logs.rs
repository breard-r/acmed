use acme_common::error::Error;
use env_logger::Builder;
use log::LevelFilter;
use syslog::Facility;

#[derive(Debug, PartialEq, Eq)]
pub enum LogSystem {
    SysLog,
    StdErr,
}

fn get_loglevel(log_level: Option<&str>) -> Result<LevelFilter, Error> {
    let level = match log_level {
        Some(v) => match v {
            "error" => LevelFilter::Error,
            "warn" => LevelFilter::Warn,
            "info" => LevelFilter::Info,
            "debug" => LevelFilter::Debug,
            "trace" => LevelFilter::Trace,
            _ => {
                return Err(format!("{}: invalid log level", v).into());
            }
        },
        None => crate::DEFAULT_LOG_LEVEL,
    };
    Ok(level)
}

fn set_log_syslog(log_level: LevelFilter) -> Result<(), Error> {
    syslog::init(
        Facility::LOG_DAEMON,
        log_level,
        Some(env!("CARGO_PKG_NAME")),
    )?;
    Ok(())
}

fn set_log_stderr(log_level: LevelFilter) -> Result<(), Error> {
    let mut builder = Builder::from_env("ACMED_LOG_LEVEL");
    builder.filter_level(log_level);
    builder.init();
    Ok(())
}

pub fn set_log_system(
    log_level: Option<&str>,
    has_syslog: bool,
    has_stderr: bool,
) -> Result<(LogSystem, LevelFilter), Error> {
    let log_level = get_loglevel(log_level)?;
    let logtype = if has_syslog {
        LogSystem::SysLog
    } else if has_stderr {
        LogSystem::StdErr
    } else {
        crate::DEFAULT_LOG_SYSTEM
    };
    match logtype {
        LogSystem::SysLog => set_log_syslog(log_level)?,
        LogSystem::StdErr => set_log_stderr(log_level)?,
    };
    Ok((logtype, log_level))
}

#[cfg(test)]
mod tests {
    use super::set_log_system;

    #[test]
    fn test_invalid_level() {
        let ret = set_log_system(Some("invalid"), false, false);
        assert!(ret.is_err());
    }

    #[test]
    fn test_default_values() {
        let ret = set_log_system(None, false, false);
        assert!(ret.is_ok());
        let (logtype, log_level) = ret.unwrap();
        assert_eq!(logtype, crate::DEFAULT_LOG_SYSTEM);
        assert_eq!(log_level, crate::DEFAULT_LOG_LEVEL);
    }
}
