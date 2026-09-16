use dynfmt::Format;
use log::{Log, Metadata, Record};
use once_cell::sync::OnceCell;
use std::fmt::{Display, Formatter};
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::ops::DerefMut;
use std::sync::Mutex;

/// Logs records in the standard output stream
pub struct StdoutLogger;

/// Logs records in the provided file by path
pub struct FileLogger {
    file: Mutex<BufWriter<File>>,
}

/// Forces flushing buffered records to a destination while dropping
pub struct LogFlushGuard;

pub const fn make_stdout_logger() -> &'static impl Log {
    const LOGGER: StdoutLogger = StdoutLogger;
    &LOGGER
}

pub fn make_file_logger(path: &str) -> std::io::Result<&'static impl Log> {
    static LOGGER: OnceCell<FileLogger> = OnceCell::new();
    assert!(LOGGER.get().is_none());

    LOGGER.get_or_try_init(|| FileLogger::new(path))
}

fn write_record(mut w: impl Write, record: &Record) -> std::io::Result<()> {
    writeln!(
        w,
        "{} [{:?}] [{}] [{}] {}",
        chrono::Local::now().format("%T.%6f"),
        std::thread::current().id(),
        record.level(),
        record.target(),
        record.args(),
    )
}

impl Log for StdoutLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            write_record(std::io::stdout(), record).unwrap();
        }
    }

    fn flush(&self) {}
}

impl FileLogger {
    pub fn new(path: &str) -> std::io::Result<Self> {
        Ok(Self {
            file: Mutex::new(BufWriter::new(
                OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .open(path)?,
            )),
        })
    }
}

impl Log for FileLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            if let Err(e) = write_record(self.file.lock().unwrap().deref_mut(), record) {
                eprintln!("Log write failure: {}", e);
            }
        }
    }

    fn flush(&self) {
        if let Err(e) = self.file.lock().unwrap().flush() {
            eprintln!("Log flush failure: {}", e);
        }
    }
}

impl Drop for FileLogger {
    fn drop(&mut self) {
        self.flush();
    }
}

impl Drop for LogFlushGuard {
    fn drop(&mut self) {
        log::logger().flush()
    }
}

#[macro_export]
macro_rules! log_id {
    ($lvl:ident, $id_chain:expr, $msg:expr) => {
        $lvl!(std::concat!("[{}] ", $msg), $id_chain)
    };
    ($lvl:ident, $id_chain:expr, $fmt:expr, $($arg:tt)*) => {
        $lvl!(std::concat!("[{}] ", $fmt), $id_chain, $($arg)*)
    };
}

pub(crate) const CLIENT_ID_FMT: &str = "CLIENT={}";
pub(crate) const TUNNEL_ID_FMT: &str = "TUN={}";
pub(crate) const CONNECTION_ID_FMT: &str = "CONN={}";

#[derive(Copy, Clone)]
pub struct IdItem<T: Copy + serde::ser::Serialize> {
    fmt: &'static str,
    id: T,
}

#[derive(Clone)]
pub struct IdChain<T: Copy + serde::ser::Serialize> {
    list: Vec<IdItem<T>>,
}

impl<T: Copy + serde::ser::Serialize> IdItem<T> {
    pub fn new(fmt: &'static str, id: T) -> Self {
        Self { fmt, id }
    }
}

impl<T: Copy + serde::ser::Serialize> IdChain<T> {
    pub fn empty() -> Self {
        Self {
            list: Default::default(),
        }
    }

    pub fn extended(&self, new: IdItem<T>) -> Self {
        let mut x = Self::with_capacity(self.list.len() + 1);
        x.list.extend(self.list.iter());
        x.list.push(new);
        x
    }

    fn with_capacity(cap: usize) -> Self {
        Self {
            list: Vec::with_capacity(cap),
        }
    }
}

impl<T: Copy + serde::ser::Serialize> From<IdItem<T>> for IdChain<T> {
    fn from(x: IdItem<T>) -> Self {
        Self { list: vec![x] }
    }
}

impl<T: Copy + serde::ser::Serialize> Display for IdChain<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = self.list.iter().fold(String::new(), |acc, i| {
            let x = dynfmt::curly::SimpleCurlyFormat
                .format(i.fmt, [i.id])
                .unwrap();

            if !acc.is_empty() {
                acc + "/" + x.as_ref()
            } else {
                x.to_string()
            }
        });
        write!(f, "{}", str)
    }
}

#[cfg(test)]
mod tests {
    use crate::log_utils::{IdChain, IdItem};

    #[test]
    fn test() {
        let mut chain = IdChain::from(IdItem::new("hello {}", 42));
        assert_eq!("hello 42", format!("{}", chain));

        chain = chain.extended(IdItem::new("ok {}", 73));
        assert_eq!("hello 42/ok 73", format!("{}", chain));
    }
}
