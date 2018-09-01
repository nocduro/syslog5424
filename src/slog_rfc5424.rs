use slog::{self, Drain, Level, OwnedKVList, Record, Serializer, KV};
use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt::Arguments;
use std::io::{self, Write};
use {Message, Rfc5424, Rfc5424Data, Severity, StructuredData};

use chrono::{SecondsFormat, Utc};

#[derive(Debug)]
pub struct Rfc5424Writer<W: Write> {
    pub writer: RefCell<W>,
    pub formatter: Rfc5424,
}

/// Wrapper struct to store all the information provied by `slog`
/// for each log message. This way we can implement the trait
/// required for RFC5424 formatting on it
struct CompleteLogEntry<'a> {
    record: &'a Record<'a>,
    values: &'a OwnedKVList,
}

/// Wrapper for a vec so that we can implement `Serializer` on it.
struct StructuredWrapper(Vec<(String, String)>);

/// The most basic serializer. Convert `key` and `val` to strings
/// and store them as pairs in a vec.
impl<'a> Serializer for StructuredWrapper {
    fn emit_arguments(&mut self, key: slog::Key, val: &Arguments) -> slog::Result {
        self.0.push((key.to_string(), format!("{}", val)));
        Ok(())
    }
}

/// Allow `CompleteLogEntry` to be used as a data source for the
/// RFC5424 formatter
impl<'a> Rfc5424Data for CompleteLogEntry<'a> {
    fn severity(&self) -> Severity {
        match self.record.level() {
            Level::Critical => Severity::Critical,
            Level::Error => Severity::Error,
            Level::Warning => Severity::Warning,
            Level::Info => Severity::Informational,
            Level::Debug => Severity::Debug,
            Level::Trace => Severity::Debug, // TODO: is this right?
        }
    }

    fn timestamp(&self) -> Option<String> {
        Some(Utc::now().to_rfc3339_opts(SecondsFormat::Micros, false))
    }
    fn structured_data(&self) -> Option<StructuredData> {
        let mut data: StructuredData = HashMap::new();
        let mut buf = StructuredWrapper(Vec::new());
        // our serializer never errors (only writes to a vec)
        self.record.kv().serialize(self.record, &mut buf).unwrap();
        self.values.serialize(self.record, &mut buf).unwrap();

        data.insert("slog", buf.0);
        Some(data)
    }
    fn message(&self) -> Option<Message> {
        Some(Message::Text(format!("{}", self.record.msg())))
    }
}

impl<W: Write> Drain for Rfc5424Writer<W> {
    type Ok = ();
    type Err = io::Error;

    fn log(&self, record: &Record, values: &OwnedKVList) -> Result<Self::Ok, Self::Err> {
        let msg = CompleteLogEntry { record, values };
        let mut writer = self.writer.borrow_mut();
        self.formatter.format(&mut *writer, msg)
    }
}
