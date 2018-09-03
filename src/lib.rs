//! A trait based formatter for syslog RFC5424.
//!
//! This crate includes a struct [`Rfc5424`](struct.Rfc5424.html) that holds metadata
//! associated with the running program that is needed to format messages.
//! [`Rfc5424`](struct.Rfc5424.html) has a function [`format`](struct.Rfc5424.html#method.format)
//! that formats any type that implements the [`Rfc5424Data`](trait.Rfc5424Data.html) trait.
//!
//! An example implementation of `Rfc5424Data` is in the `tests` module.
//!
//! There is also a [`slog`](https://github.com/slog-rs/slog) implementation here: [https://github.com/nocduro/slog-syslog5424](https://github.com/nocduro/slog-syslog5424)
//!
//! # Important details
//! Some IANA reserved keywords are not implemented yet (`timeQuality`, and `meta`).
//!
//! The formatter is fairly strict in following the RFC. It may truncate fields
//! or remove disallowed characters transparently to the caller. It will also
//! escape characters, as defined [in the RFC](https://tools.ietf.org/html/rfc5424#section-6)
//!
//! The formatter ([`Rfc5424`](struct.Rfc5424.html)) has a field for specifying if the message should be written as just
//! the bare RFC5424 format, or if it should be prepended with the length according
//! to [RFC5425](https://tools.ietf.org/html/rfc5425#section-4.3). If sending to a remote
//! syslog server (such as InfluxDB, or a remote RSYSLOG) this should be enabled, and the
//! connection should be over TLS. However, if sending to the local RSYSLOG the normal
//! 5424 format is likely correct(?).

#![deny(unsafe_code, missing_copy_implementations, unused_import_braces)]

use std::collections::HashMap;
use std::io::{self, Write};

pub mod iana;
pub mod types;
use iana::*;
use types::*;

/// Errors returned when verifying validity of metadata
#[derive(Debug, Copy, Clone)]
pub enum Error {
    FieldEmpty,
    FieldTooLong,
    InvalidCharacters,
}

/// Format of messages written out. RFC5425 just prepends the length
/// of the 5424 message
#[derive(Debug, PartialEq, Copy, Clone)]
pub enum WriteFormat {
    RFC5424,
    RFC5425,
}

impl Default for WriteFormat {
    fn default() -> WriteFormat {
        WriteFormat::RFC5424
    }
}

/// Value used when a field is optional, and not present
pub const NILVALUE: char = '-';
const BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// Holds the metadata needed for formatting a RFC5424 syslog message.
///
/// Use [`Rfc5424Builder`](struct.Rfc5424Builder.html) to construct one.
#[derive(Debug, Default)]
pub struct Rfc5424 {
    version: u8,
    hostname: HostName,
    app_name: AppName,
    pid: ProcessId,
    msg_id: MessageId,
    facility: Facility,
    enterprise_id: String,
    iana_time_quality: Vec<TimeQuality>,
    iana_origin: Vec<Origin>,
    write_format: WriteFormat,
}

/// Builder for [`Rfc5424`](struct.Rfc5424.html)
pub struct Rfc5424Builder {
    data: Rfc5424,
}

impl Rfc5424Builder {
    pub fn new(enterprise_id: &str, facility: Facility) -> Rfc5424Builder {
        Rfc5424Builder {
            data: Rfc5424 {
                version: 1,
                facility,
                enterprise_id: enterprise_id.to_string(),
                ..Default::default()
            },
        }
    }

    /// Transform the builder into a formatter struct.
    pub fn build(self) -> Rfc5424 {
        self.data
    }

    /// Set the hostname used in the header of the syslog message.
    ///
    /// # Errors
    /// * `val`'s length is larger than 255
    /// * `val` is an empty string
    /// * `val` doesn't contain printable ASCII characters (see `char::is_ascii_graphic`)
    pub fn hostname(mut self, val: &str) -> Result<Self, Error> {
        self.data.hostname = HostName::new(val)?;
        Ok(self)
    }

    /// Set the app name used in the header of the syslog message.
    ///
    /// # Errors
    /// * `val`'s length is larger than 48
    /// * `val` is an empty string
    /// * `val` doesn't contain printable ASCII characters (see `char::is_ascii_graphic`)
    pub fn app_name(mut self, val: &str) -> Result<Self, Error> {
        self.data.app_name = AppName::new(val)?;
        Ok(self)
    }

    /// Set the process id (PID) used in the header of the syslog message.
    ///
    /// # Errors
    /// * `val`'s length is larger than 128
    /// * `val` is an empty string
    /// * `val` doesn't contain printable ASCII characters (see `char::is_ascii_graphic`)
    pub fn pid(mut self, val: &str) -> Result<Self, Error> {
        self.data.pid = ProcessId::new(val)?;
        Ok(self)
    }

    /// Set the msgId used in the header of the syslog message. (OPTIONAL)
    ///
    /// The MSGID SHOULD identify the type of message.  For example, a
    /// firewall might use the MSGID "TCPIN" for incoming TCP traffic and the
    /// MSGID "TCPOUT" for outgoing TCP traffic.  Messages with the same
    /// MSGID should reflect events of the same semantics.  The MSGID itself
    /// is a string without further semantics.  **It is intended for filtering
    /// messages on a relay or collector**.
    ///
    /// # Errors
    /// * `val`'s length is larger than 32
    /// * `val` is an empty string
    /// * `val` doesn't contain printable ASCII characters (see `char::is_ascii_graphic`)
    pub fn msg_id(mut self, val: &str) -> Result<Self, Error> {
        self.data.msg_id = MessageId::new(val)?;
        Ok(self)
    }

    /// Set the format of the output between RFC5424 and RFC5425.
    ///
    /// RFC5425 is the same as RFC5424 except it prepends the length of the message.
    ///
    /// # Example
    /// RFC5424: `<11>1 - server1.example.com my_app_name 5445 msg_id [hello@ent_id id="54" progress="complete"] sample message`
    ///
    /// RFC5425: `130 <11>1 - server1.example.com my_app_name 5445 msg_id [hello@ent_id id="54" progress="complete"] sample message`
    pub fn write_format(mut self, f: WriteFormat) -> Self {
        self.data.write_format = f;
        self
    }

    /// Add an IANA reserved origin key-value pair.
    ///
    /// # Examples
    /// ```ignore
    /// let f = Rfc5424Builder::new("enterprise_id", Facility::User)
    ///     .origin(Origin::Ip("127.0.0.1"))
    ///     .origin(Origin::Version("12.2.1"))
    ///     .build();
    /// ```
    pub fn origin(mut self, o: Origin) -> Self {
        self.data.iana_origin.push(o);
        self
    }

    /// Add an IANA reserved time quality key-value pair.
    ///
    /// # Examples
    /// ```ignore
    /// let f = Rfc5424Builder::new("enterprise_id", Facility::User)
    ///     .time_quality(TimeQuality::TzKnown(true))
    ///     .time_quality(TimeQuality::IsSynced(true))
    ///     .time_quality(TimeQuality::SyncAccuracy(1000))
    ///     .build();
    /// ```
    pub fn time_quality(mut self, t: TimeQuality) -> Self {
        self.data.iana_time_quality.push(t);
        self
    }
}

/// Alias for format of structured data. The RFC does not forbid having
/// duplicate keys for PARAM-NAME, hence the vec of string pairs.
/// I'm not sure if *every* RFC5424 implementation supports this,
/// so be careful when sending duplicates; the receiver might discard some
/// of them.
pub type StructuredData<'a> = HashMap<&'a str, Vec<(String, String)>>;

/// Trait that defines what data is needed in order to create
/// a RFC5424 message. Any type that implements this can be
/// formatted with a [`Rfc5424`](struct.Rfc5424.html) struct.
pub trait Rfc5424Data {
    fn severity(&self) -> Severity;
    fn timestamp(&self) -> Option<String>;
    fn structured_data(&self) -> Option<StructuredData>;
    fn message(&self) -> Option<Message>;
}

fn generate_priority(facility: Facility, severity: Severity) -> String {
    let priority = (facility as u8 * 8) + severity as u8;
    format!("<{}>", priority)
}

impl Rfc5424 {
    /// Format `Rfc5424Data` into a RFC5424 message according to the metadata in
    /// `self`, and writes it using `writer`.
    ///
    /// # Errors
    /// Errors when `writer` returns an error (`io::Error`)
    pub fn format<W: Write>(&self, writer: &mut W, message: &impl Rfc5424Data) -> io::Result<()> {
        let mut log = String::new();

        // - HEADER -
        // PRI
        log.push_str(&generate_priority(self.facility, message.severity()));

        // VERSION
        log.push_str(&self.version.to_string()); // TODO does this have to be zero padded
        log.push(' ');

        // TIMESTAMP
        if let Some(time) = message.timestamp() {
            log.push_str(&time);
        } else {
            log.push(NILVALUE);
        }
        log.push(' ');

        // HOSTNAME
        log.push_str(&self.hostname.0);
        log.push(' ');

        // APP-NAME
        log.push_str(&self.app_name.0);
        log.push(' ');

        // PROCESS ID
        log.push_str(&self.pid.0);
        log.push(' ');

        // MESSAGE ID
        log.push_str(&self.msg_id.0);
        log.push(' ');

        // - STRUCTURED-DATA -
        // TODO: precompute this and store in formatting struct?
        if !self.iana_origin.is_empty() {
            log.push_str("[origin");
            for val in &self.iana_origin {
                log.push_str(&val.to_string());
            }
            log.push(']');
        }

        if !self.iana_time_quality.is_empty() {
            log.push_str("[timeQuality");
            for val in &self.iana_time_quality {
                log.push_str(&val.to_string());
            }
            log.push(']');
        }

        if let Some(sd) = message.structured_data() {
            sd.iter().for_each(|(id, pairs)| {
                log.push('[');
                log.push_str(&remove_invalid(id));
                log.push('@');
                log.push_str(&self.enterprise_id);
                for (name, val) in pairs {
                    log.push(' ');
                    log.push_str(&remove_invalid(name));
                    log.push('=');
                    log.push('"');
                    log.push_str(&escape_val(val));
                    log.push('"');
                }
                log.push(']');
            })
        }

        // must use NILVALUE if we don't have any structured data
        if message.structured_data().is_none()
            && self.iana_origin.is_empty()
            && self.iana_time_quality.is_empty()
        {
            log.push(NILVALUE);
        }

        // MESSAGE
        let m = message.message();
        let msg_len: Option<usize> = m.as_ref().map(|msg: &Message| {
            log.push(' ');
            match msg {
                Message::Text(s) => s.as_bytes().len() + 3, // add 3 for BOM
                Message::Binary(data) => data.as_slice().len(),
            }
        });

        // write message length according to RFC5425
        if self.write_format == WriteFormat::RFC5425 {
            let length = if let Some(bytes) = msg_len {
                log.as_bytes().len() + bytes
            } else {
                log.as_bytes().len()
            };
            writer.write_all(format!("{} ", length).as_bytes())?;
        }

        // write structured data
        writer.write_all(log.as_bytes())?;

        // write the message bytes, whether string, or binary
        if let Some(msg) = m {
            match msg {
                Message::Text(s) => {
                    writer.write_all(&BOM)?;
                    writer.write_all(s.as_bytes())?
                }
                Message::Binary(s) => writer.write_all(s.as_slice())?,
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct Rfc5424Message<'a> {
        pub severity: Severity,
        pub structured_data: Option<StructuredData<'a>>,
        pub message: Option<Message>,
    }

    impl<'a> Rfc5424Data for Rfc5424Message<'a> {
        fn severity(&self) -> Severity {
            self.severity
        }

        fn timestamp(&self) -> Option<String> {
            None
        }

        fn structured_data(&self) -> Option<StructuredData> {
            self.structured_data.clone()
        }

        fn message(&self) -> Option<Message> {
            self.message.clone()
        }
    }

    /// generate a vec with the BOM added
    /// `structured` should not end with a space
    /// `message` should not start with a space
    fn test_vec(structured: &str, message: Option<&str>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(structured.trim().as_bytes());

        if let Some(s) = message {
            out.push(' ' as u8);
            out.extend(BOM.iter());
            out.extend(s.trim().as_bytes());
        }
        out
    }

    #[test]
    fn write_something() {
        let mut hmap: StructuredData = HashMap::new();
        hmap.insert(
            "hello",
            vec![
                ("id".into(), "alpha9".into()),
                ("progress".into(), "complete".into()),
            ],
        );

        let msg = Rfc5424Message {
            severity: Severity::Error,
            structured_data: Some(hmap),
            message: Some(Message::Text("sample message. Hello there!".into())),
        };
        let f = Rfc5424Builder::new("ent_id", Facility::User)
            .app_name("my_app_name")
            .unwrap()
            .hostname("server1.example.com")
            .unwrap()
            .msg_id("msg_id")
            .unwrap()
            .pid("5445")
            .unwrap()
            .write_format(WriteFormat::RFC5425)
            .build();

        let mut out = Vec::new();
        f.format(&mut out, &msg).unwrap();
        let s = String::from_utf8(out).unwrap();
        println!("{}", s);
        assert_eq!(String::from_utf8(
            test_vec(r#"130 <11>1 - server1.example.com my_app_name 5445 msg_id [hello@ent_id id="alpha9" progress="complete"]"#, 
                Some("sample message. Hello there!"))).unwrap(), s);
    }

    #[test]
    fn message_only() {
        let msg = Rfc5424Message {
            severity: Severity::Notice,
            structured_data: None,
            message: Some(Message::Text("%% It's time to make the do-nuts.".into())),
        };
        let f = Rfc5424Builder::new("ent_id", Facility::Local4)
            .app_name("myproc")
            .unwrap()
            .hostname("192.0.2.1")
            .unwrap()
            .pid("8710")
            .unwrap()
            .write_format(WriteFormat::RFC5424)
            .build();

        let mut out = Vec::new();
        f.format(&mut out, &msg).unwrap();
        let s = String::from_utf8(out).unwrap();
        println!("{}", s);
        assert_eq!(
            String::from_utf8(test_vec(
                r#"<165>1 - 192.0.2.1 myproc 8710 - -"#,
                Some("%% It's time to make the do-nuts.")
            )).unwrap(),
            s
        );
    }

    #[test]
    fn empty() {
        let msg = Rfc5424Message {
            severity: Severity::Debug,
            structured_data: None,
            message: None,
        };
        let f = Rfc5424Builder::new("ent_id", Facility::User).build();

        let mut out = Vec::new();
        f.format(&mut out, &msg).unwrap();
        let s = String::from_utf8(out).unwrap();
        println!("{}", s);
        assert_eq!(
            String::from_utf8(test_vec(r#"<15>1 - - - - - -"#, None)).unwrap(),
            s
        );
    }

    #[test]
    fn rfc_examples() {
        let mut hmap: StructuredData = HashMap::new();
        hmap.insert(
            "exampleSDID",
            vec![
                ("iut".into(), "3".into()),
                ("eventSource".into(), "Application".into()),
                ("eventID".into(), "1011".into()),
            ],
        );

        let msg = Rfc5424Message {
            severity: Severity::Error,
            structured_data: Some(hmap.clone()),
            message: None,
        };
        let f = Rfc5424Builder::new("32473", Facility::User).build();

        let mut out = Vec::new();
        f.format(&mut out, &msg).unwrap();
        let s = String::from_utf8(out).unwrap();
        println!("{}", s);
        assert_eq!(String::from_utf8(
            test_vec(r#"<11>1 - - - - - [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]"#, 
                None)).unwrap(), s);

        hmap.insert("examplePriority", vec![("class".into(), "high".into())]);
        let msg2 = Rfc5424Message {
            severity: Severity::Warning,
            structured_data: Some(hmap),
            message: None,
        };

        let mut out = Vec::new();
        f.format(&mut out, &msg2).unwrap();
        let s = String::from_utf8(out).unwrap();
        println!("{}", s);
        assert_eq!(String::from_utf8(
            test_vec(r#"<12>1 - - - - - [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"][examplePriority@32473 class="high"]"#, 
                None)).unwrap().len(), s.len());
    }
}
