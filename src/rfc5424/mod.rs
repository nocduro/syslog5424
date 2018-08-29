use std::io::{self, Write};
use std::collections::HashMap;

pub mod types;
use self::types::*;

const NILVALUE: char = '-';

#[derive(Debug)]
pub struct Rfc5424 {
    version: u8, // version of syslog protocol. currently "1"
    hostname: HostName, // upto 255 printable ascii characters OR NILVALUE
    app_name: AppName, // name of application. upto 48 printable ascii characters OR NILVALUE
    pid: ProcessId, // process id. upto 128 printable ascii characters OR NILVALUE
    msg_id: MessageId, // only used for filtering messages on relay or collector
    facility: Facility,
    enterprise_id: String,
}

pub trait Rfc5424Data {
    fn severity(&self) -> Severity;
    fn timestamp(&self) -> Option<String>;
    fn structured_data(&self) -> Option<&StructuredData>;
    fn message(&self) -> Option<&str>;
}

#[derive(Debug)]
pub struct Rfc5424Message {
    pub severity: Severity,
    pub structured_data: Option<StructuredData>,
    pub message: Option<String>,
}

#[derive(Debug)]
pub struct StructuredData {
    pub data: HashMap<String, Vec<(String, String)>>,
    pub iana: Vec<IanaReserved>,
}

/// IANA reserved keyword
#[derive(Debug)]
pub enum IanaReserved {
    TimeQuality,
    Origin,
    Meta,
}

impl Rfc5424Data for Rfc5424Message {
    fn severity(&self) -> Severity {
        self.severity
    }

    fn timestamp(&self) -> Option<String> {
        None
    }

    fn structured_data(&self) -> Option<&StructuredData> {
        match self.structured_data {
            Some(ref s) => Some(&s),
            None => None
        }
    }

    fn message(&self) -> Option<&str> {
        match self.message {
            Some(ref s) => Some(&s),
            None => None
        }
    }
}

fn generate_priority(facility: Facility, severity: Severity) -> String {
    let priority = facility as u8 * severity as u8;
    format!("<{}>", priority)
}

impl Rfc5424 {

    pub fn new() -> Rfc5424 {
        Rfc5424 {
            version: 1,
            hostname: HostName::new("my_host").unwrap(),
            app_name: AppName::new("my_app").unwrap(),
            pid: ProcessId::new("5555").unwrap(),
            msg_id: MessageId::new("msg_id").unwrap(),
            facility: Facility::User,
            enterprise_id: "132".to_string(),
        }
    }

    pub fn format<W: Write>(&self, writer: &mut W, message: impl Rfc5424Data) -> io::Result<()> {
        let mut log = String::new();

        // - HEADER -
        // PRI
        log.push_str(&generate_priority(self.facility, message.severity()));
        log.push(' ');

        // VERSION
        log.push_str(&self.version.to_string()); // TODO does this have to be zero padded??
        log.push(' ');

        // TIMESTAMP

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
        if let Some(sd) = message.structured_data() {
            // TODO: Iana reserved keywords
            let structured: String = sd.data.iter().map(|(id, pairs)| {
                let mut elem = "[".to_string();
                elem.push_str(id);
                elem.push('@');
                elem.push_str(&self.enterprise_id);
                for (n, v) in pairs {
                    elem.push(' ');
                    elem.push_str(n);
                    elem.push('=');
                    elem.push('"');
                    elem.push_str(v);
                    elem.push('"');
                }
                elem.push(']');
                elem
            }).collect();
            log.push_str(&structured);
        } else {
            log.push(NILVALUE);            
        }

        if let Some(msg) = message.message() {
            log.push(' ');
            log.push_str(msg);
        }

        writer.write_all(log.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_something() {
        let mut hmap = HashMap::new();
        hmap.insert("hello".into(), vec![("id".into(), "alpha9".into()), ("progress".into(), "complete".into())]);
        let sd = StructuredData {
            data: hmap,
            iana: vec![],
        };

        let msg = Rfc5424Message {
            severity: Severity::Error,
            structured_data: Some(sd),
            message: Some("sample message".into()),
        };
        let f = Rfc5424::new();

        let mut out = Vec::new();
        f.format(&mut out, msg).unwrap();
        println!("log: {}", String::from_utf8(out).unwrap());
    }
}