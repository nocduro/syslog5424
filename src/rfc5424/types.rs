use Error;

#[derive(Debug, Clone, Copy)]
pub enum Facility {
    Kernel = 0,
    User = 1,
    Mail = 2,
    SystemDaemon = 3,
    SecurityAuth = 4,
    Syslog = 5,
    LinePrinter = 6,
    NetworkNews = 7,
    UUCP = 8,
    ClockDaemon = 9,
    SecurityAuth2 = 10,
    FTP = 11,
    NTP = 12,
    LogAudit = 13,
    LogAlert = 14,
    ClockDaemon2 = 15,
    Local0 = 16,
    Local1 = 17,
    Local2 = 18,
    Local3 = 19,
    Local4 = 20,
    Local5 = 21,
    Local6 = 22,
    Local7 = 23,
}

#[derive(Debug, Clone, Copy)]
pub enum Severity {
    Emergency = 0,
    Alert = 1,
    Critical = 2,
    Error = 3,
    Warning = 4,
    Notice = 5,
    Informational = 6,
    Debug = 7,
}

#[derive(Debug)]
pub struct MsgId(pub String);
impl MsgId {
    pub fn new(msg_id: &str) -> Result<MsgId, Error> {
        Ok(MsgId(new_header_val(msg_id, 32)?))
    }
}

#[derive(Debug)]
pub struct HostName(pub String);
impl HostName {
    pub fn new(hostname: &str) -> Result<HostName, Error> {
        Ok(HostName(new_header_val(hostname, 255)?))
    }
}

#[derive(Debug)]
pub struct AppName(pub String);
impl AppName {
    pub fn new(name: &str) -> Result<AppName, Error> {
        Ok(AppName(new_header_val(name, 48)?))
    }
}

#[derive(Debug)]
pub struct ProcessId(pub String);
impl ProcessId {
    pub fn new(id: &str) -> Result<ProcessId, Error> {
        Ok(ProcessId(new_header_val(id, 128)?))
    }
}

#[derive(Debug)]
pub struct MessageId(pub String);
impl MessageId {
    pub fn new(id: &str) -> Result<MessageId, Error> {
        Ok(MessageId(new_header_val(id, 32)?))
    }
}

/// Convert a string into a header value. 
/// 
/// Errors: errors when `value`'s length is larger than `max_length` and when 
///     `value` doesn't contain printable ASCII characters (see `char::is_ascii_graphic`)
fn new_header_val(value: &str, max_length: usize) -> Result<String, Error> {
    if !value.chars().all(|x| x.is_ascii_graphic()) {
        return Err(Error::InvalidCharacters)
    }
    if value.len() > max_length {
        return Err(Error::FieldTooLong)
    }
    Ok(value.to_string())
}