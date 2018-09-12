//! Types used to specify values in a RFC5424 message

use {Error, NILVALUE};

/// Syslog facility
///
/// * [Definition in RFC5424 Section 6.2.1](https://tools.ietf.org/html/rfc5424#section-6.2.1)
#[derive(Debug, Clone, Copy)]
pub enum Facility {
    Kernel = 0,
    User = 1,
    Mail = 2,
    Daemon = 3,
    Auth = 4,
    Syslog = 5,
    LinePrinter = 6,
    News = 7,
    UUCP = 8,
    Cron = 9,
    AuthPriv = 10,
    FTP = 11,
    NTP = 12,
    Security = 13,
    Console = 14,
    ClockDaemon = 15,
    Local0 = 16,
    Local1 = 17,
    Local2 = 18,
    Local3 = 19,
    Local4 = 20,
    Local5 = 21,
    Local6 = 22,
    Local7 = 23,
}

impl Default for Facility {
    fn default() -> Facility {
        Facility::User
    }
}

/// Syslog severity
///
/// * [Definition in RFC5424 Section 6.2.1](https://tools.ietf.org/html/rfc5424#section-6.2.1)
/// * [Severity Values A.3.](https://tools.ietf.org/html/rfc5424#appendix-A.3)
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

/// The message portion of a syslog message may be either UTF-8 or
/// binary.
#[derive(Debug, Clone)]
pub enum Message {
    Text(String),
    Binary(Vec<u8>),
}

/// Wrapper for `String` containing the Host Name. Limited to 255 ASCII chars.
#[derive(Debug)]
pub struct HostName(pub String);
impl HostName {
    pub fn new(hostname: &str) -> Result<HostName, Error> {
        Ok(HostName(new_header_val(hostname, 255)?))
    }
}

impl Default for HostName {
    fn default() -> HostName {
        HostName(format!("{}", NILVALUE))
    }
}

/// Wrapper for `String` containing the App Name. Limited to 48 ASCII chars.
#[derive(Debug)]
pub struct AppName(pub String);
impl AppName {
    pub fn new(name: &str) -> Result<AppName, Error> {
        Ok(AppName(new_header_val(name, 48)?))
    }
}

impl Default for AppName {
    fn default() -> AppName {
        AppName(format!("{}", NILVALUE))
    }
}

/// Wrapper for `String` containing the Process ID. Limited to 128 ASCII chars.
#[derive(Debug)]
pub struct ProcessId(pub String);
impl ProcessId {
    pub fn new(id: &str) -> Result<ProcessId, Error> {
        Ok(ProcessId(new_header_val(id, 128)?))
    }
}

impl Default for ProcessId {
    fn default() -> ProcessId {
        ProcessId(format!("{}", NILVALUE))
    }
}

/// Wrapper for `String` containing the Message ID. Limited to 32 ASCII chars.
#[derive(Debug)]
pub struct MessageId(pub String);
impl MessageId {
    pub fn new(id: &str) -> Result<MessageId, Error> {
        Ok(MessageId(new_header_val(id, 32)?))
    }
}

impl Default for MessageId {
    fn default() -> MessageId {
        MessageId(format!("{}", NILVALUE))
    }
}

/// Convert a string into a header value after verifying it is valid.
///
/// # Errors
/// * `value`'s length is larger than `max_length`
/// * `value` is an empty string
/// * `value` doesn't contain printable ASCII characters (see `char::is_ascii_graphic`)
fn new_header_val(value: &str, max_length: usize) -> Result<String, Error> {
    if value.is_empty() {
        return Err(Error::FieldEmpty);
    }
    if !value.chars().all(|x| x.is_ascii_graphic()) {
        return Err(Error::InvalidCharacters);
    }
    if value.len() > max_length {
        return Err(Error::FieldTooLong);
    }
    Ok(value.to_string())
}

/// Escape the `val` parameter according to PARAM-VALUE rule from RFC5424.
#[inline]
pub fn escape_val(val: &str) -> String {
    val.replace('\\', r#"\\"#)
        .replace('"', r#"\""#)
        .replace(']', r#"\]"#)
}

/// Remove invalid characters from `name`. Used for values in PARAM-NAME
/// and SD-ID from RFC5424. Removes `'=', ' ', ']', '"'`, and non-printable
/// ASCII characters. The filtered message is then truncated to 32 characters.
#[inline]
pub fn remove_invalid(name: &str) -> String {
    name.chars()
        .filter(char::is_ascii_graphic)
        .filter(|c| *c != '=')
        .filter(|c| *c != ' ')
        .filter(|c| *c != ']')
        .filter(|c| *c != '"')
        .take(32)
        .collect()
}
