//! Implementations of reserved IANA `SD-ID`'s

use std::fmt;

/// The SD-ID "origin" MAY be used to indicate the origin of a syslog
/// message.  The following parameters can be used.  All parameters are
/// OPTIONAL.
/// 
/// Specifying any of these parameters is primarily an aid to log
/// analyzers and similar applications.
/// 
/// Notes: 
/// * Documentation text copied from: 
/// [RFC5424 Section 7.2](https://tools.ietf.org/html/rfc5424#section-7.2)
/// * No automatic bounds checking is currently done for these fields. 
/// Check the documentation for the length limits.
#[derive(Debug)]
pub enum Origin {
    /// The "ip" parameter denotes an IP address that the originator knows it
    /// had at the time of originating the message.  It MUST contain the
    /// textual representation of an IP address as outlined in [Section 
    /// 6.2.4](https://tools.ietf.org/html/rfc5424#section-6.2.4).
    /// 
    /// This parameter can be used to provide identifying information in
    /// addition to what is present in the HOSTNAME field.  It might be
    /// especially useful if the host's IP address is included in the message
    /// while the HOSTNAME field still contains the FQDN.  It is also useful
    /// for describing all IP addresses of a multihomed host.
    ///
    /// If an originator has multiple IP addresses, it MAY either list one of
    /// its IP addresses in the "ip" parameter or it MAY include multiple
    /// "ip" parameters in a single "origin" structured data element.
    Ip(String),
    /// The "enterpriseId" parameter MUST be a 'SMI Network Management
    /// Private Enterprise Code', maintained by IANA, whose prefix is
    /// iso.org.dod.internet.private.enterprise (1.3.6.1.4.1).  The number
    /// that follows MUST be unique and MUST be registered with IANA as per
    /// [RFC 2578](https://tools.ietf.org/html/rfc2578).
    /// 
    /// An enterprise is only authorized to assign
    /// values within the iso.org.dod.internet.private.enterprise.<private
    /// enterprise number> subtree assigned by IANA to that enterprise.  The
    /// enterpriseId MUST contain only a value from the
    /// iso.org.dod.internet.private.enterprise.<private enterprise number>
    /// subtree.  In general, only the IANA-assigned private enterprise
    /// number is needed (a single number).  An enterprise might decide to
    /// use sub-identifiers below its private enterprise number.  If sub-
    /// identifiers are used, they MUST be separated by periods and be
    /// represented as decimal numbers.  An example for that would be
    /// "32473.1.2".  Please note that the ID "32473.1.2" is just an example
    /// and MUST NOT be used.  The complete up-to-date list of Private
    /// Enterprise Numbers (PEN) is maintained by IANA.
    /// 
    /// By specifying a private enterprise number, the vendor allows more
    /// specific processing of the message.
    EnterpriseId(String),
    /// The "software" parameter uniquely identifies the software that
    /// generated the message.  If it is used, "enterpriseId" SHOULD also be
    /// specified, so that a specific vendor's software can be identified.
    /// The "software" parameter is not the same as the APP-NAME header
    /// field.  It MUST always contain the name of the generating software,
    /// whereas APP-NAME can contain anything else, including an operator-
    /// configured value.
    /// 
    /// The "software" parameter is a string.  It MUST NOT be longer than 48
    /// characters.
    Software(String),
    /// The "swVersion" parameter uniquely identifies the version of the
    /// software that generated the message.  If it is used, the "software"
    /// and "enterpriseId" parameters SHOULD be provided, too.
    /// 
    /// The "swVersion" parameter is a string.  It MUST NOT be longer than 32
    /// characters.
    Version(String),
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Origin::*;
        let val = match self {
            Ip(s) => format!(r#" ip="{}""#, s),
            EnterpriseId(s) => format!(r#" enterpriseId="{}""#, s),
            Software(s) => format!(r#" software="{}""#, s),
            Version(s) => format!(r#" swVersion="{}""#, s),
        };
        write!(f, "{}", val)
    }
}

/// The SD-ID "timeQuality" MAY be used by the originator to describe its
/// notion of system time.  
/// 
/// This SD-ID SHOULD be written if the
/// originator is not properly synchronized with a reliable external time
/// source or if it does not know whether its time zone information is
/// correct.  The main use of this structured data element is to provide
/// some information on the level of trust it has in the TIMESTAMP
/// described in [Section 6.2.3](https://tools.ietf.org/html/rfc5424#section-6.2.3).  All parameters are OPTIONAL.
/// 
/// Notes: 
/// * Documentation text copied from: 
/// [RFC5424 Section 7.1](https://tools.ietf.org/html/rfc5424#section-7.1)
/// * No automatic bounds checking is currently done for these fields. 
#[derive(Debug, Copy, Clone)]
pub enum TimeQuality {
    /// The "tzKnown" parameter indicates whether the originator knows its
    /// time zone.  If it does, the value "1" MUST be used.  If the time zone
    /// information is in doubt, the value "0" MUST be used.  If the
    /// originator knows its time zone but decides to emit time in UTC, the
    /// value "1" MUST be used (because the time zone is known).
    TzKnown(bool),
    /// The "isSynced" parameter indicates whether the originator is
    /// synchronized to a reliable external time source, e.g., via NTP.  If
    /// the originator is time synchronized, the value "1" MUST be used.  If
    /// not, the value "0" MUST be used.
    IsSynced(bool),
    /// The "syncAccuracy" parameter indicates how accurate the originator
    /// thinks its time synchronization is.  It is an integer describing the
    /// maximum number of microseconds that its clock may be off between
    /// synchronization intervals.
    /// 
    /// If the value "0" is used for "isSynced", this parameter MUST NOT be
    /// specified.  If the value "1" is used for "isSynced" but the
    /// "syncAccuracy" parameter is absent, a collector or relay can assume
    /// that the time information provided is accurate enough to be
    /// considered correct.  The "syncAccuracy" parameter MUST be written
    /// only if the originator actually has knowledge of the reliability of
    /// the external time source.  In most cases, it will gain this in-depth
    /// knowledge through operator configuration.
    SyncAccuracy(u32),
}

impl fmt::Display for TimeQuality {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::TimeQuality::*;
        let val = match self {
            TzKnown(s) => if *s {
                r#" tzKnown="1""#.to_string()
            } else {
                r#" tz_known="0""#.to_string()
            },
            IsSynced(s) => if *s {
                r#" isSynced="1""#.to_string()
            } else {
                r#" isSynced="0""#.to_string()
            },
            SyncAccuracy(s) => format!(r#" syncAccuracy="{}""#, s),
        };
        write!(f, "{}", val)
    }
}
