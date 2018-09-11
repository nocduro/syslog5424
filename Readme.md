# `syslog5424` - trait based syslog 5424 message formatting
[![Build Status](https://dev.azure.com/nocduro/syslog5424/_apis/build/status/nocduro.syslog5424)](https://dev.azure.com/nocduro/syslog5424/_build/latest?definitionId=3)
[![crates.io badge](https://img.shields.io/crates/v/syslog5424.svg)](https://crates.io/crates/syslog5424)

This crate provides a way for data to be formatted as an RFC5424 (or RFC5425) message and written to any type that implements `Write`. 
Any type that implements the `Rfc5424Data` trait can be formatted.

## Documentation
https://docs.rs/syslog5424

## `slog` implementation
This crate was originally made as a way to have `slog` format its log messages as rfc 5424.

The implementation for that is here: https://github.com/nocduro/slog-syslog5424


## Example
This example shows a minimal implementation of the `Rfc5424Data` trait.
```rust
#[derive(Debug)]
pub struct Rfc5424Message<'a> {
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

fn main() {
    // create the formatter struct
    let formatter = Rfc5424Builder::new("enterprise_id", Facility::User)
        .hostname("api_server_1").unwrap()
        .app_name("api").unwrap()
        .build();
    
    // create a message to be formatted
    let mut hmap: StructuredData = HashMap::new();
    hmap.insert(
        "custom",
        vec![
            ("id".into(), "54".into()),
            ("progress".into(), "complete".into()),
        ],
    );

    let msg = Rfc5424Message {
        severity: Severity::Error,
        structured_data: Some(hmap),
        message: Some(Message::Text("sample message. Hello there!".into())),
    };

    // run the formatter
    let mut out = Vec::new();
    formatter.format(&mut out, &msg).unwrap();
    println!("log: {}", String::from_utf8(out).unwrap());
}
```

## OS support
Should work on any system where `std` is available, the OS specifics are introduced by the user when picking which `Writer` to use.

## License
MIT (see LICENSE)
