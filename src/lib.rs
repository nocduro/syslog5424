use std::io::{self, Write};

pub mod errors;
pub mod rfc5424;
pub use errors::Error;
pub use rfc5424::Rfc5424;

pub trait Formatter {
    fn format<W: Write>(&self, destination: W) -> io::Result<()>;
}
