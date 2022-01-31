use std::fmt;
use std::io;

/// Write value of a simple enum as a `serde` serialized string.
pub fn write_enum<T>(f: &mut fmt::Formatter, value: &T) -> fmt::Result {
    panic!("not implemented")
}

// Read value of a simple enum using a stub `serde` deserializer.
pub fn read_enum<'a, T>(s: &'a str) -> Result<T> {
    panic!("not implemented")
}

////////////////////////////////////////////////////////////////////////////////

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    Message(String),
    NotImplemented,
}

impl From<Error> for io::Error {
    fn from(err: Error) -> Self {
        io::Error::new(io::ErrorKind::InvalidInput, err)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Message(msg) => write!(f, "{}", msg),
            Error::NotImplemented => write!(f, "Not implemented"),
        }
    }
}

impl std::error::Error for Error {}

type Result<T> = std::result::Result<T, Error>;
