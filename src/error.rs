//! Error type shared across the crate.

use std::fmt;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Usage(String),
    Proto(String),
    Crypto(String),
    Key(String),
    HostKey(String),
    Auth(String),
    Pty(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "i/o error: {e}"),
            Error::Usage(m) => write!(f, "{m}"),
            Error::Proto(m) => write!(f, "protocol error: {m}"),
            Error::Crypto(m) => write!(f, "crypto error: {m}"),
            Error::Key(m) => write!(f, "key error: {m}"),
            Error::HostKey(m) => write!(f, "host key error: {m}"),
            Error::Auth(m) => write!(f, "authentication error: {m}"),
            Error::Pty(m) => write!(f, "pty error: {m}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl Error {
    pub fn usage(m: impl Into<String>) -> Self {
        Error::Usage(m.into())
    }
    pub fn proto(m: impl Into<String>) -> Self {
        Error::Proto(m.into())
    }
    pub fn key(m: impl Into<String>) -> Self {
        Error::Key(m.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
