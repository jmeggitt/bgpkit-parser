use bgp_models::network::Afi;
use oneio::OneIoError;
use std::fmt::{Display, Formatter};
use std::io::ErrorKind;
use std::{error::Error, fmt, io};

#[derive(Debug)]
pub enum ParserError {
    IoError(io::Error),
    IoNotEnoughBytes(),
    EofError(io::Error),
    OneIoError(OneIoError),
    EofExpected,
    ParseError(String),
    UnknownAttr(String),
    DeprecatedAttr(String),
    TruncatedMsg(String),
    Unsupported(String),
    FilterError(String),
    InvalidPrefixLength { afi: Afi, bit_length: u8 },
}

impl Error for ParserError {}

#[derive(Debug)]
pub struct ParserErrorWithBytes {
    pub error: ParserError,
    pub bytes: Option<Vec<u8>>,
}

impl Display for ParserErrorWithBytes {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.error)
    }
}

impl Error for ParserErrorWithBytes {}

/// implement Display trait for Error which satistifies the std::error::Error
/// trait's requirement (must implement Display and Debug traits, Debug already derived)
impl Display for ParserError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            ParserError::IoError(e) => write!(f, "{}", e),
            ParserError::EofError(e) => write!(f, "{}", e),
            ParserError::ParseError(s) => write!(f, "{}", s),
            ParserError::TruncatedMsg(s) => write!(f, "{}", s),
            ParserError::DeprecatedAttr(s) => write!(f, "{}", s),
            ParserError::UnknownAttr(s) => write!(f, "{}", s),
            ParserError::Unsupported(s) => write!(f, "{}", s),
            ParserError::EofExpected => write!(f, "reached end of file"),
            ParserError::OneIoError(e) => write!(f, "{}", e),
            ParserError::FilterError(e) => write!(f, "{}", e),
            ParserError::IoNotEnoughBytes() => write!(f, "Not enough bytes to read"),
            ParserError::InvalidPrefixLength { afi, bit_length } => {
                let byte_length = (bit_length + 7) / 8;
                write!(
                    f,
                    "Invalid byte length for {:?} prefix. byte_len: {}, bit_len: {}",
                    afi, byte_length, bit_length
                )
            }
        }
    }
}

impl From<OneIoError> for ParserErrorWithBytes {
    fn from(error: OneIoError) -> Self {
        ParserErrorWithBytes {
            error: ParserError::OneIoError(error),
            bytes: None,
        }
    }
}

impl From<OneIoError> for ParserError {
    fn from(error: OneIoError) -> Self {
        ParserError::OneIoError(error)
    }
}

impl From<ParserError> for ParserErrorWithBytes {
    fn from(error: ParserError) -> Self {
        ParserErrorWithBytes { error, bytes: None }
    }
}

impl From<io::Error> for ParserError {
    fn from(io_error: io::Error) -> Self {
        match io_error.kind() {
            ErrorKind::UnexpectedEof => ParserError::EofError(io_error),
            _ => ParserError::IoError(io_error),
        }
    }
}
