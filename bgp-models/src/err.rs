use std::error::Error;
use std::fmt::{Display, Formatter};
use ipnet::AddrParseError;

#[derive(Debug)]
pub enum BgpModelsError {
    PrefixParsingError(String),
}

impl Display for BgpModelsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self{
            BgpModelsError::PrefixParsingError(msg) => {
                write!(f, "cannot convert str to IP prefix: {}", msg)
            }
        }
    }
}

impl Error for BgpModelsError{}

impl From<AddrParseError> for BgpModelsError {
    fn from(err: AddrParseError) -> Self {
        BgpModelsError::PrefixParsingError(err.to_string())
    }
}