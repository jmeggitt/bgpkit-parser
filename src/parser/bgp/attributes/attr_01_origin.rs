use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;
use num_traits::FromPrimitive;

pub fn parse_origin(mut input: &[u8]) -> Result<AttributeValue, ParserError> {
    match Origin::from_u8(input.read_u8()?) {
        Some(v) => Ok(AttributeValue::Origin(v)),
        None => Err(ParserError::ParseError(
            "Failed to parse attribute type: origin".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// test parse origin
    /// ```text
    /// ORIGIN is a well-known mandatory attribute that defines the
    ///        origin of the path information.  The data octet can assume
    ///        the following values:
    ///
    ///           Value      Meaning
    ///
    ///           0         IGP - Network Layer Reachability Information
    ///                        is interior to the originating AS
    ///
    ///           1         EGP - Network Layer Reachability Information
    ///                        learned via the EGP protocol [RFC904]
    ///
    ///           2         INCOMPLETE - Network Layer Reachability
    ///                        Information learned by some other means
    ///
    /// Usage of this attribute is defined in 5.1.1.
    /// ```
    #[test]
    fn test_parse_origin() {
        assert_eq!(
            AttributeValue::Origin(Origin::IGP),
            parse_origin(&[0u8]).unwrap()
        );
        assert_eq!(
            AttributeValue::Origin(Origin::EGP),
            parse_origin(&[1u8]).unwrap()
        );
        assert_eq!(
            AttributeValue::Origin(Origin::INCOMPLETE),
            parse_origin(&[2u8]).unwrap()
        );
        assert!(matches!(
            parse_origin(&[3u8]).unwrap_err(),
            ParserError::ParseError(_)
        ));
    }
}
