use crate::models::*;
use crate::parser::ReadUtils;
use crate::ParserError;

pub fn parse_originator_id(
    mut input: &[u8],
    afi: &Option<Afi>,
) -> Result<AttributeValue, ParserError> {
    let afi = match afi {
        None => &Afi::Ipv4,
        Some(a) => a,
    };
    let addr = input.read_address(afi)?;
    Ok(AttributeValue::OriginatorId(addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn test_parse_originator_id() {
        let ipv4 = Ipv4Addr::from_str("10.0.0.1").unwrap();
        if let Ok(AttributeValue::OriginatorId(n)) = parse_originator_id(&ipv4.octets(), &None) {
            assert_eq!(n, ipv4);
        } else {
            panic!()
        }

        let ipv6 = Ipv6Addr::from_str("fc::1").unwrap();
        if let Ok(AttributeValue::OriginatorId(n)) =
            parse_originator_id(&ipv6.octets(), &Some(Afi::Ipv6))
        {
            assert_eq!(n, ipv6);
        } else {
            panic!()
        }
    }
}
