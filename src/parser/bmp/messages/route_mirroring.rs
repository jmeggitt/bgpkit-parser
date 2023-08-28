use crate::models::*;
use crate::parser::bgp::messages::parse_bgp_update_message;
use crate::parser::bmp::error::ParserBmpError;
use crate::parser::ReadUtils;
use num_traits::FromPrimitive;

#[derive(Debug)]
pub struct RouteMirroring {
    pub tlvs: Vec<RouteMirroringTlv>,
}

#[derive(Debug)]
pub struct RouteMirroringTlv {
    pub info_len: u16,
    pub value: RouteMirroringValue,
}

#[derive(Debug)]
pub enum RouteMirroringValue {
    BgpMessage(BgpUpdateMessage),
    Information(RouteMirroringInfo),
}

#[derive(Debug, Primitive)]
pub enum RouteMirroringInfo {
    ErroredPdu = 0,
    MessageLost = 1,
}

pub fn parse_route_mirroring(
    data: &mut &[u8],
    asn_len: &AsnLength,
) -> Result<RouteMirroring, ParserBmpError> {
    let mut tlvs = vec![];
    while data.remaining() > 4 {
        match data.read_u16()? {
            0 => {
                let info_len = data.read_u16()?;
                let (bytes, remaining) = data.split_at(info_len as usize);
                *data = remaining;
                let value = parse_bgp_update_message(bytes, false, asn_len)?;
                tlvs.push(RouteMirroringTlv {
                    info_len,
                    value: RouteMirroringValue::BgpMessage(value),
                });
            }
            1 => {
                let info_len = data.read_u16()?;
                let value = RouteMirroringInfo::from_u16(data.read_u16()?).unwrap();
                tlvs.push(RouteMirroringTlv {
                    info_len,
                    value: RouteMirroringValue::Information(value),
                });
            }
            _ => return Err(ParserBmpError::CorruptedBmpMessage),
        }
    }
    Ok(RouteMirroring { tlvs })
}
