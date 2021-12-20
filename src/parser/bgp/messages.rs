use std::io::{Read, Take};

use bgp_models::bgp::*;
use bgp_models::network::*;
use byteorder::ReadBytesExt;
use num_traits::FromPrimitive;

use crate::error::ParserErrorKind;
use crate::parser::{AttributeParser, parse_nlri_list, ReadUtils};
use log::warn;

/// BGP message
///
/// Format:
/// ```text
/// 0                   1                   2                   3
/// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// +                                                               +
/// |                                                               |
/// +                                                               +
/// |                           Marker                              |
/// +                                                               +
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |          Length               |      Type     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
pub fn parse_bgp_message<T: Read>(input: &mut T, add_path: bool, afi: &Afi, asn_len: &AsnLength, total_size: usize) -> Result<BgpMessage, ParserErrorKind> {
    // https://tools.ietf.org/html/rfc4271#section-4
    // 16 (4 x 4 bytes) octets marker
    input.read_32b()?;
    input.read_32b()?;
    input.read_32b()?;
    input.read_32b()?;
    /*
     This 2-octet unsigned integer indicates the total length of the
     message, including the header in octets.  Thus, it allows one
     to locate the (Marker field of the) next message in the TCP
     stream.  The value of the Length field MUST always be at least
     19 and no greater than 4096, and MAY be further constrained,
     depending on the message type.  "padding" of extra data after
     the message is not allowed.  Therefore, the Length field MUST
     have the smallest value required, given the rest of the
     message.
     */
    let length = input.read_16b()?;
    if !(length >= 19 && length <= 4096) {
        return Err(ParserErrorKind::ParseError(format!("invalid BGP message length {}", length)))
    }

    let bgp_msg_length =
        if (length as usize) > total_size {
            // return Err(ParserError::TruncatedMsg(format!("Truncated message: {} bytes available, {} bytes to read", total_size, length)))
            (total_size-19) as u64
        } else {
            (length - 19) as u64
        };

    let msg_type: BgpMessageType = match BgpMessageType::from_u8(input.read_8b()?){
        Some(t) => t,
        None => {
            return Err(ParserErrorKind::ParseError(format!("Unknown BGP Message Type")))
        }
    };

    // make sure we don't read over the bound
    let mut bgp_msg_input = input.take(bgp_msg_length);

    Ok(
        match msg_type{
            BgpMessageType::OPEN => {
                BgpMessage::Open(parse_bgp_open_message(&mut bgp_msg_input)?)
            }
            BgpMessageType::UPDATE => {
                BgpMessage::Update(parse_bgp_update_message(&mut bgp_msg_input, add_path, afi, asn_len, bgp_msg_length)?)
            }
            BgpMessageType::NOTIFICATION => {
                BgpMessage::Notification(parse_bgp_notification_message(input, bgp_msg_length - 2)?)
            }
            BgpMessageType::KEEPALIVE => {
                BgpMessage::KeepAlive(BgpKeepAliveMessage{})
            }
        }
    )
}

pub fn parse_bgp_notification_message<T: Read>(input: &mut T, bgp_msg_length: u64) -> Result<BgpNotificationMessage, ParserErrorKind> {
    let error_code = input.read_8b()?;
    let error_subcode = input.read_8b()?;
    let mut data = Vec::with_capacity((bgp_msg_length - 2) as usize);
    input.read_to_end(&mut data)?;
    Ok(
        BgpNotificationMessage{
            error_code,
            error_subcode,
            data
        })
}

pub fn parse_bgp_open_message<T: Read>(input: &mut T) -> Result<BgpOpenMessage, ParserErrorKind> {
    let version = input.read_8b()?;
    let asn = Asn{asn: input.read_16b()? as i32, len: AsnLength::Bits16};
    let hold_time = input.read_16b()?;
    let sender_ip = input.read_ipv4_address()?;
    let opt_params_len = input.read_8b()?;
    let mut opt_bytes = input.take(opt_params_len as u64);
    let mut extended_length = false;
    let mut first= true;

    let mut params: Vec<OptParam> = vec![];
    while opt_bytes.limit()>0 {
        let param_type = opt_bytes.read_8b()?;
        if first {
            // first parameter, check if it is extended length message
            if opt_params_len == 255 && param_type == 255 {
                extended_length = true;
                break
            } else {
                first = false;
            }
        }
        // reaching here means all the remain params are regular non-extended-length parameters

        let parm_length = opt_bytes.read_8b()?;
        // https://tools.ietf.org/html/rfc3392
        // https://www.iana.org/assignments/bgp-parameters/bgp-parameters.xhtml#bgp-parameters-11

        let param_value = match param_type{
            2 => {
                // capacity
                let code = opt_bytes.read_8b()?;
                let len = opt_bytes.read_8b()?;
                let value = opt_bytes.read_n_bytes(len as u64)?;

                ParamValue::Capability(
                    Capability{
                        code,
                        len,
                        value
                    }
                )
            }
            _ => {
                // unsupported param, read as raw bytes
                let bytes = opt_bytes.read_n_bytes(parm_length as u64)?;
                ParamValue::Raw(bytes)
            }
        };
        params.push(
            OptParam{
                param_type,
                param_len: parm_length as u16,
                param_value
            }
        );
    }

    Ok(
        BgpOpenMessage{
            version,
            asn,
            hold_time,
            sender_ip,
            extended_length,
            opt_params: params
        })
}

/// read nlri portion of a bgp update message.
fn read_nlri<T: Read>(input: &mut Take<T>, length: usize, afi: &Afi, add_path: bool) -> Result<Vec<NetworkPrefix>, ParserErrorKind> {
    if length==0{
        return Ok(vec![])
    }
    if length==1 {
        // 1 byte does not make sense
        warn!("seeing strange one-byte NLRI field");
        input.read_u8().unwrap();
        return Ok(vec![])
    }

    let mut buf=Vec::with_capacity(length);
    input.read_to_end(&mut buf)?;

    let mut nlri_input = buf.as_slice().take(length as u64);

    let prefixes = parse_nlri_list(&mut nlri_input, add_path, &afi)?;

    Ok(prefixes)
}

/// read bgp update message.
pub fn parse_bgp_update_message<T: Read>(input: &mut T, add_path:bool, afi: &Afi, asn_len: &AsnLength, bgp_msg_length: u64) -> Result<BgpUpdateMessage, ParserErrorKind> {
    // parse withdrawn prefixes nlri
    let withdrawn_length = input.read_16b()? as u64;
    let mut withdrawn_input = input.take(withdrawn_length);
    let withdrawn_prefixes = read_nlri(&mut withdrawn_input, withdrawn_length as usize, afi, add_path)?;

    // parse attributes
    let attribute_length = input.read_16b()? as u64;
    let attr_parser = AttributeParser::new(add_path);
    let mut attr_input = input.take(attribute_length);
    let attributes = attr_parser.parse_attributes(&mut attr_input, asn_len, None, None, None)?;

    // parse announced prefixes nlri
    let nlri_length = bgp_msg_length - 4 - withdrawn_length - attribute_length;
    let mut nlri_input = input.take(nlri_length);
    let announced_prefixes = read_nlri(&mut nlri_input, nlri_length as usize, afi, add_path)?;

    Ok(
        BgpUpdateMessage{
            withdrawn_prefixes,
            attributes,
            announced_prefixes
        }
    )
}
