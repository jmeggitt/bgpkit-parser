/*!
Provides IO utility functions for read bytes of different length and converting to corresponding structs.
 */
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::io::Cursor;
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};

use bgp_models::network::{Afi, Asn, AsnLength, NetworkPrefix, Safi};
use byteorder::{ReadBytesExt, BE};
use num_traits::FromPrimitive;
use std::net::IpAddr;

use crate::error::ParserError;

// Allow reading IPs from Reads
pub trait ReadUtils: io::Read {
    fn read_8b(&mut self) -> io::Result<u8> {
        self.read_u8()
    }

    fn read_16b(&mut self) -> io::Result<u16> {
        self.read_u16::<BE>()
    }

    fn read_32b(&mut self) -> io::Result<u32> {
        self.read_u32::<BE>()
    }

    fn read_64b(&mut self) -> io::Result<u64> {
        self.read_u64::<BE>()
    }

    fn read_128b(&mut self) -> io::Result<u128> {
        self.read_u128::<BE>()
    }

    fn read_address(&mut self, afi: &Afi) -> io::Result<IpAddr> {
        match afi {
            Afi::Ipv4 => match self.read_ipv4_address() {
                Ok(ip) => Ok(IpAddr::V4(ip)),
                _ => Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Cannot parse IPv4 address".to_string(),
                )),
            },
            Afi::Ipv6 => match self.read_ipv6_address() {
                Ok(ip) => Ok(IpAddr::V6(ip)),
                _ => Err(io::Error::new(
                    io::ErrorKind::Other,
                    "Cannot parse IPv6 address".to_string(),
                )),
            },
        }
    }

    fn read_ipv4_address(&mut self) -> Result<Ipv4Addr, ParserError> {
        let addr = self.read_32b()?;
        Ok(Ipv4Addr::from(addr))
    }

    fn read_ipv6_address(&mut self) -> Result<Ipv6Addr, ParserError> {
        let buf = self.read_u128::<BE>()?;
        Ok(Ipv6Addr::from(buf))
    }

    fn read_ipv4_prefix(&mut self) -> Result<Ipv4Net, ParserError> {
        let addr = self.read_ipv4_address()?;
        let mask = self.read_8b()?;
        match Ipv4Net::new(addr, mask) {
            Ok(n) => Ok(n),
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Invalid prefix mask").into()),
        }
    }

    fn read_ipv6_prefix(&mut self) -> Result<Ipv6Net, ParserError> {
        let addr = self.read_ipv6_address()?;
        let mask = self.read_8b()?;
        match Ipv6Net::new(addr, mask) {
            Ok(n) => Ok(n),
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Invalid prefix mask").into()),
        }
    }

    fn read_asn(&mut self, as_length: &AsnLength) -> Result<Asn, ParserError> {
        match as_length {
            AsnLength::Bits16 => Ok(Asn::new_16bit(self.read_u16::<BE>()?)),
            AsnLength::Bits32 => Ok(Asn::new_32bit(self.read_32b()?)),
        }
    }

    fn read_asns(&mut self, as_length: &AsnLength, count: usize) -> Result<Vec<Asn>, ParserError> {
        let mut asns = Vec::with_capacity(count);

        match as_length {
            AsnLength::Bits16 => {
                for _ in 0..count {
                    asns.push(Asn::new_16bit(self.read_u16::<BE>()?));
                }
            }
            AsnLength::Bits32 => {
                for _ in 0..count {
                    asns.push(Asn::new_32bit(self.read_32b()?));
                }
            }
        }

        Ok(asns)
    }

    fn read_afi(&mut self) -> Result<Afi, ParserError> {
        let afi = self.read_u16::<BE>()?;
        match Afi::from_i16(afi as i16) {
            Some(afi) => Ok(afi),
            None => Err(crate::error::ParserError::Unsupported(format!(
                "Unknown AFI type: {}",
                afi
            ))),
        }
    }

    fn read_safi(&mut self) -> Result<Safi, ParserError> {
        let safi = self.read_8b()?;
        match Safi::from_u8(safi) {
            Some(safi) => Ok(safi),
            None => Err(crate::error::ParserError::Unsupported(format!(
                "Unknown SAFI type: {}",
                safi
            ))),
        }
    }

    /// An alternative to [ReadUtils::read_nlri_prefix] which is easier for the compiler to
    /// optimize. Calling `x.read_v4_nlri_prefix()` is functionally equivalent to
    /// `x.read_nlri_prefix(&Afi::Ipv4, false)`.
    #[inline(always)]
    fn read_v4_nlri_prefix(&mut self) -> Result<NetworkPrefix, ParserError> {
        // Length in bits and bytes
        let bit_len = self.read_8b()?;

        if bit_len > 32 {
            return Err(ParserError::InvalidPrefixLength {
                afi: Afi::Ipv4,
                bit_length: bit_len,
            });
        }

        let byte_len: usize = (bit_len as usize + 7) / 8;

        let mut buff = [0; 4];
        self.read_exact(&mut buff[..byte_len])?;

        let prefix = match Ipv4Net::new(Ipv4Addr::from(buff), bit_len) {
            Ok(v) => IpNet::V4(v),
            Err(_) => unreachable!("Bit length has already been checked"),
        };

        Ok(NetworkPrefix { prefix, path_id: 0 })
    }

    /// An alternative to [ReadUtils::read_nlri_prefix] which is easier for the compiler to
    /// optimize. Calling `x.read_v6_nlri_prefix()` is functionally equivalent to
    /// `x.read_nlri_prefix(&Afi::Ipv6, false)`.
    #[inline(always)]
    fn read_v6_nlri_prefix(&mut self) -> Result<NetworkPrefix, ParserError> {
        // Length in bits and bytes
        let bit_len = self.read_8b()?;

        // 16 bytes
        if bit_len > 128 {
            return Err(ParserError::InvalidPrefixLength {
                afi: Afi::Ipv6,
                bit_length: bit_len,
            });
        }
        let byte_len: usize = (bit_len as usize + 7) / 8;

        let mut buff = [0; 16];
        self.read_exact(&mut buff[..byte_len])?;

        let prefix = match Ipv6Net::new(Ipv6Addr::from(buff), bit_len) {
            Ok(v) => IpNet::V6(v),
            Err(_) => unreachable!("Bit length has already been checked"),
        };

        Ok(NetworkPrefix { prefix, path_id: 0 })
    }

    /// Read announced/withdrawn prefix.
    ///
    /// The length in bits is 1 byte, and then based on the IP version it reads different number of bytes.
    /// If the `add_path` is true, it will also first read a 4-byte path id first; otherwise, a path-id of 0
    /// is automatically set.
    fn read_nlri_prefix(
        &mut self,
        afi: &Afi,
        add_path: bool,
    ) -> Result<NetworkPrefix, ParserError> {
        let path_id = if add_path { self.read_32b()? } else { 0 };

        // Length in bits and bytes
        let bit_len = self.read_8b()?;
        let byte_len: usize = (bit_len as usize + 7) / 8;

        let prefix = match afi {
            Afi::Ipv4 => {
                // 4 bytes
                if bit_len > 32 {
                    return Err(ParserError::InvalidPrefixLength {
                        afi: Afi::Ipv4,
                        bit_length: bit_len,
                    });
                }

                let mut buff = [0; 4];
                self.read_exact(&mut buff[..byte_len])?;

                match Ipv4Net::new(Ipv4Addr::from(buff), bit_len) {
                    Ok(v) => IpNet::V4(v),
                    Err(_) => unreachable!("Bit length has already been checked"),
                }
            }
            Afi::Ipv6 => {
                // 16 bytes
                if bit_len > 128 {
                    return Err(ParserError::InvalidPrefixLength {
                        afi: Afi::Ipv6,
                        bit_length: bit_len,
                    });
                }

                let mut buff = [0; 16];
                self.read_exact(&mut buff[..byte_len])?;

                match Ipv6Net::new(Ipv6Addr::from(buff), bit_len) {
                    Ok(v) => IpNet::V6(v),
                    Err(_) => unreachable!("Bit length has already been checked"),
                }
            }
        };

        Ok(NetworkPrefix::new(prefix, path_id))
    }

    fn read_n_bytes(&mut self, n_bytes: usize) -> Result<Vec<u8>, ParserError> {
        let mut buffer = vec![0; n_bytes];
        self.read_exact(&mut buffer[..])?;
        Ok(buffer)
    }

    fn read_n_bytes_to_string(&mut self, n_bytes: usize) -> Result<String, ParserError> {
        let buffer = self.read_n_bytes(n_bytes)?;

        String::from_utf8(buffer).map_err(|e| {
            let msg = format!("Attempted to read non-utf8 bytes to string: {}", e);
            ParserError::ParseError(msg)
        })
    }
}

#[cold]
#[inline(never)]
fn parse_nlri_list_fallback(
    mut input: &[u8],
    afi: Afi,
    add_path: bool,
) -> Result<Vec<NetworkPrefix>, ParserError> {
    let mut prefixes = Vec::with_capacity(input.len() / 4);
    while !input.is_empty() {
        prefixes.push((&mut input).read_nlri_prefix(&afi, add_path)?);
    }

    Ok(prefixes)
}

fn parse_nlri_list_v4(mut input: &[u8]) -> Result<Vec<NetworkPrefix>, ParserError> {
    let retry_input = input;
    let mut prefixes = Vec::with_capacity(input.len() / 3);

    while !input.is_empty() {
        if input[0] == 0 {
            return match parse_nlri_list_fallback(retry_input, Afi::Ipv4, true) {
                Ok(v) => Ok(v),
                Err(_) => parse_nlri_list_fallback(retry_input, Afi::Ipv4, false),
            };
        }

        prefixes.push((&mut input).read_v4_nlri_prefix()?);
    }

    Ok(prefixes)
}

fn parse_nlri_list_v6(mut input: &[u8]) -> Result<Vec<NetworkPrefix>, ParserError> {
    let retry_input = input;
    let mut prefixes = Vec::with_capacity(input.len() / 5);

    while !input.is_empty() {
        if input[0] == 0 {
            return match parse_nlri_list_fallback(retry_input, Afi::Ipv6, true) {
                Ok(v) => Ok(v),
                Err(_) => parse_nlri_list_fallback(retry_input, Afi::Ipv6, false),
            };
        }

        prefixes.push((&mut input).read_v6_nlri_prefix()?);
    }

    Ok(prefixes)
}

pub fn parse_nlri_list(
    input: &[u8],
    add_path: bool,
    afi: Afi,
) -> Result<Vec<NetworkPrefix>, ParserError> {
    if add_path {
        return parse_nlri_list_fallback(input, afi, true);
    }

    match afi {
        Afi::Ipv4 => parse_nlri_list_v4(input),
        Afi::Ipv6 => parse_nlri_list_v6(input),
    }
}

#[inline(always)]
pub fn next_slice_in_cursor<'a>(input: &mut Cursor<&'a [u8]>, length: u64) -> &'a [u8] {
    let input_ref =
        &input.get_ref()[input.position() as usize..(input.position() + length) as usize];
    input.set_position(input.position() + length);

    input_ref
}

// All types that implement Read can now read prefixes
impl<R: io::Read> ReadUtils for R {}
