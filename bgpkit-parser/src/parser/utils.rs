/*!
Provides IO utility functions for read bytes of different length and converting to corresponding structs.
 */
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::io::{Cursor, Seek, SeekFrom};
use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr},
};

use bgp_models::network::{Afi, Asn, AsnLength, NetworkPrefix, Safi};
use byteorder::{ReadBytesExt, BE};
use log::debug;
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

pub fn parse_nlri_list(
    input: &mut Cursor<&[u8]>,
    add_path: bool,
    afi: &Afi,
    total_bytes: u64,
) -> Result<Vec<NetworkPrefix>, ParserError> {
    let pos_end = input.position() + total_bytes;

    let mut is_add_path = add_path;
    let mut prefixes = vec![];

    let mut retry = false;
    let mut guessed = false;

    let pos_save = input.position();

    while input.position() < pos_end {
        if !is_add_path && input.get_ref()[input.position() as usize] == 0 {
            // it's likely that this is a add-path wrongfully wrapped in non-add-path msg
            debug!("not add-path but with NLRI size to be 0, likely add-path msg in wrong msg type, treat as add-path now");
            is_add_path = true;
            guessed = true;
        }
        let prefix = match input.read_nlri_prefix(afi, is_add_path) {
            Ok(p) => p,
            Err(e) => {
                if guessed {
                    retry = true;
                    break;
                } else {
                    return Err(e);
                }
            }
        };
        prefixes.push(prefix);
    }

    if retry {
        prefixes.clear();
        // try again without attempt to guess add-path
        input.seek(SeekFrom::Start(pos_save))?;
        while input.position() < pos_end {
            let prefix = input.read_nlri_prefix(afi, add_path)?;
            prefixes.push(prefix);
        }
    }

    Ok(prefixes)
}

// All types that implement Read can now read prefixes
impl<R: io::Read> ReadUtils for R {}
