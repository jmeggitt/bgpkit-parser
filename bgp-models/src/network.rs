//! Common network-related structs.

use crate::err::BgpModelsError;
use ipnet::IpNet;
use serde::{Deserialize, Serialize, Serializer};
use std::convert::TryFrom;
use std::fmt::{Display, Formatter};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::str::FromStr;

/// Meta information for an address/prefix.
///
/// [AddrMeta] is a struct that used to save address family and as number length information
/// when parsing [TableDumpMessage].
///
/// The meta information includes:
/// 1. `afi`: address family ([Afi]): IPv4 or IPv6,
/// 2. `asn_len`: AS number length ([AsnLength]): 16 or 32 bits.
#[derive(Debug, Clone, Serialize, Copy)]
pub struct AddrMeta {
    pub afi: Afi,
    pub asn_len: AsnLength,
}

/// AS number length: 16 or 32 bits.
#[derive(Debug, Clone, Serialize, Copy, Deserialize, PartialEq, Eq)]
pub enum AsnLength {
    Bits16,
    Bits32,
}

/// ASN -- Autonomous System Number
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Hash)]
#[repr(transparent)]
pub struct Asn {
    asn: u32,
}

impl Asn {
    pub const fn new_16bit(asn: u16) -> Self {
        Asn { asn: asn as u32 }
    }

    pub const fn new_32bit(asn: u32) -> Self {
        Asn { asn }
    }

    pub fn size(&self) -> AsnLength {
        if self.asn <= u16::MAX as u32 {
            AsnLength::Bits16
        } else {
            AsnLength::Bits32
        }
    }

    /// Checks if the given ASN is reserved for private use.
    ///
    /// <https://datatracker.ietf.org/doc/rfc7249/>
    pub const fn is_private(&self) -> bool {
        match self.asn {
            64512..=65534 => true,           // reserved by RFC6996
            4200000000..=4294967294 => true, // reserved by RFC6996
            _ => false,
        }
    }

    /// Checks if the given ASN is public. This is done by checking that the asn is not included
    /// within IANA's "Special-Purpose AS Numbers" registry. This includes checking against private
    /// ASN ranges, ASNs reserved for documentation, and ASNs reserved for specific uses by various
    /// RFCs.
    ///
    /// Up to date as of 2023-03-01 (Registry was last updated 2015-08-07).
    ///
    /// For additional details see:
    ///  - <https://datatracker.ietf.org/doc/rfc7249/>
    ///  - <https://www.iana.org/assignments/iana-as-numbers-special-registry/iana-as-numbers-special-registry.xhtml>
    pub const fn is_public(&self) -> bool {
        match self.asn {
            0 => false,                       // reserved by RFC7607
            112 => false,                     // reserved by RFC7534
            23456 => false,                   // reserved by RFC6793
            64496..=64511 => false,           // reserved by RFC5398
            64512..=65534 => false,           // reserved by RFC6996
            65535 => false,                   // reserved by RFC7300
            65536..=65551 => false,           // reserved by RFC5398
            4200000000..=4294967294 => false, // reserved by RFC6996
            4294967295 => false,              // reserved by RFC7300
            _ => true,
        }
    }

    /// Checks if the given ASN is reserved for use in documentation and sample code.
    ///
    /// <https://datatracker.ietf.org/doc/rfc7249/>
    pub const fn is_reserved_for_documentation(&self) -> bool {
        match self.asn {
            64496..=64511 => true, // reserved by RFC5398
            65536..=65551 => true, // reserved by RFC5398
            _ => false,
        }
    }
}

impl Deref for Asn {
    type Target = u32;

    fn deref(&self) -> &Self::Target {
        &self.asn
    }
}

impl PartialEq<u32> for Asn {
    fn eq(&self, other: &u32) -> bool {
        self.asn == *other
    }
}

impl From<u32> for Asn {
    fn from(asn: u32) -> Self {
        Asn::new_32bit(asn)
    }
}

impl From<u16> for Asn {
    fn from(asn: u16) -> Self {
        Asn::new_16bit(asn)
    }
}

impl From<Asn> for u32 {
    fn from(value: Asn) -> Self {
        value.asn
    }
}

impl TryFrom<Asn> for u16 {
    type Error = <u16 as TryFrom<u32>>::Error;

    fn try_from(value: Asn) -> Result<Self, Self::Error> {
        u16::try_from(value.asn)
    }
}

impl Serialize for Asn {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u32(self.asn)
    }
}

/// AFI -- Address Family Identifier
///
/// https://www.iana.org/assignments/address-family-numbers/address-family-numbers.xhtml
#[derive(Debug, PartialEq, Primitive, Clone, Copy, Serialize, Eq)]
pub enum Afi {
    Ipv4 = 1,
    Ipv6 = 2,
}

/// SAFI -- Subsequent Address Family Identifier
///
/// SAFI can be: Unicast, Multicast, or both.
#[derive(Debug, PartialEq, Primitive, Clone, Copy, Serialize, Eq)]
pub enum Safi {
    Unicast = 1,
    Multicast = 2,
    UnicastMulticast = 3,
}

/// enum that represents the type of the next hop address.
///
/// [NextHopAddress] is used when parsing for next hops in [Nlri].
#[derive(Debug, PartialEq, Copy, Clone, Serialize, Eq)]
pub enum NextHopAddress {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Ipv6LinkLocal(Ipv6Addr, Ipv6Addr),
}

/// A representation of a IP prefix with optional path ID.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct NetworkPrefix {
    pub prefix: IpNet,
    pub path_id: u32,
}

impl Serialize for NetworkPrefix {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.to_string().as_str())
    }
}

impl FromStr for NetworkPrefix {
    type Err = BgpModelsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let prefix = IpNet::from_str(s)?;
        Ok(NetworkPrefix { prefix, path_id: 0 })
    }
}

impl NetworkPrefix {
    pub fn new(prefix: IpNet, path_id: u32) -> NetworkPrefix {
        NetworkPrefix { prefix, path_id }
    }
}

impl Display for NetworkPrefix {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.prefix)
    }
}

impl Display for Asn {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "AS{}", self.asn)
    }
}
