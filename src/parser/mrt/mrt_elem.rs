#![allow(unused)]
//! This module handles converting MRT records into individual per-prefix BGP elements.
//!
//! Each MRT record may contain reachability information for multiple prefixes. This module breaks
//! down MRT records into corresponding BGP elements, and thus allowing users to more conveniently
//! process BGP information on a per-prefix basis.
use crate::models::*;
use crate::parser::bgp::messages::parse_bgp_update_message;
use itertools::Itertools;
use log::warn;
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr};

pub struct Elementor {
    peer_table: Option<PeerIndexTable>,
}

impl Elementor {
    pub fn new() -> Elementor {
        Elementor { peer_table: None }
    }

    /// Convert a [BgpMessage] to a vector of [BgpElem]s.
    ///
    /// A [BgpMessage] may include `Update`, `Open`, `Notification` or `KeepAlive` messages,
    /// and only `Update` message contains [BgpElem]s.
    pub fn bgp_to_elems(
        msg: BgpMessage,
        timestamp: f64,
        peer_ip: &IpAddr,
        peer_asn: &Asn,
    ) -> Vec<BgpElem> {
        match msg {
            BgpMessage::Update(msg) => {
                Elementor::bgp_update_to_elems(msg, timestamp, peer_ip, peer_asn)
            }
            BgpMessage::Open(_) | BgpMessage::Notification(_) | BgpMessage::KeepAlive(_) => {
                vec![]
            }
        }
    }

    /// Convert a [BgpUpdateMessage] to a vector of [BgpElem]s.
    pub fn bgp_update_to_elems(
        msg: BgpUpdateMessage,
        timestamp: f64,
        peer_ip: &IpAddr,
        peer_asn: &Asn,
    ) -> Vec<BgpElem> {
        let mut elems = vec![];
        elems.extend(BgpUpdateToElemsIter::new(
            msg, timestamp, *peer_ip, *peer_asn,
        ));
        elems
    }

    /// Convert a [MrtRecord] to a vector of [BgpElem]s.
    pub fn record_to_elems(&mut self, record: MrtRecord) -> Vec<BgpElem> {
        let mut buffer = Vec::new();
        self.record_to_elems_into(record, &mut buffer);
        buffer
    }

    pub fn record_to_elems_into(&mut self, record: MrtRecord, elems: &mut Vec<BgpElem>) {
        let t = record.common_header.timestamp;
        let timestamp: f64 = if let Some(micro) = &record.common_header.microsecond_timestamp {
            let m = (*micro as f64) / 1000000.0;
            t as f64 + m
        } else {
            f64::from(t)
        };

        match record.message {
            MrtMessage::TableDumpMessage(msg) => {
                let mut bgp_msg = BgpElem::new_empty(timestamp, msg.peer_address, msg.peer_asn);
                bgp_msg.prefix = msg.prefix;

                let _ = apply_attrs_to_bgp_elem(&mut bgp_msg, msg.attributes);
                elems.push(bgp_msg);
            }
            MrtMessage::TableDumpV2Message(msg) => match msg {
                TableDumpV2Message::PeerIndexTable(p) => self.peer_table = Some(p),
                TableDumpV2Message::RibAfiEntries(t) => {
                    for entry in t.rib_entries.into_iter().rev() {
                        let peer = self
                            .peer_table
                            .as_ref()
                            .and_then(|x| x.peers_map.get(&(entry.peer_index as u32)))
                            .expect("missing peer table/index");

                        let mut bgp_elem =
                            BgpElem::new_empty(timestamp, peer.peer_address, peer.peer_asn);
                        bgp_elem.prefix = t.prefix;

                        let (announced, withdrawn) =
                            apply_attrs_to_bgp_elem(&mut bgp_elem, entry.attributes);
                        assert!(withdrawn.is_none());

                        if bgp_elem.next_hop.is_none() {
                            bgp_elem.next_hop =
                                announced.and_then(|x| x.next_hop).map(|x| match x {
                                    NextHopAddress::Ipv4(x) => IpAddr::V4(x),
                                    NextHopAddress::Ipv6(x) => IpAddr::V6(x),
                                    NextHopAddress::Ipv6LinkLocal(x, _) => IpAddr::V6(x),
                                });
                        }

                        elems.push(bgp_elem);
                    }
                }
                TableDumpV2Message::RibGenericEntries(_) => {
                    warn!("to_elem for TableDumpV2Message::RibGenericEntries not yet implemented");
                }
            },
            MrtMessage::Bgp4Mp(msg) => match msg {
                Bgp4Mp::Bgp4MpStateChange(_) | Bgp4Mp::Bgp4MpStateChangeAs4(_) => {}
                Bgp4Mp::Bgp4MpMessage(v)
                | Bgp4Mp::Bgp4MpMessageLocal(v)
                | Bgp4Mp::Bgp4MpMessageAs4(v)
                | Bgp4Mp::Bgp4MpMessageAs4Local(v) => {
                    if let BgpMessage::Update(update) = v.bgp_message {
                        elems.extend(BgpUpdateToElemsIter::new(
                            update, timestamp, v.peer_ip, v.peer_asn,
                        ));
                    }
                }
            },
        }
    }
}

fn apply_attrs_to_bgp_elem(
    base_elem: &mut BgpElem,
    attributes: Vec<Attribute>,
) -> (Option<Nlri>, Option<Nlri>) {
    let mut as_path = None;
    let mut as4_path = None;
    let mut announced = None;
    let mut withdrawn = None;
    for attribute in attributes {
        match attribute.value {
            AttributeValue::Origin(x) => base_elem.origin = Some(x),
            AttributeValue::AsPath(x) => as_path = Some(x),
            AttributeValue::As4Path(x) => as4_path = Some(x),
            AttributeValue::NextHop(x) => base_elem.next_hop = Some(x),
            AttributeValue::MultiExitDiscriminator(x) => base_elem.med = Some(x),
            AttributeValue::LocalPreference(x) => base_elem.local_pref = Some(x),
            AttributeValue::AtomicAggregate(x) => base_elem.atomic = Some(x),
            AttributeValue::OnlyToCustomer(x) => base_elem.only_to_customer = Some(x),
            AttributeValue::Aggregator(x, y) => {
                base_elem.aggr_asn = Some(x);
                base_elem.aggr_ip = Some(y);
            }
            AttributeValue::Communities(x) => base_elem
                .communities
                .get_or_insert_with(Vec::new)
                .extend(x.into_iter().map(MetaCommunity::Community)),
            AttributeValue::ExtendedCommunities(x) => base_elem
                .communities
                .get_or_insert_with(Vec::new)
                .extend(x.into_iter().map(MetaCommunity::ExtendedCommunity)),
            AttributeValue::LargeCommunities(x) => base_elem
                .communities
                .get_or_insert_with(Vec::new)
                .extend(x.into_iter().map(MetaCommunity::LargeCommunity)),
            AttributeValue::OriginatorId(_)
            | AttributeValue::Clusters(_)
            | AttributeValue::Development(_) => {}
            AttributeValue::MpReachNlri(x) => announced = Some(x),
            AttributeValue::MpUnreachNlri(x) => withdrawn = Some(x),
            AttributeValue::Deprecated(x) => {
                base_elem.deprecated.get_or_insert_with(Vec::new).push(x)
            }
            AttributeValue::Unknown(x) => base_elem.unknown.get_or_insert_with(Vec::new).push(x),
        }
    }

    base_elem.as_path = match (as_path, as4_path) {
        (None, None) => None,
        (Some(v), None) => Some(v),
        (None, Some(v)) => Some(v),
        (Some(v1), Some(v2)) => AsPath::merge_aspath_as4path(&v1, &v2),
    };

    base_elem.origin_asns = base_elem.as_path.as_ref().and_then(|x| x.get_origin());

    (announced, withdrawn)
}

pub struct BgpUpdateToElemsIter {
    base_elem: BgpElem,
    withdrawn: Vec<NetworkPrefix>,
    announced: Vec<NetworkPrefix>,
}

impl BgpUpdateToElemsIter {
    pub fn new(update: BgpUpdateMessage, timestamp: f64, peer_ip: IpAddr, peer_asn: Asn) -> Self {
        let BgpUpdateMessage {
            mut withdrawn_prefixes,
            attributes,
            mut announced_prefixes,
        } = update;
        let mut base_elem = BgpElem::new_empty(timestamp, peer_ip, peer_asn);
        let (announced, withdrawn) = apply_attrs_to_bgp_elem(&mut base_elem, attributes);

        announced.map(|x| {
            if announced_prefixes.is_empty() {
                announced_prefixes = x.prefixes;
            } else {
                announced_prefixes.extend(x.prefixes);
            }
        });

        withdrawn.map(|x| {
            if withdrawn_prefixes.is_empty() {
                withdrawn_prefixes = x.prefixes;
            } else {
                withdrawn_prefixes.extend(x.prefixes);
            }
        });

        BgpUpdateToElemsIter {
            base_elem,
            withdrawn: withdrawn_prefixes,
            announced: announced_prefixes,
        }
    }
}

impl Iterator for BgpUpdateToElemsIter {
    type Item = BgpElem;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(prefix) = self.withdrawn.pop() {
            return Some(BgpElem {
                timestamp: self.base_elem.timestamp,
                elem_type: ElemType::WITHDRAW,
                peer_ip: self.base_elem.peer_ip,
                peer_asn: self.base_elem.peer_asn,
                prefix,
                next_hop: None,
                as_path: None,
                origin: None,
                origin_asns: None,
                local_pref: None,
                med: None,
                communities: None,
                atomic: None,
                aggr_asn: None,
                aggr_ip: None,
                only_to_customer: self.base_elem.only_to_customer,
                unknown: None,
                deprecated: None,
            });
        }

        let prefix = self.announced.pop()?;
        if self.announced.is_empty() {
            // Since this is the last one, just take the existing instance to avoid allocation and
            // copying
            let mut next = std::mem::take(&mut self.base_elem);
            next.prefix = prefix;
            return Some(next);
        }

        let mut next = self.base_elem.clone();
        next.prefix = prefix;
        Some(next)
    }
}
