use std::collections::HashMap;
use std::convert;
use std::error;
use std::fmt;
use std::hash::{Hasher, BuildHasherDefault};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::prelude::*;

use byteorder::{BigEndian, ReadBytesExt};

use ipnetwork::IpNetwork;

use num_traits::FromPrimitive;

use parser::EntryMetadata;
use parser::ReadUtils;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    ParseError(String)
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self {
            Error::IoError(e) => e.description(),
            Error::ParseError(s) => &s
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match self {
            Error::IoError(ref e) => Some(e),
            _ => None
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Error: ")
    }
}

impl convert::From<io::Error> for Error {
    fn from(io_error: io::Error) -> Self {
        Error::IoError(io_error)
    }
}

pub type Asn = u32;

#[derive(Debug, PartialEq, Primitive)]
pub enum Afi {
    Ipv4 = 1,
    Ipv6 = 2
}

#[derive(Debug, PartialEq, Primitive)]
pub enum Safi {
    Unicast = 1,
    Multicast = 2,
    UnicastMulticast = 3,
}

#[derive(Debug, PartialEq)]
pub enum NextHopAddress {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Ipv6LinkLocal(Ipv6Addr, Ipv6Addr),
}

// Attribute hasher

#[derive(Default)]
pub struct AttributeHasher {
    value: u64
}

impl Hasher for AttributeHasher {
    fn finish(&self) -> u64 {
        self.value
    }

    fn write(&mut self, bytes: &[u8]) {
        if bytes.len() != 1 {
            panic!("Trying to hash slice of size {:?}", bytes.len());
        }
        self.value |= bytes[0] as u64;
    }
}

pub type AttributeMap = HashMap<u8, Attribute, BuildHasherDefault<AttributeHasher>>;

// The actual header Parser::next returns

#[derive(Debug)]
pub struct Entry {
    pub header: CommonHeader,
    pub body: Body,
    pub attributes: AttributeMap
}

#[derive(Debug)]
pub enum Body {
    TableDump(TableDumpHeader)
}

// Common header for all format types

#[derive(Debug, Primitive)]
pub enum EntryType {
    TableDump = 12
}

#[derive(Debug)]
pub struct CommonHeader {
    pub timestamp: DateTime<Utc>,
    pub entry_type: EntryType,
    pub entry_subtype: u16,
    pub length: u32,
}

impl CommonHeader {
    pub fn new<T: io::Read>(input: &mut T) -> Result<CommonHeader, Error> {
        let timestamp = input.read_u32::<BigEndian>()? as i64;
        let entry_type = input.read_u16::<BigEndian>()?;
        let entry_type = match EntryType::from_u16(entry_type) {
            Some(t) => Ok(t),
            None => Err(Error::ParseError("Failed to parse entry type".to_string()))
        }?;
        let entry_subtype = input.read_u16::<BigEndian>()?;
        let length = input.read_u32::<BigEndian>()?;
        Ok(
            CommonHeader {
                timestamp: DateTime::from_utc(NaiveDateTime::from_timestamp(timestamp, 0), Utc),
                entry_type,
                entry_subtype,
                length
            }
        )
    }
}

#[derive(Debug, PartialEq)]
pub struct NetworkPrefix {
    prefix: IpNetwork,
    path_id: u32
}

impl NetworkPrefix {
    pub fn new(prefix: IpNetwork, path_id: u32) -> NetworkPrefix {
        NetworkPrefix {
            prefix,
            path_id
        }
    }
}

// TABLE_DUMP specific

#[derive(Debug)]
pub struct TableDumpHeader {
    pub view_number: u16,
    pub sequence_number: u16,
    pub prefix: NetworkPrefix,
    pub status: u8,
    pub originated_time: DateTime<Utc>,
    pub peer_address: IpAddr,
    pub peer_asn: Asn
}

impl TableDumpHeader {
    pub fn new<T: io::Read>(metadata: &EntryMetadata,
                            input: &mut T) -> Result<TableDumpHeader, Error> {
        let view_number = input.read_u16::<BigEndian>()?;
        let sequence_number = input.read_u16::<BigEndian>()?;
        let prefix = match metadata.afi {
            Afi::Ipv4 => input.read_ipv4_prefix().map(IpNetwork::V4),
            Afi::Ipv6 => input.read_ipv6_prefix().map(IpNetwork::V6),
        }?;
        let status = input.read_u8()?;
        let time = input.read_u32::<BigEndian>()? as i64;
        let peer_address: IpAddr = match metadata.afi {
            Afi::Ipv4 => input.read_ipv4_address().map(IpAddr::V4),
            Afi::Ipv6 => input.read_ipv6_address().map(IpAddr::V6),
        }?;
        let peer_asn = input.read_asn(&metadata.as_length)?;
        Ok(
            TableDumpHeader {
                view_number,
                sequence_number,
                prefix: NetworkPrefix::new(prefix, 0 /*path_id*/),
                status,
                originated_time: DateTime::from_utc(NaiveDateTime::from_timestamp(time, 0), Utc),
                peer_address,
                peer_asn
            }
        )
    }
}

// Attributes

pub mod constants {
    pub mod attributes {
        pub const ORIGIN:   u8 = 1;
        pub const AS_PATH:  u8 = 2;
        pub const NEXT_HOP: u8 = 3;
        pub const MULTI_EXIT_DISCRIMINATOR: u8 = 4;
        pub const LOCAL_PREFERENCE: u8 = 5;
        pub const ATOMIC_AGGREGATE: u8 = 6;
        pub const AGGREGATOR: u8 = 7;
        pub const COMMUNITIES: u8 = 8;
        pub const ORIGINATOR_ID: u8 = 9;
        pub const CLUSTER_LIST: u8 = 10;
        pub const MP_REACHABLE_NLRI: u8 = 14;
        pub const MP_UNREACHABLE_NLRI: u8 = 15;
        pub const AS4_PATH: u8 = 17;
        pub const AS4_AGGREGATOR: u8 = 18;
        pub const LARGE_COMMUNITIES: u8 = 32;
        pub const ATTRIBUTES_END: u8 = LARGE_COMMUNITIES + 1;
    }
}

#[derive(Debug, PartialEq)]
pub enum Attribute {
    Origin(u8),
    AsPath(AsPath),
    NextHop(Ipv4Addr),
    MultiExitDiscriminator(u32),
    LocalPreference(u32),
    Aggregator(Asn, Ipv4Addr),
    Communities(Vec<Community>),
    LargeCommunities(Vec<LargeCommunity>),
    OriginatorId(Ipv4Addr),
    Clusters(Vec<Ipv4Addr>),
    MpReachableNlri(MpReachableNlri),
    MpUnreachableNlri(MpUnreachableNlri),
    As4Aggregator(Asn, Ipv4Addr),
    As4Path(AsPath),
}

// AS path models

#[derive(Debug, PartialEq, Clone)]
pub enum AsPathSegment {
    AsSequence(Vec<Asn>),
    AsSet(Vec<Asn>),
    ConfedSequence(Vec<Asn>),
    ConfedSet(Vec<Asn>),
}

impl AsPathSegment {
    pub fn count_asns(&self) -> usize {
        match self {
            AsPathSegment::AsSequence(v) | AsPathSegment::ConfedSequence(v) => v.len(),
            AsPathSegment::AsSet(_) | AsPathSegment::ConfedSet(_) => 1,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub struct AsPath {
    segments: Vec<AsPathSegment>,
}

impl AsPath {
    pub fn new() -> AsPath {
        AsPath {
            segments: vec![]
        }
    }

    pub fn from_segments(segments: Vec<AsPathSegment>) -> AsPath {
        AsPath {
            segments
        }
    }

    pub fn add_segment(&mut self, segment: AsPathSegment) {
        self.segments.push(segment);
    }

    pub fn segments(&self) -> &Vec<AsPathSegment> {
        &self.segments
    }

    pub fn count_asns(&self) -> usize {
        self.segments.iter().map(AsPathSegment::count_asns).sum()
    }
}

impl fmt::Display for AsPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for (index, segment) in self.segments.iter().enumerate() {
            write!(f, "{}", segment)?;
            if index != self.segments.len() - 1 {
                f.write_str(" ")?;
            }
        }
        Ok(())
    }
}

impl fmt::Display for AsPathSegment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut write_vec = |v : &Vec<Asn>, separator, prefix, suffix| {
            f.write_str(prefix)?;
            if v.len() > 0 {
                write!(f, "{}", &v[0])?;
                for i in &v[1..] {
                    write!(f, "{}{}", separator, i)?;
                };
            }
            f.write_str(suffix)
        };
        match self {
            AsPathSegment::AsSequence(ref s) | AsPathSegment::ConfedSequence(ref s) => {
                write_vec(s, " ", "", "")
            },
            AsPathSegment::AsSet(ref s) | AsPathSegment::ConfedSet(ref s) => {
                write_vec(s, ", ", "{ ", " }")
            }
        }
    }
}

// Communities

#[derive(Debug, PartialEq)]
pub enum Community {
    NoExport,
    NoAdvertise,
    NoExportSubConfed,
    Custom(Asn, u16)
}

#[derive(Debug, PartialEq)]
pub struct LargeCommunity {
    global_administrator: u32,
    local_data: [u32; 2]
}

impl LargeCommunity {
    pub fn new(global_administrator: u32, local_data: [u32; 2]) -> LargeCommunity {
        LargeCommunity {
            global_administrator,
            local_data
        }
    }
}

// NLRI

#[derive(Debug, PartialEq)]
pub struct MpReachableNlri {
    afi: Afi,
    safi: Safi,
    next_hop: NextHopAddress,
    prefixes: Vec<NetworkPrefix>,
}

impl MpReachableNlri {
    pub fn new(afi: Afi, safi: Safi, next_hop: NextHopAddress,
               prefixes: Vec<NetworkPrefix>) -> MpReachableNlri {
        MpReachableNlri {
            afi,
            safi,
            next_hop,
            prefixes
        }
    }
}

#[derive(Debug, PartialEq)]
pub struct MpUnreachableNlri {
    afi: Afi,
    safi: Safi,
    prefixes: Vec<NetworkPrefix>,
}

impl MpUnreachableNlri {
    pub fn new(afi: Afi, safi: Safi, prefixes: Vec<NetworkPrefix>) -> MpUnreachableNlri {
        MpUnreachableNlri {
            afi,
            safi,
            prefixes
        }
    }
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_as_path_segment_display() {
        assert_eq!(
            AsPathSegment::AsSequence(vec![]).to_string(),
            ""
        );
        assert_eq!(
            AsPathSegment::AsSet(vec![]).to_string(),
            "{  }"
        );
    }

    #[test]
    fn as_path_segment_display() {
        assert_eq!(
            AsPathSegment::AsSequence(vec![1, 2, 3]).to_string(),
            "1 2 3"
        );
        assert_eq!(
            AsPathSegment::ConfedSequence(vec![1, 2, 3]).to_string(),
            "1 2 3"
        );
        assert_eq!(
            AsPathSegment::AsSet(vec![1, 2, 3]).to_string(),
            "{ 1, 2, 3 }"
        );
        assert_eq!(
            AsPathSegment::ConfedSet(vec![1, 2, 3]).to_string(),
            "{ 1, 2, 3 }"
        );
    }

    #[test]
    fn as_path_display() {
        assert_eq!(
            AsPath::from_segments(vec![
                AsPathSegment::AsSequence(vec![1, 2, 3]),
            ]).to_string(),
            "1 2 3"
        );

        assert_eq!(
            AsPath::from_segments(vec![
                AsPathSegment::AsSequence(vec![1, 2, 3]),
                AsPathSegment::AsSequence(vec![4, 5]),
            ]).to_string(),
            "1 2 3 4 5"
        );

        assert_eq!(
            AsPath::from_segments(vec![
                AsPathSegment::AsSequence(vec![1, 2, 3]),
                AsPathSegment::AsSet(vec![4, 5]),
            ]).to_string(),
            "1 2 3 { 4, 5 }"
        );
    }
}
