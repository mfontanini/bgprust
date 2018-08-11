use std::convert;
use std::error;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr};

use chrono::prelude::*;

use byteorder::{BigEndian, ReadBytesExt};

use ipnetwork::IpNetwork;

use num_traits::FromPrimitive;

use parser::EntryMetadata;
use parser::Afi;
use parser::ReadUtils;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    ParseError(String)
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match self {
            Error::Io(e) => e.description(),
            Error::ParseError(s) => &s
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match self {
            Error::Io(ref e) => Some(e),
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
        Error::Io(io_error)
    }
}

pub type Asn = u32;

// The actual header Parser::next returns

#[derive(Debug)]
pub struct Entry {
    pub header: CommonHeader,
    pub body: Body,
    pub attributes: Vec<Attribute>
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

// TABLE_DUMP specific

#[derive(Debug)]
pub struct TableDumpHeader {
    pub view_number: u16,
    pub sequence_number: u16,
    pub prefix: IpNetwork,
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
                prefix,
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
}

// AS path models

#[derive(Debug, PartialEq)]
pub enum AsPathSegment {
    AsSequence(Vec<Asn>),
    AsSet(Vec<Asn>),
    ConfedSequence(Vec<Asn>),
    ConfedSet(Vec<Asn>),
}

#[derive(Debug, PartialEq)]
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
}

/*impl Display for AsPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "({}, {})", self.x, self.y)
    }
}

impl Display for AsPathSegment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AsSequence(s) => 
        }
    }
}
*/

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
