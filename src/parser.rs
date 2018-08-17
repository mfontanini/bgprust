use std::mem;
use std::hash::BuildHasherDefault;
use std::io;
use std::io::Read;
use std::io::BufRead;
use std::net::{Ipv4Addr, Ipv6Addr};

use byteorder::{BigEndian, ReadBytesExt};

use ipnetwork::{Ipv4Network, Ipv6Network};

use num_traits::FromPrimitive;

use models::*;

// Allow reading IPs from Reads
pub trait ReadUtils: io::Read {
    fn read_ipv4_address(&mut self) -> io::Result<Ipv4Addr> {
        let addr = self.read_u32::<BigEndian>()?;
        Ok(Ipv4Addr::from(addr))
    }

    fn read_ipv6_address(&mut self) -> io::Result<Ipv6Addr> {
        let mut buf = [0; 16];
        self.read_exact(&mut buf)?;
        Ok(Ipv6Addr::from(buf))
    }

    fn read_ipv4_prefix(&mut self) -> io::Result<Ipv4Network> {
        let addr = self.read_ipv4_address()?;
        let mask = self.read_u8()?;
        match Ipv4Network::new(addr, mask) {
            Ok(n) => Ok(n),
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Invalid prefix mask"))
        }
    }

    fn read_ipv6_prefix(&mut self) -> io::Result<Ipv6Network> {
        let addr = self.read_ipv6_address()?;
        let mask = self.read_u8()?;
        match Ipv6Network::new(addr, mask) {
            Ok(n) => Ok(n),
            Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Invalid prefix mask"))
        }
    }

    fn read_asn(&mut self, as_length: &AsLength) -> io::Result<Asn> {
        match as_length {
            AsLength::Bits16 => Ok(self.read_u16::<BigEndian>()? as u32),
            AsLength::Bits32 => self.read_u32::<BigEndian>(),
        }
    }

    fn read_asns(&mut self, as_length: &AsLength, count: usize) -> io::Result<Vec<Asn>> {
        let mut path = Vec::with_capacity(count);
        match as_length {
            AsLength::Bits16 => {
                for _ in 0..count {
                    path.push(self.read_u16::<BigEndian>()? as u32);
                }
            },
            AsLength::Bits32 => {
                for _ in 0..count {
                    path.push(self.read_u32::<BigEndian>()?);
                }
            }
        };
        Ok(path)
    }
}

// All types that implement Read can now read prefixes
impl<R: io::Read + ?Sized> ReadUtils for R {}

// Parser 

pub struct Parser<T: io::Read> {
    input: Option<io::BufReader<T>>,
}

impl<T: io::Read> Parser<T> {
    pub fn new(input: T) -> Parser<T> {
        Parser{
            input: Some(io::BufReader::new(input)),
        }
    }

    pub fn next(&mut self) -> Result<Option<Entry>, Error> {
        let header = CommonHeader::new(self.input.as_mut().unwrap());
        if let Err(e) = header {
            match e {
                Error::Io(ref e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
                e => Err(e)
            }
        }
        else {
            let header = header.unwrap();

            let input = mem::replace(&mut self.input, None).unwrap();
            let mut body_input = input.take(header.length as u64);
            let output = match header.entry_type {
                EntryType::TableDump => {
                    let mut parser = MrtParser::new();
                    parser.next(header, &mut body_input)
                }
            };
            // Restore the input
            self.input = Some(body_input.into_inner());
            output
        }
    }

    pub fn iter(&mut self) -> ParserIterator<T> {
        ParserIterator::new(self)
    }
}

impl<T: io::Read> IntoIterator for Parser<T> {
    type Item = Entry;
    type IntoIter = ParserIntoIterator<T>;

    fn into_iter(self) -> Self::IntoIter {
        ParserIntoIterator::new(self)
    }
}

// Into iterator

pub struct ParserIntoIterator<T: io::Read> {
    parser: Parser<T>
}

impl<T: io::Read> ParserIntoIterator<T> {
    fn new(parser: Parser<T>) -> ParserIntoIterator<T> {
        ParserIntoIterator {
            parser
        }
    }
}

impl<T: io::Read> Iterator for ParserIntoIterator<T> {
    type Item = Entry;

    fn next(&mut self) -> Option<Self::Item> {
        match self.parser.next() {
            Ok(v) => v,
            Err(_) => None
        }
    }
}

// Normal iterator

pub struct ParserIterator<'a, T: io::Read + 'a> {
    parser: &'a mut Parser<T>
}

impl<'a, T: io::Read + 'a> ParserIterator<'a, T> {
    fn new(parser: &'a mut Parser<T>) -> ParserIterator<T> {
        ParserIterator {
            parser
        }
    }
}

impl<'a, T: io::Read + 'a> Iterator for ParserIterator<'a, T> {
    type Item = Entry;

    fn next(&mut self) -> Option<Self::Item> {
        match self.parser.next() {
            Ok(v) => v,
            Err(_) => None
        }
    }
}


// Subtype

#[derive(Primitive, Debug)]
pub enum TableDumpSubtype {
    // IPv4
    Ipv4 = 1,
    // IPv6
    Ipv6 = 2,
    // IPv4 using 32 bit ASes
    Ipv4As4 = 3,
    // IPv6 using 32 bit ASes
    Ipv6As4 = 4,
}

#[derive(Debug)]
pub enum Afi {
    Ipv4,
    Ipv6
}

#[derive(Debug)]
pub enum AsLength {
    Bits16,
    Bits32,
}

#[derive(Debug)]
pub struct EntryMetadata {
    pub afi: Afi,
    pub as_length: AsLength,
}

impl EntryMetadata {
    fn from_table_dump(entry_subtype: &TableDumpSubtype) -> EntryMetadata {
        match entry_subtype {
            TableDumpSubtype::Ipv4 => {
                EntryMetadata {
                    afi: Afi::Ipv4,
                    as_length: AsLength::Bits16
                }
            },
            TableDumpSubtype::Ipv6 => {
                EntryMetadata {
                    afi: Afi::Ipv6,
                    as_length: AsLength::Bits16
                }
            },
            TableDumpSubtype::Ipv4As4 => {
                EntryMetadata {
                    afi: Afi::Ipv4,
                    as_length: AsLength::Bits32
                }
            },
            TableDumpSubtype::Ipv6As4 => {
                EntryMetadata {
                    afi: Afi::Ipv6,
                    as_length: AsLength::Bits32
                }
            },
        }
    }   
}

// Parser

pub struct MrtParser {
}

impl MrtParser {
    const ATTRIBUTE_EXTENDED_LENGTH: u8 = 0x10;

    pub fn new() -> MrtParser {
        MrtParser {

        }
    }

    pub fn next<T>(&self, header: CommonHeader, input: &mut T) -> Result<Option<Entry>, Error>
        where T: io::BufRead
    {
        self.parse_table_dump(header, input)
    }

    fn parse_table_dump<T>(&self, header: CommonHeader,
                           input: &mut T) -> Result<Option<Entry>, Error>
        where T: io::BufRead
    {
        let sub_type = match TableDumpSubtype::from_i16(header.entry_subtype as i16) {
            Some(t) => Ok(t),
            None => Err(Error::ParseError("Invalid subtype found".to_string()))
        }?;
        let metadata = EntryMetadata::from_table_dump(&sub_type);
        let table_dump_header = TableDumpHeader::new(&metadata, input)?;
        let attribute_parser = AttributeParser::new();
        let attributes = attribute_parser.process_attributes(&header, metadata, input)?;
        Ok(
            Some(
                Entry {
                    header: header,
                    body: Body::TableDump(table_dump_header),
                    attributes
                }
            )
        )
    }
}

struct AttributeParser {
    attributes: AttributeMap,
}

impl AttributeParser {
    // AS path flags
    const AS_PATH_AS_SET: u8 = 1;
    const AS_PATH_AS_SEQUENCE: u8 = 2;
    const AS_PATH_CONFED_SEQUENCE: u8 = 3;
    const AS_PATH_CONFED_SET: u8 = 4;

    fn new() -> AttributeParser {
        AttributeParser {
            attributes: AttributeMap::with_hasher(
                BuildHasherDefault::<AttributeHasher>::default()
            )
        }
    }

    fn process_attributes<T>(mut self, _header: &CommonHeader, metadata: EntryMetadata,
                             input: &mut T) -> Result<AttributeMap, Error>
        where T: io::BufRead
    {
        let count = input.read_u16::<BigEndian>()?;
        // We only want to read at most `count` bytes
        let mut input = input.take(count as u64);
        while input.limit() > 0 {
            let flag = input.read_u8()?;
            let attr_type = input.read_u8()?;
            let length = match flag & MrtParser::ATTRIBUTE_EXTENDED_LENGTH {
                MrtParser::ATTRIBUTE_EXTENDED_LENGTH => {
                    input.read_u16::<BigEndian>().map(|x| x as u64)
                },
                _ => input.read_u8().map(|x| x as u64)
            }?;
            // Pull the attribute's bytes and process them
            let mut attr_input = input.take(length);
            let attr = self.parse_attribute(attr_type, &metadata, &mut attr_input)?;
            match attr {
                // If we found an attribute we know how to parse, push it
                Some(attr) => {
                    self.attributes.insert(attr_type, attr);
                },
                // If we don't know how to parse it, discard it
                None => {
                    let buffer_length = attr_input.fill_buf()?.len() as usize;
                    let mut length = length as usize - buffer_length;

                    // For some reason, Take doesn't force the underlying BufReader/Take
                    // to read past its buffered data. We shouldn't hit this nasty loop
                    // very often anyway
                    attr_input.consume(buffer_length);
                    while length > 0 {
                        attr_input.read_u8()?;
                        length -= 1;
                    }
                }
            }
            // Restore the wrapped buffer
            input = attr_input.into_inner();
        }
        Ok(self.attributes)
    }

    fn parse_attribute<T>(&mut self, attr_type: u8, metadata: &EntryMetadata,
                          input: &mut io::Take<T>) -> Result<Option<Attribute>, Error>
        where T: io::BufRead
    {
        match attr_type {
            constants::attributes::ORIGIN =>  self.parse_origin(input).map(Some),
            constants::attributes::AS_PATH => self.parse_as_path(&metadata.as_length, input).map(Some),
            constants::attributes::NEXT_HOP => self.parse_next_hop(input).map(Some),
            constants::attributes::MULTI_EXIT_DISCRIMINATOR => self.parse_med(input).map(Some),
            constants::attributes::LOCAL_PREFERENCE => self.parse_local_pref(input).map(Some),
            constants::attributes::AGGREGATOR => self.parse_aggregator(metadata, input).map(Some),
            constants::attributes::COMMUNITIES => self.parse_communities(input).map(Some),
            constants::attributes::ORIGINATOR_ID => self.parse_originator_id(input).map(Some),
            constants::attributes::CLUSTER_LIST => self.parse_clusters(input).map(Some),
            constants::attributes::AS4_PATH => self.parse_as4_path(input).map(Some),
            constants::attributes::AS4_AGGREGATOR => self.parse_as4_aggregator(input).map(Some),
            constants::attributes::LARGE_COMMUNITIES => self.parse_large_communities(input).map(Some),
            _ => Ok(None)
        }
    }

    fn parse_origin<T>(&self, input: &mut io::Take<T>) -> Result<Attribute, Error>
        where T: io::BufRead
    {
        Ok(input.read_u8().map(Attribute::Origin)?)
    }

    fn parse_as_path<T>(&self, as_length: &AsLength,
                        input: &mut io::Take<T>) -> Result<Attribute, Error>
        where T: io::BufRead
    {
        let mut output = AsPath::new();
        while input.limit() > 0 {
            let segment = self.parse_as_segment(as_length, input)?;
            output.add_segment(segment);
        }
        Ok(Attribute::AsPath(output))
    }

    fn parse_as4_path<T>(&self, input: &mut io::Take<T>) -> Result<Attribute, Error>
        where T: io::BufRead
    {
        match self.parse_as_path(&AsLength::Bits32, input) {
            Ok(Attribute::AsPath(p)) => Ok(Attribute::As4Path(p)),
            Ok(_) => panic!("parse_as_path didn't return an AS path"),
            Err(e) => Err(e)
        }
    }

    fn parse_as_segment<T>(&self, as_length: &AsLength,
                           input: &mut io::Take<T>) -> Result<AsPathSegment, Error>
        where T: io::BufRead
    {
        let segment_type = input.read_u8()?;
        let count = input.read_u8()?;
        let path = input.read_asns(as_length, count as usize)?;
        match segment_type {
            AttributeParser::AS_PATH_AS_SET => Ok(AsPathSegment::AsSet(path)),
            AttributeParser::AS_PATH_AS_SEQUENCE => Ok(AsPathSegment::AsSequence(path)),
            AttributeParser::AS_PATH_CONFED_SEQUENCE => Ok(AsPathSegment::ConfedSequence(path)),
            AttributeParser::AS_PATH_CONFED_SET => Ok(AsPathSegment::ConfedSet(path)),
            _ => Err(Error::ParseError("Invalid AS path segment type".to_string()))
        }
    }

    fn parse_next_hop<T>(&self, input: &mut io::Take<T>) -> Result<Attribute, Error>
        where T: io::BufRead
    {
        Ok(input.read_ipv4_address().map(Attribute::NextHop)?)
    }

    fn parse_med<T>(&self, input: &mut io::Take<T>) -> Result<Attribute, Error>
        where T: io::BufRead
    {
        Ok(input.read_u32::<BigEndian>().map(Attribute::MultiExitDiscriminator)?)
    }

    fn parse_local_pref<T>(&self, input: &mut io::Take<T>) -> Result<Attribute, Error>
        where T: io::BufRead
    {
        Ok(input.read_u32::<BigEndian>().map(Attribute::LocalPreference)?)
    }

    fn parse_aggregator<T>(&self, metadata: &EntryMetadata,
                           input: &mut io::Take<T>) -> Result<Attribute, Error>
        where T: io::BufRead
    {
        let asn = input.read_asn(&metadata.as_length)?;
        let addr = input.read_ipv4_address()?;
        Ok(Attribute::Aggregator(asn, addr))
    }

    fn parse_communities<T>(&self, input: &mut io::Take<T>) -> Result<Attribute, Error>
        where T: io::BufRead
    {
        const COMMUNITY_NO_EXPORT: u32 = 0xFFFFFF01;
        const COMMUNITY_NO_ADVERTISE: u32 = 0xFFFFFF02;
        const COMMUNITY_NO_EXPORT_SUBCONFED: u32 = 0xFFFFFF03;
        let mut communities = Vec::with_capacity((input.limit() / 4) as usize);
        while input.limit() > 0 {
            let community = input.read_u32::<BigEndian>()?;
            match community {
                COMMUNITY_NO_EXPORT => communities.push(Community::NoExport),
                COMMUNITY_NO_ADVERTISE => communities.push(Community::NoAdvertise),
                COMMUNITY_NO_EXPORT_SUBCONFED => communities.push(Community::NoExportSubConfed),
                value => {
                    let asn = (value >> 16) & 0xffff;
                    let value = (value & 0xffff) as u16;
                    communities.push(Community::Custom(asn, value));
                }
            }
        }
        Ok(Attribute::Communities(communities))
    }

    fn parse_originator_id<T>(&self, input: &mut io::Take<T>) -> Result<Attribute, Error>
        where T: io::BufRead
    {
        Ok(Attribute::OriginatorId(input.read_ipv4_address()?))
    }

    fn parse_clusters<T>(&self, input: &mut io::Take<T>) -> Result<Attribute, Error>
        where T: io::BufRead
    {
        let mut clusters = Vec::new();
        while input.limit() > 0 {
            clusters.push(input.read_ipv4_address()?);
        }
        Ok(Attribute::Clusters(clusters))
    }

    fn parse_as4_aggregator<T>(&self, input: &mut io::Take<T>) -> Result<Attribute, Error>
        where T: io::BufRead
    {
        let asn = input.read_asn(&AsLength::Bits32)?;
        let addr = input.read_ipv4_address()?;
        Ok(Attribute::As4Aggregator(asn, addr))
    }

    fn parse_large_communities<T>(&self, input: &mut io::Take<T>) -> Result<Attribute, Error>
        where T: io::BufRead
    {
        let mut communities = Vec::new();
        while input.limit() > 0 {
            let global_administrator = input.read_u32::<BigEndian>()?;
            let mut local_data : [u32; 2] = [0; 2];
            local_data[0] = input.read_u32::<BigEndian>()?;
            local_data[1] = input.read_u32::<BigEndian>()?;
            communities.push(LargeCommunity::new(global_administrator, local_data));
        }
        Ok(Attribute::LargeCommunities(communities))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_as_path_as16() {
        let as_length = AsLength::Bits16;
        let parser = AttributeParser::new();
        let buf = "\x02\x03\x00\x01\x00\x02\x00\x03\x01\x02\x00\x04\x00\x05".as_bytes();
        let reader = io::BufReader::new(buf);
        let result = parser.parse_as_path(&as_length, &mut reader.take(buf.len() as u64));
        assert_eq!(
            result.unwrap(),
            Attribute::AsPath(
                AsPath::from_segments(
                    vec![
                        AsPathSegment::AsSequence(vec![1, 2, 3]),
                        AsPathSegment::AsSet(vec![4, 5]),
                    ]
                )
            )
        );
    }

    #[test]
    fn parse_as_path_as32() {
        let as_length = AsLength::Bits32;
        let parser = AttributeParser::new();
        let buf = "\x02\x03\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03".as_bytes();
        let reader = io::BufReader::new(buf);
        let result = parser.parse_as_path(&as_length, &mut reader.take(buf.len() as u64));
        assert_eq!(
            result.unwrap(),
            Attribute::AsPath(
                AsPath::from_segments(
                    vec![
                        AsPathSegment::AsSequence(vec![1, 2, 3]),
                    ]
                )
            )
        );
    }

    #[test]
    fn parse_as_path_invalid() {
        let as_length = AsLength::Bits32;
        let parser = AttributeParser::new();
        let buf = "\x02\x03\x00\x00".as_bytes();
        let reader = io::BufReader::new(buf);
        let result = parser.parse_as_path(&as_length, &mut reader.take(buf.len() as u64));
        assert!(result.is_err());
    }

    #[test]
    fn parse_communities() {
        let buf = [12, 185, 15, 160, 12, 185, 19, 175].as_ref();
        let reader = io::BufReader::new(buf);
        let parser = AttributeParser::new();
        let result = parser.parse_communities(&mut reader.take(buf.len() as u64));
        assert_eq!(
            result.unwrap(),
            Attribute::Communities(
                vec![
                    Community::Custom(3257, 4000),
                    Community::Custom(3257, 5039)
                ]
            )
        );
    }
}
