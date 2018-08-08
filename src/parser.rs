use std::mem;
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
}

impl<T: io::Read> IntoIterator for Parser<T> {
    type Item = Entry;
    type IntoIter = ParserIterator<T>;

    fn into_iter(self) -> Self::IntoIter {
        ParserIterator::new(self)
    }
}

pub struct ParserIterator<T: io::Read> {
    parser: Parser<T>
}

impl<T: io::Read> ParserIterator<T> {
    fn new(parser: Parser<T>) -> ParserIterator<T> {
        ParserIterator {
            parser
        }
    }
}

impl<T: io::Read> Iterator for ParserIterator<T> {
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
    // AS path flags
    const AS_PATH_AS_SET: u8 = 1;
    const AS_PATH_AS_SEQUENCE: u8 = 2;
    const AS_PATH_CONFED_SEQUENCE: u8 = 3;
    const AS_PATH_CONFED_SET: u8 = 4;

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

}

impl AttributeParser {
    fn new() -> AttributeParser {
        AttributeParser { }
    }

    fn process_attributes<T>(&self, header: &CommonHeader, metadata: EntryMetadata,
                             input: &mut T) -> Result<Vec<Attribute>, Error>
        where T: io::BufRead
    {
        let count = input.read_u16::<BigEndian>()?;
        // We only want to read at most `count` bytes
        let mut input = input.take(count as u64);
        let mut output = Vec::new();
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
            let attr = self.parse_attribute(attr_type, header, &metadata, &mut attr_input)?;
            match attr {
                // If we found an attribute we know how to parse, push it
                Some(attr) => {
                    output.push(attr);
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
        Ok(output)
    }

    fn parse_attribute<T>(&self, flag: u8, _header: &CommonHeader, metadata: &EntryMetadata,
                          input: &mut io::Take<T>) -> Result<Option<Attribute>, Error>
        where T: io::BufRead
    {
        match flag {
            constants::attributes::ORIGIN =>  self.parse_origin(input).map(Some),
            constants::attributes::AS_PATH => self.parse_as_path(metadata, input).map(Some),
            _ => Ok(None)
        }
    }

    fn parse_origin<T>(&self, input: &mut io::Take<T>) -> Result<Attribute, Error>
        where T: io::BufRead
    {
        Ok(input.read_u8().map(|x| Attribute::Origin(x))?)
    }

    fn parse_as_path<T>(&self, metadata: &EntryMetadata,
                        input: &mut io::Take<T>) -> Result<Attribute, Error>
        where T: io::BufRead
    {
        let mut output = AsPath::new();
        while input.limit() > 0 {
            let segment = self.parse_as_segment(metadata, input)?;
            output.add_segment(segment);
        }
        Ok(Attribute::AsPath(output))
    }

    fn parse_as_segment<T>(&self, metadata: &EntryMetadata,
                           input: &mut io::Take<T>) -> Result<AsPathSegment, Error>
        where T: io::BufRead
    {
        let segment_type = input.read_u8()?;
        let count = input.read_u8()?;
        let mut path = Vec::with_capacity(count as usize);        
        for _ in 0..count {
            path.push(input.read_asn(&metadata.as_length)?);
        }
        match segment_type {
            MrtParser::AS_PATH_AS_SET => Ok(AsPathSegment::AsSet(path)),
            MrtParser::AS_PATH_AS_SEQUENCE => Ok(AsPathSegment::AsSequence(path)),
            MrtParser::AS_PATH_CONFED_SEQUENCE => Ok(AsPathSegment::ConfedSequence(path)),
            MrtParser::AS_PATH_CONFED_SET => Ok(AsPathSegment::ConfedSet(path)),
            _ => Err(Error::ParseError("Invalid AS path segment type".to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_as_path_as16() {
        let metadata = EntryMetadata {
            afi: Afi::Ipv4,
            as_length: AsLength::Bits16
        };
        let parser = AttributeParser::new();
        let buf = "\x02\x03\x00\x01\x00\x02\x00\x03\x01\x02\x00\x04\x00\x05".as_bytes();
        let reader = io::BufReader::new(buf);
        let result = parser.parse_as_path(&metadata, &mut reader.take(buf.len() as u64));
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
        let metadata = EntryMetadata {
            afi: Afi::Ipv4,
            as_length: AsLength::Bits32
        };
        let parser = AttributeParser::new();
        let buf = "\x02\x03\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03".as_bytes();
        let reader = io::BufReader::new(buf);
        let result = parser.parse_as_path(&metadata, &mut reader.take(buf.len() as u64));
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
        let metadata = EntryMetadata {
            afi: Afi::Ipv4,
            as_length: AsLength::Bits32
        };
        let parser = AttributeParser::new();
        let buf = "\x02\x03\x00\x00".as_bytes();
        let reader = io::BufReader::new(buf);
        let result = parser.parse_as_path(&metadata, &mut reader.take(buf.len() as u64));
        assert!(result.is_err());
    }
}
