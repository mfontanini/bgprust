use std::convert;
use std::error;
use std::fmt;
use std::mem;
use std::io;
use std::io::Read;
use std::net::{Ipv4Addr, Ipv6Addr};

use byteorder::{BigEndian, ReadBytesExt};

use ipnetwork::{Ipv4Network, Ipv6Network};

use num_traits::FromPrimitive;

use models::*;

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

    fn read_asn(&mut self, subtype: &TableDumpSubtype) -> io::Result<u32> {
        match subtype {
            TableDumpSubtype::Ipv4 | TableDumpSubtype::Ipv6 => {
                Ok(self.read_u16::<BigEndian>()? as u32)
            }
            TableDumpSubtype::Ipv4As4 | TableDumpSubtype::Ipv6As4 => {
                self.read_u32::<BigEndian>()
            }
        }
    }
}

// All types that implement Read can now read prefixes
impl<R: io::Read + ?Sized> ReadUtils for R {}

// Parser 

pub struct Parser<T: io::Read> {
    input: Option<io::BufReader<T>>,
    mrt_parser: MrtParser,
}

impl<T: io::Read> Parser<T> {
    pub fn new(input: T) -> Parser<T> {
        Parser{
            input: Some(io::BufReader::new(input)),
            mrt_parser: MrtParser::new(),
        }
    }

    pub fn next(&mut self) -> Result<Option<Entry>, Error> {
        let header = CommonHeader::new(self.input.as_mut().unwrap())?;

        let input = mem::replace(&mut self.input, None).unwrap();
        let mut body_input = input.take(header.length as u64);
        let output = match header.entry_type {
            EntryType::TableDump => {
                self.mrt_parser.next(header, &mut body_input)
            }
            _ => {
                Ok(None)
            }
        };
        // Restore the input
        self.input = Some(body_input.into_inner());
        output
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

// Parser

pub struct MrtParser {
    read_buffer: [u8; 65536]
}

impl MrtParser {
    const ATTRIBUTE_EXTENDED_LENGTH: u8 = 0x10;
    // Attribute flags
    const ATTRIBUTE_AS_PATH: u8 = 2;
    // AS path flags
    const AS_PATH_AS_SET: u8 = 1;
    const AS_PATH_AS_SEQUENCE: u8 = 2;
    const AS_PATH_CONFED_SEQUENCE: u8 = 3;
    const AS_PATH_CONFED_SET: u8 = 4;

    pub fn new() -> MrtParser {
        MrtParser {
            read_buffer: [0; 65536]
        }
    }

    pub fn next<T: io::Read>(&mut self, header: CommonHeader,
                             input: &mut T) -> Result<Option<Entry>, Error> {
        self.parse_table_dump(header, input)
    }

    fn parse_table_dump<T: io::Read>(&mut self, header: CommonHeader,
                                     input: &mut T) -> Result<Option<Entry>, Error> {
        let sub_type = match TableDumpSubtype::from_i16(header.entry_subtype as i16) {
            Some(t) => Ok(t),
            None => Err(Error::ParseError("Invalid subtype found".to_string()))
        }?;
        let table_dump_header = TableDumpHeader::new(&sub_type, input)?;
        let attributes = self.process_attributes(&header, sub_type, input)?;
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

    fn process_attributes<T: io::Read>(&mut self, header: &CommonHeader,
                                       sub_type: TableDumpSubtype,
                                       input: &mut T) -> Result<Vec<Attribute>, Error> {
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
            let attr = self.parse_attribute(attr_type, header, &sub_type, &mut attr_input)?;
            match attr {
                // If we found an attribute we know how to parse, push it
                Some(attr) => {
                    output.push(attr);
                },
                // If we don't know how to parse it, discard it
                None => {
                    // Make sure to read all of the data we need
                    let mut length = length as usize;
                    while length > 0 {
                        length -= attr_input.read(&mut self.read_buffer[0..length])?;
                    }
                }
            }
            // Restore the wrapped buffer
            input = attr_input.into_inner();
        }
        Ok(output)
    }

    fn parse_attribute<T: io::Read>(&self, flag: u8, _header: &CommonHeader,
                                    sub_type: &TableDumpSubtype,
                                    input: &mut io::Take<T>) -> Result<Option<Attribute>, Error>
    {
        match flag {
            MrtParser::ATTRIBUTE_AS_PATH => self.parse_as_path(sub_type, input).map(Some),
            _ => Ok(None)
        }
    }

    fn parse_as_path<T: io::Read>(&self, sub_type: &TableDumpSubtype,
                                  input: &mut io::Take<T>) -> Result<Attribute, Error> {
        let mut output = AsPath::new();
        while input.limit() > 0 {
            let segment = self.parse_as_segment(sub_type, input)?;
            output.add_segment(segment);
        }
        Ok(Attribute::AsPath(output))
    }

    fn parse_as_segment<T: io::Read>(&self, sub_type: &TableDumpSubtype,
                                     input: &mut io::Take<T>) -> Result<AsPathSegment, Error>
    {
        let segment_type = input.read_u8()?;
        let count = input.read_u8()?;
        let mut path = Vec::with_capacity(count as usize);
        match sub_type {
            TableDumpSubtype::Ipv4As4 | TableDumpSubtype::Ipv6As4 => {
                for _ in 0..count {
                    path.push(input.read_u32::<BigEndian>()?);
                }
            },
            TableDumpSubtype::Ipv4 | TableDumpSubtype::Ipv6 => {
                for _ in 0..count {
                    path.push(input.read_u16::<BigEndian>().map(|i| i as u32)?);
                }
            }
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
        let parser = MrtParser::new();
        let buf = "\x02\x03\x00\x01\x00\x02\x00\x03\x01\x02\x00\x04\x00\x05".as_bytes();
        let reader = io::BufReader::new(buf);
        let result = parser.parse_as_path(&TableDumpSubtype::Ipv4,
                                          &mut reader.take(buf.len() as u64));
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
        let parser = MrtParser::new();
        let buf = "\x02\x03\x00\x00\x00\x01\x00\x00\x00\x02\x00\x00\x00\x03".as_bytes();
        let reader = io::BufReader::new(buf);
        let result = parser.parse_as_path(&TableDumpSubtype::Ipv4As4,
                                          &mut reader.take(buf.len() as u64));
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
}
