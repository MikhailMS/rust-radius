//! RADIUS Dictionary implementation


use std::fs::File;
use std::io::{self, BufRead};

use super::error::RadiusError;

#[derive(Debug, PartialEq)]
/// Represents a list of supported data types
/// as defined in RFC 2865 & RFC 8044
pub enum SupportedAttributeTypes {
    /// Rust's String; RFC 8044 calls this "text" - UTF-8 text
    AsciiString,
    /// Rusts's [u8]; RFC 8044 calls this "string" (FreeRADIUS calls this "octets") - binary data as a sequence of undistinguished octets
    ByteString,
    /// Rust's u32
    Integer,
    /// Rust's u64
    Integer64,
    /// Rust's u32; RFC 8044 calls this "time"
    Date,
    /// Rust's \[u8;4\]
    IPv4Addr,
    /// Rust's \[u8;5\]
    IPv4Prefix,
    /// Rust's \[u8;16\]
    IPv6Addr,
    /// Rust's \[u8;18\]
    IPv6Prefix,
    /// Rust's \[u8;8\]; RFC 8044 calls this "ifid"
    InterfaceId,
    /// Rust's u32
    Enum,
    /// Rust's [u8]
    Tlv,
    /// Rust's [u8]; RFC 8044 defines this as vendor-specific data
    Vsa,
    /// Rust's [u8]; RFC 8044 defines this as Extended-Vendor-Specific Attribute (FreeRADIUS
    /// accepts VSA instead of EVS data type)
    Evs,
    /// Rust's [u8]; Doesn't look like a type on its own, but rather an extension to some data types (in FreeRADIUS this is a flag)
    /// usually string/octets
    Concat,
    /// Rust's [u8]; Doesn't look like a type on its own, but rather an extension to some data types (in FreeRADIUS this is a flag)
    Extended,
    /// Rust's [u8]; Doesn't look like a type on its own, but rather an extension to some data types (in FreeRADIUS this is a flag)
    LongExtended
}


#[derive(Debug, PartialEq)]
/// Represents an ATTRIBUTE from RADIUS dictionary file
pub struct DictionaryAttribute {
    /*
     * |--------|   name  | code | code type |
     * ATTRIBUTE User-Name   1      string
     */
    name:        String,
    vendor_name: String,
    code:        u8,
    code_type:   Option<SupportedAttributeTypes>
}

impl DictionaryAttribute {
    /// Return name of the Attribute
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return code of the Attribute
    pub fn code(&self) -> u8 {
        self.code
    }

    /// Return code_type of the Attribute
    pub fn code_type(&self) -> &Option<SupportedAttributeTypes> {
        &self.code_type
    }
}


#[derive(Debug, PartialEq)]
/// Represents a VALUE from RADIUS dictionary file
pub struct DictionaryValue {
    attribute_name: String,
    value_name:     String,
    vendor_name:    String,
    value:          String
}

impl DictionaryValue {
    /// Return name of the Value
    pub fn name(&self) -> &str {
        &self.value_name
    }

    /// Return attribute_name of the Value
    pub fn attribute_name(&self) -> &str {
        &self.attribute_name
    }

    /// Return value of the Value
    pub fn value(&self) -> &str {
        &self.value
    }
}


#[derive(Debug, PartialEq)]
/// Represents a VENDOR from RADIUS dictionary file
pub struct DictionaryVendor {
    name: String,
    id:   u8
}


const COMMENT_PREFIX: &str = "#";

#[derive(Debug, Default, PartialEq)]
/// Represents RADIUS dictionary
pub struct Dictionary {
    attributes: Vec<DictionaryAttribute>,
    values:     Vec<DictionaryValue>,
    vendors:    Vec<DictionaryVendor>
}

#[allow(unused)]
impl Dictionary {
    fn from_lines(lines: StringIterator) -> Result<Dictionary, RadiusError> {
        let mut attributes:  Vec<DictionaryAttribute> = Vec::new();
        let mut values:      Vec<DictionaryValue>     = Vec::new();
        let mut vendors:     Vec<DictionaryVendor>    = Vec::new();

        match parse_lines(lines, &mut attributes, &mut values, &mut vendors) {
            Ok(()) => Ok(Dictionary { attributes, values, vendors }),
            Err(error) => Err(error),
        }
    }

    /// Creates Dictionary from a string
    pub fn from_str(dictionary_str: &str) -> Result<Dictionary, RadiusError> {
        let lines = read_str(dictionary_str);
        Dictionary::from_lines(lines)
    }

    /// Creates Dictionary from a RADIUS dictionary file
    pub fn from_file(file_path: &str) -> Result<Dictionary, RadiusError> {
        match read_file(file_path) {
            Ok(lines) => Dictionary::from_lines(lines),
            Err(error) => Err(error)
        }
    }

    /// The add functions process attributes, values and vendors from a supplied dictionary file
    /// and merge them into an existing set of attributes, values and vendors

    /// Adds a dictionary string to existing Dictionary
    pub fn add_str(&mut self, dictionary_str: &str) -> Result<(), RadiusError> {
        let lines = read_str(dictionary_str);
        parse_lines(lines, &mut self.attributes, &mut self.values, &mut self.vendors)
    }
  
    /// Adds a dictionary file to existing Dictionary
    pub fn add_file(&mut self, file_path: &str) -> Result<(), RadiusError> {
        match read_file(file_path) {
            Ok(lines) => parse_lines(
                lines, &mut self.attributes, &mut self.values, &mut self.vendors
            ),
            Err(error) => Err(error)
        }
    }

    /// Returns parsed DictionaryAttributes
    pub fn attributes(&self) -> &[DictionaryAttribute] {
        &self.attributes
    }

    /// Returns parsed DictionaryValues
    pub fn values(&self) -> &[DictionaryValue] {
        &self.values
    }

    /// Returns parsed DictionaryVendors
    pub fn vendors(&self) -> &[DictionaryVendor] {
        &self.vendors
    }
}

fn assign_attribute_type(code_type: &str) -> Option<SupportedAttributeTypes> {
    match code_type {
        "text"          => Some(SupportedAttributeTypes::AsciiString),
        "string"        => Some(SupportedAttributeTypes::ByteString),
        "integer"       => Some(SupportedAttributeTypes::Integer),
        "integer64"     => Some(SupportedAttributeTypes::Integer64),
        "time"          => Some(SupportedAttributeTypes::Date),
        "ipv4addr"      => Some(SupportedAttributeTypes::IPv4Addr),
        "ipv4prefix"    => Some(SupportedAttributeTypes::IPv4Prefix),
        "ipv6addr"      => Some(SupportedAttributeTypes::IPv6Addr),
        "ipv6prefix"    => Some(SupportedAttributeTypes::IPv6Prefix),
        "ifid"          => Some(SupportedAttributeTypes::InterfaceId),
        "enum"          => Some(SupportedAttributeTypes::Enum),
        "tlv"           => Some(SupportedAttributeTypes::Tlv),
        "vsa"           => Some(SupportedAttributeTypes::Vsa),
        "evs"           => Some(SupportedAttributeTypes::Evs),
        "concat"        => Some(SupportedAttributeTypes::Concat),
        "extended"      => Some(SupportedAttributeTypes::Extended),
        "long-extended" => Some(SupportedAttributeTypes::LongExtended),
        _               => None
    }
}

type StringIterator = Box<dyn Iterator<Item = String>>;

fn filter_lines<T: Iterator<Item = String> + 'static>(lines: T) -> StringIterator {
    Box::new(
        lines
            .filter(|line| !line.is_empty())
            .filter(|line| !line.contains(&COMMENT_PREFIX))
    )
}

fn read_file(file_path: &str) -> Result<StringIterator, RadiusError> {
    let reader = io::BufReader::new(File::open(file_path).map_err(|error| RadiusError::MalformedDictionaryError { error })?);
    Ok(filter_lines(reader.lines().filter_map(Result::ok)))
}

fn read_str(dictionary_str: &str) -> StringIterator {
    let lines: Vec<String> = dictionary_str.to_string().lines()
            .map(|line| line.to_owned()).collect();
    filter_lines(lines.into_iter())
}

fn parse_lines(lines: StringIterator, attributes: &mut Vec<DictionaryAttribute>, values: &mut Vec<DictionaryValue>, vendors: &mut Vec<DictionaryVendor>) -> Result<(), RadiusError>{
    let mut vendor_name: String = String::new();

    for line in lines {
        let parsed_line: Vec<&str> = line.split_whitespace().filter(|&item| !item.is_empty()).collect();
        match parsed_line[0] {
            "ATTRIBUTE"    => parse_attribute(parsed_line, &vendor_name, attributes),
            "VALUE"        => parse_value(parsed_line, &vendor_name, values),
            "VENDOR"       => parse_vendor(parsed_line, vendors),
            "BEGIN-VENDOR" => { vendor_name.insert_str(0, parsed_line[1]) },
            "END-VENDOR"   => { vendor_name.clear() },
            _              => continue
        }
    };

    Ok(())
}

fn parse_attribute(parsed_line: Vec<&str>, vendor_name: &str, attributes: &mut Vec<DictionaryAttribute>) {
    if let Ok(code) = parsed_line[2].parse::<u8>() {
        attributes.push(DictionaryAttribute {
            name:        parsed_line[1].to_string(),
            vendor_name: vendor_name.to_string(),
            code,
            code_type:   assign_attribute_type(parsed_line[3])
        });
    }
}

fn parse_value(parsed_line: Vec<&str>, vendor_name: &str, values: &mut Vec<DictionaryValue>) {
    values.push(DictionaryValue {
        attribute_name: parsed_line[1].to_string(),
        value_name:     parsed_line[2].to_string(),
        vendor_name:    vendor_name.to_string(),
        value:          parsed_line[3].to_string()
    })
}

fn parse_vendor(parsed_line: Vec<&str>, vendors: &mut Vec<DictionaryVendor>) {
    if let Ok(id) = parsed_line[2].parse::<u8>() {
        vendors.push(DictionaryVendor {
            name: parsed_line[1].to_string(),
            id,
        })
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_str() {
        let dictionary_str = include_str!("../../dict_examples/test_dictionary_dict");

        let dict = Dictionary::from_str(dictionary_str).unwrap();

        let mut attributes: Vec<DictionaryAttribute> = Vec::new();
        attributes.push(DictionaryAttribute {
            name:        "User-Name".to_string(),
            vendor_name: "".to_string(),
            code:        1,
            code_type:   Some(SupportedAttributeTypes::AsciiString)
        });
        attributes.push(DictionaryAttribute {
            name:        "NAS-IP-Address".to_string(),
            vendor_name: "".to_string(),
            code:        4,
            code_type:   Some(SupportedAttributeTypes::IPv4Addr)
        });
        attributes.push(DictionaryAttribute {
            name:        "NAS-Port-Id".to_string(),
            vendor_name: "".to_string(),
            code:        5,
            code_type:   Some(SupportedAttributeTypes::Integer)
        });
        attributes.push(DictionaryAttribute {
            name:        "Framed-Protocol".to_string(),
            vendor_name: "".to_string(),
            code:        7,
            code_type:   Some(SupportedAttributeTypes::Integer)
        });
        attributes.push(DictionaryAttribute {
            name:        "Chargeable-User-Identity".to_string(),
            vendor_name: "".to_string(),
            code:        89,
            code_type:   Some(SupportedAttributeTypes::ByteString)
        });
        attributes.push(DictionaryAttribute {
            name:        "Delegated-IPv6-Prefix".to_string(),
            vendor_name: "".to_string(),
            code:        123,
            code_type:   Some(SupportedAttributeTypes::IPv6Prefix)
        });
        attributes.push(DictionaryAttribute {
            name:        "MIP6-Feature-Vector".to_string(),
            vendor_name: "".to_string(),
            code:        124,
            code_type:   Some(SupportedAttributeTypes::Integer64)
        });
        attributes.push(DictionaryAttribute {
            name:        "Mobile-Node-Identifier".to_string(),
            vendor_name: "".to_string(),
            code:        145,
            code_type:   Some(SupportedAttributeTypes::ByteString)
        });
        attributes.push(DictionaryAttribute {
            name:        "PMIP6-Home-Interface-ID".to_string(),
            vendor_name: "".to_string(),
            code:        153,
            code_type:   Some(SupportedAttributeTypes::InterfaceId)
        });
        attributes.push(DictionaryAttribute {
            name:        "PMIP6-Home-IPv4-HoA".to_string(),
            vendor_name: "".to_string(),
            code:        155,
            code_type:   Some(SupportedAttributeTypes::IPv4Prefix)
        });
        attributes.push(DictionaryAttribute {
            name:        "Somevendor-Name".to_string(),
            vendor_name: "Somevendor".to_string(),
            code:        1,
            code_type:   Some(SupportedAttributeTypes::AsciiString)
        });
        attributes.push(DictionaryAttribute {
            name:        "Somevendor-Number".to_string(),
            vendor_name: "Somevendor".to_string(),
            code:        2,
            code_type:   Some(SupportedAttributeTypes::Integer)
        });
        attributes.push(DictionaryAttribute {
            name:        "Class".to_string(),
            vendor_name: "".to_string(),
            code:        25,
            code_type:   Some(SupportedAttributeTypes::ByteString)
        });

        let mut values: Vec<DictionaryValue> = Vec::new();
        values.push(DictionaryValue {
            attribute_name: "Framed-Protocol".to_string(),
            value_name:     "PPP".to_string(),
            vendor_name:    "".to_string(),
            value:          "1".to_string()
        });
        values.push(DictionaryValue {
            attribute_name: "Somevendor-Number".to_string(),
            value_name:     "Two".to_string(),
            vendor_name:    "Somevendor".to_string(),
            value:          "2".to_string()
        });

        let mut vendors: Vec<DictionaryVendor> = Vec::new();
        vendors.push(DictionaryVendor {
            name: "Somevendor".to_string(),
            id:   10,
        });

        let expected_dict = Dictionary { attributes, values, vendors };
        assert_eq!(dict, expected_dict)
    }

    #[test]
    fn test_from_file() {
        let dictionary_path = "./dict_examples/test_dictionary_dict";

        let dict = Dictionary::from_file(dictionary_path).unwrap();

        let mut attributes: Vec<DictionaryAttribute> = Vec::new();
        attributes.push(DictionaryAttribute {
            name:        "User-Name".to_string(),
            vendor_name: "".to_string(),
            code:        1,
            code_type:   Some(SupportedAttributeTypes::AsciiString)
        });
        attributes.push(DictionaryAttribute {
            name:        "NAS-IP-Address".to_string(),
            vendor_name: "".to_string(),
            code:        4,
            code_type:   Some(SupportedAttributeTypes::IPv4Addr)
        });
        attributes.push(DictionaryAttribute {
            name:        "NAS-Port-Id".to_string(),
            vendor_name: "".to_string(),
            code:        5,
            code_type:   Some(SupportedAttributeTypes::Integer)
        });
        attributes.push(DictionaryAttribute {
            name:        "Framed-Protocol".to_string(),
            vendor_name: "".to_string(),
            code:        7,
            code_type:   Some(SupportedAttributeTypes::Integer)
        });
        attributes.push(DictionaryAttribute {
            name:        "Chargeable-User-Identity".to_string(),
            vendor_name: "".to_string(),
            code:        89,
            code_type:   Some(SupportedAttributeTypes::ByteString)
        });
        attributes.push(DictionaryAttribute {
            name:        "Delegated-IPv6-Prefix".to_string(),
            vendor_name: "".to_string(),
            code:        123,
            code_type:   Some(SupportedAttributeTypes::IPv6Prefix)
        });
        attributes.push(DictionaryAttribute {
            name:        "MIP6-Feature-Vector".to_string(),
            vendor_name: "".to_string(),
            code:        124,
            code_type:   Some(SupportedAttributeTypes::Integer64)
        });
        attributes.push(DictionaryAttribute {
            name:        "Mobile-Node-Identifier".to_string(),
            vendor_name: "".to_string(),
            code:        145,
            code_type:   Some(SupportedAttributeTypes::ByteString)
        });
        attributes.push(DictionaryAttribute {
            name:        "PMIP6-Home-Interface-ID".to_string(),
            vendor_name: "".to_string(),
            code:        153,
            code_type:   Some(SupportedAttributeTypes::InterfaceId)
        });
        attributes.push(DictionaryAttribute {
            name:        "PMIP6-Home-IPv4-HoA".to_string(),
            vendor_name: "".to_string(),
            code:        155,
            code_type:   Some(SupportedAttributeTypes::IPv4Prefix)
        });
        attributes.push(DictionaryAttribute {
            name:        "Somevendor-Name".to_string(),
            vendor_name: "Somevendor".to_string(),
            code:        1,
            code_type:   Some(SupportedAttributeTypes::AsciiString)
        });
        attributes.push(DictionaryAttribute {
            name:        "Somevendor-Number".to_string(),
            vendor_name: "Somevendor".to_string(),
            code:        2,
            code_type:   Some(SupportedAttributeTypes::Integer)
        });
        attributes.push(DictionaryAttribute {
            name:        "Class".to_string(),
            vendor_name: "".to_string(),
            code:        25,
            code_type:   Some(SupportedAttributeTypes::ByteString)
        });

        let mut values: Vec<DictionaryValue> = Vec::new();
        values.push(DictionaryValue {
            attribute_name: "Framed-Protocol".to_string(),
            value_name:     "PPP".to_string(),
            vendor_name:    "".to_string(),
            value:          "1".to_string()
        });
        values.push(DictionaryValue {
            attribute_name: "Somevendor-Number".to_string(),
            value_name:     "Two".to_string(),
            vendor_name:    "Somevendor".to_string(),
            value:          "2".to_string()
        });

        let mut vendors: Vec<DictionaryVendor> = Vec::new();
        vendors.push(DictionaryVendor {
            name: "Somevendor".to_string(),
            id:   10,
        });

        let expected_dict = Dictionary { attributes, values, vendors };
        assert_eq!(dict, expected_dict)
    }

    #[test]
    fn test_add_str() {
        let empty_dictionary_str = include_str!("../../dict_examples/empty_test_dictionary_dict");
        let dictionary_str       = include_str!("../../dict_examples/test_dictionary_dict");

        let mut dict = Dictionary::from_str(empty_dictionary_str).unwrap();
        dict.add_str(dictionary_str).unwrap();

        let mut attributes: Vec<DictionaryAttribute> = Vec::new();
        attributes.push(DictionaryAttribute {
            name:        "User-Name".to_string(),
            vendor_name: "".to_string(),
            code:        1,
            code_type:   Some(SupportedAttributeTypes::AsciiString)
        });
        attributes.push(DictionaryAttribute {
            name:        "NAS-IP-Address".to_string(),
            vendor_name: "".to_string(),
            code:        4,
            code_type:   Some(SupportedAttributeTypes::IPv4Addr)
        });
        attributes.push(DictionaryAttribute {
            name:        "NAS-Port-Id".to_string(),
            vendor_name: "".to_string(),
            code:        5,
            code_type:   Some(SupportedAttributeTypes::Integer)
        });
        attributes.push(DictionaryAttribute {
            name:        "Framed-Protocol".to_string(),
            vendor_name: "".to_string(),
            code:        7,
            code_type:   Some(SupportedAttributeTypes::Integer)
        });
        attributes.push(DictionaryAttribute {
            name:        "Chargeable-User-Identity".to_string(),
            vendor_name: "".to_string(),
            code:        89,
            code_type:   Some(SupportedAttributeTypes::ByteString)
        });
        attributes.push(DictionaryAttribute {
            name:        "Delegated-IPv6-Prefix".to_string(),
            vendor_name: "".to_string(),
            code:        123,
            code_type:   Some(SupportedAttributeTypes::IPv6Prefix)
        });
        attributes.push(DictionaryAttribute {
            name:        "MIP6-Feature-Vector".to_string(),
            vendor_name: "".to_string(),
            code:        124,
            code_type:   Some(SupportedAttributeTypes::Integer64)
        });
        attributes.push(DictionaryAttribute {
            name:        "Mobile-Node-Identifier".to_string(),
            vendor_name: "".to_string(),
            code:        145,
            code_type:   Some(SupportedAttributeTypes::ByteString)
        });
        attributes.push(DictionaryAttribute {
            name:        "PMIP6-Home-Interface-ID".to_string(),
            vendor_name: "".to_string(),
            code:        153,
            code_type:   Some(SupportedAttributeTypes::InterfaceId)
        });
        attributes.push(DictionaryAttribute {
            name:        "PMIP6-Home-IPv4-HoA".to_string(),
            vendor_name: "".to_string(),
            code:        155,
            code_type:   Some(SupportedAttributeTypes::IPv4Prefix)
        });
        attributes.push(DictionaryAttribute {
            name:        "Somevendor-Name".to_string(),
            vendor_name: "Somevendor".to_string(),
            code:        1,
            code_type:   Some(SupportedAttributeTypes::AsciiString)
        });
        attributes.push(DictionaryAttribute {
            name:        "Somevendor-Number".to_string(),
            vendor_name: "Somevendor".to_string(),
            code:        2,
            code_type:   Some(SupportedAttributeTypes::Integer)
        });
        attributes.push(DictionaryAttribute {
            name:        "Class".to_string(),
            vendor_name: "".to_string(),
            code:        25,
            code_type:   Some(SupportedAttributeTypes::ByteString)
        });

        let mut values: Vec<DictionaryValue> = Vec::new();
        values.push(DictionaryValue {
            attribute_name: "Framed-Protocol".to_string(),
            value_name:     "PPP".to_string(),
            vendor_name:    "".to_string(),
            value:          "1".to_string()
        });
        values.push(DictionaryValue {
            attribute_name: "Somevendor-Number".to_string(),
            value_name:     "Two".to_string(),
            vendor_name:    "Somevendor".to_string(),
            value:          "2".to_string()
        });

        let mut vendors: Vec<DictionaryVendor> = Vec::new();
        vendors.push(DictionaryVendor {
            name: "Somevendor".to_string(),
            id:   10,
        });

        let expected_dict = Dictionary { attributes, values, vendors };
        assert_eq!(dict, expected_dict)
    }

    #[test]
    fn test_add_file() {
        let empty_dictionary_path = "./dict_examples/empty_test_dictionary_dict";
        let dictionary_path       = "./dict_examples/test_dictionary_dict";

        let mut dict = Dictionary::from_file(empty_dictionary_path).unwrap();
        dict.add_file(dictionary_path).unwrap();

        let mut attributes: Vec<DictionaryAttribute> = Vec::new();
        attributes.push(DictionaryAttribute {
            name:        "User-Name".to_string(),
            vendor_name: "".to_string(),
            code:        1,
            code_type:   Some(SupportedAttributeTypes::AsciiString)
        });
        attributes.push(DictionaryAttribute {
            name:        "NAS-IP-Address".to_string(),
            vendor_name: "".to_string(),
            code:        4,
            code_type:   Some(SupportedAttributeTypes::IPv4Addr)
        });
        attributes.push(DictionaryAttribute {
            name:        "NAS-Port-Id".to_string(),
            vendor_name: "".to_string(),
            code:        5,
            code_type:   Some(SupportedAttributeTypes::Integer)
        });
        attributes.push(DictionaryAttribute {
            name:        "Framed-Protocol".to_string(),
            vendor_name: "".to_string(),
            code:        7,
            code_type:   Some(SupportedAttributeTypes::Integer)
        });
        attributes.push(DictionaryAttribute {
            name:        "Chargeable-User-Identity".to_string(),
            vendor_name: "".to_string(),
            code:        89,
            code_type:   Some(SupportedAttributeTypes::ByteString)
        });
        attributes.push(DictionaryAttribute {
            name:        "Delegated-IPv6-Prefix".to_string(),
            vendor_name: "".to_string(),
            code:        123,
            code_type:   Some(SupportedAttributeTypes::IPv6Prefix)
        });
        attributes.push(DictionaryAttribute {
            name:        "MIP6-Feature-Vector".to_string(),
            vendor_name: "".to_string(),
            code:        124,
            code_type:   Some(SupportedAttributeTypes::Integer64)
        });
        attributes.push(DictionaryAttribute {
            name:        "Mobile-Node-Identifier".to_string(),
            vendor_name: "".to_string(),
            code:        145,
            code_type:   Some(SupportedAttributeTypes::ByteString)
        });
        attributes.push(DictionaryAttribute {
            name:        "PMIP6-Home-Interface-ID".to_string(),
            vendor_name: "".to_string(),
            code:        153,
            code_type:   Some(SupportedAttributeTypes::InterfaceId)
        });
        attributes.push(DictionaryAttribute {
            name:        "PMIP6-Home-IPv4-HoA".to_string(),
            vendor_name: "".to_string(),
            code:        155,
            code_type:   Some(SupportedAttributeTypes::IPv4Prefix)
        });
        attributes.push(DictionaryAttribute {
            name:        "Somevendor-Name".to_string(),
            vendor_name: "Somevendor".to_string(),
            code:        1,
            code_type:   Some(SupportedAttributeTypes::AsciiString)
        });
        attributes.push(DictionaryAttribute {
            name:        "Somevendor-Number".to_string(),
            vendor_name: "Somevendor".to_string(),
            code:        2,
            code_type:   Some(SupportedAttributeTypes::Integer)
        });
        attributes.push(DictionaryAttribute {
            name:        "Class".to_string(),
            vendor_name: "".to_string(),
            code:        25,
            code_type:   Some(SupportedAttributeTypes::ByteString)
        });

        let mut values: Vec<DictionaryValue> = Vec::new();
        values.push(DictionaryValue {
            attribute_name: "Framed-Protocol".to_string(),
            value_name:     "PPP".to_string(),
            vendor_name:    "".to_string(),
            value:          "1".to_string()
        });
        values.push(DictionaryValue {
            attribute_name: "Somevendor-Number".to_string(),
            value_name:     "Two".to_string(),
            vendor_name:    "Somevendor".to_string(),
            value:          "2".to_string()
        });

        let mut vendors: Vec<DictionaryVendor> = Vec::new();
        vendors.push(DictionaryVendor {
            name: "Somevendor".to_string(),
            id:   10,
        });

        let expected_dict = Dictionary { attributes, values, vendors };
        assert_eq!(dict, expected_dict)
    }
}
