//! RADIUS Dictionary implementation


use std::fs::File;
use std::io::{self, BufRead};

use super::error::RadiusError;

#[derive(Debug, PartialEq)]
/// Represents a list of supported data types
/// as defined in RFC 2865
pub enum SupportedAttributeTypes {
    /// Rust's String
    AsciiString,
    /// Rust's u32
    Integer,
    /// Rust's u64
    Date,
    /// Rust's \[u8;4\]
    IPv4Addr,
    /// Rust's \[u8;16\]
    IPv6Addr,
    /// Rust's \[u8;18\]
    IPv6Prefix
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
    code:        String,
    code_type:   Option<SupportedAttributeTypes>
}

impl DictionaryAttribute {
    /// Return name of the Attribute
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return code of the Attribute
    pub fn code(&self) -> &str {
        &self.code
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
    id:   String  // ideally should be u16
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
    /// Creates Dictionary from a string
    pub fn from_str(dictionary_str: &str) -> Result<Dictionary, RadiusError> {
        todo!()
    }

    /// Creates Dictionary from a RADIUS dictionary file
    pub fn from_file(file_path: &str) -> Result<Dictionary, RadiusError> {
        let mut attributes:  Vec<DictionaryAttribute> = Vec::new();
        let mut values:      Vec<DictionaryValue>     = Vec::new();
        let mut vendors:     Vec<DictionaryVendor>    = Vec::new();
        let mut vendor_name: String                   = String::new();
        let comment_prefix:  String                   = String::from("#");

        let reader = io::BufReader::new(File::open(file_path).map_err(|error| RadiusError::MalformedDictionaryError { error })?);
        let lines  = reader.lines()
            .filter_map(Result::ok)
            .filter(|line| !line.is_empty())
            .filter(|line| !line.contains(&COMMENT_PREFIX));

        for line in lines {
            let parsed_line: Vec<&str> = line.split_whitespace().filter(|&item| !item.is_empty()).collect();
            match parsed_line[0] {
                "ATTRIBUTE"    => parse_attribute(parsed_line, &vendor_name, &mut attributes),
                "VALUE"        => parse_value(parsed_line, &vendor_name, &mut values),
                "VENDOR"       => parse_vendor(parsed_line, &mut vendors),
                "BEGIN-VENDOR" => { vendor_name.insert_str(0, parsed_line[1]) },
                "END-VENDOR"   => { vendor_name.clear() },
                _              => continue
            }
        };
        Ok(Dictionary { attributes, values, vendors })
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
        "string"     => Some(SupportedAttributeTypes::AsciiString),
        "integer"    => Some(SupportedAttributeTypes::Integer),
        "date"       => Some(SupportedAttributeTypes::Date),
        "ipaddr"     => Some(SupportedAttributeTypes::IPv4Addr),
        "ipv6addr"   => Some(SupportedAttributeTypes::IPv6Addr),
        "ipv6prefix" => Some(SupportedAttributeTypes::IPv6Prefix),
        _            => None
    }
}

fn parse_attribute(parsed_line: Vec<&str>, vendor_name: &str, attributes: &mut Vec<DictionaryAttribute>) {
    attributes.push(DictionaryAttribute {
        name:        parsed_line[1].to_string(),
        vendor_name: vendor_name.to_string(),
        code:        parsed_line[2].to_string(),
        code_type:   assign_attribute_type(parsed_line[3])
    });
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
    vendors.push(DictionaryVendor {
        name: parsed_line[1].to_string(),
        id:   parsed_line[2].to_string(),
    })
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_file() {
        let dictionary_path = "./dict_examples/test_dictionary_dict";

        let dict = Dictionary::from_file(dictionary_path).unwrap();

        let mut attributes: Vec<DictionaryAttribute> = Vec::new();
        attributes.push(DictionaryAttribute {
            name:        "User-Name".to_string(),
            vendor_name: "".to_string(),
            code:        "1".to_string(),
            code_type:   Some(SupportedAttributeTypes::AsciiString) 
        });
        attributes.push(DictionaryAttribute {
            name:        "NAS-IP-Address".to_string(),
            vendor_name: "".to_string(),
            code:        "4".to_string(),
            code_type:   Some(SupportedAttributeTypes::IPv4Addr)
        });
        attributes.push(DictionaryAttribute {
            name:        "NAS-Port-Id".to_string(),
            vendor_name: "".to_string(),
            code:        "5".to_string(),
            code_type:   Some(SupportedAttributeTypes::Integer)
        });
        attributes.push(DictionaryAttribute {
            name:        "Framed-Protocol".to_string(),
            vendor_name: "".to_string(),
            code:        "7".to_string(),
            code_type:   Some(SupportedAttributeTypes::Integer)
        });
        attributes.push(DictionaryAttribute {
            name:        "Somevendor-Name".to_string(),
            vendor_name: "Somevendor".to_string(),
            code:        "1".to_string(),
            code_type:   Some(SupportedAttributeTypes::AsciiString)
        });
        attributes.push(DictionaryAttribute {
            name:        "Somevendor-Number".to_string(),
            vendor_name: "Somevendor".to_string(),
            code:        "2".to_string(),
            code_type:   Some(SupportedAttributeTypes::Integer)
        });
        attributes.push(DictionaryAttribute {
            name:        "Test-IP".to_string(),
            vendor_name: "".to_string(),
            code:        "25".to_string(),
            code_type:   Some(SupportedAttributeTypes::IPv4Addr)
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
            id:   "10".to_string(),
        });

        let expected_dict = Dictionary { attributes, values, vendors };
        assert_eq!(dict, expected_dict)
    }
}
