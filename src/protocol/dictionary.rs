use std::fs::File;
use std::io::{self, BufRead};
use std::error::Error;

#[derive(Debug, PartialEq)]
pub struct DictionaryAttribute {
    pub name:    String,
    vendor_name: String,
    pub code:    String,
    code_type:   String
}

impl DictionaryAttribute {
    pub fn to_bytes(&self) -> Vec<u8> {
        [self.name.as_bytes(), self.vendor_name.as_bytes(), self.code.as_bytes(), self.code_type.as_bytes()].concat()
    }
}


#[derive(Debug, PartialEq)]
pub struct DictionaryValue {
    attribute_name: String,
    value_name:     String,
    vendor_name:    String,
    value:          String
}

impl DictionaryValue {
    pub fn to_bytes(&self) -> Vec<u8> {
        [self.attribute_name.as_bytes(), self.value_name.as_bytes(), self.vendor_name.as_bytes(), self.value.as_bytes()].concat()
    }
}


#[derive(Debug, PartialEq)]
pub struct DictionaryVendor {
    name: String,
    id:   String  // ideally should be u16
}

impl DictionaryVendor {
    pub fn to_bytes(&self) -> Vec<u8> {
        [self.name.as_bytes(), self.id.as_bytes()].concat()
    }
}


#[derive(Debug, Default, PartialEq)]
pub struct Dictionary {
    pub attributes: Vec<DictionaryAttribute>,
    values:         Vec<DictionaryValue>,
    vendors:        Vec<DictionaryVendor>
}

#[allow(unused)]
impl Dictionary {
    pub fn from_str(dictionary_str: &str) -> Dictionary {
        todo!()
    }

    pub fn from_file(file_path: &str) -> Result<Dictionary, Box<dyn Error>> {
        let mut attributes:  Vec<DictionaryAttribute> = Vec::new();
        let mut values:      Vec<DictionaryValue>     = Vec::new();
        let mut vendors:     Vec<DictionaryVendor>    = Vec::new();
        let mut vendor_name: String                   = String::new();
        let comment_prefix:  String                   = String::from("#");

        let reader = io::BufReader::new(File::open(file_path)?);
        let lines  = reader.lines()
            .filter_map(Result::ok)
            .filter(|line| !line.is_empty())
            .filter(|line| !line.contains(&comment_prefix));

        for line in lines {
            let parsed_line: Vec<&str> = line.split(" ").filter(|&item| !item.is_empty()).collect();
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

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes: Vec<u8> = Vec::new();
        for attr in &self.attributes {
            bytes.extend(&attr.to_bytes());
        };
        for value in &self.values {
            bytes.extend(&value.to_bytes());
        };
        for vendor in &self.vendors {
            bytes.extend(&vendor.to_bytes());
        };
        
        bytes
    }
}


fn parse_attribute(parsed_line: Vec<&str>, vendor_name: &str, attributes: &mut Vec<DictionaryAttribute>) {
    attributes.push(DictionaryAttribute {
        name:        parsed_line[1].to_string(),
        vendor_name: vendor_name.to_string(),
        code:        parsed_line[2].to_string(),
        code_type:   parsed_line[3].to_string().to_lowercase()
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
    fn test_attribute_to_bytes() {
        let mut attributes: Vec<DictionaryAttribute> = Vec::new();
        attributes.push(DictionaryAttribute {
            name:        "User-Name".to_string(),
            vendor_name: "".to_string(),
            code:        "1".to_string(),
            code_type:   "string".to_string()
        });
        
        let attribute_as_bytes = attributes[0].to_bytes();
        assert_eq!(String::from_utf8(attribute_as_bytes).unwrap(), "User-Name1string".to_string());
    }

    #[test]
    fn test_value_to_bytes() {
        let mut values: Vec<DictionaryValue> = Vec::new();
        values.push(DictionaryValue {
            attribute_name: "Framed-Protocol".to_string(),
            value_name:     "PPP".to_string(),
            vendor_name:    "".to_string(),
            value:          "1".to_string()
        });
        
        let value_as_bytes = values[0].to_bytes();
        assert_eq!(String::from_utf8(value_as_bytes).unwrap(), "Framed-ProtocolPPP1".to_string());
    }

    #[test]
    fn test_vendor_to_bytes() {
        let mut vendors: Vec<DictionaryVendor> = Vec::new();
        vendors.push(DictionaryVendor {
            name: "Somevendor".to_string(),
            id:   "10".to_string(),
        });
        
        let vendor_as_bytes = vendors[0].to_bytes();
        assert_eq!(String::from_utf8(vendor_as_bytes).unwrap(), "Somevendor10".to_string());
    }

    #[test]
    fn test_dictionary_to_bytes() {
        let mut attributes: Vec<DictionaryAttribute> = Vec::new();
        attributes.push(DictionaryAttribute {
            name:        "User-Name".to_string(),
            vendor_name: "".to_string(),
            code:        "1".to_string(),
            code_type:   "string".to_string()
        });
        let mut values: Vec<DictionaryValue> = Vec::new();
        values.push(DictionaryValue {
            attribute_name: "Framed-Protocol".to_string(),
            value_name:     "PPP".to_string(),
            vendor_name:    "".to_string(),
            value:          "1".to_string()
        });
        let mut vendors: Vec<DictionaryVendor> = Vec::new();
        vendors.push(DictionaryVendor {
            name: "Somevendor".to_string(),
            id:   "10".to_string(),
        });

        let dictionary = Dictionary { attributes, values, vendors };
        let dictionary_as_bytes = dictionary.to_bytes();

        assert_eq!(String::from_utf8(dictionary_as_bytes).unwrap(), "User-Name1stringFramed-ProtocolPPP1Somevendor10".to_string())
    }
    

    #[test]
    fn test_from_file() {
        let dictionary_path = "./dict_examples/test_dictionary_dict";

        let dict = Dictionary::from_file(dictionary_path).unwrap();

        let mut attributes: Vec<DictionaryAttribute> = Vec::new();
        attributes.push(DictionaryAttribute {
            name:        "User-Name".to_string(),
            vendor_name: "".to_string(),
            code:        "1".to_string(),
            code_type:   "string".to_string()
        });
        attributes.push(DictionaryAttribute {
            name:        "NAS-IP-Address".to_string(),
            vendor_name: "".to_string(),
            code:        "4".to_string(),
            code_type:   "ipaddr".to_string()
        });
        attributes.push(DictionaryAttribute {
            name:        "NAS-Port-Id".to_string(),
            vendor_name: "".to_string(),
            code:        "5".to_string(),
            code_type:   "integer".to_string()
        });
        attributes.push(DictionaryAttribute {
            name:        "Framed-Protocol".to_string(),
            vendor_name: "".to_string(),
            code:        "7".to_string(),
            code_type:   "integer".to_string()
        });
        attributes.push(DictionaryAttribute {
            name:        "Somevendor-Name".to_string(),
            vendor_name: "Somevendor".to_string(),
            code:        "1".to_string(),
            code_type:   "string".to_string()
        });
        attributes.push(DictionaryAttribute {
            name:        "Somevendor-Number".to_string(),
            vendor_name: "Somevendor".to_string(),
            code:        "2".to_string(),
            code_type:   "integer".to_string()
        });
        attributes.push(DictionaryAttribute {
            name:        "Test-IP".to_string(),
            vendor_name: "".to_string(),
            code:        "25".to_string(),
            code_type:   "ipaddr".to_string()
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
