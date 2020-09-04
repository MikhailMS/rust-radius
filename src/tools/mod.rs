use crypto::digest::Digest;
use crypto::md5::Md5;

use std::str::FromStr;
use std::net::Ipv6Addr;
use std::convert::TryInto;

use crate::protocol::error::RadiusError;


/// Converts IPv6 Address string into vector of bytes
///
/// Should be used for any Attribute of type ipv6addr or ipv6prefix to ensure value is encoded correctly
pub fn ipv6_string_to_bytes(ipv6: &str) -> Result<Vec<u8>, RadiusError> {
    let parsed_ipv6: Vec<&str> = ipv6.split("/").collect();
    let mut bytes: Vec<u8>     = Vec::with_capacity(18);
    let ipv6_address           = Ipv6Addr::from_str(parsed_ipv6[0]).map_err(|error| RadiusError::MalformedIpAddr { error: error.to_string() })?;

    if parsed_ipv6.len() == 2 {
        bytes.append( &mut encode_subnet(parsed_ipv6[1].parse::<u16>().unwrap()).to_vec() )
    }
    bytes.append(&mut ipv6_address.octets().to_vec());
    Ok(bytes)
}

/// Converts IPv6 bytes into IPv6 string
pub fn bytes_to_ipv6_string(ipv6: &[u8]) -> Result<String, RadiusError> {
    if ipv6.len() == 18 {
        // Case with subnet
        let subnet = u16_from_be_bytes(&ipv6[0..2]);
        let ipv6_string = Ipv6Addr::new(
            u16_from_be_bytes(&ipv6[2..4]),
            u16_from_be_bytes(&ipv6[4..6]),
            u16_from_be_bytes(&ipv6[6..8]),
            u16_from_be_bytes(&ipv6[8..10]),
            u16_from_be_bytes(&ipv6[10..12]),
            u16_from_be_bytes(&ipv6[12..14]),
            u16_from_be_bytes(&ipv6[14..16]),
            u16_from_be_bytes(&ipv6[16..]),
            ).to_string();
        Ok(format!("{}/{}",ipv6_string, subnet))
    } else {
        // Case without subnet
        Ok(Ipv6Addr::new(
            u16_from_be_bytes(&ipv6[0..2]),
            u16_from_be_bytes(&ipv6[2..4]),
            u16_from_be_bytes(&ipv6[4..6]),
            u16_from_be_bytes(&ipv6[6..8]),
            u16_from_be_bytes(&ipv6[8..10]),
            u16_from_be_bytes(&ipv6[10..12]),
            u16_from_be_bytes(&ipv6[12..14]),
            u16_from_be_bytes(&ipv6[14..]),
            ).to_string())
    }
}

/// Converts IPv4 Address string into vector of bytes
///
/// Should be used for any Attribute of type ipaddr to ensure value is encoded correctly
pub fn ipv4_string_to_bytes(ipv4: &str) -> Result<Vec<u8>, RadiusError> {
    if ipv4.contains("/") {
        return Err( RadiusError::MalformedIpAddr { error: format!("Subnets are not supported for IPv4: {}", ipv4) } )
    }

    let mut bytes: Vec<u8> = Vec::with_capacity(4);
    for group in ipv4.trim().split(".").map(|group| group.parse::<u8>().unwrap()) {
        bytes.push(group);
    }

    Ok(bytes)
}

/// Converts IPv4 bytes into IPv4 string
pub fn bytes_to_ipv4_string(ipv4: &[u8]) -> Result<String, RadiusError> {
    if ipv4.len() != 4 {
        return Err( RadiusError::MalformedIpAddr { error: format!("Malformed IPv4: {:?}", ipv4) } )
    }

    let ipv4_string: Vec<String> = ipv4.iter().map(|group| group.to_string()).collect();
    Ok(ipv4_string.join("."))
}

/// Converts u32 into vector of bytes
///
/// Should be used for any Attribute of type integer to ensure value is encoded correctly
pub fn integer_to_bytes(integer: u32) -> Vec<u8> {
    integer.to_be_bytes().to_vec()
}

/// Converts integer bytes into u32
pub fn bytes_to_integer(integer: &[u8; 4]) -> u32 {
    u32::from_be_bytes(*integer)
}

/// Converts timestamp (u64) into vector of bytes
///
/// Should be used for any Attribute of type date to ensure value is encoded correctly
pub fn timestamp_to_bytes(timestamp: u64) -> Vec<u8> {
    timestamp.to_be_bytes().to_vec()
}

/// Converts timestamp bytes into u64
pub fn bytes_to_timestamp(timestamp: &[u8; 8]) -> u64 {
    u64::from_be_bytes(*timestamp)
}

/// Encrypts data since RADIUS packet is sent in plain text
///
/// Should be used to encrypt value of **User-Password** attribute (but could also be used to encrypt
/// any data)
pub fn encrypt_data(data: &str, authenticator: &[u8], secret: &[u8]) -> Vec<u8> {
    /* Step 1. Ensure that data buffer's length is multiple of 16
    *  Step 2. Construct hash:
    *
    *  On each iteration:
    *   1. consume 16 elements from data buffer
    *   2. calculate MD5 hash for: provided secret + (authenticator(on 1st iteration) or 16 elements of result from previous iteration (2nd+ iteration))
    *   3. execute bitwise XOR between each of 16 elements of MD5 hash and data buffer and record it in results vector
    *
    * Step 3. Return result vector
    */
    let mut prev_result = authenticator.to_vec();
    let mut data_buffer = data.as_bytes().to_vec();

    let missing_length = data_buffer.len() % 16;
    if missing_length != 0 {
        data_buffer.append(&mut vec![0u8; 16 - missing_length]);
    }
    
    let mut result = Vec::with_capacity(data_buffer.len());
    
    while !data_buffer.is_empty() {
        let mut temp = secret.to_vec();
        temp.append(&mut prev_result.to_vec());

        let mut md5  = Md5::new();
        let mut hash = [0; 16];
        md5.input(&temp);
        md5.result(&mut hash);

        for i in 0..16 {
            result.push(hash[i] ^ data_buffer[i]);
        }

        prev_result = result[(result.len() - 16)..].to_vec();
        data_buffer = data_buffer[16..].to_vec();
    }
    result   
}

/// Decrypts data since RADIUS packet is sent in plain text
pub fn decrypt_data(data: &[u8], authenticator: &[u8], secret: &[u8]) -> Vec<u8> {
    /* 
     * To decrypt the data, we need to apply the same algorithm as in encrypt_data()
     * but with small change
     *
     *  On each iteration:
     *   1. consume 16 elements from data buffer
     *   2. calculate MD5 hash for: provided secret + (authenticator(on 1st iteration) or 16 elements of data buffer from previous iteration (2nd+ iteration))
     *   3. execute bitwise XOR between each of 16 elements of MD5 hash and data buffer and record it in results vector
     *
     */
    let mut data_buffer = data.to_vec();
    let mut result      = Vec::with_capacity(data_buffer.len());
    let mut prev_result = authenticator.to_vec();

    while !data_buffer.is_empty() {
        let mut temp = secret.to_vec();
        temp.append(&mut prev_result.to_vec());

        let mut md5  = Md5::new();
        let mut hash = [0; 16];
        md5.input(&temp);
        md5.result(&mut hash);
        
        for i in 0..16 {
            result.push(hash[i] ^ data_buffer[i]);
        }

        prev_result = data_buffer[..16].to_vec();
        data_buffer = data_buffer[16..].to_vec();
    }
    while result[result.len()-1] == 0 {
        result.pop();
    }
    result
}

// -----------------------------------------
fn encode_subnet(u16_data: u16) -> [u8;2] {
    [ (u16_data >> 8) as u8, u16_data as u8 ]
}

fn u16_from_be_bytes(bytes: &[u8]) -> u16 {
    u16::from_be_bytes(bytes.try_into().expect("slice with incorrect length"))
}
// -----------------------------------------


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_to_bytes_wo_subnet() {
        let ipv6_bytes = ipv6_string_to_bytes("fc66::1").unwrap();
        assert_eq!(ipv6_bytes, vec![252, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }
    #[test]
    fn test_bytes_to_ipv6_string_wo_subnet() {
        let expected_ipv6_string = "fc66::1";
        let ipv6_bytes           = vec![252, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        assert_eq!(expected_ipv6_string, bytes_to_ipv6_string(&ipv6_bytes).unwrap());
    }

    #[test]
    fn test_ipv6_to_bytes_w_subnet() {
        let ipv6_bytes = ipv6_string_to_bytes("fc66::1/64").unwrap();
        assert_eq!(ipv6_bytes, [0, 64, 252, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }
    #[test]
    fn test_bytes_to_ipv6_string_w_subnet() {
        let expected_ipv6_string = "fc66::1/64";
        let ipv6_bytes           = vec![0, 64, 252, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

        assert_eq!(expected_ipv6_string, bytes_to_ipv6_string(&ipv6_bytes).unwrap());
    }

    #[test]
    fn test_ipv4_string_to_bytes() {
        let ipv4_bytes = ipv4_string_to_bytes("192.1.10.1").unwrap();

        assert_eq!(ipv4_bytes, [192, 1, 10, 1]);
    }

    #[test]
    fn test_ipv4_bytes_to_string() {
        let ipv4_bytes = vec![192, 1, 10, 1];
        let ipv4_string = bytes_to_ipv4_string(&ipv4_bytes).unwrap();

        assert_eq!(ipv4_string, "192.1.10.1".to_string());
    }

    #[test]
    fn test_encrypt_data() {
        let secret        = String::from("secret");
        let authenticator = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        let encrypted_bytes = encrypt_data("password", &authenticator, &secret.as_bytes());

        assert_eq!(encrypted_bytes, vec![135, 116, 155, 239, 226, 89, 90, 221, 62, 29, 218, 130, 102, 174, 191, 250]);
    }

    #[test]
    fn test_decrypt_data() {
        let secret         = String::from("secret");
        let authenticator  = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        let expected_data  = String::from("password");
        let encrypted_data = vec![135, 116, 155, 239, 226, 89, 90, 221, 62, 29, 218, 130, 102, 174, 191, 250];

        let decrypted_data = decrypt_data(&encrypted_data, &authenticator, &secret.as_bytes());

        assert_eq!(expected_data.as_bytes().to_vec(), decrypted_data);
    }

    #[test]
    fn test_integer_to_bytes() {
        let integer: u32 = 10000;

        assert_eq!(vec![0, 0, 39, 16], integer_to_bytes(integer));
    }

    #[test]
    fn test_bytes_to_integer() {
        let integer_bytes = [0, 0, 39, 16];

        assert_eq!(10000, bytes_to_integer(&integer_bytes));
    }

    #[test]
    fn test_timestamp_to_bytes() {
        let timestamp: u64 = 1598523933;

        assert_eq!(vec![0, 0, 0, 0, 95, 71, 138, 29], timestamp_to_bytes(timestamp));
    }

    #[test]
    fn test_bytes_to_timestamp() {
        let timestamp_bytes = [0, 0, 0, 0, 95, 71, 138, 29];

        assert_eq!(1598523933, bytes_to_timestamp(&timestamp_bytes));
    }
}
