use crypto::digest::Digest;
use crypto::md5::Md5;

use std::fmt;
use std::error::Error;
use std::str::FromStr;


/* Convertion of IPv6 from string into bytes
 * 
 * Conversion from string to IPv6 u128 is taken from
 * https://gist.github.com/little-dude/ad56d56afcd30ea39fafd807e16f05d1
 * and updated to fit the need of this crate
 *
 */

#[derive(Debug)]
pub struct MalformedAddress(String);

impl fmt::Display for MalformedAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "malformed address: \"{}\"", self.0)
    }
}

impl Error for MalformedAddress {
    fn description(&self) -> &str {
        "the string cannot be parsed as an IP address"
    }

    fn cause(&self) -> Option<&Error> {
        None
    }
}

#[derive(Debug, Copy, Eq, PartialEq, Hash, Clone)]
struct Ipv4Address(u32);

impl Ipv4Address {
    fn parse(_: &[u8]) -> Result<u32, MalformedAddress> {
        unimplemented!();
    }
}

#[derive(Debug, Copy, Eq, PartialEq, Hash, Clone)]
struct Ipv6Address {
    address: u128
}

impl Ipv6Address {
    pub fn to_bytes(&self) -> Vec<u8> {
        self.address.to_be_bytes().to_vec()
    }
}

impl FromStr for Ipv6Address {
    type Err = MalformedAddress;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // We'll manipulate bytes instead of UTF-8 characters, because the characters that
        // represent an IPv6 address are supposed to be ASCII characters.
        let bytes = s.as_bytes();

        // The maximimum length of a string representing an IPv6 is the length of:
        //
        //      1111:2222:3333:4444:5555:6666:7777:8888
        //
        // The minimum length of a string representing an IPv6 is the length of:
        //
        //      ::
        //
        if bytes.len() > 38 || bytes.len() < 2 {
            return Err(MalformedAddress(s.into()));
        }

        let mut offset = 0;
        let mut ellipsis: Option<usize> = None;

        // Handle the special case where the IP start with "::"
        if bytes[0] == b':' {
            if bytes[1] == b':' {
                if bytes.len() == 2 {
                    return Ok(Ipv6Address { address: 0 });
                }
                ellipsis = Some(0);
                offset += 2;
            } else {
                // An IPv6 cannot start with a single column. It must be a double column.
                // So this is an invalid address
                return Err(MalformedAddress(s.into()));
            }
        }

        // When dealing with IPv6, it's easier to reason in terms of "hextets" instead of octets.
        // An IPv6 is 8 hextets. At the end, we'll convert that array into an u128.
        let mut address: [u16; 8] = [0; 8];

        // Keep track of the number of hextets we process
        let mut hextet_index = 0;

        loop {
            if offset == bytes.len() {
                break;
            }

            // Try to read an hextet
            let (bytes_read, hextet) = read_hextet(&bytes[offset..]);

            // Handle the case where we could not read an hextet
            if bytes_read == 0 {
                match bytes[offset] {
                    // We could not read an hextet because the first character in the slace was ":"
                    // This may be because we have two consecutive columns.
                    b':' => {
                        // Check if already saw an ellipsis. If so, fail parsing, because an IPv6
                        // can only have one ellipsis.
                        if ellipsis.is_some() {
                            return Err(MalformedAddress(s.into()));
                        }
                        // Otherwise, remember the position of the ellipsis. We'll need that later
                        // to count the number of zeros the ellipsis represents.
                        ellipsis = Some(hextet_index);
                        offset += 1;
                        // Continue and try to read the next hextet
                        continue;
                    }
                    // We now the first character does not represent an hexadecimal digit
                    // (otherwise read_hextet() would have read at least one character), and that
                    // it's not ":", so the string does not represent an IPv6 address
                    _ => return Err(MalformedAddress(s.into())),
                }
            }

            // At this point, we know we read an hextet.

            address[hextet_index] = hextet;
            offset += bytes_read;
            hextet_index += 1;

            // If this was the last hextet of if we reached the end of the buffer, we should be
            // done
            if hextet_index == 8 || offset == bytes.len() {
                break
            }

            // Read the next charachter. After a hextet, we usually expect a column, but there's a special
            // case for IPv6 that ends with an IPv4.
            match bytes[offset] {
                // We saw the column, we can continue
                b':' => offset += 1,
                // Handle the special IPv4 case, ie address like below
                // Note that the hextet we just read is part of that IPv4 address:
                //
                //
                // aaaa:bbbb:cccc:dddd:eeee:ffff:a.b.c.d.
                //                               ^^
                //                               ||
                // hextet we just read, that  ---+|
                // is actually the first byte of  +--- dot we're handling
                // the ipv4.
                b'.' => {
                    // The hextet was actually part of the IPv4, so not that we start reading the
                    // IPv4 at `offset - bytes_read`.
                    let ipv4: u32 = Ipv4Address::parse(&bytes[offset-bytes_read..])?.into();
                    // Replace the hextet we just read by the 16 most significant bits of the
                    // IPv4 address (a.b in the comment above)
                    address[hextet_index - 1] = ((ipv4 & 0xffff_0000) >> 16) as u16;
                    // Set the last hextet to the 16 least significant bits of the IPv4 address
                    // (c.d in the comment above)
                    address[hextet_index] = (ipv4 & 0x0000_ffff) as u16;
                    hextet_index += 1;
                    // After successfully parsing an IPv4, we should be done.
                    // If there are bytes left in the buffer, or if we didn't read enough hextet,
                    // we'll fail later.
                    break;
                }
                _ => return Err(MalformedAddress(s.into())),
            }
        } // end of loop

        // If we exited the loop, we should have reached the end of the buffer.
        // If there are trailing characters, parsing should fail.
        if offset < bytes.len() {
            return Err(MalformedAddress(s.into()));
        }

        if hextet_index == 8 && ellipsis.is_some() {
            // We parsed an address that looks like 1111:2222::3333:4444:5555:6666:7777,
            // ie with an empty ellipsis.
            return Err(MalformedAddress(s.into()));
        }

        // We didn't parse enough hextets, but this may be due to an ellipsis
        if hextet_index < 8 {
            if let Some(ellipsis_index) = ellipsis {
                // Count how many zeros the ellipsis accounts for
                let nb_zeros = 8 - hextet_index;
                // Shift the hextet that we read after the ellipsis by the number of zeros
                for index in (ellipsis_index..hextet_index).rev() {
                    address[index+nb_zeros] = address[index];
                    address[index] = 0;
                }
            } else {
                return Err(MalformedAddress(s.into()));
            }
        }

        // Build the IPv6 address from the array of hextets
        return Ok(Ipv6Address {
            address: (
                ((address[0] as u128) << 112)
                + ((address[1] as u128) << 96)
                + ((address[2] as u128) << 90)
                + ((address[3] as u128) << 64)
                + ((address[4] as u128) << 48)
                + ((address[5] as u128) << 32)
                + ((address[6] as u128) << 16)
                + address[7] as u128)
        })
    }
}

fn is_hex_digit(byte: u8) -> bool {
    // Check whether an ASCII character represents an hexadecimal digit
    match byte {
        b'0' ..= b'9' | b'a' ..= b'f' | b'A' ..= b'F' => true,
        _ => false,
    }
}

fn hex_to_digit(byte: u8) -> u8 {
    // Convert an ASCII character that represents an hexadecimal digit into this digit
    match byte {
        b'0' ..= b'9' => byte - b'0',
        b'a' ..= b'f' => byte - b'a' + 10,
        b'A' ..= b'F' => byte - b'A' + 10,
        _ => unreachable!(),
    }
}

fn read_hextet(bytes: &[u8]) -> (usize, u16) {
    /* Read up to four ASCII characters that represent hexadecimal digits, and return their value, as
    *  well as the number of characters that were read. If not character is read, `(0, 0)` is returned.
    */ 

    let mut count = 0;
    let mut digits: [u8; 4] = [0; 4];

    for b in bytes {
        if is_hex_digit(*b) {
            digits[count] = hex_to_digit(*b);
            count += 1;
            if count == 4 {
                break;
            }
        } else {
            break;
        }
    }

    if count == 0 {
        return (0, 0);
    }

    let mut shift = (count - 1) * 4;
    let mut res   = 0;
    for digit in &digits[0..count] {
        res += (*digit as u16) << shift;
        if shift >= 4 {
            shift -= 4;
        } else {
            break;
        }
    }

    (count, res)
}
// -----------------------------------------

// The only thing which needs to be available to users
pub fn ipv6_string_to_bytes(ipv6: &str) -> Result<Vec<u8>, MalformedAddress> {
    let parsed_ipv6: Vec<&str> = ipv6.split("/").collect();
    let mut bytes: Vec<u8>     = Vec::with_capacity(18);
    let mut ipv6_address       = Ipv6Address::from_str(parsed_ipv6[0]).unwrap().to_bytes();

    if parsed_ipv6.len() == 2 {
        bytes.append( &mut encode_subnet(parsed_ipv6[1].parse::<u16>().unwrap()).to_vec() )
    }
    bytes.append(&mut ipv6_address);
    Ok(bytes)
}

pub fn bytes_to_ipv6_string(ipv6: Vec<u8>) -> Result<String, MalformedAddress> {
    todo!();
}

pub fn ipv4_string_to_bytes(ipv4: &str) -> Result<Vec<u8>, MalformedAddress> {
    if ipv4.contains("/") {
        return Err(MalformedAddress(format!("Subnets are not supported for IPv4: {}", ipv4)))
    }

    let mut bytes: Vec<u8> = Vec::with_capacity(4);
    for group in ipv4.trim().split(".").map(|group| group.parse::<u8>().unwrap()) {
        bytes.push(group);
    }

    Ok(bytes)
}

pub fn bytes_to_ipv4_string(ipv4: Vec<u8>) -> Result<String, MalformedAddress> {
    if ipv4.len() != 4 {
        return Err(MalformedAddress(format!("Malformed IPv4: {:?}", ipv4)))
    }

    let ipv4_string: Vec<String> = ipv4.iter().map(|group| group.to_string()).collect();
    Ok(ipv4_string.join("."))
}

pub fn integer_to_bytes(integer: u32) -> Vec<u8> {
    integer.to_be_bytes().to_vec()
}

pub fn bytes_to_integer(integer: [u8; 4]) -> u32 {
    u32::from_be_bytes(integer)
}

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


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv6_to_bytes_wo_subnet() {
        let ipv6_bytes = ipv6_string_to_bytes("fc66::1").unwrap();
        assert_eq!(ipv6_bytes, vec![252, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn test_ipv6_to_bytes_w_subnet() {
        let ipv6_bytes = ipv6_string_to_bytes("fc66::1/64").unwrap();
        assert_eq!(ipv6_bytes, [0, 64, 252, 102, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn test_ipv4_string_to_bytes() {
        let ipv4_bytes = ipv4_string_to_bytes("192.1.10.1").unwrap();

        assert_eq!(ipv4_bytes, [192, 1, 10, 1]);
    }

    #[test]
    fn test_ipv4_bytes_to_string() {
        let ipv4_string = bytes_to_ipv4_string(vec![192, 1, 10, 1]).unwrap();

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

        assert_eq!(10000, bytes_to_integer(integer_bytes));
    }
}
