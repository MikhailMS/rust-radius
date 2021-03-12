//! Custom errors that are used in radius-rust crate to notify users of RADIUS specific error
//! states


use thiserror::Error;

// TODO - https://rust-lang.github.io/api-guidelines/naming.html#c-word-order
#[derive(Debug, Error)]
/// Represents all errors generated by this library
pub enum RadiusError {
    /// Error happens, when Radius Packet fails validation
    #[error("Verification failed for incoming Radius packet")]
    ValidationError         {
        /// Error definition received from crate
        error: String
    },
    /// Error happens, when packet has been badly constructed or got corrupted
    #[error("Radius packet is malformed")]
    MalformedPacketError    {
        /// Error definition received from crate
        error: String
    },
    /// Error happens, when attribute has been badly constructed or got corrupted
    #[error("Radius packet attribute is malformed")]
    MalformedAttributeError {
        /// Error definition received from crate
        error: String
    },
    /// Error happens, when IPv6 Address was badly added to Radius Packet or got corrupted
    #[error("Provided IPv6 address is malformed")]
    MalformedIpAddrError    {
        /// Error definition received from crate
        error: String
    },
    /// Error happens, when there is some sort of connection error between sockets, or socket
    /// cannot bind to the given hostname/port
    #[error(transparent)]
    SocketConnectionError(#[from] std::io::Error),
    /// Error won't happen, but represents the case when socket gets message from unknwon source
    #[error("Invalid socket connection")]
    SocketInvalidConnectionError {
        /// Error definition received from crate
        error: String
    },
    /// Error happens, when socket cannot parse given hostname/port
    #[error(transparent)]
    SocketAddrParseError(#[from] std::net::AddrParseError),
    /// Error happens, when dictionary file cannot be parsed
    #[error("Dictionary is malformed or inaccessible")]
    MalformedDictionaryError     {
        /// Error definition received from crate
        error: std::io::Error
    },
    /// Error happens, when wrong RADIUS Code is supplied
    #[error("Supplied RADIUS Code is not supported by this library")]
    UnsupportedTypeCodeError     {
        /// Error definition received from crate
        error: String
    },
    /// Error happens, when MutexClient cannot acquire the lock on socket_poll
    #[error("MutexClient is not able to acquire the lock on socket_poll")]
    MutexLockFailureError        {
        /// Error definition received from crate
        error: String
    },
    /// Error happens, when RADIUS Server gets a request from non-allowed server
    #[error("RADIUS Server is not allowed to accept packet from source IP")]
    IncorrrectSourceIpError      {
        /// Error definition received from crate
        error: String
    }
}
