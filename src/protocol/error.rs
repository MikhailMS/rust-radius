use thiserror::Error;


#[derive(Debug, Error)]
/// Represents all errors generated by this library
pub enum RadiusError {
    /// Error happens, when Radius Packet fails validation
    #[error("Verification failed for incoming Radius packet")]
    ValidationError         { error: String },
    /// Error happens, when packet has been badly constructed or got corrupted
    #[error("Radius packet is malformed")]
    MalformedPacket         { error: String },
    /// Error happens, when attribute has been badly constructed or got corrupted
    #[error("Radius packet attribute is malformed")]
    MalformedAttribute      { error: String },
    /// Error happens, when IPv6 Address was badly added to Radius Packet or got corrupted
    #[error("Provided IPv6 address is malformed")]
    MalformedIpAddr         { error: String },
    /// Error happens, when there is some sort of connection error between sockets, or socket
    /// cannot bind to the given hostname/port
    #[error(transparent)]
    SocketConnectionError(#[from] std::io::Error),
    /// Error won't happen, but represents the case when socket gets message from unknwon source
    #[error("Invalid socket connection")]
    SocketInvalidConnection { error: String },
    /// Error happens, when socket cannot parse given hostname/port
    #[error(transparent)]
    SocketAddrParseError(#[from] std::net::AddrParseError),
    /// Error happens, when dictionary file cannot be parsed
    #[error("Dictionary is malformed or inaccessible")]
    MalformedDictionary     { error: std::io::Error },
    /// Error happens, when wrong RADIUS Code is supplied
    #[error("Supplied RADIUS Code is not supported by this library")]
    UnsupportedTypeCode     { error: String }
}