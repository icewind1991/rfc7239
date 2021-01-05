//! Parser for [rfc7239] formatted `Forwarded` headers.
//!
//! ## Usage
//!
//! ```
//! use rfc7239::parse;
//! # use std::error::Error;
//!
//! # fn main() -> Result<(), Box<dyn Error>> {
//! // get the header value from your favorite http server library
//! let header_value = "for=192.0.2.60;proto=http;by=203.0.113.43,for=192.168.10.10";
//!
//! for node_result in parse(header_value) {
//!     let node = node_result?;
//!     if let Some(forwarded_for) = node.forwarded_for {
//!         println!("Forwarded by {}", forwarded_for)
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! [rfc7239]: https://tools.ietf.org/html/rfc7239
use std::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;
use uncased::UncasedStr;

#[derive(Debug)]
pub enum RfcError {
    InvalidIdentifier,
    InvalidPort,
    UnknownParameter,
    MalformedParameter,
}

impl Display for RfcError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            RfcError::InvalidIdentifier => "Invalid node identifier",
            RfcError::InvalidPort => "Invalid node port",
            RfcError::UnknownParameter => "Unknown parameter name",
            RfcError::MalformedParameter => "Parameter doesn't consist of key value pair",
        };
        write!(f, "{}", str)
    }
}

impl Error for RfcError {}

/// Parse an rfc7239 header value into a list of forwarded nodes
pub fn parse(header_value: &str) -> impl Iterator<Item = Result<Forwarded, RfcError>> {
    header_value.split(',').map(str::trim).map(Forwarded::parse)
}

#[test]
fn test_parse() {
    assert_eq!(
        parse("for=192.0.2.60;proto=http;by=203.0.113.43,for=192.168.10.10")
            .collect::<Result<Vec<_>, _>>()
            .unwrap(),
        vec![
            Forwarded {
                forwarded_for: Some(NodeIdentifier::parse("192.0.2.60").unwrap()),
                forwarded_by: Some(NodeIdentifier::parse("203.0.113.43").unwrap()),
                protocol: Some("http"),
                ..Default::default()
            },
            Forwarded {
                forwarded_for: Some(NodeIdentifier::parse("192.168.10.10").unwrap()),
                ..Default::default()
            },
        ]
    )
}

#[derive(Debug, Default, PartialEq)]
pub struct Forwarded<'a> {
    pub forwarded_for: Option<NodeIdentifier<'a>>,
    pub forwarded_by: Option<NodeIdentifier<'a>>,
    pub host: Option<&'a str>,
    pub protocol: Option<&'a str>,
}

impl<'a> Forwarded<'a> {
    fn parse(forward: &'a str) -> Result<Self, RfcError> {
        let mut result = Forwarded::default();

        let parts = forward.split(';');

        for part in parts {
            if let Some(i) = part.find('=') {
                let param = UncasedStr::new(&part[..i]);
                let value = &part[i + 1..];
                if param == "by" {
                    result.forwarded_by = Some(NodeIdentifier::parse(value.trim_matches('"'))?);
                }
                if param == "for" {
                    result.forwarded_for = Some(NodeIdentifier::parse(value.trim_matches('"'))?);
                }
                if param == "host" {
                    result.host = Some(value);
                }
                if param == "proto" {
                    result.protocol = Some(value);
                }
            } else {
                return Err(RfcError::MalformedParameter);
            }
        }

        Ok(result)
    }
}

impl<'a> Display for Forwarded<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut needs_delim = false;
        if let Some(ident) = &self.forwarded_for {
            if ident.display_needs_quote() {
                write!(f, "for=\"{}\"", ident)?;
            } else {
                write!(f, "for={}", ident)?;
            }
            needs_delim = true;
        }
        if let Some(ident) = &self.forwarded_by {
            if needs_delim {
                write!(f, ";")?;
            }

            if ident.display_needs_quote() {
                write!(f, "by=\"{}\"", ident)?;
            } else {
                write!(f, "by={}", ident)?;
            }
            needs_delim = true;
        }
        if let Some(ident) = &self.host {
            if needs_delim {
                write!(f, ";")?;
            }

            write!(f, "host={}", ident)?;
            needs_delim = true;
        }
        if let Some(ident) = &self.protocol {
            if needs_delim {
                write!(f, ";")?;
            }

            write!(f, "proto={}", ident)?;
        }

        Ok(())
    }
}

#[test]
fn test_parse_forwarded() {
    assert_eq!(
        Forwarded {
            forwarded_for: Some(NodeIdentifier::parse("1.2.3.4").unwrap()),
            ..Default::default()
        },
        Forwarded::parse("for=1.2.3.4").unwrap()
    );
    assert_eq!(
        Forwarded {
            forwarded_for: Some(NodeIdentifier::parse("1.2.3.4").unwrap()),
            ..Default::default()
        },
        Forwarded::parse("For=1.2.3.4").unwrap()
    );
    assert_eq!(
        Forwarded {
            forwarded_for: Some(NodeIdentifier::parse("1.2.3.4").unwrap()),
            forwarded_by: Some(NodeIdentifier::parse("[1::1]:80").unwrap()),
            host: Some("foo"),
            protocol: Some("https")
        },
        Forwarded::parse("for=1.2.3.4;by=\"[1::1]:80\";host=foo;proto=https").unwrap()
    );
}

#[test]
fn test_display_forwarded() {
    assert_eq!(
        format!(
            "{}",
            Forwarded {
                forwarded_for: Some(NodeIdentifier::parse("1.2.3.4").unwrap()),
                ..Default::default()
            }
        ),
        "for=1.2.3.4"
    );
    assert_eq!(
        format!(
            "{}",
            Forwarded {
                forwarded_for: Some(NodeIdentifier::parse("1.2.3.4").unwrap()),
                forwarded_by: Some(NodeIdentifier::parse("[1::1]:80").unwrap()),
                host: Some("foo"),
                protocol: Some("https")
            }
        ),
        "for=1.2.3.4;by=\"[1::1]:80\";host=foo;proto=https"
    );
}

#[derive(Debug, Eq, PartialEq)]
pub struct NodeIdentifier<'a> {
    pub name: NodeName<'a>,
    pub port: Option<u16>,
}

impl<'a> NodeIdentifier<'a> {
    fn parse(name: &'a str) -> Result<Self, RfcError> {
        match (name.rfind(':'), name.rfind(']')) {
            (Some(delim), Some(ip6_end)) if delim > ip6_end => {
                Self::parse_name_port(&name[0..delim], Some(&name[delim + 1..]))
            }
            (Some(delim), None) => Self::parse_name_port(&name[..delim], Some(&name[delim + 1..])),
            _ => Self::parse_name_port(name, None),
        }
    }

    fn parse_name_port(name: &'a str, port: Option<&str>) -> Result<Self, RfcError> {
        Ok(NodeIdentifier {
            name: NodeName::parse(name)?,
            port: port
                .map(u16::from_str)
                .transpose()
                .map_err(|_| RfcError::InvalidPort)?,
        })
    }

    /// values containing `:` or `[]` characters need to be quoted
    fn display_needs_quote(&self) -> bool {
        self.port.is_some() || matches!(self.name, NodeName::Ip(IpAddr::V6(_)))
    }
}

impl<'a> Display for NodeIdentifier<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self.port {
            Some(port) => write!(f, "{}:{}", self.name, port),
            None => write!(f, "{}", self.name),
        }
    }
}

#[test]
fn test_parse_node_identifier() {
    assert_eq!(
        NodeIdentifier {
            name: NodeName::Ip("1.2.3.4".parse().unwrap()),
            port: None
        },
        NodeIdentifier::parse("1.2.3.4").unwrap()
    );
    assert_eq!(
        NodeIdentifier {
            name: NodeName::Ip("1.2.3.4".parse().unwrap()),
            port: Some(8080)
        },
        NodeIdentifier::parse("1.2.3.4:8080").unwrap()
    );
    assert_eq!(
        NodeIdentifier {
            name: NodeName::Ip("2001:db8:cafe::17".parse().unwrap()),
            port: Some(8080)
        },
        NodeIdentifier::parse("[2001:db8:cafe::17]:8080").unwrap()
    );

    assert!(matches!(
        NodeIdentifier::parse("unknown:99999").unwrap_err(),
        RfcError::InvalidPort
    ));
}

#[test]
fn test_display_node_identifier() {
    assert_eq!(
        format!(
            "{}",
            NodeIdentifier {
                name: NodeName::Ip("1.2.3.4".parse().unwrap()),
                port: None
            }
        ),
        "1.2.3.4"
    );
    assert_eq!(
        format!(
            "{}",
            NodeIdentifier {
                name: NodeName::Ip("1.2.3.4".parse().unwrap()),
                port: Some(8080)
            }
        ),
        "1.2.3.4:8080"
    );
    assert_eq!(
        format!(
            "{}",
            NodeIdentifier {
                name: NodeName::Ip("2001:db8:cafe::17".parse().unwrap()),
                port: Some(8080)
            }
        ),
        "[2001:db8:cafe::17]:8080"
    );
}

#[derive(Debug, Eq, PartialEq)]
pub enum NodeName<'a> {
    Ip(IpAddr),
    Unknown,
    Obfuscated(&'a str),
}

impl<'a> NodeName<'a> {
    fn parse(name: &'a str) -> Result<Self, RfcError> {
        match name {
            "unknown" => Ok(NodeName::Unknown),
            obfuscated if obfuscated.starts_with("_") => {
                if obfuscated
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '.' || c == '_')
                {
                    Ok(NodeName::Obfuscated(obfuscated))
                } else {
                    Err(RfcError::InvalidIdentifier)
                }
            }
            ip6 if ip6.starts_with('[') && ip6.ends_with(']') => ip6[1..ip6.len() - 1]
                .parse()
                .map(IpAddr::V6)
                .map(NodeName::Ip)
                .map_err(|_| RfcError::InvalidIdentifier),
            ip4 => ip4
                .parse()
                .map(IpAddr::V4)
                .map(NodeName::Ip)
                .map_err(|_| RfcError::InvalidIdentifier),
        }
    }
}

impl<'a> Display for NodeName<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            NodeName::Ip(IpAddr::V4(ip)) => write!(f, "{}", ip),
            NodeName::Ip(IpAddr::V6(ip)) => write!(f, "[{}]", ip),
            NodeName::Unknown => {
                write!(f, "unknown")
            }
            NodeName::Obfuscated(name) => write!(f, "{}", name),
        }
    }
}

#[test]
fn test_parse_node_name() {
    assert_eq!(
        NodeName::Ip("1.2.3.4".parse().unwrap()),
        NodeName::parse("1.2.3.4").unwrap()
    );
    assert_eq!(
        NodeName::Ip("2001:db8:cafe::17".parse().unwrap()),
        NodeName::parse("[2001:db8:cafe::17]").unwrap()
    );
    assert_eq!(NodeName::Unknown, NodeName::parse("unknown").unwrap());
    assert_eq!(
        NodeName::Obfuscated("_FOO"),
        NodeName::parse("_FOO").unwrap()
    );

    // obfuscated identifiers must be _[a-zA-Z0-9_.]*
    assert!(matches!(
        NodeName::parse("_FOO-INVALID").unwrap_err(),
        RfcError::InvalidIdentifier
    ));
    assert!(matches!(
        NodeName::parse("FOO").unwrap_err(),
        RfcError::InvalidIdentifier
    ));

    // ip6 identifiers must be surrounded with []
    assert!(matches!(
        NodeName::parse("2001:db8:cafe::17").unwrap_err(),
        RfcError::InvalidIdentifier
    ));
}

#[test]
fn test_display_node_name() {
    assert_eq!(
        format!("{}", NodeName::Ip("1.2.3.4".parse().unwrap())),
        "1.2.3.4"
    );
    assert_eq!(
        format!("{}", NodeName::Ip("2001:db8:cafe::17".parse().unwrap())),
        "[2001:db8:cafe::17]"
    );
    assert_eq!(format!("{}", NodeName::Unknown), "unknown");
    assert_eq!(format!("{}", NodeName::Obfuscated("_FOO")), "_FOO");
}
