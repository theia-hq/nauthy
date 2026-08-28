//! The name of a service a capability grants access to.

use core::fmt;
use core::str::FromStr;

/// A service name, as passed to `expose name=addr` and carried in a [`Cap`](crate::Cap).
///
/// Newtyped and validated at the edge because the name is embedded into a biscuit datalog check
/// (`service == "<name>"`). Restricting it to a small, quote-free alphabet keeps a service name from
/// ever being confused with datalog syntax, so a name can never smuggle a term or a rule into the token.
/// The alphabet (ASCII alphanumerics plus `-`, `_`, `.`, `/`, `:`) covers real service names like
/// `ssh`, `web`, `docker`, `unix:/run/x`, and `default` while excluding quotes, whitespace, and
/// backslashes.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Service(String);

impl Service {
    /// The maximum length of a service name, in bytes. Bounded so a name cannot bloat a token.
    pub const MAX_LEN: usize = 128;

    /// The reserved service a membership badge grants: `theia:member`.
    ///
    /// A cap minted for this service is not access to a named service but a claim of MEMBERSHIP: "the
    /// bearer is one of my devices." A family gate honors it as whole-node admission. Only the signing
    /// identity can mint one (minting needs the root secret), so a delegated capability can never become a
    /// membership badge: attenuation only ever adds checks, so a cap for some other service can never come
    /// to grant `theia:member`. The `theia:` prefix is reserved for such protocol services, kept distinct
    /// from user service names like `ssh` or `web`.
    pub const MEMBERSHIP: &str = "theia:member";

    /// The service name as a string slice.
    pub fn as_str(&self) -> &str {
        let Self(name) = self;
        name
    }

    /// The membership service, [`Service::MEMBERSHIP`]. Infallible: the constant is a valid name by
    /// construction (a test pins that it parses), so this needs no error path.
    pub fn membership() -> Self {
        Self(Self::MEMBERSHIP.to_owned())
    }
}

impl FromStr for Service {
    type Err = ServiceParseError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        if text.is_empty() {
            return Err(ServiceParseError::Empty);
        }
        if text.len() > Self::MAX_LEN {
            return Err(ServiceParseError::TooLong);
        }
        if let Some(bad) = text.chars().find(|char| !is_service_char(*char)) {
            return Err(ServiceParseError::BadChar(bad));
        }
        Ok(Self(text.to_owned()))
    }
}

/// The characters a [`Service`] name may contain: ASCII alphanumerics and a few punctuation marks that
/// appear in real names, deliberately excluding anything with datalog meaning (quotes, whitespace,
/// backslash, parentheses, commas).
fn is_service_char(char: char) -> bool {
    char.is_ascii_alphanumeric() || matches!(char, '-' | '_' | '.' | '/' | ':')
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Service({})", self.as_str())
    }
}

/// Why a string could not be parsed into a [`Service`].
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ServiceParseError {
    /// The name was empty.
    #[error("service name is empty")]
    Empty,
    /// The name exceeded [`Service::MAX_LEN`] bytes.
    #[error("service name is too long")]
    TooLong,
    /// The name contained a character outside the permitted alphabet.
    #[error("service name contains an invalid character {0:?}")]
    BadChar(char),
}
