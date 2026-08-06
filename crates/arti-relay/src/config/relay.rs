//! Code for parsing the relay specific config options.

use serde::{Deserialize, Serialize};

/// An error while deserializing a [`RelayConfig`](super::RelayConfig).
#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum RelayConfigError {
    /// The nickname failed validation.
    #[error("Relay nickname must be between 1 and 19 ASCII alphanumeric characters")]
    InvalidNickname,
    /// The contact information failed validation.
    #[error("Relay contact information must be a single line not starting with whitespace")]
    InvalidContact,
}

/// The nickname of a relay set by an operator in the configuration.
///
/// This nickname has restrictions as in it must be between 1 and 19 characters and ASCII
/// alphanumeric.
///
/// This wraps tor-netdoc's nickname type so we can easily deleguate validation to that
/// internal type. It prevents us from duplicating the validation rules but still keeping
/// a wrapper to avoid exposing the tor-netdoc's internals.
#[derive(Clone, Debug, Eq, PartialEq, derive_more::Display, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(crate) struct Nickname(tor_netdoc::types::Nickname);

impl TryFrom<String> for Nickname {
    type Error = RelayConfigError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Ok(Self(
            s.parse().map_err(|_| RelayConfigError::InvalidNickname)?,
        ))
    }
}

impl From<Nickname> for String {
    fn from(nickname: Nickname) -> String {
        nickname.0.to_string()
    }
}

impl From<&Nickname> for tor_netdoc::types::Nickname {
    fn from(nickname: &Nickname) -> Self {
        nickname.0.clone()
    }
}

/// The contact information of a relay set by an operator in the configuration.
///
/// This is free form text with the restriction that it must be a single line and must
/// not start with whitespace.
///
/// This wraps tor-netdoc's contact info type so we can easily deleguate validation to
/// that internal type. It prevents us from duplicating the validation rules but still
/// keeping a wrapper to avoid exposing the tor-netdoc's internals.
#[derive(Clone, Debug, Eq, PartialEq, derive_more::Display, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub(crate) struct Contact(tor_netdoc::types::ContactInfo);

impl TryFrom<String> for Contact {
    type Error = RelayConfigError;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        Ok(Self(
            s.parse().map_err(|_| RelayConfigError::InvalidContact)?,
        ))
    }
}

impl From<Contact> for String {
    fn from(contact: Contact) -> String {
        contact.0.to_string()
    }
}

impl From<&Contact> for tor_netdoc::types::ContactInfo {
    fn from(contact: &Contact) -> Self {
        contact.0.clone()
    }
}

/// Return the default relay nickname. Again, taken from C-tor.
pub(crate) fn default_nickname() -> Nickname {
    Nickname("Unnamed".parse().expect("Default nickname is invalid"))
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_time_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    #![allow(clippy::string_slice)] // See arti#2571
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->

    use super::*;

    #[test]
    fn contact_valid() {
        for info in [
            "Arti relay team",
            "8096R/DEADBEEF Bob Burger<bob@burger.com>",
            "trailing whitespace is fine  ",
            "Du français avec accent ééé c'est OK",
        ] {
            let contact = Contact::try_from(info.to_string()).unwrap();
            assert_eq!(contact.to_string(), info);
        }
    }

    #[test]
    fn contact_invalid() {
        for info in [
            " leading whitespace", // No leading whitespace
            "\tleading tab",       // Same but tab
            "two\nlines",          // No new line
            "trailing newline\n",  // Trailing new line
        ] {
            assert!(Contact::try_from(info.to_string()).is_err());
        }
    }

    #[test]
    fn nickname_valid() {
        // Some basic names that are all valid.
        for name in ["Unnamed", "a", "42", "Op3nB0rd3rs", "A".repeat(19).as_str()] {
            let nickname = Nickname::try_from(name.to_string()).unwrap();
            assert_eq!(nickname.to_string(), name);
        }
    }

    #[test]
    fn nickname_invalid() {
        for name in [
            "",                      // Too short
            "A".repeat(20).as_str(), // Too long
            "with space",            // Common Windows non alphanumeric
            "under_score",           // Common non alphanumeric
            "dash-ing",              // Common non alphanumeric
            "unicödé",               // The French... :P
        ] {
            assert!(Nickname::try_from(name.to_string()).is_err());
        }
    }
}
