use acme_common::error::Error;
use std::fmt;
use std::str::FromStr;

fn clean_mailto(value: &str) -> Result<String, Error> {
    // TODO: implement a simple RFC 6068 parser
    //  - no "hfields"
    //  - max one "addr-spec" in the "to" component
    Ok(value.to_string())
}

// TODO: implement other URI shemes
// https://www.iana.org/assignments/uri-schemes/uri-schemes.xhtml
// https://en.wikipedia.org/wiki/List_of_URI_schemes
// Exemples:
//   - P1: tel, sms
//   - P2: geo, maps
//   - P3: irc, irc6, ircs, xmpp
//   - P4: sip, sips
#[derive(Clone, Debug, PartialEq)]
pub enum ContactType {
    Mailto,
}

impl ContactType {
    pub fn clean_value(&self, value: &str) -> Result<String, Error> {
        match self {
            ContactType::Mailto => clean_mailto(value),
        }
    }
}

impl FromStr for ContactType {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        match s.to_lowercase().as_str() {
            "mailto" => Ok(ContactType::Mailto),
            _ => Err(format!("{}: unknown contact type.", s).into()),
        }
    }
}

impl fmt::Display for ContactType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            ContactType::Mailto => "mailto",
        };
        write!(f, "{}", s)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AccountContact {
    pub contact_type: ContactType,
    pub value: String,
}

impl AccountContact {
    pub fn new(contact_type: &str, value: &str) -> Result<Self, Error> {
        let contact_type: ContactType = contact_type.parse()?;
        let value = contact_type.clean_value(value)?;
        Ok(AccountContact {
            contact_type,
            value,
        })
    }
}

impl fmt::Display for AccountContact {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.contact_type, self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_account_contact_eq() {
        let c1 = AccountContact::new("mailto", "derp.derpson@example.com").unwrap();
        let c2 = AccountContact::new("mailto", "derp.derpson@example.com").unwrap();
        let c3 = AccountContact::new("mailto", "derp@example.com").unwrap();
        assert_eq!(c1, c2);
        assert_eq!(c2, c1);
        assert_ne!(c1, c3);
        assert_ne!(c2, c3);
    }

    #[test]
    fn test_account_contact_in_vec() {
        let contacts = vec![
            AccountContact::new("mailto", "derp.derpson@example.com").unwrap(),
            AccountContact::new("mailto", "derp@example.com").unwrap(),
        ];
        let c = AccountContact::new("mailto", "derp@example.com").unwrap();
        assert!(contacts.contains(&c));
    }

    #[test]
    fn test_account_contact_not_in_vec() {
        let contacts = vec![
            AccountContact::new("mailto", "derp.derpson@example.com").unwrap(),
            AccountContact::new("mailto", "derp@example.com").unwrap(),
        ];
        let c = AccountContact::new("mailto", "derpina@example.com").unwrap();
        assert!(!contacts.contains(&c));
    }
}
