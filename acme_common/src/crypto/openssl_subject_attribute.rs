use openssl::nid::Nid;

pub type SubjectAttribute = super::BaseSubjectAttribute;

impl SubjectAttribute {
    pub fn get_nid(&self) -> Nid {
        match self {
            SubjectAttribute::CountryName => Nid::COUNTRYNAME,
            SubjectAttribute::LocalityName => Nid::LOCALITYNAME,
            SubjectAttribute::StateOrProvinceName => Nid::STATEORPROVINCENAME,
            SubjectAttribute::StreetAddress => Nid::STREETADDRESS,
            SubjectAttribute::OrganizationName => Nid::ORGANIZATIONNAME,
            SubjectAttribute::OrganizationalUnitName => Nid::ORGANIZATIONALUNITNAME,
            SubjectAttribute::Name => Nid::NAME,
            SubjectAttribute::GivenName => Nid::GIVENNAME,
            SubjectAttribute::Initials => Nid::INITIALS,
            SubjectAttribute::Title => Nid::TITLE,
            SubjectAttribute::Surname => Nid::SURNAME,
            SubjectAttribute::Pseudonym => Nid::PSEUDONYM,
            SubjectAttribute::GenerationQualifier => Nid::GENERATIONQUALIFIER,
            SubjectAttribute::FriendlyName => Nid::FRIENDLYNAME,
        }
    }
}
