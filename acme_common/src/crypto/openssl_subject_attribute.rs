use openssl::nid::Nid;

pub type SubjectAttribute = super::BaseSubjectAttribute;

impl SubjectAttribute {
	pub fn get_nid(&self) -> Nid {
		match self {
			SubjectAttribute::CountryName => Nid::COUNTRYNAME,
			SubjectAttribute::GenerationQualifier => Nid::GENERATIONQUALIFIER,
			SubjectAttribute::GivenName => Nid::GIVENNAME,
			SubjectAttribute::Initials => Nid::INITIALS,
			SubjectAttribute::LocalityName => Nid::LOCALITYNAME,
			SubjectAttribute::Name => Nid::NAME,
			SubjectAttribute::OrganizationName => Nid::ORGANIZATIONNAME,
			SubjectAttribute::OrganizationalUnitName => Nid::ORGANIZATIONALUNITNAME,
			SubjectAttribute::Pkcs9EmailAddress => Nid::PKCS9_EMAILADDRESS,
			SubjectAttribute::PostalAddress => Nid::POSTALADDRESS,
			SubjectAttribute::PostalCode => Nid::POSTALCODE,
			SubjectAttribute::StateOrProvinceName => Nid::STATEORPROVINCENAME,
			SubjectAttribute::Street => Nid::STREETADDRESS,
			SubjectAttribute::Surname => Nid::SURNAME,
			SubjectAttribute::Title => Nid::TITLE,
		}
	}
}
