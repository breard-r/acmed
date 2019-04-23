#[macro_export]
macro_rules! deserialize_from_str {
    ($t: ty) => {
        impl FromStr for $t {
            type Err = Error;

            fn from_str(data: &str) -> Result<Self, Self::Err> {
                let res = serde_json::from_str(data)?;
                Ok(res)
            }
        }
    };
}

mod account;
mod authorization;
mod directory;
mod order;

pub use account::{Account, AccountDeactivation, AccountResponse, AccountUpdate};
pub use authorization::{Authorization, AuthorizationStatus, Challenge};
pub use directory::Directory;
pub use order::{Identifier, IdentifierType, NewOrder, Order, OrderStatus};
