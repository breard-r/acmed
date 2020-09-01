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
mod error;
mod order;

pub use account::{
    Account, AccountDeactivation, AccountKeyRollover, AccountResponse, AccountUpdate,
};
pub use authorization::{Authorization, AuthorizationStatus, Challenge};
pub use deserialize_from_str;
pub use directory::Directory;
pub use error::{AcmeError, ApiError, HttpApiError};
pub use order::{Identifier, NewOrder, Order, OrderStatus};
