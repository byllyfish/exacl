#[cfg(feature = "serde")]
mod format_serde;

#[cfg(not(feature = "serde"))]
mod format_no_serde;

#[cfg(feature = "serde")]
pub use format_serde::{read_enum, write_enum, Error};

#[cfg(not(feature = "serde"))]
pub use format_no_serde::{read_enum, write_enum, Error};
