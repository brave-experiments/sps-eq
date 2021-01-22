use std::fmt;
use std::fmt::Display;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum SpsEqSignatureError {
    UnmatchedCapacity,
    InvalidSignature,
}

impl Display for SpsEqSignatureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            SpsEqSignatureError::UnmatchedCapacity
            => write!(f, "The capacities do not match"),
            SpsEqSignatureError::InvalidSignature
            => write!(f, "Invalid signature"),
        }
    }
}