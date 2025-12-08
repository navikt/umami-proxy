use std::fmt::{self, Display, Formatter};

use strum::{EnumString, IntoStaticStr};

#[derive(Debug, PartialEq, Eq, EnumString, IntoStaticStr)]
pub enum UmamiProxyError {
	RequestContainsInvalidJson,
	JsonCoParseError,
	NoMatchingPeer,
	// This one matches the pingora::Error::Custom(string) exactly
	PrematureBodyEnd,
	FieldTooLong,
}

impl Display for UmamiProxyError {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		write!(f, "{self:?}")
	}
}
#[derive(Debug, PartialEq, Eq, IntoStaticStr)]
pub enum ErrorDescription {
	SslError,
	ConnectionError,
	UpstreamConnectionFailure,
	UntrackedError,
	ClientDisconnectedError,
	UmamiProxyError(UmamiProxyError),
}
impl ErrorDescription {
	pub fn as_str(&self) -> &str {
		match self {
			Self::UmamiProxyError(e) => e.into(),
			_ => self.into(),
		}
	}
}
impl Display for ErrorDescription {
	fn fmt(&self, f: &mut Formatter) -> fmt::Result {
		write!(f, "{self:?}")
	}
}

impl From<UmamiProxyError> for ErrorDescription {
	fn from(error: UmamiProxyError) -> Self {
		Self::UmamiProxyError(error)
	}
}
