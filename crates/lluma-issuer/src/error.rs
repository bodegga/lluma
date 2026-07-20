//! Typed `IssuerError` — the single error enum surfaced by the issuer service.
//!
//! Privacy invariant (leak L8, spec §7): no variant embeds plaintext, token,
//! blinded, account, or inner crypto `Display` bytes. Static messages only.
//! The `From<lluma_crypto::CryptoError>` impl maps every crypto failure to
//! `Internal` and discards the inner error's `Display` string entirely — a
//! blind-signature or encoding failure must never leak which subsystem or what
//! input shape was rejected.

/// All errors returned by the issuer service. Variants map 1:1 to HTTP status
/// codes and stable `code` strings rendered in error bodies (see Task 7's
/// `IntoResponse` impl).
#[derive(Debug, thiserror::Error)]
pub enum IssuerError {
    #[error("insufficient credits")]
    InsufficientCredits,
    #[error("unauthorized")]
    Unauthorized,
    #[error("token invalid")]
    TokenInvalid,
    #[error("double spend")]
    DoubleSpend,
    #[error("request id conflict")]
    RequestIdConflict,
    #[error("bad request")]
    BadRequest,
    #[error("internal error")]
    Internal,
}

impl IssuerError {
    /// Stable machine-readable code string rendered in error response bodies.
    /// Never interpolates request bytes — fixed strings only.
    pub fn code(&self) -> &'static str {
        match self {
            IssuerError::InsufficientCredits => "insufficient_credits",
            IssuerError::Unauthorized => "unauthorized",
            IssuerError::TokenInvalid => "token_invalid",
            IssuerError::DoubleSpend => "double_spend",
            IssuerError::RequestIdConflict => "request_id_conflict",
            IssuerError::BadRequest => "bad_request",
            IssuerError::Internal => "internal",
        }
    }

    /// HTTP status code for the variant (spec §7).
    pub fn status(&self) -> u16 {
        match self {
            IssuerError::InsufficientCredits => 402,
            IssuerError::Unauthorized => 403,
            IssuerError::TokenInvalid => 422,
            IssuerError::DoubleSpend => 409,
            IssuerError::RequestIdConflict => 409,
            IssuerError::BadRequest => 422,
            IssuerError::Internal => 500,
        }
    }
}

/// L8: every `CryptoError` collapses to `Internal`. The inner `Display` string
/// (which may interpolate blind/RSA failure detail) is dropped — never kept.
impl From<lluma_crypto::CryptoError> for IssuerError {
    fn from(_: lluma_crypto::CryptoError) -> Self {
        IssuerError::Internal
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insufficient_credits_maps_402() {
        assert_eq!(IssuerError::InsufficientCredits.status(), 402);
        assert_eq!(IssuerError::InsufficientCredits.code(), "insufficient_credits");
    }

    #[test]
    fn unauthorized_maps_403() {
        assert_eq!(IssuerError::Unauthorized.status(), 403);
        assert_eq!(IssuerError::Unauthorized.code(), "unauthorized");
    }

    #[test]
    fn token_invalid_maps_422() {
        assert_eq!(IssuerError::TokenInvalid.status(), 422);
        assert_eq!(IssuerError::TokenInvalid.code(), "token_invalid");
    }

    #[test]
    fn double_spend_maps_409() {
        assert_eq!(IssuerError::DoubleSpend.status(), 409);
        assert_eq!(IssuerError::DoubleSpend.code(), "double_spend");
    }

    #[test]
    fn request_id_conflict_maps_409() {
        assert_eq!(IssuerError::RequestIdConflict.status(), 409);
        assert_eq!(
            IssuerError::RequestIdConflict.code(),
            "request_id_conflict"
        );
    }

    #[test]
    fn bad_request_maps_422() {
        assert_eq!(IssuerError::BadRequest.status(), 422);
        assert_eq!(IssuerError::BadRequest.code(), "bad_request");
    }

    #[test]
    fn internal_maps_500() {
        assert_eq!(IssuerError::Internal.status(), 500);
        assert_eq!(IssuerError::Internal.code(), "internal");
    }

    #[test]
    fn crypto_error_collapses_to_internal() {
        // Any CryptoError variant must map to Internal — never preserve inner
        // Display (which could leak blind/RSA failure detail, leak L8).
        let crypto = lluma_crypto::CryptoError::TokenInvalid;
        let issuer: IssuerError = crypto.into();
        assert_eq!(issuer.code(), "internal");
        assert_eq!(issuer.status(), 500);
    }
}