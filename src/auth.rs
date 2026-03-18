use anyhow::{anyhow, Result};
use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};

/// JWT claims expected from the identity provider
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — the user ID
    pub sub: String,
    /// Roles for ACL enforcement
    #[serde(default)]
    pub roles: Vec<String>,
    /// Expiry (standard claim, validated by jsonwebtoken)
    pub exp: usize,
}

/// Validates the Bearer token in the Authorization header.
///
/// Returns parsed claims on success, or an error that the filter converts
/// into a 401 response. The JWT secret should come from an env var or a
/// secrets manager (Vault, AWS SM, etc.) — never hardcode in production.
pub fn validate_jwt(auth_header: &str) -> Result<Claims> {
    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| anyhow!("Authorization header must use Bearer scheme"))?;

    let secret = std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "change-me-in-production".to_string());

    let mut validation = Validation::new(Algorithm::HS256);
    validation.validate_exp = true;

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|e| anyhow!("JWT validation failed: {e}"))?;

    Ok(token_data.claims)
}

/// Returns true if the user has at least one of the required roles.
pub fn has_role(user_roles: &[String], required: &[&str]) -> bool {
    required.iter().any(|r| user_roles.iter().any(|ur| ur == r))
}

/// Path-to-role ACL table.
///
/// In production, drive this from a database or config file and hot-reload
/// via a background task. The current approach is a simple static match
/// good enough for a DMZ with a known service surface.
pub fn required_roles_for_path(path: &str) -> Option<&'static [&'static str]> {
    if path.starts_with("/api/admin") {
        Some(&["admin"])
    } else if path.starts_with("/api/internal") {
        Some(&["service", "admin"])
    } else {
        // Public API paths — JWT still required, any role accepted
        None
    }
}
