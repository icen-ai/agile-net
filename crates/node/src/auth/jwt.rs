//! JWT authentication (Access + Refresh dual tokens)
//!
//! Security notes:
//! - HS256 secret generated at first node startup and persisted in node_config (never hardcoded)
//! - access_token: 15min; refresh_token: 7d (admin only — delegated consumers authenticate
//!   the data plane with their token directly, no control-plane session)
//! - refresh_token jti hash stored in DB, supports revocation and rotation

use crate::db::{Database, generate_secret_hex, sha256_hex};
use agile_net_core::error::{Error, Result};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

/// admin access token TTL (seconds)
pub const ADMIN_ACCESS_TTL: i64 = 15 * 60;
/// admin refresh token TTL (seconds)
pub const ADMIN_REFRESH_TTL: i64 = 7 * 24 * 3600;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub username: String,
    pub role: String,
    pub exp: usize,
    pub iat: usize,
    pub jti: String,
    /// "access" | "refresh"
    pub typ: String,
    /// Control-plane scope tier: ro (read-only) / rules (read + rule write) / full. Existing tokens default to full.
    #[serde(default = "default_scope")]
    pub scope: String,
}

fn default_scope() -> String {
    "full".into()
}

/// Token set issued on login/refresh
pub struct IssuedTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
}

/// JWT service: secret loaded from the database (generated if absent).
pub struct JwtService {
    secret: String,
    db: Database,
}

impl JwtService {
    /// Load the secret from the database, or generate and persist one.
    pub fn load_or_create(db: Database) -> Result<Self> {
        let secret = match db.get_config("jwt_secret")? {
            Some(s) if !s.is_empty() => s,
            _ => {
                let s = generate_secret_hex();
                db.set_config("jwt_secret", &s)?;
                s
            }
        };
        Ok(Self { secret, db })
    }

    /// Issue access + refresh; scope defaults to full.
    pub fn issue(&self, subject: &str, username: &str, role: &str) -> Result<IssuedTokens> {
        self.issue_with_scope(subject, username, role, "full")
    }

    /// Issue access + refresh with an explicit control-plane scope tier.
    pub fn issue_with_scope(
        &self,
        subject: &str,
        username: &str,
        role: &str,
        scope: &str,
    ) -> Result<IssuedTokens> {
        let (access_ttl, refresh_ttl) = (ADMIN_ACCESS_TTL, ADMIN_REFRESH_TTL);

        let access_token = self.sign(subject, username, role, "access", access_ttl, scope)?;
        let (refresh_token, jti) =
            self.sign_refresh(subject, username, role, refresh_ttl, scope)?;

        // persist refresh jti hash (revocable)
        let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(refresh_ttl))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        self.db
            .store_refresh_token(&sha256_hex(jti.as_bytes()), subject, role, &expires_at)?;

        Ok(IssuedTokens {
            access_token,
            refresh_token,
            expires_in: access_ttl,
        })
    }

    /// Exchange a refresh_token for a new access_token (rotating the refresh_token itself).
    pub fn refresh(&self, refresh_token: &str) -> Result<(Claims, IssuedTokens)> {
        let claims = self.verify(refresh_token)?;
        if claims.typ != "refresh" {
            return Err(Error::Auth("not a refresh token".into()));
        }
        let jti_hash = sha256_hex(claims.jti.as_bytes());
        if !self.db.is_refresh_token_valid(&jti_hash)? {
            return Err(Error::Auth("refresh token revoked or expired".into()));
        }
        // rotate: revoke the old jti (scope carries over with the session)
        self.db.revoke_refresh_token(&jti_hash)?;
        let issued =
            self.issue_with_scope(&claims.sub, &claims.username, &claims.role, &claims.scope)?;
        Ok((claims, issued))
    }

    /// Revoke a refresh_token (logout).
    pub fn revoke(&self, refresh_token: &str) -> Result<()> {
        if let Ok(claims) = self.verify(refresh_token) {
            self.db
                .revoke_refresh_token(&sha256_hex(claims.jti.as_bytes()))?;
        }
        Ok(())
    }

    /// Revoke all refresh tokens of a subject.
    pub fn revoke_all(&self, subject: &str) -> Result<()> {
        self.db.revoke_all_refresh_tokens(subject)
    }

    /// Verify a token and return its Claims.
    pub fn verify(&self, token: &str) -> Result<Claims> {
        let mut validation = Validation::default();
        validation.validate_exp = true;
        let data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.secret.as_bytes()),
            &validation,
        )
        .map_err(|e| Error::Auth(e.to_string()))?;
        Ok(data.claims)
    }

    fn sign(
        &self,
        subject: &str,
        username: &str,
        role: &str,
        typ: &str,
        ttl: i64,
        scope: &str,
    ) -> Result<String> {
        let now = chrono::Utc::now();
        let claims = Claims {
            sub: subject.to_string(),
            username: username.to_string(),
            role: role.to_string(),
            exp: (now.timestamp() + ttl) as usize,
            iat: now.timestamp() as usize,
            jti: uuid::Uuid::new_v4().to_string(),
            typ: typ.to_string(),
            scope: scope.to_string(),
        };
        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
        .map_err(|e| Error::Auth(e.to_string()))
    }

    fn sign_refresh(
        &self,
        subject: &str,
        username: &str,
        role: &str,
        ttl: i64,
        scope: &str,
    ) -> Result<(String, String)> {
        let now = chrono::Utc::now();
        let jti = uuid::Uuid::new_v4().to_string();
        let claims = Claims {
            sub: subject.to_string(),
            username: username.to_string(),
            role: role.to_string(),
            exp: (now.timestamp() + ttl) as usize,
            iat: now.timestamp() as usize,
            jti: jti.clone(),
            typ: "refresh".to_string(),
            scope: scope.to_string(),
        };
        let token = encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.secret.as_bytes()),
        )
        .map_err(|e| Error::Auth(e.to_string()))?;
        Ok((token, jti))
    }
}
