//! JWT 认证（Access + Refresh 双 Token）
//!
//! 安全要点：
//! - HS256 密钥在节点首次启动时生成并持久化到 node_config（绝不硬编码）
//! - access_token：admin 15min / client 1h
//! - refresh_token：admin 7d / client 30d，jti 哈希落库，支持吊销与轮换
//! - tunnel_token：仅 client，数据面认证用，随登录/刷新轮换

use crate::db::{Database, generate_secret_hex, generate_tunnel_token, sha256_hex};
use agile_net_core::error::{Error, Result};
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

/// admin access token 有效期（秒）
pub const ADMIN_ACCESS_TTL: i64 = 15 * 60;
/// client access token 有效期（秒）
pub const CLIENT_ACCESS_TTL: i64 = 60 * 60;
/// admin refresh token 有效期（秒）
pub const ADMIN_REFRESH_TTL: i64 = 7 * 24 * 3600;
/// client refresh token 有效期（秒）
pub const CLIENT_REFRESH_TTL: i64 = 30 * 24 * 3600;

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
    /// 管理面授权档位：ro（只读）/ rules（只读+规则写）/ full（全权）。既有 token 缺省 full。
    #[serde(default = "default_scope")]
    pub scope: String,
}

fn default_scope() -> String {
    "full".into()
}

/// 登录/刷新签发的令牌集合
pub struct IssuedTokens {
    pub access_token: String,
    pub refresh_token: String,
    /// 仅 client 角色
    pub tunnel_token: Option<String>,
    pub expires_in: i64,
}

/// JWT 服务：密钥从数据库装载（不存在则生成）。
pub struct JwtService {
    secret: String,
    db: Database,
}

impl JwtService {
    /// 从数据库装载或生成密钥
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

    /// 签发 access + refresh（client 同时轮换 tunnel_token），scope 默认 full。
    pub fn issue(&self, subject: &str, username: &str, role: &str) -> Result<IssuedTokens> {
        self.issue_with_scope(subject, username, role, "full")
    }

    /// 签发 access + refresh（指定管理面 scope 档位）。
    pub fn issue_with_scope(
        &self,
        subject: &str,
        username: &str,
        role: &str,
        scope: &str,
    ) -> Result<IssuedTokens> {
        let (access_ttl, refresh_ttl) = match role {
            "admin" => (ADMIN_ACCESS_TTL, ADMIN_REFRESH_TTL),
            _ => (CLIENT_ACCESS_TTL, CLIENT_REFRESH_TTL),
        };

        let access_token = self.sign(subject, username, role, "access", access_ttl, scope)?;
        let (refresh_token, jti) =
            self.sign_refresh(subject, username, role, refresh_ttl, scope)?;

        // refresh jti 哈希落库（可吊销）
        let expires_at = (chrono::Utc::now() + chrono::Duration::seconds(refresh_ttl))
            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
        self.db
            .store_refresh_token(&sha256_hex(jti.as_bytes()), subject, role, &expires_at)?;

        // client 角色：轮换 tunnel_token
        let tunnel_token = if role == "client" {
            let t = generate_tunnel_token();
            self.db
                .set_account_tunnel_token(subject, Some(&sha256_hex(t.as_bytes())))?;
            Some(t)
        } else {
            None
        };

        Ok(IssuedTokens {
            access_token,
            refresh_token,
            tunnel_token,
            expires_in: access_ttl,
        })
    }

    /// 用 refresh_token 换新 access_token（并轮换 refresh_token 本身）。
    pub fn refresh(&self, refresh_token: &str) -> Result<(Claims, IssuedTokens)> {
        let claims = self.verify(refresh_token)?;
        if claims.typ != "refresh" {
            return Err(Error::Auth("not a refresh token".into()));
        }
        let jti_hash = sha256_hex(claims.jti.as_bytes());
        if !self.db.is_refresh_token_valid(&jti_hash)? {
            return Err(Error::Auth("refresh token revoked or expired".into()));
        }
        // 轮换：吊销旧 jti（scope 随会话保留）
        self.db.revoke_refresh_token(&jti_hash)?;
        let issued =
            self.issue_with_scope(&claims.sub, &claims.username, &claims.role, &claims.scope)?;
        Ok((claims, issued))
    }

    /// 吊销 refresh_token（登出）。
    pub fn revoke(&self, refresh_token: &str) -> Result<()> {
        if let Ok(claims) = self.verify(refresh_token) {
            self.db
                .revoke_refresh_token(&sha256_hex(claims.jti.as_bytes()))?;
        }
        Ok(())
    }

    /// 吊销某主体全部 refresh token。
    pub fn revoke_all(&self, subject: &str) -> Result<()> {
        self.db.revoke_all_refresh_tokens(subject)
    }

    /// 验证 token 并返回 Claims。
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
