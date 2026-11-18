//! Authentication, role-based authorization, API tokens and audit logging.
//!
//! Passwords and API tokens are stored as Argon2id PHC strings. Session tokens
//! are random 256-bit values kept in memory and expire automatically.

use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const SESSION_SECONDS: u64 = 8 * 60 * 60;
const MAX_FAILURES: u32 = 5;
const LOCK_SECONDS: u64 = 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    SuperAdmin,
    FirewallAdmin,
    NetworkEngineer,
    SecurityAnalyst,
    Auditor,
}

impl Role {
    pub fn parse(value: &str) -> Option<Role> {
        match value {
            "super_admin" | "super-admin" | "superadmin" => Some(Role::SuperAdmin),
            "firewall_admin" | "firewall-admin" => Some(Role::FirewallAdmin),
            "network_engineer" | "network-engineer" => Some(Role::NetworkEngineer),
            "security_analyst" | "security-analyst" => Some(Role::SecurityAnalyst),
            "auditor" | "read_only" | "read-only" => Some(Role::Auditor),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Role::SuperAdmin => "super_admin",
            Role::FirewallAdmin => "firewall_admin",
            Role::NetworkEngineer => "network_engineer",
            Role::SecurityAnalyst => "security_analyst",
            Role::Auditor => "auditor",
        }
    }

    pub fn can_write(self) -> bool {
        matches!(
            self,
            Role::SuperAdmin | Role::FirewallAdmin | Role::NetworkEngineer
        )
    }

    pub fn can_admin(self) -> bool {
        self == Role::SuperAdmin
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApiToken {
    pub id: String,
    pub name: String,
    pub hash: String,
    pub role: Role,
    pub created: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Admin {
    pub username: String,
    pub password_hash: String,
    pub role: Role,
    pub enabled: bool,
    pub created: u64,
    #[serde(default)]
    pub api_tokens: Vec<ApiToken>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Store {
    admins: Vec<Admin>,
}

#[derive(Clone, Debug)]
pub struct Session {
    pub username: String,
    pub role: Role,
    pub expires: Instant,
    /// Per-session token used to defend cookie-authenticated writes from CSRF.
    pub csrf: String,
}

#[derive(Default)]
struct Attempt {
    failures: u32,
    last: Option<Instant>,
    locked_until: Option<Instant>,
}

pub struct Auth {
    path: PathBuf,
    audit_path: PathBuf,
    store: Mutex<Store>,
    sessions: Mutex<HashMap<String, Session>>,
    attempts: Mutex<HashMap<String, Attempt>>,
    pub bootstrap_path: Option<PathBuf>,
}

pub struct Bootstrap {
    pub username: String,
    pub password: String,
    pub path: PathBuf,
}

impl Auth {
    /// Load the admin store, creating a bootstrap administrator if none exists.
    /// An initial password can be supplied with VELA_ADMIN_PASSWORD; otherwise
    /// a random password is written to a mode-0600 file beside the store.
    pub fn load(config_path: &Path) -> Result<(Auth, Option<Bootstrap>), String> {
        let path = config_path.with_extension("auth.json");
        let audit_path = config_path.with_extension("audit.log");
        let mut bootstrap = None;
        let store = if path.exists() {
            let bytes = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
            serde_json::from_slice::<Store>(&bytes)
                .map_err(|e| format!("parse {}: {e}", path.display()))?
        } else {
            let password = std::env::var("VELA_ADMIN_PASSWORD").ok().filter(|p| p.len() >= 8);
            let password = match password {
                Some(p) => p,
                None => random_hex(18),
            };
            let username = std::env::var("VELA_ADMIN_USER")
                .ok()
                .filter(|u| !u.trim().is_empty())
                .unwrap_or_else(|| "admin".to_string());
            let admin = Admin {
                username: username.clone(),
                password_hash: hash_secret(&password)?,
                role: Role::SuperAdmin,
                enabled: true,
                created: now(),
                api_tokens: Vec::new(),
            };
            let store = Store {
                admins: vec![admin],
            };
            write_private_json(&path, &store)?;
            if std::env::var("VELA_ADMIN_PASSWORD").is_err() {
                let bootstrap_path = config_path.with_extension("bootstrap-password");
                write_private(&bootstrap_path, &password)?;
                bootstrap = Some(Bootstrap {
                    username,
                    password,
                    path: bootstrap_path,
                });
            }
            store
        };
        Ok((
            Auth {
                path,
                audit_path,
                store: Mutex::new(store),
                sessions: Mutex::new(HashMap::new()),
                attempts: Mutex::new(HashMap::new()),
                bootstrap_path: bootstrap.as_ref().map(|b| b.path.clone()),
            },
            bootstrap,
        ))
    }

    pub fn login(&self, username: &str, password: &str) -> Result<(String, Session), String> {
        self.check_throttle(username)?;
        let hash = {
            let store = self.store.lock().unwrap();
            store
                .admins
                .iter()
                .find(|a| a.username == username)
                .filter(|a| a.enabled)
                .map(|a| (a.password_hash.clone(), a.role))
        };
        let Some((hash, role)) = hash else {
            self.record_failure(username);
            return Err("invalid credentials".to_string());
        };
        if verify_secret(&hash, password).is_err() {
            self.record_failure(username);
            return Err("invalid credentials".to_string());
        }
        self.clear_failures(username);
        let token = random_hex(32);
        let session = Session {
            username: username.to_string(),
            role,
            expires: Instant::now() + Duration::from_secs(SESSION_SECONDS),
            csrf: random_hex(24),
        };
        self.sessions
            .lock()
            .unwrap()
            .insert(token.clone(), session.clone());
        self.audit(username, "login", "password session created");
        Ok((token, session))
    }

    pub fn logout(&self, token: &str) {
        let removed = self.sessions.lock().unwrap().remove(token);
        if let Some(session) = removed {
            self.audit(&session.username, "logout", "session closed");
        }
    }

    pub fn session(&self, token: &str) -> Option<Session> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions.get(token)?.clone();
        if session.expires <= Instant::now() {
            sessions.remove(token);
            return None;
        }
        Some(session)
    }

    pub fn authenticate_api_token(&self, token: &str) -> Option<Session> {
        let store = self.store.lock().unwrap();
        for admin in store.admins.iter().filter(|a| a.enabled) {
            for stored in &admin.api_tokens {
                if verify_secret(&stored.hash, token).is_ok() {
                    return Some(Session {
                        username: admin.username.clone(),
                        role: stored.role,
                        expires: Instant::now() + Duration::from_secs(SESSION_SECONDS),
                        csrf: String::new(),
                    });
                }
            }
        }
        None
    }

    pub fn create_api_token(
        &self,
        actor: &Session,
        username: &str,
        name: &str,
        role: Role,
    ) -> Result<String, String> {
        if !actor.role.can_admin() {
            return Err("super administrator role required".to_string());
        }
        let plain = format!("vela_{}", random_hex(32));
        let hash = hash_secret(&plain)?;
        let mut store = self.store.lock().unwrap();
        let admin = store
            .admins
            .iter_mut()
            .find(|a| a.username == username)
            .ok_or_else(|| format!("unknown administrator '{username}'"))?;
        admin.api_tokens.push(ApiToken {
            id: random_hex(8),
            name: name.to_string(),
            hash,
            role,
            created: now(),
        });
        write_private_json(&self.path, &*store)?;
        drop(store);
        self.audit(actor.username.as_str(), "token.create", username);
        Ok(plain)
    }

    pub fn add_admin(
        &self,
        actor: &Session,
        username: &str,
        password: &str,
        role: Role,
    ) -> Result<(), String> {
        if !actor.role.can_admin() {
            return Err("super administrator role required".to_string());
        }
        if username.trim().is_empty() {
            return Err("username cannot be empty".to_string());
        }
        if password.len() < 8 {
            return Err("password must be at least 8 characters".to_string());
        }
        let mut store = self.store.lock().unwrap();
        if store.admins.iter().any(|a| a.username == username) {
            return Err(format!("administrator '{username}' already exists"));
        }
        store.admins.push(Admin {
            username: username.to_string(),
            password_hash: hash_secret(password)?,
            role,
            enabled: true,
            created: now(),
            api_tokens: Vec::new(),
        });
        write_private_json(&self.path, &*store)?;
        drop(store);
        self.audit(actor.username.as_str(), "admin.create", username);
        Ok(())
    }

    pub fn delete_admin(&self, actor: &Session, username: &str) -> Result<(), String> {
        if !actor.role.can_admin() {
            return Err("super administrator role required".to_string());
        }
        if actor.username == username {
            return Err("refusing to delete the active administrator".to_string());
        }
        let mut store = self.store.lock().unwrap();
        let before = store.admins.len();
        store.admins.retain(|a| a.username != username);
        if store.admins.len() == before {
            return Err(format!("unknown administrator '{username}'"));
        }
        if !store.admins.iter().any(|a| a.role.can_admin() && a.enabled) {
            return Err("at least one enabled super administrator is required".to_string());
        }
        write_private_json(&self.path, &*store)?;
        drop(store);
        self.audit(actor.username.as_str(), "admin.delete", username);
        Ok(())
    }

    pub fn change_password(
        &self,
        actor: &Session,
        username: &str,
        current: Option<&str>,
        new_password: &str,
    ) -> Result<(), String> {
        if new_password.len() < 8 {
            return Err("password must be at least 8 characters".to_string());
        }
        if actor.username != username && !actor.role.can_admin() {
            return Err("super administrator role required".to_string());
        }
        let mut store = self.store.lock().unwrap();
        let admin = store
            .admins
            .iter_mut()
            .find(|a| a.username == username)
            .ok_or_else(|| format!("unknown administrator '{username}'"))?;
        if actor.username == username {
            let current = current.ok_or_else(|| "current password is required".to_string())?;
            verify_secret(&admin.password_hash, current)?;
        }
        admin.password_hash = hash_secret(new_password)?;
        // Password changes invalidate existing sessions for that administrator.
        self.sessions
            .lock()
            .unwrap()
            .retain(|_, session| session.username != username);
        write_private_json(&self.path, &*store)?;
        drop(store);
        self.audit(actor.username.as_str(), "admin.password", username);
        Ok(())
    }

    pub fn list_tokens(
        &self,
        actor: &Session,
        username: &str,
    ) -> Result<Vec<TokenView>, String> {
        if actor.username != username && !actor.role.can_admin() {
            return Err("super administrator role required".to_string());
        }
        let store = self.store.lock().unwrap();
        let admin = store
            .admins
            .iter()
            .find(|a| a.username == username)
            .ok_or_else(|| format!("unknown administrator '{username}'"))?;
        Ok(admin
            .api_tokens
            .iter()
            .map(|t| TokenView {
                id: t.id.clone(),
                name: t.name.clone(),
                role: t.role,
                created: t.created,
            })
            .collect())
    }

    pub fn revoke_token(
        &self,
        actor: &Session,
        username: &str,
        token_id: &str,
    ) -> Result<(), String> {
        if actor.username != username && !actor.role.can_admin() {
            return Err("super administrator role required".to_string());
        }
        let mut store = self.store.lock().unwrap();
        let admin = store
            .admins
            .iter_mut()
            .find(|a| a.username == username)
            .ok_or_else(|| format!("unknown administrator '{username}'"))?;
        let before = admin.api_tokens.len();
        admin.api_tokens.retain(|t| t.id != token_id);
        if before == admin.api_tokens.len() {
            return Err(format!("unknown token '{token_id}'"));
        }
        write_private_json(&self.path, &*store)?;
        drop(store);
        self.audit(actor.username.as_str(), "token.revoke", token_id);
        Ok(())
    }

    pub fn list_admins(&self, actor: &Session) -> Result<Vec<AdminView>, String> {
        if !actor.role.can_admin() {
            return Err("super administrator role required".to_string());
        }
        let store = self.store.lock().unwrap();
        Ok(store
            .admins
            .iter()
            .map(|a| AdminView {
                username: a.username.clone(),
                role: a.role,
                enabled: a.enabled,
                created: a.created,
                token_count: a.api_tokens.len(),
            })
            .collect())
    }

    pub fn audit(&self, actor: &str, action: &str, detail: &str) {
        let record = serde_json::json!({
            "ts": now(),
            "actor": actor,
            "action": action,
            "detail": detail,
        });
        if let Ok(mut file) = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&self.audit_path)
        {
            let _ = writeln!(file, "{record}");
        }
    }

    pub fn audit_records(&self, actor: &Session, limit: usize) -> Vec<serde_json::Value> {
        if !actor.role.can_admin() {
            return Vec::new();
        }
        let text = fs::read_to_string(&self.audit_path).unwrap_or_default();
        let mut rows: Vec<_> = text
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .collect();
        if rows.len() > limit {
            rows.drain(0..rows.len() - limit);
        }
        rows
    }

    fn check_throttle(&self, username: &str) -> Result<(), String> {
        let mut attempts = self.attempts.lock().unwrap();
        let attempt = attempts.entry(username.to_string()).or_default();
        if let Some(until) = attempt.locked_until {
            if until > Instant::now() {
                return Err("too many failed attempts; try again later".to_string());
            }
            attempt.locked_until = None;
            attempt.failures = 0;
        }
        Ok(())
    }

    fn record_failure(&self, username: &str) {
        let mut attempts = self.attempts.lock().unwrap();
        let attempt = attempts.entry(username.to_string()).or_default();
        if attempt
            .last
            .map(|last| last.elapsed() > Duration::from_secs(LOCK_SECONDS * 5))
            .unwrap_or(true)
        {
            attempt.failures = 0;
        }
        attempt.failures += 1;
        attempt.last = Some(Instant::now());
        if attempt.failures >= MAX_FAILURES {
            attempt.locked_until = Some(Instant::now() + Duration::from_secs(LOCK_SECONDS));
        }
    }

    fn clear_failures(&self, username: &str) {
        self.attempts.lock().unwrap().remove(username);
    }
}

#[derive(Serialize)]
pub struct TokenView {
    pub id: String,
    pub name: String,
    pub role: Role,
    pub created: u64,
}

#[derive(Serialize)]
pub struct AdminView {
    pub username: String,
    pub role: Role,
    pub enabled: bool,
    pub created: u64,
    pub token_count: usize,
}

pub fn hash_secret(secret: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(secret.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| format!("password hash: {e}"))
}

pub fn verify_secret(hash: &str, secret: &str) -> Result<(), String> {
    let parsed = PasswordHash::new(hash).map_err(|e| format!("stored hash: {e}"))?;
    Argon2::default()
        .verify_password(secret.as_bytes(), &parsed)
        .map_err(|_| "invalid credentials".to_string())
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    let mut out = String::with_capacity(bytes * 2);
    for b in buf {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn write_private(path: &Path, text: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    }
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    fs::write(&tmp, text).map_err(|e| format!("write {}: {e}", tmp.display()))?;
    fs::set_permissions(&tmp, std::os::unix::fs::PermissionsExt::from_mode(0o600))
        .map_err(|e| format!("chmod {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("rename {}: {e}", path.display()))
}

fn write_private_json(path: &Path, store: &Store) -> Result<(), String> {
    let text = serde_json::to_string_pretty(store).map_err(|e| format!("serialize admins: {e}"))?;
    write_private(path, &text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn hashes_and_verifies_passwords() {
        let hash = hash_secret("correct horse battery staple").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_secret(&hash, "correct horse battery staple").is_ok());
        assert!(verify_secret(&hash, "wrong password").is_err());
    }

    #[test]
    fn role_permissions_are_explicit() {
        assert!(Role::SuperAdmin.can_admin());
        assert!(Role::FirewallAdmin.can_write());
        assert!(!Role::NetworkEngineer.can_admin());
        assert!(!Role::SecurityAnalyst.can_write());
        assert!(!Role::Auditor.can_write());
        assert_eq!(Role::parse("super-admin"), Some(Role::SuperAdmin));
    }

    #[test]
    fn rejects_bad_credentials_and_unknown_admins() {
        let dir = std::env::temp_dir().join(format!("vela-auth-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("firewall.conf");
        fs::write(&path, "system hostname test\n").unwrap();
        let (auth, boot) = Auth::load(&path).unwrap();
        let boot = boot.unwrap();
        assert!(auth.login(&boot.username, "not-the-password").is_err());
        let (token, session) = auth.login(&boot.username, &boot.password).unwrap();
        assert_eq!(session.role, Role::SuperAdmin);
        assert!(auth.session(&token).is_some());
        auth.logout(&token);
        assert!(auth.session(&token).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn bootstrap_password_is_private() {
        let dir = std::env::temp_dir().join(format!("vela-auth-mode-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("firewall.conf");
        fs::write(&path, "system hostname test\n").unwrap();
        let (_auth, boot) = Auth::load(&path).unwrap();
        let boot = boot.unwrap();
        let mode = fs::metadata(&boot.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }
}
