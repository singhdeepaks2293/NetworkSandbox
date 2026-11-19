//! TLS for the management web interface.
//!
//! A self-signed certificate is generated on first use when no certificate is
//! configured. The private key is written with mode 0600. Production
//! deployments should replace the generated pair with a certificate from their
//! management PKI.

use crate::model::Settings;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::ServerConfig;
use std::fs::{self, OpenOptions};
use std::io::BufReader;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub fn server_config(
    config_path: Option<&Path>,
    settings: &Settings,
    hostname: &str,
) -> Result<Arc<ServerConfig>, String> {
    let (cert_path, key_path) = certificate_paths(config_path, settings)?;
    if !cert_path.exists() || !key_path.exists() {
        generate(&cert_path, &key_path, hostname)?;
    }
    let cert_bytes =
        fs::read(&cert_path).map_err(|e| format!("read {}: {e}", cert_path.display()))?;
    let key_bytes = fs::read(&key_path).map_err(|e| format!("read {}: {e}", key_path.display()))?;
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut BufReader::new(cert_bytes.as_slice()))
            .collect::<Result<_, _>>()
            .map_err(|e| format!("parse {}: {e}", cert_path.display()))?;
    if certs.is_empty() {
        return Err(format!("{} contains no certificates", cert_path.display()));
    }
    let key: PrivateKeyDer<'static> =
        rustls_pemfile::private_key(&mut BufReader::new(key_bytes.as_slice()))
            .map_err(|e| format!("parse {}: {e}", key_path.display()))?
            .ok_or_else(|| format!("{} contains no private key", key_path.display()))?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map(Arc::new)
        .map_err(|e| format!("TLS configuration: {e}"))
}

fn certificate_paths(
    config_path: Option<&Path>,
    settings: &Settings,
) -> Result<(PathBuf, PathBuf), String> {
    if let (Some(cert), Some(key)) = (&settings.tls_cert, &settings.tls_key) {
        return Ok((PathBuf::from(cert), PathBuf::from(key)));
    }
    if settings.tls_cert.is_some() || settings.tls_key.is_some() {
        return Err("system tls-cert and tls-key must be configured together".to_string());
    }
    let base = config_path
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("/etc/firewall/firewall.conf"));
    Ok((base.with_extension("crt"), base.with_extension("key")))
}

fn generate(cert_path: &Path, key_path: &Path, hostname: &str) -> Result<(), String> {
    let mut names = vec![
        hostname.to_string(),
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ];
    names.sort();
    names.dedup();
    let CertifiedKey { cert, key_pair } = generate_simple_self_signed(names)
        .map_err(|e| format!("generate management certificate: {e}"))?;
    for path in [cert_path, key_path] {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
        }
    }
    write_private(key_path, key_pair.serialize_pem().as_bytes())?;
    fs::write(cert_path, cert.pem()).map_err(|e| format!("write {}: {e}", cert_path.display()))?;
    println!(
        "tls: generated self-signed management certificate {} (replace it with a trusted certificate)",
        cert_path.display()
    );
    Ok(())
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("open {}: {e}", path.display()))?;
    use std::io::Write;
    file.write_all(bytes)
        .map_err(|e| format!("write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn generated_pair_loads() {
        let dir = std::env::temp_dir().join(format!("fw-tls-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let config = dir.join("firewall.conf");
        let settings = Settings::default();
        let cfg = server_config(Some(&config), &settings, "fw-test").unwrap();
        assert_eq!(cfg.alpn_protocols.len(), 0);
        assert!(dir.join("firewall.crt").exists());
        let mode = fs::metadata(dir.join("firewall.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }
}
