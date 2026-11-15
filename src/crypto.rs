use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::Argon2;
use rand::RngCore;
use std::error::Error;

const NONCE_SIZE: usize = 12;

/// Deriva una clave de 32 bytes desde una contraseña usando Argon2id
/// Parámetros OWASP 2023: 64MB memoria, 3 iteraciones, 4 hilos
pub fn derive_key(password: &str) -> [u8; 32] {
    // Salt fijo para demo (en producción debería ser único por vault)
    let salt = b"vault-cli-salt-v2-argon2";

    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(65536, 3, 4, Some(32)).expect("Params invalid"),
    );

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("Argon2 hashing failed");

    key
}

/// Cifra datos plaintext usando AES-256-GCM
pub fn encrypt(plaintext: &[u8], password: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let key = derive_key(password);
    let cipher = Aes256Gcm::new_from_slice(&key)?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext)?;

    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Descifra datos cifrados con encrypt()
pub fn decrypt(ciphertext_with_nonce: &[u8], password: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if ciphertext_with_nonce.len() < NONCE_SIZE {
        return Err("Datos cifrados demasiado cortos".into());
    }

    let key = derive_key(password);
    let cipher = Aes256Gcm::new_from_slice(&key)?;

    let (nonce_bytes, ct) = ciphertext_with_nonce.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ct)?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = "mi-clave-maestra";
        let data = b"Hola mundo secreto";

        let encrypted = encrypt(data, password).unwrap();
        let decrypted = decrypt(&encrypted, password).unwrap();

        assert_eq!(data.to_vec(), decrypted);
    }

    #[test]
    fn test_wrong_password_fails() {
        let data = b"datos sensibles";
        let encrypted = encrypt(data, "clave-correcta").unwrap();

        let result = decrypt(&encrypted, "clave-incorrecta");
        assert!(result.is_err());
    }

    #[test]
    fn test_derive_key_deterministic() {
        let key1 = derive_key("test-password");
        let key2 = derive_key("test-password");
        assert_eq!(key1, key2);
    }
}