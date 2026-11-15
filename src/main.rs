mod crypto;

use clap::{Parser, Subcommand};
use directories::ProjectDirs;
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::PathBuf;

// ─── Estructuras de datos ───────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Credential {
    pub service: String,
    pub username: String,
    pub password: String,
    pub notes: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct Vault {
    pub entries: HashMap<String, Credential>,
}

impl Vault {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    pub fn add(&mut self, key: String, credential: Credential) {
        self.entries.insert(key, credential);
    }

    pub fn get(&self, key: &str) -> Option<&Credential> {
        self.entries.get(key)
    }

    pub fn search(&self, query: &str) -> Vec<(&String, &Credential)> {
        self.entries
            .iter()
            .filter(|(key, _)| key.to_lowercase().contains(&query.to_lowercase()))
            .collect()
    }

    pub fn list(&self) -> Vec<&String> {
        self.entries.keys().collect()
    }
}

// ─── CLI con Clap ───────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "vault-cli", about = "Gestor de contraseñas local cifrado")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Inicializar un nuevo vault (crea archivo cifrado)
    Init,
    /// Añadir una credencial
    Add {
        /// Clave única para la credencial (ej: github, gmail)
        key: String,
        /// Nombre del servicio
        #[arg(long)]
        service: String,
        /// Nombre de usuario
        #[arg(long)]
        username: String,
        /// Notas opcionales
        #[arg(long)]
        notes: Option<String>,
    },
    /// Obtener una credencial por clave
    Get {
        /// Clave de la credencial
        key: String,
    },
    /// Buscar credenciales
    Search {
        /// Término de búsqueda
        query: String,
    },
    /// Listar todas las claves almacenadas
    List,
    /// Eliminar una credencial por clave
    Delete {
        /// Clave de la credencial a eliminar
        key: String,
    },
}

// ─── Funciones auxiliares ───────────────────────────────────────────────

fn prompt_confirm(message: &str) -> bool {
    print!("{} [s/N]: ", message);
    io::stdout().flush().expect("Error flushing stdout");

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Error leyendo input");

    let trimmed = input.trim().to_lowercase();
    matches!(trimmed.as_str(), "s" | "si" | "y" | "yes")
}

// ─── Funciones de persistencia ──────────────────────────────────────────

fn vault_path() -> PathBuf {
    let proj_dirs = ProjectDirs::from("com", "vault-cli", "vault")
        .expect("No se pudo determinar directorio de proyecto");
    proj_dirs.data_dir().join("vault.dat")
}

fn load_vault(password: &str) -> Result<Vault, Box<dyn std::error::Error>> {
    let path = vault_path();
    if !path.exists() {
        return Err("Vault no existe. Ejecuta 'vault-cli init' primero.".into());
    }
    let encrypted = fs::read(&path)?;
    let decrypted = crypto::decrypt(&encrypted, password)?;
    let vault: Vault = bincode::deserialize(&decrypted)?;
    Ok(vault)
}

fn save_vault(vault: &Vault, password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = vault_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let serialized = bincode::serialize(vault)?;
    let encrypted = crypto::encrypt(&serialized, password)?;
    fs::write(&path, encrypted)?;
    Ok(())
}

fn prompt_master_password() -> String {
    prompt_password("🔑 Contraseña maestra: ").expect("Error leyendo contraseña")
}

// ─── Main ───────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Init => {
            println!("🏗️  Inicializando nuevo vault...");
            let password = prompt_master_password();
            let vault = Vault::new();
            save_vault(&vault, &password).expect("Error guardando vault");
            println!("✅ Vault inicializado en: {:?}", vault_path());
        }

        Commands::Add {
            key,
            service,
            username,
            notes,
        } => {
            let password = prompt_master_password();
            let mut vault = load_vault(&password).expect("Error cargando vault");

            println!("🔐 Contraseña para '{}': ", service);
            let pwd = prompt_password("").expect("Error leyendo contraseña");

            let cred = Credential {
                service,
                username,
                password: pwd,
                notes,
            };

            vault.add(key.clone(), cred);
            save_vault(&vault, &password).expect("Error guardando vault");
            println!("✅ Credencial '{}' añadida", key);
        }

        Commands::Get { key } => {
            let password = prompt_master_password();
            let vault = load_vault(&password).expect("Error cargando vault");

            match vault.get(&key) {
                Some(cred) => {
                    println!("📋 Servicio : {}", cred.service);
                    println!("👤 Usuario  : {}", cred.username);
                    println!("🔑 Password : {}", cred.password);
                    if let Some(notes) = &cred.notes {
                        println!("📝 Notas   : {}", notes);
                    }
                }
                None => println!("❌ Credencial '{}' no encontrada", key),
            }
        }

        Commands::Search { query } => {
            let password = prompt_master_password();
            let vault = load_vault(&password).expect("Error cargando vault");

            let results = vault.search(&query);
            if results.is_empty() {
                println!("❌ No se encontraron resultados para '{}'", query);
            } else {
                println!("🔍 Resultados para '{}':", query);
                for (key, cred) in results {
                    println!("  - {} ({})", key, cred.service);
                }
            }
        }

        Commands::List => {
            let password = prompt_master_password();
            let vault = load_vault(&password).expect("Error cargando vault");

            let keys = vault.list();
            if keys.is_empty() {
                println!("📭 Vault vacío");
            } else {
                println!("📋 Credenciales almacenadas ({}):", keys.len());
                for key in keys {
                    println!("  - {}", key);
                }
            }
        }

        Commands::Delete { key } => {
            let password = prompt_master_password();
            let mut vault = load_vault(&password).expect("Error cargando vault");

            if vault.get(&key).is_none() {
                println!("❌ Credencial '{}' no encontrada", key);
                return;
            }

            if !prompt_confirm(&format!("¿Eliminar credencial '{}'?", key)) {
                println!("🚫 Operación cancelada");
                return;
            }

            vault.entries.remove(&key);
            save_vault(&vault, &password).expect("Error guardando vault");
            println!("✅ Credencial '{}' eliminada", key);
        }
    }
}