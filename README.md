# Vault CLI

Gestor de contraseñas local en terminal. Almacena credenciales en un único archivo cifrado con Argon2id + AES-256-GCM.

## Características

-   **Seguridad:** KDF Argon2id (OWASP 2023) + Cifrado autenticado AES-256-GCM
-   **Privacidad:** Sin nube, sin telemetría, archivo local cifrado
-   **CLI Completo:** Init, Add, Get, Search, List, Delete
-   **Ligero:** Binario <1MB optimizado para Windows

## Uso Rápido

```powershell
# Inicializar vault
vault-cli init

# Añadir credencial
vault-cli add github --service GitHub --username user --notes "Personal"

# Recuperar contraseña
vault-cli get github

# Buscar credenciales
vault-cli search git

# Eliminar credencial (con confirmación)
vault-cli delete github