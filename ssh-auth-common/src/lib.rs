use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use nix::unistd::User;

pub const CONFIG_DIR: &str = "/etc/ssh/auth_cmd.d";
pub const DEFAULT_TIMEOUT: u64 = 30;
pub const SSHD_CONFIG_DEFAULT: &str = "/etc/ssh/sshd_config";

#[derive(Debug, Serialize, Deserialize)]
pub struct CommandConfig {
    pub name: String,
    pub command: String,
    pub args: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub timeout: Option<u64>,
    pub user: Option<String>,
    pub readonly: Option<bool>,
}

#[derive(Debug)]
pub enum AuthError {
    ConfigurationError(String),
    PermissionError(String),
    ExecutionError(String),
    TimeoutError(String),
    UserNotFound(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            AuthError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
            AuthError::PermissionError(msg) => write!(f, "Permission error: {}", msg),
            AuthError::ExecutionError(msg) => write!(f, "Execution error: {}", msg),
            AuthError::TimeoutError(msg) => write!(f, "Timeout error: {}", msg),
            AuthError::UserNotFound(msg) => write!(f, "User not found: {}", msg),
        }
    }
}

impl std::error::Error for AuthError {}

pub type Result<T> = std::result::Result<T, AuthError>;










pub fn check_secure_permissions(path: &Path, item_type: &str) -> Result<()> {
    let metadata = fs::metadata(path)
        .map_err(|e| AuthError::PermissionError(format!("Cannot read metadata for {}: {}", path.display(), e)))?;
    
    let permissions = metadata.permissions();

    // Check that file/directory is not writable by group or others
    if permissions.mode() & 0o022 != 0 {
        return Err(AuthError::PermissionError(
            format!("{} {} is writable by group or others", item_type, path.display())
        ));
    }

    // Check ownership - must be owned by root (like sshd does)
    if metadata.uid() != 0 {
        return Err(AuthError::PermissionError(
            format!("{} {} is not owned by root", item_type, path.display())
        ));
    }

    Ok(())
}

pub fn check_config_directory_permissions() -> Result<()> {
    let config_dir = Path::new(CONFIG_DIR);

    if !config_dir.exists() {
        return Err(AuthError::ConfigurationError(
            format!("Configuration directory {} does not exist", CONFIG_DIR)
        ));
    }

    check_secure_permissions(config_dir, "Configuration directory")
}

pub fn load_all_configs() -> Result<Vec<CommandConfig>> {
    let config_dir = Path::new(CONFIG_DIR);
    let mut configs = Vec::new();

    if !config_dir.exists() {
        return Ok(configs);
    }

    let entries = fs::read_dir(config_dir)
        .map_err(|e| AuthError::ConfigurationError(format!("Cannot read config directory: {}", e)))?;
    
    let mut config_files: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().map_or(false, |ext| ext == "toml"))
        .collect();

    config_files.sort();

    for config_file in config_files {
        check_secure_permissions(&config_file, "Configuration file")?;

        let config_content = fs::read_to_string(&config_file)
            .map_err(|e| AuthError::ConfigurationError(format!("Cannot read config file {}: {}", config_file.display(), e)))?;
        
        let config: CommandConfig = toml::from_str(&config_content)
            .map_err(|e| AuthError::ConfigurationError(format!("Failed to parse config file {}: {}", config_file.display(), e)))?;

        configs.push(config);
    }

    Ok(configs)
}







pub fn get_user_ids(username: &str) -> Result<(u32, u32)> {
    let user = User::from_name(username)
        .map_err(|e| AuthError::UserNotFound(format!("Failed to lookup user '{}': {}", username, e)))?
        .ok_or_else(|| AuthError::UserNotFound(format!("User '{}' not found", username)))?;
    
    Ok((user.uid.as_raw(), user.gid.as_raw()))
}




