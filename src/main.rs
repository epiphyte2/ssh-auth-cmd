use std::env;
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::prelude::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use std::thread;
use serde::{Deserialize, Serialize};
use clap::{Args, Parser, Subcommand};
use nix::unistd::{Uid, User};

#[derive(Debug, Serialize, Deserialize)]
struct CommandConfig {
    name: String,
    command: String,
    args: Option<Vec<String>>,
    enabled: Option<bool>,
    timeout: Option<u64>,
    user: Option<String>,
    readonly: Option<bool>,
}

#[derive(Parser)]
#[command(name = "ssh-auth-cmd")]
#[command(version = "0.1.0")]
#[command(about = "Chainable SSH AuthorizedKeysCommand")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Execute key commands (used by OpenSSH)
    KeyCmd(SshContext),
    /// Check configuration files and permissions
    ConfigCheck,
    /// Install ssh-auth-cmd into OpenSSH configuration
    Install(InstallArgs),
}

#[derive(Args, Debug)]
struct SshContext {
    /// Connection specification (%C)
    #[arg(short = 'c', long = "connection-spec")]
    connection_spec: Option<String>,
    
    /// Routing domain (%D)
    #[arg(short = 'D', long = "routing-domain")]
    routing_domain: Option<String>,
    
    /// Key fingerprint (%f)
    #[arg(short = 'f', long = "fingerprint")]
    fingerprint: Option<String>,
    
    /// Hostname (%h)
    #[arg(short = 'h', long = "hostname")]
    hostname: Option<String>,
    
    /// Key (%k)
    #[arg(short = 'k', long = "key")]
    key: Option<String>,
    
    /// Key type (%t)
    #[arg(short = 't', long = "key-type")]
    key_type: Option<String>,
    
    /// Original user (%U)
    #[arg(short = 'U', long = "original-user")]
    original_user: Option<String>,
    
    /// User (%u)
    #[arg(short = 'u', long = "user", required = true)]
    user: String,
}

#[derive(Args)]
struct InstallArgs {
    /// OpenSSH config file path
    #[arg(long = "config")]
    config: Option<String>,
    
    /// AuthorizedKeysCommandUser
    #[arg(long = "user")]
    user: Option<String>,
}

const CONFIG_DIR: &str = "/etc/ssh-auth-cmd.d";
const DEFAULT_TIMEOUT: u64 = 30;
const SSHD_CONFIG_DEFAULT: &str = "/etc/ssh/sshd_config";

#[derive(Debug)]
enum AuthError {
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

type Result<T> = std::result::Result<T, AuthError>;

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::KeyCmd(ref context) => run_auth_commands(&context),
        Commands::ConfigCheck => config_check(),
        Commands::Install(ref args) => {
            let config_file = args.config.as_deref().unwrap_or(SSHD_CONFIG_DEFAULT);
            let user = args.user.as_deref();
            install_to_sshd_config(config_file, user)
        },
    };

    match result {
        Ok(_) => {
            match cli.command {
                Commands::ConfigCheck => println!("Configuration check passed"),
                Commands::Install(_) => println!("Installation completed successfully"),
                Commands::KeyCmd(_) => {}, // Output handled in run_auth_commands
            }
        },
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}

fn run_auth_commands(context: &SshContext) -> Result<()> {
    check_config_directory_permissions()?;

    let configs = load_all_configs()?;

    for config in &configs {
        if let Some(false) = config.enabled {
            continue;
        }

        match execute_command(config, context) {
            Ok(_) => {
                // Command executed successfully, output was handled directly
            },
            Err(e) => {
                eprintln!("Warning: Command '{}' failed: {}", config.name, e);
            }
        }
    }

    Ok(())
}

fn check_secure_permissions(path: &Path, item_type: &str) -> Result<()> {
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

fn check_config_directory_permissions() -> Result<()> {
    let config_dir = Path::new(CONFIG_DIR);

    if !config_dir.exists() {
        return Err(AuthError::ConfigurationError(
            format!("Configuration directory {} does not exist", CONFIG_DIR)
        ));
    }

    check_secure_permissions(config_dir, "Configuration directory")
}

fn check_config_file_permissions(path: &Path) -> Result<()> {
    check_secure_permissions(path, "Configuration file")
}

fn load_all_configs() -> Result<Vec<CommandConfig>> {
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
        check_config_file_permissions(&config_file)?;

        let config_content = fs::read_to_string(&config_file)
            .map_err(|e| AuthError::ConfigurationError(format!("Cannot read config file {}: {}", config_file.display(), e)))?;
        
        let config: CommandConfig = toml::from_str(&config_content)
            .map_err(|e| AuthError::ConfigurationError(format!("Failed to parse config file {}: {}", config_file.display(), e)))?;

        configs.push(config);
    }

    Ok(configs)
}

fn execute_command(config: &CommandConfig, context: &SshContext) -> Result<()> {
    let timeout = config.timeout.unwrap_or(DEFAULT_TIMEOUT);
    let target_user = config.user.as_ref();
    let is_readonly = config.readonly.unwrap_or(false);

    let mut cmd = Command::new(&config.command);

    if let Some(ref args) = config.args {
        for arg in args {
            let processed_arg = substitute_placeholders(arg, context)?;
            cmd.arg(processed_arg);
        }
    } else {
        cmd.arg(&context.user);
    }

    // Set stdout based on readonly flag
    if is_readonly {
        cmd.stdout(Stdio::null());
    } else {
        cmd.stdout(Stdio::inherit()); // Pass through to ssh-auth-cmd's stdout
    }
    
    cmd.stderr(Stdio::piped())
        .stdin(Stdio::null());

    // Only attempt user switching if we're root and a target user is specified
    if is_running_as_root() && target_user.is_some() {
        let username = target_user.unwrap();
        let (uid, gid) = get_user_ids(username)?;
        cmd.uid(uid);
        cmd.gid(gid);
    }

    let child = cmd.spawn()
        .map_err(|e| AuthError::ExecutionError(format!("Failed to spawn command '{}': {}", config.command, e)))?;
    
    let output = wait_with_timeout(child, timeout)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(AuthError::ExecutionError(format!(
            "Command '{}' failed with exit code {:?}: {}", 
            config.name, output.status.code(), stderr
        )));
    }

    Ok(())
}

fn substitute_placeholders(arg: &str, context: &SshContext) -> Result<String> {
    let mut result = String::new();
    let mut chars = arg.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            if let Some(&next_char) = chars.peek() {
                match next_char {
                    '%' => {
                        chars.next();
                        result.push('%');
                    },
                    'C' => {
                        chars.next();
                        result.push_str(context.connection_spec.as_deref().unwrap_or(""));
                    },
                    'D' => {
                        chars.next();
                        result.push_str(context.routing_domain.as_deref().unwrap_or(""));
                    },
                    'f' => {
                        chars.next();
                        result.push_str(context.fingerprint.as_deref().unwrap_or(""));
                    },
                    'h' => {
                        chars.next();
                        result.push_str(context.hostname.as_deref().unwrap_or(""));
                    },
                    'k' => {
                        chars.next();
                        result.push_str(context.key.as_deref().unwrap_or(""));
                    },
                    't' => {
                        chars.next();
                        result.push_str(context.key_type.as_deref().unwrap_or(""));
                    },
                    'U' => {
                        chars.next();
                        result.push_str(context.original_user.as_deref().unwrap_or(""));
                    },
                    'u' => {
                        chars.next();
                        result.push_str(&context.user);
                    },
                    _ => {
                        return Err(AuthError::ConfigurationError(format!("Invalid placeholder: %{}", next_char)));
                    }
                }
            } else {
                return Err(AuthError::ConfigurationError("Incomplete placeholder at end of string".to_string()));
            }
        } else {
            result.push(ch);
        }
    }

    Ok(result)
}

fn is_running_as_root() -> bool {
    Uid::effective().is_root()
}

fn get_user_ids(username: &str) -> Result<(u32, u32)> {
    let user = User::from_name(username)
        .map_err(|e| AuthError::UserNotFound(format!("Failed to lookup user '{}': {}", username, e)))?
        .ok_or_else(|| AuthError::UserNotFound(format!("User '{}' not found", username)))?;
    
    Ok((user.uid.as_raw(), user.gid.as_raw()))
}

fn wait_with_timeout(mut child: std::process::Child, timeout_secs: u64) -> Result<std::process::Output> {
    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                // For inherit stdout, we don't need to read it
                let stdout = Vec::new();
                let stderr = read_child_output_stderr(child.stderr.take())?;

                return Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            },
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(AuthError::TimeoutError(format!("Command timed out after {} seconds", timeout_secs)));
                }
                thread::sleep(Duration::from_millis(100));
            },
            Err(e) => {
                return Err(AuthError::ExecutionError(format!("Error waiting for child process: {}", e)));
            }
        }
    }
}

fn read_child_output_stderr(output: Option<std::process::ChildStderr>) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    if let Some(mut stream) = output {
        stream.read_to_end(&mut buf)
            .map_err(|e| AuthError::ExecutionError(format!("Failed to read child stderr: {}", e)))?;
    }
    Ok(buf)
}

fn config_check() -> Result<()> {
    check_config_directory_permissions()?;
    let configs = load_all_configs()?;

    for config in &configs {
        check_command_permissions(&config.command)?;

        if let Some(ref args) = config.args {
            for arg in args {
                validate_argument_substitutions(arg)?;
            }
        }
    }

    Ok(())
}

fn check_command_permissions(command_path: &str) -> Result<()> {
    let path = Path::new(command_path);

    if !path.exists() {
        return Err(AuthError::ConfigurationError(format!("Command '{}' does not exist", command_path)));
    }

    check_secure_permissions(path, "Command")
}

fn validate_argument_substitutions(arg: &str) -> Result<()> {
    let mut chars = arg.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            if let Some(&next_char) = chars.peek() {
                match next_char {
                    '%' | 'C' | 'D' | 'f' | 'h' | 'k' | 't' | 'U' | 'u' => {
                        chars.next();
                    },
                    _ => {
                        return Err(AuthError::ConfigurationError(format!("Invalid placeholder: %{}", next_char)));
                    }
                }
            } else {
                return Err(AuthError::ConfigurationError("Incomplete placeholder at end of string".to_string()));
            }
        }
    }

    Ok(())
}

fn install_to_sshd_config(config_file: &str, user_override: Option<&str>) -> Result<()> {
    fs::create_dir_all(CONFIG_DIR)
        .map_err(|e| AuthError::ConfigurationError(format!("Failed to create config directory: {}", e)))?;

    let (existing_auth_cmd, existing_user) = parse_sshd_config(config_file)?;
    let auth_user = user_override.unwrap_or("root");

    if let Some(existing_cmd) = existing_auth_cmd {
        migrate_existing_command(&existing_cmd, existing_user.as_deref())?;
    }

    update_sshd_config(config_file, auth_user)?;
    Ok(())
}

fn parse_sshd_config(config_file: &str) -> Result<(Option<String>, Option<String>)> {
    let content = fs::read_to_string(config_file)
        .map_err(|e| AuthError::ConfigurationError(format!("Cannot read sshd config file '{}': {}", config_file, e)))?;
    
    let mut auth_cmd = None;
    let mut auth_user = None;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("AuthorizedKeysCommand ") && !line.starts_with("#") {
            auth_cmd = Some(line.split_whitespace().skip(1).collect::<Vec<_>>().join(" "));
        } else if line.starts_with("AuthorizedKeysCommandUser ") && !line.starts_with("#") {
            auth_user = Some(line.split_whitespace().nth(1).unwrap_or("").to_string());
        }
    }

    Ok((auth_cmd, auth_user))
}

fn migrate_existing_command(existing_cmd: &str, existing_user: Option<&str>) -> Result<()> {
    let cmd_parts: Vec<&str> = existing_cmd.split_whitespace().collect();
    if cmd_parts.is_empty() {
        return Err(AuthError::ConfigurationError("Empty existing command".to_string()));
    }

    let cmd_path = Path::new(cmd_parts[0]);
    let basename = cmd_path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("legacy");

    let config_filename = format!("{}.toml", basename);
    let config_path = Path::new(CONFIG_DIR).join(&config_filename);

    if config_path.exists() {
        return Err(AuthError::ConfigurationError(
            format!("Configuration file {} already exists", config_path.display())
        ));
    }

    let migration_config = CommandConfig {
        name: format!("migrated_{}", basename),
        command: cmd_parts[0].to_string(),
        args: if cmd_parts.len() > 1 {
            Some(cmd_parts[1..].iter().map(|s| s.to_string()).collect())
        } else {
            None
        },
        enabled: Some(true),
        timeout: Some(DEFAULT_TIMEOUT),
        user: existing_user.map(|u| u.to_string()),
        readonly: Some(false),
    };

    let toml_content = toml::to_string_pretty(&migration_config)
        .map_err(|e| AuthError::ConfigurationError(format!("Failed to serialize migration config: {}", e)))?;
    
    fs::write(&config_path, toml_content)
        .map_err(|e| AuthError::ConfigurationError(format!("Failed to write migration config: {}", e)))?;

    let mut perms = fs::metadata(&config_path)
        .map_err(|e| AuthError::PermissionError(format!("Cannot read metadata for migration config: {}", e)))?
        .permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&config_path, perms)
        .map_err(|e| AuthError::PermissionError(format!("Cannot set permissions for migration config: {}", e)))?;

    println!("Migrated existing command to {}", config_path.display());
    Ok(())
}

fn update_sshd_config(config_file: &str, auth_user: &str) -> Result<()> {
    let content = fs::read_to_string(config_file)
        .map_err(|e| AuthError::ConfigurationError(format!("Cannot read sshd config file: {}", e)))?;
    
    let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();

    for line in &mut lines {
        let trimmed = line.trim();
        if (trimmed.starts_with("AuthorizedKeysCommand ") || trimmed.starts_with("AuthorizedKeysCommandUser ")) 
           && !trimmed.starts_with("#") {
            *line = format!("# {}", line);
        }
    }

    let current_exe = env::current_exe()
        .map_err(|e| AuthError::ConfigurationError(format!("Cannot determine current executable path: {}", e)))?;
    let exe_path = current_exe.to_string_lossy();

    lines.push("# Added by ssh-auth-cmd install".to_string());
    lines.push(format!("AuthorizedKeysCommand {} key-cmd -c %C -D %D -f %f -h %h -k %k -t %t -U %U -u %u", exe_path));
    lines.push(format!("AuthorizedKeysCommandUser {}", auth_user));

    let new_content = lines.join("\n");
    fs::write(config_file, new_content)
        .map_err(|e| AuthError::ConfigurationError(format!("Failed to write updated sshd config: {}", e)))?;

    println!("Updated OpenSSH configuration in {}", config_file);
    Ok(())
}
