use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use clap::{Args, Parser, Subcommand};
use ssh_auth_common::{
    load_all_configs, Result, AuthError, CommandConfig, DEFAULT_TIMEOUT, CONFIG_DIR, SSHD_CONFIG_DEFAULT,
    check_config_directory_permissions, get_user_ids, check_secure_permissions
};

#[derive(Parser)]
#[command(name = "ssh-auth-config")]
#[command(version = "0.1.0")]
#[command(about = "SSH AuthorizedKeysCommand multiplexer - Configuration management")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Check configuration files and permissions
    ConfigCheck,
    /// Install ssh-auth-cmd into OpenSSH configuration
    Install(InstallArgs),
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

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
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
            }
        },
        Err(e) => {
            eprintln!("Error: {}", e);
            std::process::exit(1);
        }
    }
}



fn check_sshd_user_configuration(configs_with_users: &[&CommandConfig]) -> Result<()> {
    // Try common sshd_config locations
    let possible_configs = [
        "/etc/ssh/sshd_config",
        "/etc/sshd_config", 
        "/usr/local/etc/ssh/sshd_config",
    ];

    let mut sshd_config_path = None;
    for path in &possible_configs {
        if Path::new(path).exists() {
            sshd_config_path = Some(*path);
            break;
        }
    }

    let config_path = sshd_config_path.ok_or_else(|| {
        AuthError::ConfigurationError(
            "Cannot find sshd_config file to verify AuthorizedKeysCommandUser setting".to_string()
        )
    })?;

    let (auth_cmd, auth_user) = parse_sshd_config(config_path)?;

    // Check if ssh-auth-cmd is configured
    if auth_cmd.is_none() {
        return Err(AuthError::ConfigurationError(
            "No AuthorizedKeysCommand found in sshd_config, but command configs specify user switching".to_string()
        ));
    }

    // Check if the command looks like it's pointing to ssh-auth-cmd
    let auth_cmd = auth_cmd.unwrap();
    if !auth_cmd.contains("ssh-auth-cmd") {
        eprintln!("Warning: AuthorizedKeysCommand doesn't appear to use ssh-auth-cmd: {}", auth_cmd);
    }

    // Check AuthorizedKeysCommandUser
    let auth_user = auth_user.ok_or_else(|| {
        AuthError::ConfigurationError(
            "No AuthorizedKeysCommandUser specified in sshd_config, but command configs require user switching".to_string()
        )
    })?;

    if auth_user != "root" {
        let user_list: Vec<String> = configs_with_users.iter()
            .map(|config| format!("'{}' (user: {})",
                config.name,
                config.user.as_ref().unwrap()
            ))
            .collect();

        return Err(AuthError::ConfigurationError(format!(
            "AuthorizedKeysCommandUser is set to '{}' but the following commands require user switching: {}\n\
             Set AuthorizedKeysCommandUser to 'root' in {} to enable user switching",
            auth_user, user_list.join(", "), config_path
        )));
    }

    Ok(())
}

fn config_check() -> Result<()> {
    check_config_directory_permissions()?;
    let configs = load_all_configs()?;

    // Check if any configs specify user switching
    let configs_with_users: Vec<_> = configs.iter()
        .filter(|config| config.user.is_some())
        .collect();

    if !configs_with_users.is_empty() {
        // Check sshd configuration to ensure it runs as root
        check_sshd_user_configuration(&configs_with_users)?;
    }

    for config in &configs {
        // Check command permissions
        check_command_permissions(&config.command)?;

        // Check that specified users exist (if we can check)
        if let Some(ref username) = config.user {
            if let Err(e) = get_user_ids(username) {
                return Err(AuthError::ConfigurationError(format!(
                    "Command '{}' specifies user '{}' but user lookup failed: {}",
                    config.name, username, e
                )));
            }
        }

        // Validate argument substitutions
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
    let exe_path = if let Some(parent_dir) = current_exe.parent() {
        let ssh_auth_cmd = parent_dir.join("ssh-auth-cmd");
        if ssh_auth_cmd.exists() {
            ssh_auth_cmd.to_string_lossy().to_string()
        } else {
            "/usr/local/bin/ssh-auth-cmd".to_string()
        }
    } else {
        current_exe.to_string_lossy().to_string()
    };

    lines.push("# Added by ssh-auth-cmd install".to_string());
    lines.push(format!("AuthorizedKeysCommand {} -c %C -D %D -f %f -H %h -k %k -t %t -U %U -u %u", exe_path));
    lines.push(format!("AuthorizedKeysCommandUser {}", auth_user));

    let new_content = lines.join("\n");
    fs::write(config_file, new_content)
        .map_err(|e| AuthError::ConfigurationError(format!("Failed to write updated sshd config: {}", e)))?;

    println!("Updated OpenSSH configuration in {}", config_file);
    Ok(())
}


