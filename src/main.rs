use std::collections::HashMap;
use std::env;
use std::fs::{self, Permissions};
use std::io::{self, Write, BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use serde::{Deserialize, Serialize};
use clap::{Arg, Command as ClapCommand, ArgMatches};

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

const CONFIG_DIR: &str = "/etc/ssh-auth-cmd.d";
const DEFAULT_TIMEOUT: u64 = 30;
const SSHD_CONFIG_DEFAULT: &str = "/etc/ssh/sshd_config";

#[derive(Debug)]
struct SshContext {
    connection_spec: Option<String>,  // %C
    routing_domain: Option<String>,   // %D
    fingerprint: Option<String>,      // %f
    hostname: Option<String>,         // %h
    key: Option<String>,              // %k
    key_type: Option<String>,         // %t
    original_user: Option<String>,    // %U
    user: String,                     // %u
}

fn main() {
    let matches = build_cli().get_matches();

    match matches.subcommand() {
        Some(("key-cmd", sub_matches)) => {
            let context = parse_ssh_context(sub_matches);
            match run_auth_commands(&context) {
                Ok(_) => {},
                Err(e) => {
                    eprintln!("Error: {}", e);
                    std::process::exit(1);
                }
            }
        },
        Some(("config-check", _)) => {
            match config_check() {
                Ok(_) => {
                    println!("Configuration check passed");
                    std::process::exit(0);
                },
                Err(e) => {
                    eprintln!("Configuration check failed: {}", e);
                    std::process::exit(1);
                }
            }
        },
        Some(("install", sub_matches)) => {
            let config_file = sub_matches.get_one::<String>("config")
                .map(|s| s.as_str())
                .unwrap_or(SSHD_CONFIG_DEFAULT);
            let user = sub_matches.get_one::<String>("user").map(|s| s.as_str());

            match install_to_sshd_config(config_file, user) {
                Ok(_) => {
                    println!("Installation completed successfully");
                    std::process::exit(0);
                },
                Err(e) => {
                    eprintln!("Installation failed: {}", e);
                    std::process::exit(1);
                }
            }
        },
        _ => {
            eprintln!("Invalid usage. Use --help for usage information.");
            std::process::exit(1);
        }
    }
}

fn build_cli() -> ClapCommand {
    ClapCommand::new("ssh-auth-cmd")
        .version("0.1.0")
        .about("Chainable SSH AuthorizedKeysCommand")
        .subcommand(
            ClapCommand::new("key-cmd")
                .about("Execute key commands (used by OpenSSH)")
                .arg(Arg::new("connection-spec").short('c').long("connection-spec").value_name("SPEC"))
                .arg(Arg::new("routing-domain").short('D').long("routing-domain").value_name("DOMAIN"))
                .arg(Arg::new("fingerprint").short('f').long("fingerprint").value_name("FINGERPRINT"))
                .arg(Arg::new("hostname").short('h').long("hostname").value_name("HOSTNAME"))
                .arg(Arg::new("key").short('k').long("key").value_name("KEY"))
                .arg(Arg::new("key-type").short('t').long("key-type").value_name("TYPE"))
                .arg(Arg::new("original-user").short('U').long("original-user").value_name("USER"))
                .arg(Arg::new("user").short('u').long("user").value_name("USER").required(true))
        )
        .subcommand(
            ClapCommand::new("config-check")
                .about("Check configuration files and permissions")
        )
        .subcommand(
            ClapCommand::new("install")
                .about("Install ssh-auth-cmd into OpenSSH configuration")
                .arg(Arg::new("config").long("config").value_name("FILE").help("OpenSSH config file path"))
                .arg(Arg::new("user").long("user").value_name("USER").help("AuthorizedKeysCommandUser"))
        )
}

fn parse_ssh_context(matches: &ArgMatches) -> SshContext {
    SshContext {
        connection_spec: matches.get_one::<String>("connection-spec").cloned(),
        routing_domain: matches.get_one::<String>("routing-domain").cloned(),
        fingerprint: matches.get_one::<String>("fingerprint").cloned(),
        hostname: matches.get_one::<String>("hostname").cloned(),
        key: matches.get_one::<String>("key").cloned(),
        key_type: matches.get_one::<String>("key-type").cloned(),
        original_user: matches.get_one::<String>("original-user").cloned(),
        user: matches.get_one::<String>("user").unwrap().clone(),
    }
}

fn run_auth_commands(context: &SshContext) -> Result<(), Box<dyn std::error::Error>> {
    check_config_directory_permissions()?;

    let configs = load_all_configs()?;
    let mut all_keys = Vec::new();

    for config in &configs {
        // Skip disabled commands
        if let Some(false) = config.enabled {
            continue;
        }

        match execute_command(config, context) {
            Ok(mut keys) => {
                // Only add keys if not readonly
                if !config.readonly.unwrap_or(false) {
                    all_keys.append(&mut keys);
                }
            },
            Err(e) => {
                eprintln!("Warning: Command '{}' failed: {}", config.name, e);
                // Continue with other commands even if one fails
            }
        }
    }

    // Output all collected keys
    for key in all_keys {
        println!("{}", key);
    }

    Ok(())
}

fn check_config_directory_permissions() -> Result<(), Box<dyn std::error::Error>> {
    let config_dir = Path::new(CONFIG_DIR);

    if !config_dir.exists() {
        return Err(format!("Configuration directory {} does not exist", CONFIG_DIR).into());
    }

    // Check directory permissions - should be owned by root and not writable by others
    let metadata = fs::metadata(config_dir)?;
    let permissions = metadata.permissions();

    if permissions.mode() & 0o022 != 0 {
        return Err(format!("Configuration directory {} is writable by group or others", CONFIG_DIR).into());
    }

    // Check if running as root to verify ownership
    if unsafe { libc::getuid() } == 0 {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 {
            return Err(format!("Configuration directory {} is not owned by root", CONFIG_DIR).into());
        }
    }

    Ok(())
}

fn check_config_file_permissions(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::metadata(path)?;
    let permissions = metadata.permissions();

    // Config files should not be writable by group or others
    if permissions.mode() & 0o022 != 0 {
        return Err(format!("Configuration file {} is writable by group or others", path.display()).into());
    }

    // Check ownership if running as root
    if unsafe { libc::getuid() } == 0 {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 {
            return Err(format!("Configuration file {} is not owned by root", path.display()).into());
        }
    }

    Ok(())
}

fn load_all_configs() -> Result<Vec<CommandConfig>, Box<dyn std::error::Error>> {
    let config_dir = Path::new(CONFIG_DIR);
    let mut configs = Vec::new();

    if !config_dir.exists() {
        return Ok(configs);
    }

    let entries = fs::read_dir(config_dir)?;
    let mut config_files: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.extension().map_or(false, |ext| ext == "toml"))
        .collect();

    // Sort for consistent ordering
    config_files.sort();

    for config_file in config_files {
        check_config_file_permissions(&config_file)?;

        let config_content = fs::read_to_string(&config_file)?;
        let config: CommandConfig = toml::from_str(&config_content)
            .map_err(|e| format!("Failed to parse config file {}: {}", config_file.display(), e))?;

        configs.push(config);
    }

    Ok(configs)
}

fn execute_command(config: &CommandConfig, context: &SshContext) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let timeout = config.timeout.unwrap_or(DEFAULT_TIMEOUT);

    // Check if we need to switch user
    let current_uid = unsafe { libc::getuid() };
    let target_user = config.user.as_ref();

    // Prepare command and arguments
    let mut cmd = Command::new(&config.command);

    if let Some(ref args) = config.args {
        for arg in args {
            let processed_arg = substitute_placeholders(arg, context)?;
            cmd.arg(processed_arg);
        }
    } else {
        // If no args specified, pass username as single argument
        cmd.arg(&context.user);
    }

    // Configure command execution
    cmd.stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(Stdio::null());

    // Switch user if running as root and user is specified
    if current_uid == 0 && target_user.is_some() {
        let username = target_user.unwrap();
        cmd.uid(get_user_uid(username)?);
        cmd.gid(get_user_gid(username)?);
    }

    // Execute with timeout
    let child = cmd.spawn()?;
    let output = wait_with_timeout(child, timeout)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("Command failed with exit code {:?}: {}",
                           output.status.code(), stderr).into());
    }

    // Parse output into individual keys
    let stdout = String::from_utf8_lossy(&output.stdout);
    let keys: Vec<String> = stdout
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| line.to_string())
        .collect();

    Ok(keys)
}

fn substitute_placeholders(arg: &str, context: &SshContext) -> Result<String, Box<dyn std::error::Error>> {
    let mut result = String::new();
    let mut chars = arg.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            if let Some(&next_char) = chars.peek() {
                match next_char {
                    '%' => {
                        chars.next(); // consume the second %
                        result.push('%');
                    },
                    'C' => {
                        chars.next();
                        result.push_str(&context.connection_spec.as_deref().unwrap_or(""));
                    },
                    'D' => {
                        chars.next();
                        result.push_str(&context.routing_domain.as_deref().unwrap_or(""));
                    },
                    'f' => {
                        chars.next();
                        result.push_str(&context.fingerprint.as_deref().unwrap_or(""));
                    },
                    'h' => {
                        chars.next();
                        result.push_str(&context.hostname.as_deref().unwrap_or(""));
                    },
                    'k' => {
                        chars.next();
                        result.push_str(&context.key.as_deref().unwrap_or(""));
                    },
                    't' => {
                        chars.next();
                        result.push_str(&context.key_type.as_deref().unwrap_or(""));
                    },
                    'U' => {
                        chars.next();
                        result.push_str(&context.original_user.as_deref().unwrap_or(""));
                    },
                    'u' => {
                        chars.next();
                        result.push_str(&context.user);
                    },
                    _ => {
                        return Err(format!("Invalid placeholder: %{}", next_char).into());
                    }
                }
            } else {
                return Err("Incomplete placeholder at end of string".into());
            }
        } else {
            result.push(ch);
        }
    }

    Ok(result)
}

fn get_user_uid(username: &str) -> Result<u32, Box<dyn std::error::Error>> {
    use std::ffi::CString;

    let c_username = CString::new(username)?;
    let passwd = unsafe { libc::getpwnam(c_username.as_ptr()) };

    if passwd.is_null() {
        return Err(format!("User '{}' not found", username).into());
    }

    Ok(unsafe { (*passwd).pw_uid })
}

fn get_user_gid(username: &str) -> Result<u32, Box<dyn std::error::Error>> {
    use std::ffi::CString;

    let c_username = CString::new(username)?;
    let passwd = unsafe { libc::getpwnam(c_username.as_ptr()) };

    if passwd.is_null() {
        return Err(format!("User '{}' not found", username).into());
    }

    Ok(unsafe { (*passwd).pw_gid })
}

fn wait_with_timeout(mut child: std::process::Child, timeout_secs: u64) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    use std::time::{Duration, Instant};
    use std::thread;

    let start = Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    loop {
        match child.try_wait()? {
            Some(status) => {
                let stdout = {
                    let mut buf = Vec::new();
                    if let Some(mut stdout) = child.stdout.take() {
                        use std::io::Read;
                        stdout.read_to_end(&mut buf)?;
                    }
                    buf
                };

                let stderr = {
                    let mut buf = Vec::new();
                    if let Some(mut stderr) = child.stderr.take() {
                        use std::io::Read;
                        stderr.read_to_end(&mut buf)?;
                    }
                    buf
                };

                return Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                });
            },
            None => {
                if start.elapsed() >= timeout {
                    child.kill()?;
                    child.wait()?;
                    return Err(format!("Command timed out after {} seconds", timeout_secs).into());
                }
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn config_check() -> Result<(), Box<dyn std::error::Error>> {
    // Check directory permissions
    check_config_directory_permissions()?;

    // Load and validate all configs
    let configs = load_all_configs()?;

    for config in &configs {
        // Check that command binary exists and is only writable by root
        check_command_permissions(&config.command)?;

        // Check argument substitutions
        if let Some(ref args) = config.args {
            for arg in args {
                validate_argument_substitutions(arg)?;
            }
        }
    }

    Ok(())
}

fn check_command_permissions(command_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(command_path);

    if !path.exists() {
        return Err(format!("Command '{}' does not exist", command_path).into());
    }

    let metadata = fs::metadata(path)?;
    let permissions = metadata.permissions();

    // Command should not be writable by group or others
    if permissions.mode() & 0o022 != 0 {
        return Err(format!("Command '{}' is writable by group or others", command_path).into());
    }

    // Check ownership if running as root
    if unsafe { libc::getuid() } == 0 {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 {
            return Err(format!("Command '{}' is not owned by root", command_path).into());
        }
    }

    Ok(())
}

fn validate_argument_substitutions(arg: &str) -> Result<(), Box<dyn std::error::Error>> {
    let mut chars = arg.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '%' {
            if let Some(&next_char) = chars.peek() {
                match next_char {
                    '%' | 'C' | 'D' | 'f' | 'h' | 'k' | 't' | 'U' | 'u' => {
                        chars.next(); // consume the placeholder
                    },
                    _ => {
                        return Err(format!("Invalid placeholder: %{}", next_char).into());
                    }
                }
            } else {
                return Err("Incomplete placeholder at end of string".into());
            }
        }
    }

    Ok(())
}

fn install_to_sshd_config(config_file: &str, user_override: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    // Create config directory if it doesn't exist
    fs::create_dir_all(CONFIG_DIR)?;

    // Read and parse existing sshd_config
    let (existing_auth_cmd, existing_user) = parse_sshd_config(config_file)?;

    // Determine the user for AuthorizedKeysCommandUser
    let auth_user = user_override.unwrap_or("root");

    // If there's an existing AuthorizedKeysCommand, migrate it
    if let Some(existing_cmd) = existing_auth_cmd {
        migrate_existing_command(&existing_cmd, existing_user.as_deref())?;
    }

    // Update sshd_config
    update_sshd_config(config_file, auth_user)?;

    Ok(())
}

fn parse_sshd_config(config_file: &str) -> Result<(Option<String>, Option<String>), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(config_file)?;
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

fn migrate_existing_command(existing_cmd: &str, existing_user: Option<&str>) -> Result<(), Box<dyn std::error::Error>> {
    // Extract basename from the command path
    let cmd_parts: Vec<&str> = existing_cmd.split_whitespace().collect();
    if cmd_parts.is_empty() {
        return Err("Empty existing command".into());
    }

    let cmd_path = Path::new(cmd_parts[0]);
    let basename = cmd_path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("legacy");

    let config_filename = format!("{}.toml", basename);
    let config_path = Path::new(CONFIG_DIR).join(&config_filename);

    // Check if file already exists
    if config_path.exists() {
        return Err(format!("Configuration file {} already exists", config_path.display()).into());
    }

    // Create the migration config
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

    let toml_content = toml::to_string_pretty(&migration_config)?;
    fs::write(&config_path, toml_content)?;

    // Set proper permissions
    let mut perms = fs::metadata(&config_path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(&config_path, perms)?;

    println!("Migrated existing command to {}", config_path.display());

    Ok(())
}

fn update_sshd_config(config_file: &str, auth_user: &str) -> Result<(), Box<dyn std::error::Error>> {
    let content = fs::read_to_string(config_file)?;
    let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();

    let mut found_auth_cmd = false;
    let mut found_auth_user = false;

    // Update or comment out existing lines
    for line in &mut lines {
        let trimmed = line.trim();
        if trimmed.starts_with("AuthorizedKeysCommand ") && !trimmed.starts_with("#") {
            *line = format!("# {}", line); // Comment out old line
            found_auth_cmd = true;
        } else if trimmed.starts_with("AuthorizedKeysCommandUser ") && !trimmed.starts_with("#") {
            *line = format!("# {}", line); // Comment out old line
            found_auth_user = true;
        }
    }

    // Add new configuration
    let current_exe = env::current_exe()?;
    let exe_path = current_exe.to_string_lossy();

    lines.push("# Added by ssh-auth-cmd install".to_string());
    lines.push(format!("AuthorizedKeysCommand {} key-cmd -c %C -D %D -f %f -h %h -k %k -t %t -U %U -u %u", exe_path));
    lines.push(format!("AuthorizedKeysCommandUser {}", auth_user));

    // Write back to file
    let new_content = lines.join("\n");
    fs::write(config_file, new_content)?;

    println!("Updated OpenSSH configuration in {}", config_file);

    Ok(())
}