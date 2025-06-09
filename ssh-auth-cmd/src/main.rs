use std::process::{Command, Stdio};
use std::os::unix::prelude::CommandExt;
use std::time::{Duration, Instant};
use std::thread;
use std::io::Read;

use clap::Parser;
use nix::unistd::Uid;
use ssh_auth_common::{AuthError, Result, CommandConfig, DEFAULT_TIMEOUT, check_config_directory_permissions, load_all_configs, get_user_ids};

#[derive(Parser)]
#[command(name = "ssh-auth-cmd")]
#[command(version = "0.1.0")]
#[command(about = "Chainable SSH AuthorizedKeysCommand")]
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
    #[arg(short = 'H', long = "hostname")]
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



fn main() {
    let context = SshContext::parse();
    
    let result = run_auth_commands(&context);

    match result {
        Ok(_) => {},
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

    // Handle user switching if requested and possible
    if let Some(username) = target_user {
        if is_running_as_root() {
            let (uid, gid) = get_user_ids(username)?;
            cmd.uid(uid);
            cmd.gid(gid);
        } else {
            eprintln!("Warning: Command '{}' specifies user '{}' but ssh-auth-cmd is not running as root. \
                      Check that AuthorizedKeysCommandUser is set to 'root' in sshd_config", 
                     config.name, username);
        }
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


