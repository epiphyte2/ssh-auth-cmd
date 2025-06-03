# ssh-auth-cmd Configuration and Setup

## Overview

`ssh-auth-cmd` is a Rust application designed to chain multiple SSH `AuthorizedKeysCommand` configurations, since OpenSSH only supports configuring a single one. The new version supports individual configuration files, user switching, comprehensive OpenSSH placeholder support, and automatic installation.

## Installation

1. Build the application:
```bash
cargo build --release
```

2. Install the binary:
```bash
sudo cp target/release/ssh-auth-cmd /usr/local/bin/
sudo chmod +x /usr/local/bin/ssh-auth-cmd
```

3. Install using the built-in installer (recommended):
```bash
sudo /usr/local/bin/ssh-auth-cmd install
```

Or with a specific user:
```bash
sudo /usr/local/bin/ssh-auth-cmd install --user nobody
```

## Configuration Directory Structure

Commands are now configured in individual TOML files in `/etc/ssh-auth-cmd.d/`:

```
/etc/ssh-auth-cmd.d/
├── 01-local-keys.toml
├── 02-ldap-keys.toml
├── 03-database-keys.toml
└── 99-emergency-keys.toml
```

Files are processed in alphabetical order, so you can use prefixes to control execution order.

## Configuration File Format

Each configuration file contains a single command definition:

### Example: `/etc/ssh-auth-cmd.d/01-local-keys.toml`
```toml
name = "local_keys"
command = "cat"
args = ["/home/%u/.ssh/authorized_keys"]
enabled = true
timeout = 30
user = "nobody"
readonly = false
```

### Example: `/etc/ssh-auth-cmd.d/02-ldap-keys.toml`
```toml
name = "ldap_keys"
command = "/usr/local/bin/ldap-ssh-keys"
args = ["--user", "%u", "--hostname", "%h", "--connection", "%C"]
enabled = true
timeout = 60
user = "ldap-user"
readonly = false
```

### Example: `/etc/ssh-auth-cmd.d/03-audit-only.toml`
```toml
name = "audit_logger"
command = "/usr/local/bin/ssh-audit-log"
args = ["--user", "%u", "--key-type", "%t", "--fingerprint", "%f"]
enabled = true
timeout = 10
user = "audit"
readonly = true  # Don't include output in authorized keys
```

## Configuration Options

### Required Fields
- `name`: A descriptive name for the command
- `command`: The command/script to execute

### Optional Fields
- `args`: Array of arguments to pass to the command
- `enabled`: Whether this command is enabled (default: true)
- `timeout`: Timeout in seconds for command execution (default: 30)
- `user`: UNIX user to run the command as (only when ssh-auth-cmd runs as root)
- `readonly`: If true, discard stdout output (useful for logging/auditing)

## OpenSSH Placeholder Support

The following OpenSSH placeholders are supported in the `args` array:

- `%C`: Connection specification (user, client IP, client port, server IP, server port)
- `%D`: Routing domain
- `%f`: Key fingerprint
- `%h`: Hostname
- %k`: Key being offered for authentication
- `%t`: Key type
- `%U`: Original username (before any transformations)
- `%u`: Username being authenticated
- `%%`: Literal `%` character

### Example with Multiple Placeholders
```toml
name = "comprehensive_auth"
command = "/usr/local/bin/auth-checker"
args = [
    "--user", "%u",
    "--original-user", "%U", 
    "--hostname", "%h",
    "--connection", "%C",
    "--key-type", "%t",
    "--fingerprint", "%f",
    "--key", "%k",
    "--domain", "%D",
    "--literal-percent", "%%"
]
```

## OpenSSH Configuration

When using the install command, ssh-auth-cmd configures OpenSSH as:

```
AuthorizedKeysCommand /usr/local/bin/ssh-auth-cmd key-cmd -c %C -D %D -f %f -h %h -k %k -t %t -U %U -u %u
AuthorizedKeysCommandUser root
```

This exhaustively uses all OpenSSH substitution variables currently defined.

## User Switching

When `ssh-auth-cmd` runs as root (recommended), you can specify different users for each command:

- If `user` is specified in a command config, that command runs as the specified user
- If `user` is not specified, the command runs as the same user as `ssh-auth-cmd`
- If `ssh-auth-cmd` is not running as root, the `user` field is ignored

This allows for principle of least privilege - each command can run with only the permissions it needs.

## Commands and Usage

### Key Command Mode (used by OpenSSH)
```bash
ssh-auth-cmd key-cmd -c %C -D %D -f %f -h %h -k %k -t %t -U %U -u %u
```

This is the mode OpenSSH calls. It processes all enabled configurations and outputs authorized keys.

### Configuration Check
```bash
sudo ssh-auth-cmd config-check
```

Validates:
- Configuration directory and file permissions
- Configuration file syntax
- Placeholder substitution validity
- Command binary permissions
- That all command binaries are only writable by root

### Installation
```bash
# Install with default settings (AuthorizedKeysCommandUser root)
sudo ssh-auth-cmd install

# Install with specific user
sudo ssh-auth-cmd install --user nobody

# Install with custom sshd_config location
sudo ssh-auth-cmd install --config /etc/ssh/sshd_config.custom
```

The install command:
- Migrates existing `AuthorizedKeysCommand` to a config file in `/etc/ssh-auth-cmd.d/`
- Comments out the old configuration
- Adds the new ssh-auth-cmd configuration
- Preserves existing `AuthorizedKeysCommandUser` settings when migrating
- Will not overwrite existing files in `/etc/ssh-auth-cmd.d/`

## Security Considerations

### File Permissions
All configuration files and the configuration directory must have secure permissions:

```bash
# Set proper permissions
sudo chown -R root:root /etc/ssh-auth-cmd.d/
sudo chmod 755 /etc/ssh-auth-cmd.d/
sudo chmod 600 /etc/ssh-auth-cmd.d/*.toml
```

The `config-check` command verifies these permissions automatically.

### Command Security
- All configured command binaries must be owned by root and not writable by others
- Commands run with the privileges of the specified `user` (or the user running ssh-auth-cmd)
- Use the `readonly` flag for commands that should only log/audit without providing keys

### User Isolation
Different commands can run as different users for security isolation:
- LDAP queries might run as a dedicated `ldap-auth` user
- Database queries might run as a `db-auth` user
- Local file access might run as `nobody`
- Audit logging might run as an `audit` user

## Example Configurations

### Basic Local + LDAP Setup

`/etc/ssh-auth-cmd.d/01-local.toml`:
```toml
name = "local_keys"
command = "cat"
args = ["/home/%u/.ssh/authorized_keys"]
enabled = true
timeout = 30
user = "nobody"
```

`/etc/ssh-auth-cmd.d/02-ldap.toml`:
```toml
name = "ldap_lookup"
command = "/usr/local/bin/ldap-ssh-keys"
args = ["--user", "%u", "--hostname", "%h"]
enabled = true
timeout = 60
user = "ldap-auth"
```

### Enterprise Setup with Audit Trail

`/etc/ssh-auth-cmd.d/01-audit.toml`:
```toml
name = "connection_audit"
command = "/usr/local/bin/log-ssh-attempt"
args = [
    "--user", "%u",
    "--original-user", "%U",
    "--connection", "%C",
    "--hostname", "%h",
    "--key-fingerprint", "%f",
    "--key-type", "%t"
]
enabled = true
timeout = 10
user = "audit"
readonly = true  # Just for logging, don't provide keys
```

`/etc/ssh-auth-cmd.d/02-corporate-keys.toml`:
```toml
name = "corporate_ldap"
command = "/usr/local/bin/corporate-auth"
args = ["--user", "%u", "--domain", "corp.example.com"]
enabled = true
timeout = 60
user = "corp-auth"
```

`/etc/ssh-auth-cmd.d/03-emergency.toml`:
```toml
name = "emergency_access"
command = "/usr/local/bin/emergency-keys"
args = ["--user", "%u", "--validate-emergency"]
enabled = true
timeout = 30
user = "emergency-auth"
```

### Development/Testing Setup

`/etc/ssh-auth-cmd.d/01-local.toml`:
```toml
name = "local_keys"
command = "cat"
args = ["/home/%u/.ssh/authorized_keys"]
enabled = true
timeout = 30
```

`/etc/ssh-auth-cmd.d/02-shared-dev.toml`:
```toml
name = "shared_dev_keys"
command = "cat"
args = ["/etc/ssh/shared_dev_keys"]
enabled = true
timeout = 10
```

## Migration from Single Configuration

If you're migrating from the original single-file configuration:

1. Run the install command to automatically migrate:
```bash
sudo ssh-auth-cmd install
```

2. The installer will:
   - Move your existing `AuthorizedKeysCommand` to a config file
   - Comment out the old configuration
   - Install the new ssh-auth-cmd configuration

3. Verify the migration:
```bash
sudo ssh-auth-cmd config-check
```

## Troubleshooting

### Configuration Issues
```bash
# Check all configurations
sudo ssh-auth-cmd config-check

# Test manually for a specific user
sudo ssh-auth-cmd key-cmd -u testuser

# Test with full OpenSSH context
sudo ssh-auth-cmd key-cmd -c "testuser,192.168.1.100,22,10.0.0.1,22" -u testuser -h hostname.example.com
```

### Permission Problems
```bash
# Fix directory permissions
sudo chown -R root:root /etc/ssh-auth-cmd.d/
sudo chmod 755 /etc/ssh-auth-cmd.d/
sudo chmod 600 /etc/ssh-auth-cmd.d/*.toml

# Check command permissions
ls -la /usr/local/bin/your-auth-command
```

### SSH Debug Mode
Enable SSH debug logging to see what's happening:
```bash
# In /etc/ssh/sshd_config
LogLevel DEBUG

# Then check logs
sudo tail -f /var/log/auth.log
```

### Common Issues

1. **"Configuration directory is writable by group or others"**
   - Fix: `sudo chmod 755 /etc/ssh-auth-cmd.d/`

2. **"Configuration file is writable by group or others"**
   - Fix: `sudo chmod 600 /etc/ssh-auth-cmd.d/*.toml`

3. **"Command is not owned by root"**
   - Fix: `sudo chown root:root /path/to/command`

4. **"Invalid placeholder"**
   - Check that you're only using supported placeholders: %C, %D, %f, %h, %k, %t, %U, %u, %%

5. **"User not found"**
   - Ensure the user specified in the `user` field exists on the system

## Performance Considerations

- Commands run sequentially in alphabetical order by filename
- Set appropriate timeouts to prevent hanging connections
- Use `readonly = true` for audit/logging commands that don't provide keys
- Consider disabling unnecessary commands in production environments

## Best Practices

1. **Naming Convention**: Use numbered prefixes (01-, 02-, etc.) to control execution order
2. **User Separation**: Run different commands as different users for security isolation
3. **Timeouts**: Set conservative timeouts to prevent hanging SSH connections
4. **Auditing**: Use readonly commands for comprehensive audit logging
5. **Testing**: Always test configurations with `config-check` before deployment
6. **Monitoring**: Monitor command execution times and failure rates
7. **Backup**: Keep backups of working configurations before making changes

## Integration Examples

### With HashiCorp Vault
```toml
name = "vault_ssh_ca"
command = "/usr/local/bin/vault-ssh-helper"
args = ["-mode", "ca", "-username", "%u"]
enabled = true
timeout = 45
user = "vault-ssh"
```

### With FreeIPA/Red Hat IdM
```toml
name = "ipa_keys"
command = "/usr/bin/sss_ssh_authorizedkeys"
args = ["%u"]
enabled = true
timeout = 30
user = "sssd"
```

### With Custom Database
```toml
name = "db_keys"
command = "/usr/local/bin/db-ssh-keys"
args = [
    "--user", "%u",
    "--client-ip", "%C",
    "--hostname", "%h"
]
enabled = true
timeout = 60
user = "db-auth"
```

This comprehensive setup provides a secure, flexible, and maintainable way to chain multiple SSH authentication sources while maintaining full OpenSSH compatibility and security best practices.