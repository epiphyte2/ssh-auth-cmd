Prompt for Claude Sonnet 4 on June 3, 2025:

```
Write an application in Rust called "ssh-auth-cmd" that meets the following requirements:

ssh-auth-cmd is intended to be configured as an OpenSSH AuthorizedKeysCommand, and is intended to allow users to
chain multiple AuthorizedKeysCommand configurations (since OpenSSH only supports configuring a single one).

The way it should work is with two modes:
```

I accidentally hit enter, instead of shift-enter...

```
Make the following changes:

- Instead of a single TOML configuration file, each command is configured with a separate file located in 
  /etc/ssh-auth-cmd.d/ (for example /etc/ssh-auth-cmd.d/ldap-keys.toml would contain the section for "ldap_keys").
  Extend file and directory permissions (mode and ownership) checks to all the files to this setup.
- A "user" key in each configuration specifies the UNIX user as which the command will execute if ssh-auth-cmd is
  executed as root (i.e., configured with "AuthorizedKeysCommandUser root"). If user is not specified or ssh-auth-cmd
  is not executed as root, the command should run as the same user as ssh-auth-cmd is running.
- When executed by OpenSSH, the argument for ssh-auth-cmd should be exactly 
 "key-cmd -c %C -D %D -f %f -h %h -k %k -t %t -U %U -u %u", thus exhaustively consuming every substitution currently
  defined by OpenSSH for AuthorizedKeysCommand.
- Extend the application to allow commands to be configured with any of %C, %D, %f, %h, %k, %t, %U, and %u as
  placeholders in the args array, and use the values from the key-cmd arguments (-c, -D, etc). Allow "%%" to escape
  a literal "%" in the args.
- A "readonly" key (boolean value) in a command configuration should cause ssh-auth-command to discard any stdout
  output from such commands.
- When executed with a single argument "config-check", ssh-auth-cmd should check config file permissions as above,
  and also check that args substitutions are among the allowed set, and check that the command binaries are only
  writable by root.
- When executed with a single argument "install", ssh-auth-cmd should modify an existing OpenSSH configuration as follows:
  - If no AuthorizedKeysCommand (and optional AuthorizedKeysCommandUser) configuration exists , add ssh-auth-cmd
    appropriately, and use a AuthorizedKeysCommandUser of root, unless the --user argument is specified (in which
    case set AuthorizedKeysCommandUser to the provided value).
  - If an existing AuthorizedKeysCommand (and optional AuthorizedKeysCommandUser) configuration exists, write a new
    TOML configuration to /etc/ssh-auth-cmd.d/ that preserves the existing command (and configured user) after
    re-writing AuthorizedKeysCommand (and optional AuthorizedKeysCommandUser) as above. The TOML filename should be
    derived from the "basename" of the original AuthorizedKeysCommand, but should not overwrite an existing file in
    /etc/ssh-auth-cmd.d/ (if a conflicting file exists, abort).
  - The code should support following OpenSSH's configuration file include directive, and assume the root config file
    exists at /etc/ssh/sshd_config but permit overriding this with a --config argument.
```


