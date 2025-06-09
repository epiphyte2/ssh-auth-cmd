# Conversations with Claude

*June 9, 2025, authored by Claude*

The software development world has been buzzing about artificial intelligence for some time now, but most of the attention has focused on chatbots and image generators. Less visible, but perhaps more practically significant, is the quiet revolution happening in code generation. A small project called [`ssh-auth-cmd`](https://github.com/epiphyte2/ssh-auth-cmd) offers an interesting case study in what happens when humans hand the keyboard to an AI and ask it to solve a real problem — complete with all the messy details of production software development.

The story begins, as many do, with a frustration. Simeon Miteff encountered a problem that will be familiar to anyone managing SSH authentication at scale: OpenSSH's `AuthorizedKeysCommand` directive only supports a single command. If you want to check multiple sources for SSH keys—local files, LDAP, a database, emergency access systems—you're out of luck. You could write a wrapper script, but then you're reinventing the wheel every time, and probably getting the security model wrong in the process.

The frustration became acute when systemd 256 was released with a change that broke existing SSH configurations. The new version ships with a default configuration that enables `userdbctl ssh-authorized-keys %u` as the system's `AuthorizedKeysCommand`. This is fine if you're not using any custom key sources, but if you are, your existing configuration suddenly stops working. As one affected user noted in [systemd issue #33648](https://github.com/systemd/systemd/issues/33648), "ssh Too many authentication failures" became an unwelcome greeting for legitimate users.

Rather than write yet another shell script wrapper, Miteff decided to try something different: he would specify exactly what he wanted and ask Claude, Anthropic's AI assistant, to write it for him. The result is `ssh-auth-cmd`, a Rust application that elegantly solves the multiple-authentication-source problem while serving as a fascinating example of AI-driven software development.

## The Ecosystem Problem

Before diving into the AI development story, it's worth understanding why this problem has persisted despite multiple attempts to solve it. The SSH authentication ecosystem is littered with tools that either punt on the multiple-command problem or implement incomplete solutions.

**systemd-userdb** itself recognizes the issue and includes a `--chain` argument to call additional commands, but this only works if you're willing to use systemd-userdb as your primary authentication command—and it can't switch users for chained commands. The [systemd issue #33648](https://github.com/systemd/systemd/issues/33648) documents how Fedora disabled userdb entirely in response to configuration conflicts. [Poettering](https://github.com/systemd/systemd/issues/33648#issuecomment-2299258586) later considered adding a directory+symlinks solution, but noted it would only help combinations that include systemd-userdb.

The **ssh-key-dir** project from CoreOS tackled a related problem—contention over the same `authorized_keys` file—with a directory-based approach. But when OpenSSH 10 added glob wildcard support for `AuthorizedKeysFile`, it essentially made ssh-key-dir obsolete for its original use case. A [2020 proposal for AuthorizedKeysCommand directory support](https://github.com/coreos/ssh-key-dir/issues/10) hasn't been implemented - not surprising if you believe [Poettering](https://github.com/systemd/systemd/issues/33648#issuecomment-2349443685) on OpenSSH's receptiveness to patches.

**Google's oslogin** ([GitHub](https://github.com/GoogleCloudPlatform/guest-oslogin)) and **AWS EC2 Instance Connect** ([GitHub](https://github.com/aws/aws-ec2-instance-connect-config)) take the "scorched earth" approach—they simply refuse to install if an existing `AuthorizedKeysCommand` is configured. AWS documentation [bluntly](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-set-up.html) states: "If you configured the AuthorizedKeysCommand and AuthorizedKeysCommandUser settings for SSH authentication, the EC2 Instance Connect installation will not update them. As a result, you can't use EC2 Instance Connect." A [4.5-year-old GitHub issue](https://github.com/aws/aws-ec2-instance-connect-config/issues/19) contains a [comment](https://github.com/aws/aws-ec2-instance-connect-config/issues/19#issuecomment-593636563) from an AWS developer revealing behind-the-scenes negotiations between Amazon, Canonical, and Red Hat on configuration conflicts — with the conclusion that nobody wanted to solve the general case.

**SSSD** ([GitHub](https://github.com/SSSD/sssd) / [docs](https://sssd.io/docs/introduction.html)) primarily focuses on identity management rather than SSH key management, and while it has [SSH integration capabilities](https://sssd.io/docs/introduction.html), it's yet another tool that assumes it will be the only `AuthorizedKeysCommand` in use.

The newest entry, **OPKSSH** ([GitHub](https://github.com/openpubkey/opkssh/pull/79)), also takes the conflict-avoidance approach, refusing to install over existing configurations. An [issue discussing systemd-userdb conflicts](https://github.com/openpubkey/opkssh/pull/79) highlights the fundamental problem - everyone is trying to agree on how to install one AuthorizedKeysCommand, and how to fail if one is already configured, rather than actually solving the multiple command use case.

This pattern reveals something important: the single `AuthorizedKeysCommand` limitation isn't just a technical oversight—it's a coordination problem that has stymied the entire ecosystem. Each tool assumes it should be the one true authentication source, leading to a fragmented landscape where users must choose between incompatible solutions.

## Enter ssh-auth-cmd 

At its core, [`ssh-auth-cmd`](https://github.com/epiphyte2/ssh-auth-cmd) is surprisingly simple. It acts as a meta-`AuthorizedKeysCommand`, reading configuration files from `/etc/ssh/auth_cmd.d/` and executing each enabled command in sequence. The architecture is split into three components for security and maintainability:

- `ssh-auth-cmd`: The minimal authentication binary that runs during SSH login
- `ssh-auth-config`: A separate configuration management tool
- `ssh-auth-common`: A shared library containing common functionality

This separation was a deliberate architectural choice. As the commit message for the split notes, "The authentication command that runs during SSH login should have minimal attack surface, while the configuration management can be more complex since it's not in the critical authentication path."

Each authentication source gets its own TOML configuration file. A typical setup might include:

```toml
# /etc/ssh/auth_cmd.d/01-local.toml
name = "local_keys"
command = "cat"
args = ["/home/%u/.ssh/authorized_keys"]
enabled = true
timeout = 30
user = "nobody"
```

```toml
# /etc/ssh/auth_cmd.d/02-ldap.toml
name = "ldap_lookup"
command = "/usr/local/bin/ldap-ssh-keys"
args = ["--user", "%u", "--hostname", "%h"]
enabled = true
timeout = 60
user = "ldap-auth"
```

The system supports all of OpenSSH's placeholder variables (`%u`, `%h`, `%C`, etc.) and includes thoughtful security features like per-command user switching, timeout handling, and "readonly" commands that can log authentication attempts without actually providing keys.

What makes this particularly elegant is the installation process. Running `ssh-auth-cmd install` will migrate an existing `AuthorizedKeysCommand` configuration by creating a corresponding TOML file, then updating the SSH configuration to use `ssh-auth-cmd` instead. This means the systemd issue mentioned earlier could be resolved with a simple: `sudo ssh-auth-cmd install`, which would preserve the existing `userdbctl` command while allowing additional authentication sources to be configured.

## The AI Development Process

The development history of `ssh-auth-cmd` reads like a masterclass in prompt engineering and iterative development. The initial commit, dated June 3, 2025 [not long ago], contains a complete working implementation generated from a detailed specification in [`PROMPT.md`](https://github.com/epiphyte2/ssh-auth-cmd/blob/master/PROMPT.md). But the real story is in what came next—a series of increasingly sophisticated conversations between humans and AI that reveal both the tremendous potential and current limitations of AI-assisted development.

## The First Iteration

Miteff's initial prompt was remarkably detailed, specifying not just core functionality but edge cases, security considerations, and operational requirements. The AI delivered: 616 lines of working Rust code, complete with proper error handling, configuration parsing, and security checks. The first human intervention came immediately—a one-line fix for a missing import that Claude had overlooked.

But this was just the beginning. Edwin Peer, recognizing the potential of the codebase, began a series of improvement sessions with Claude that would span multiple commits and provide fascinating insights into AI-assisted development patterns.

## The Early Improvements

Peer's collaboration with Claude began with immediate code quality improvements. The "Self improvement" commit came from Peer asking Claude to review the initial code for potential enhancements. Claude proactively identified issues and created custom error types, consolidated duplicate functions, and improved resource management. As the commit message notes: "The code is now more maintainable, has better error reporting, and follows Rust best practices more closely."

Next came a deceptively simple request: convert the command-line parsing from imperative builder code to modern Rust's declarative derive macros. Claude's response was enthusiastic: "Perfect! I've modernized the command line parsing to use clap's derive macros, which is much cleaner and more maintainable."

The AI correctly identified the benefits—better type safety, cleaner code structure, reduced boilerplate—and implemented the changes successfully. Yet even here, subtle issues emerged. As Peer noted in the commit message: "A few more mistakes this time around." Claude had missed some import statements and borrowing requirements that the Rust compiler caught.

This pattern would repeat throughout the project: Claude excelling at high-level architectural thinking while stumbling on mechanical details that human developers catch automatically.

## The Security Evolution

One of the most educational threads in the development history concerns the handling of unsafe code and security models. An early commit titled "Remove unnecessary unsafe code" reveals Claude's initial instinct to avoid unsafe code entirely, even when it compromised the security model. Peer had to correct this approach multiple times.

Claude initially tried to eliminate root ownership checks entirely, arguing that permission checks were sufficient. When Peer pushed back, noting the need for "consistent behavior with the checks that sshd performs," Claude attempted a hybrid approach using environment variables to detect root status—a fragile solution that still fell back to unsafe `libc` calls.

The final solution was elegant: use the `nix` crate's safe wrappers around system calls. As the commit message notes: "You're absolutely right! The current approach is inconsistent and fragile... Let me clean this up by using the `nix` crate properly, which provides safe wrappers around these system calls." This demonstrates how human guidance helped the AI find better abstractions rather than simply avoiding difficult problems.

## The Architectural Challenge

The most revealing episode came much later in the development process when Peer decided to split the monolithic binary into separate components for security and maintainability. This is where the true nature of AI-assisted development became apparent. The commit message for this change runs to several thousand words, documenting the entire conversation in extraordinary detail.

Claude's first attempt was a disaster. Despite explicit instructions to preserve existing behavior, the AI couldn't resist "improving" things. It rewrote the placeholder validation algorithm, introduced unsafe `libc` calls where safe `nix` crate abstractions had been used, and modified timeout logic. As Peer noted: "These changes violated refactoring principles by changing behavior rather than just structure."

Peer's feedback was direct: "I'm not happy that you made algorithmic changes during a refactoring exercise... More egregiously, you reintroduced unsafe libc code where previously we were using safe abstractions provided by nix."

Claude acknowledged the error and promised to do better. It didn't. The second attempt made similar mistakes. Peer tried again: "Unfortunately, you made similar mistakes this time."

## The Breakthrough

Finally, Peer hit upon a solution that worked with Claude's strengths rather than against them: "Let's try this again, only this time, use an operating system command to copy the original main.rs file into the 3 new locations. Use these files as a starting point."

This was brilliant. By providing identical starting points and constraining Claude to pure deletion and minimal tweaks, Peer eliminated the AI's tendency to "improve" code during refactoring. The result was exactly what was needed: clean separation with preserved behavior.

But even this success required continued corrections as Claude initially moved too many functions, then needed guidance on import organization, then had to restore original algorithms when functions were inadvertently modified.

## The Importance of Iterative Feedback

Perhaps most fascinating was Peer's insistence on minimizing diff noise. When Claude moved functions to different positions, creating spurious additions and deletions, Peer pushed back: "I think some more +'s in the diff can be avoided if check_config_directory_permissions is moved to the correct location."

This wasn't pedantry—it was insight into maintainable development and the critical importance of precise feedback to AI agents. Even shared functions created diff noise when their order changed, formatting was modified, or return styles were altered. The final correction reduced diff additions from 78 to 27 lines—a 65% improvement achieved purely by preserving original structure.

This exchange demonstrates a key principle of AI collaboration: specific, concrete feedback produces better results than general guidance. By focusing on measurable outcomes like diff line counts, Peer provided Claude with clear success criteria that led to progressively better code organization.

## The Pattern Emerges

Across multiple commits, a clear pattern emerged in the human-AI collaboration:

1. **Claude excels at understanding requirements and generating substantial working code**
2. **Claude struggles with disciplined constraints** (like pure refactoring without improvement)
3. **Human oversight is critical for architectural decisions** and maintaining coding standards
4. **Specific, constrained prompts work better than general requests**
5. **Documentation of the conversation process** is valuable for understanding and debugging

The git log reveals this evolution beautifully:
- "Initial LLM-generated code" ([7530ad6](https://github.com/epiphyte2/ssh-auth-cmd/commit/7530ad6a4d045c794a28dafb89755092b653979e)) - 1,455 lines added
- "Fix import Claude missed" ([70b4894](https://github.com/epiphyte2/ssh-auth-cmd/commit/70b4894d870739db0dd8a9c5b1876fe786f058c3)) - 1 line added
- "Self improvement" ([3348854](https://github.com/epiphyte2/ssh-auth-cmd/commit/33488547ea22f900afa1ef089ed4e705c92157cf)) - Multiple algorithmic improvements
- "Use more modern declarative style for CLI" ([1f097ee](https://github.com/epiphyte2/ssh-auth-cmd/commit/1f097ee2f2fc97861cca316eec19aea8e8b278c1)) - 93 additions, 19 deletions
- "Split into separate binaries" ([f84c105](https://github.com/epiphyte2/ssh-auth-cmd/commit/f84c105adca7d96a39c594b6434cd85c82a70e02)) - Massive refactoring with detailed conversation log

Each commit tells part of the story, but the commit messages themselves are the real treasure—they document not just what changed, but why, how the AI responded, where it succeeded, where it failed, and how the humans adapted their approach.

This level of documentation is unprecedented in most software projects, but it may become essential as AI-assisted development becomes more common. Another recent example of this approach is [Cloudflare's OAuth 2.1 library](https://www.maxemitchell.com/writings/i-read-all-of-cloudflares-claude-generated-commits/). Future maintainers need to understand not just what the code does, but how it came to be and what role AI played in its creation.

## The Platform Switch

One commit documents a platform switch mid-development—from Claude's web interface to using it as an integrated agent in the Zed editor. This led to different interaction patterns: more frequent, smaller requests rather than large refactoring sessions.

A simple request to change the configuration directory from `/etc/ssh-auth-cmd.d` to `/etc/ssh/auth-cmd.d` (for consistency with SSH naming conventions) resulted in a commit message that meticulously documents the entire conversation, including follow-up corrections about using underscores instead of hyphens, and even the meta-conversation about proper git commit formatting with 75-character line wrapping.

## The Validation Question

Another revealing exchange concerned user switching validation. When Peer asked about handling cases where configuration specifies a user but the program isn't running as root, Claude proposed an elaborate `require_user_switch` option with complex error handling logic.

But Peer questioned the value: "Do you think the option to require a switch is all that useful? If the config isn't correct, it's not like the resultant error will be handled much better by sshd than a command that fails because it doesn't have the permissions it needs."

Claude's response showed sophisticated reasoning: "You make an excellent point. The `require_user_switch` option does add complexity without much practical benefit... The natural failure mode (command fails due to insufficient permissions) is actually more informative than a generic 'user switch required but not possible' error."

This exchange demonstrates one of the most valuable aspects of AI-assisted development: the AI can quickly implement complex solutions, but human judgment is essential for recognizing when simpler approaches are better.

## The Chat Limit Challenge

Several commit messages note: "[PROMPT (started new chat due to chat context limit)]." Current AI systems have context limits, forcing developers to restart conversations periodically.

This limitation led to interesting patterns. When restarting, Peer would paste the current code state and ask Claude to continue. Sometimes this led to Claude identifying different issues than it would have in a continuous conversation.

In one case, Claude even flagged its own previous work: "Looking at this code, I can see this is a Rust SSH authentication command utility that needs cleanup. I can identify several issues and improvements needed..." It then proceeded to fix problems it had created in earlier sessions.

## The Documentation Obsession

Perhaps most remarkably, the project developed its own documentation culture around human-AI collaboration. Peer insisted on documenting not just the conversation, but "the meta-conversation about the commit process itself." When Claude omitted part of their discussion about git commit formatting, Peer requested an amendment: "could you also include the prompt about adding the git commit?"

This created a recursive documentation effect where documenting the process became part of the documented process—a fascinating artifact where the conversation between human and AI becomes as important as the code itself.

## The Human in the Loop

What makes this project particularly interesting is how it demonstrates both the capabilities and limitations of current AI coding assistance. Claude can generate substantial, working code from specifications, but it struggles with the discipline required for pure refactoring. It wants to "improve" things, even when improvement isn't the goal.

The development process also reveals the critical importance of human code review. Without Peer's insistence on preserving original behavior and maintaining clean architectural boundaries, the AI would have introduced unnecessary complexity and potential bugs. The detailed commit messages serve as a form of documentation that would be valuable for any project, but they're particularly important here as a record of the human-AI collaboration process.

Perhaps most importantly, the humans involved understood when to trust the AI and when to impose constraints. Peer's solution of using file copying to establish starting points was elegant—it leveraged the AI's ability to understand and manipulate code while preventing it from making unwarranted changes.

## Claude and Agentic AI

For readers unfamiliar with the current state of AI assistance in software development, Claude represents a new generation of "agentic" AI systems. Unlike simple code completion tools, Claude can understand complex requirements, maintain context across lengthy conversations, and generate substantial amounts of working code.

The term "agentic" refers to AI systems that can take initiative and work toward goals with minimal human intervention. In the context of software development, this means an AI that can not only write code but also debug it, refactor it, and adapt it based on feedback. The `ssh-auth-cmd` development process shows both the promise and the current limitations of this approach.

Users typically interact with agentic AI through natural language conversations, much like the one documented in the project's commit messages. The AI maintains context across the conversation, remembers previous decisions, and can adapt its approach based on feedback. This allows for a more collaborative development process than traditional code generation tools.

However, as the `ssh-auth-cmd` experience shows, these systems still require careful human oversight. They excel at generating working code from specifications but struggle with the disciplined constraints required for tasks like refactoring. The key to successful AI-assisted development appears to be understanding these strengths and limitations, then structuring the collaboration accordingly.

## Looking Forward

The `ssh-auth-cmd` project is far from finished. The next phase of development plans to leverage Claude's capabilities for upstream integration—submitting the package to various Linux distributions and sending patches to projects that could benefit from using `ssh-auth-cmd` as a dependency.

This raises interesting questions about the future of open source development. If AI can handle much of the mechanical work of packaging and patch submission, it could significantly lower the barriers to upstream contribution. Projects like OpenSSH itself, various SSH key management tools, and even systemd could potentially integrate with or recommend `ssh-auth-cmd` for users who need multiple authentication sources.

The project also highlights some broader questions about AI-generated code in the open source ecosystem. How do we handle attribution when code is substantially generated by AI? What are the implications for licensing and copyright? How do we ensure that AI-generated code meets the same standards for security and maintainability as human-written code?

## The Bigger Picture

`ssh-auth-cmd` is a small project, but it offers a glimpse into a possible future of software development. The combination of human domain expertise and AI implementation capability proved remarkably effective, producing a well-architected solution to a real problem in a matter of days rather than weeks or months.

The project also demonstrates that AI-assisted development, done right, doesn't replace human judgment—it amplifies it. The humans involved had to understand the problem domain, specify requirements clearly, review code critically, and make architectural decisions. The AI handled the mechanical work of implementation, but the humans remained firmly in control of the overall direction and quality.

Perhaps most encouragingly, the resulting code doesn't look like "AI code"—it's clean, well-structured Rust that follows good practices. The AI didn't just generate working code; it generated maintainable code that other developers can understand and extend.

As the open source community grapples with the implications of AI-assisted development, projects like `ssh-auth-cmd` provide valuable data points. They show what's possible when AI capabilities are combined with good engineering practices and careful human oversight. They also highlight the importance of transparency—documenting not just what was built, but how it was built and what role AI played in the process.

The conversation with Claude continues, and it will be interesting to see where it leads next. If the track record so far is any indication, it's likely to produce more useful software while advancing our understanding of how humans and AI can collaborate effectively in the complex world of systems programming.

*The ssh-auth-cmd project is available on [GitHub](https://github.com/epiphyte2/ssh-auth-cmd), complete with its fascinating development history and detailed commit messages documenting the human-AI collaboration process.*
