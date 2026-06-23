# Security Policy

basta is a sandbox, so a defect can mean a sandboxed process reaching the host.
It's shared as-is with no warranty, but security reports are
welcome and taken seriously.

## Reporting

**Report privately — don't open a public issue for a suspected sandbox escape or
egress bypass.** Use the repo **Security** tab → **Advisories → Report a
vulnerability**. Include `basta --version`, host distro/kernel, the launch flags,
and a minimal repro (a PoC showing host access from inside the sandbox is ideal).

## Scope

In scope: a sandboxed process reaching a host path that wasn't bound (or writing a
read-only / workspace-lock target); reaching a destination not permitted by
`--allow*` or modifying the in-netns nftables rules; escaping the namespaces,
regaining capabilities, or defeating seccomp; a planted autorun file the host
later runs despite the workspace lock.

Out of scope (documented non-goals — see README "Security model" / "Limits"):
kernel exploits, side channels, a compromised host user, unknown malware (use a
VM); a credential you deliberately `--env`/`--seed` in being visible to the agent
(the allowlist is the containment, not secrecy); explicit escape hatches
(`--net host`, `--no-seccomp`, `--no-lock`) behaving as documented; a confined
SELinux domain denying bubblewrap's mounts.

Pre-1.0: only the latest release is supported — reproduce against `main` first.
