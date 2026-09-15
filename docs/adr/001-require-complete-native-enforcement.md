# ADR 001: Require complete native enforcement

- Status: Accepted
- Date: 2026-09-15

## Context

A platform may expose only part of the mechanisms needed for a process sandbox.
For example, seccomp reduces Linux system calls but does not restrict pathnames,
and a namespace may be disabled inside a container. Treating one partial
mechanism as a sandbox would give callers a false security guarantee.

## Decision

Saiph reports a backend as available only after its required native mechanisms
can be activated in a disposable process. Linux requires namespaces, Landlock,
and seccomp together. macOS requires a compiled deny-by-default Seatbelt
profile. Windows requires successful creation and launch of an AppContainer.

Policy setup happens before user code. Any setup error terminates the launcher
with status 126. No backend falls back to `Process.spawn` without restrictions.
The implementation uses Ruby's standard library and native OS APIs through
Fiddle; it does not add a privileged helper or native extension.

## Consequences

Saiph can be unavailable in otherwise supported operating systems, especially
inside CI containers. Callers must surface that state or choose their own
explicit fallback. Supporting more Linux hosts may later justify an audited
external helper, but it must preserve the same fail-closed contract.

Windows filesystem grants remain unsupported until the embedding application
can provision and restore ACLs it owns. Saiph rejects those policies instead of
silently broadening access.
