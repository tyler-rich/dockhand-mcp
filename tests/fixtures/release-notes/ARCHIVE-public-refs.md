# ARCHIVE — decision log and history

Invented fixture: issue and PR numbers before and after the public launch. Entries up to and
including "Public launch" name the private archive repository's items; later entries name this
repository's.

## §14 Decisions

Entry format:

```
### YYYY-MM-DD — <short title> (PR #n, branch <name>)
**Decision:** …
```

### 2026-01-10 — Release pipeline and docs, v0.1.0 (PR #2, branch chore/release)
**Decision:** Ship v0.1.0.

### 2026-01-12 — Fix #5: stale label (PR #6, branch fix/label; replaces PR #3)
**Decision:** The label names the right revision. Fixes #5, filed after upstream owner/other#12.

### 2026-01-20 — Public launch (PR #7, branch chore/public-launch)
**Decision:** Prepare the public import; history stays in PR #1 through PR #7.

### 2026-01-22 — Fix #3: after the launch (PR #4, branch fix/after)
**Decision:** Fixes #3, reported in this repository.
