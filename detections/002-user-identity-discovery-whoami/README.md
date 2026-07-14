# 002 — User Identity Discovery via whoami (T1033)

## Behavior

An attacker who has gained initial access usually does not know which
account they are operating under. They run the `whoami` command to
determine their current identity and privileges. The output shapes the
attacker's next move: if it is `SYSTEM` or an administrator account,
they attempt to establish persistence on the system; if it is a normal
user, they attempt privilege escalation (TA0004).

## Data Source

This detection uses Sysmon Event ID 1 (Process Creation), collected from
the `Microsoft-Windows-Sysmon/Operational` channel and forwarded to Wazuh
by the agent.

The rule matches on two fields: `parentImage`, which identifies which
process spawned the command, and `image`, which identifies what was
executed. In this rule, `parentImage` is constrained to `cmd.exe` or
`powershell.exe` (an interactive shell), and `image` to `whoami.exe`.

Unlike `net.exe`, which is a multi-purpose tool where the subcommand in
`commandLine` defines the behavior, `whoami` serves a single purpose.
Matching on `image` alone is sufficient to identify the behavior, so a
`commandLine` condition would add no information — it would only make
the rule more fragile. In testing, the two legitimate invocations
produced different `commandLine` values (`whoami` vs.
`"C:\WINDOWS\system32\whoami.exe"`) while `image` stayed identical —
confirming this design choice.

## Rule

See [rule.xml](./rule.xml).

Rule 61603 is Wazuh's base rule for Sysmon Event ID 1 (process creation).
It has level 0, meaning it matches silently and never generates an alert
on its own. Our rule builds on it via `if_sid`, so it is only evaluated
against process-creation events rather than every incoming log.

The pattern `(cmd|powershell)\.exe` accepts either shell as the parent
process. The `type="pcre2"` attribute is mandatory here: without it,
Wazuh defaults to its legacy OS_Regex engine, which does not support the
`|` operator — the rule would silently never match, with no error or
warning.

In the `image` field, the dot is escaped (`\.`) because an unescaped `.`
matches any character in regex; escaping it ensures the pattern matches
a literal dot.

The rule is assigned level 10: `whoami` execution is not proof of
compromise on its own, but spawned from an interactive shell it warrants
analyst attention. The MITRE tag `T1033` (System Owner/User Discovery)
maps the alert to a shared vocabulary, linking it to the Discovery
tactic and to external resources that use the same framework.

## Testing

The rule was originally written to match only `powershell.exe` as the
parent. After extending the pattern to `(cmd|powershell)\.exe`, three
tests were run:

| # | Type | Action | Expected | Observed |
|---|------|--------|----------|----------|
| 1 | Positive + regression | `whoami` from PowerShell | Alert fires (existing coverage still works after the edit) | Rule 100102 fired, level 10, `parentImage: powershell.exe` |
| 2 | Positive | `whoami` from cmd | Alert fires (new coverage works) | Rule 100102 fired, level 10, `parentImage: cmd.exe` |
| 3 | Negative | `whoami` via Task Manager (parent: `taskmgr.exe`) | No alert (the `parentImage` condition still constrains the rule) | No alert — silence confirmed |

The silence in test 3 is meaningful: tests 1 and 2 generated alerts
within the same minutes, proving the pipeline was healthy. The absence
of an alert therefore demonstrates that the rule constrains correctly,
not that the system was broken.

A side observation from the alerts: the `integrityLevel` field differed
between the two positive tests (`Medium` from cmd, `High` from an
elevated PowerShell). This field directly reflects the fork described
in the Behavior section — an analyst can read the attacker's privilege
level straight from the alert. Raising the rule level when
`integrityLevel` is `High` or `System` is a candidate improvement.

## Lessons Learned

- **A single-purpose binary needs fewer fields.** `net.exe` required a
  `commandLine` condition because its subcommands define its behavior;
  `whoami.exe` does one thing, so matching `image` is sufficient. Every
  unnecessary field is a liability — the two legitimate `commandLine`
  variants observed in testing would have made a `commandLine`-based
  rule fragile.
- **OS_Regex strikes again: `|` joins `?` on the unsupported list.**
  Any field using a modern regex operator must declare `type="pcre2"`.
  Without it, the rule fails silently — no error, no warning, no match.
  "The rule exists" and "the rule works" are not the same thing; only a
  positive test proves the latter.
- **`<field>` conditions are AND-ed; alternatives live inside a single
  pattern.** To accept two parent processes, the alternation
  `(cmd|powershell)` goes inside one `parentImage` field — a second
  `<field>` line would demand both parents at once and never match.
- **The description is the rule's promise.** After extending coverage to
  cmd, the description still said "via powershell". A description that
  contradicts the event data erodes analyst trust in the alert itself.
- **A negative test is only meaningful next to a positive one.** Silence
  proves constraint only when nearby alerts prove the pipeline works.
- **An unexpected parent is a stronger signal, not a gap.** `whoami`
  spawned by `winword.exe` or `w3wp.exe` indicates a payload or web
  shell — a higher-severity detection candidate, deliberately left out
  of this rule and noted for future work alongside the `$env:USERNAME`
  evasion (which never creates a process and therefore requires
  PowerShell Script Block Logging, Event ID 4104, rather than Sysmon
  Event ID 1).