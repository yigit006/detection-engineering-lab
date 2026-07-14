# 003 — User Identity Discovery via Environment Variable (T1033)

## Behavior

Detection 002 catches identity discovery through `whoami.exe`. An attacker
aware of process-based monitoring can avoid spawning that binary entirely
by reading the same information from a PowerShell environment variable:

```powershell
$env:USERNAME
```

This returns the current user without creating a new process. It is a
direct evasion of the 002 detection: the intent (identity discovery,
T1033) is identical, but the technical footprint is completely different.

## Data Source

This is the core lesson of this detection: **the evasion is invisible to
the data source used by 001 and 002.**

Sysmon Event ID 1 records *process creation*. Reading `$env:USERNAME`
does not create a process — the variable is resolved inside the already
running `powershell.exe`. No process, no Event ID 1, no detection. The
gap is not in the rule; it is in the data source itself.

To see this behavior we need a different telemetry source: **PowerShell
Script Block Logging (Event ID 4104)**, delivered on the
`Microsoft-Windows-PowerShell/Operational` channel. Its key field is
`scriptBlockText`, which contains the actual code the engine
interpreted — not a process name. This is the only source that can
observe an action which never spawns a process.

Two setup steps were required, because neither is enabled by default:

1. **Enable Script Block Logging on Windows.** Windows 11 Home has no
   `gpedit.msc`, so the policy was set directly in the registry:
   `HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging`,
   value `EnableScriptBlockLogging = 1`.
2. **Tell the Wazuh agent to read the channel.** A second `<localfile>`
   block was added to `ossec.conf` for
   `Microsoft-Windows-PowerShell/Operational`, then the agent was
   restarted.

## Rule

```xml
<group name="sysmon_custom">
  <rule id="100103" level="10">
    <if_sid>91816</if_sid>
    <field name="win.eventdata.scriptBlockText" type="pcre2">\$env:USERNAME</field>
    <description>User identity discovery: environment variable queried instead of whoami (evasion)</description>
    <mitre><id>T1033</id></mitre>
  </rule>
</group>
```

The base rule here is **not** the generic Sysmon rule used by 001/002.
When the first `$env:USERNAME` event arrived, `wazuh-logtest` (and the
raw event itself) showed it already matched Wazuh's built-in rule
**91816** — "Powershell script querying system environment variables"
(T1082, level 4). That rule is generic: it fires on *any* environment
variable query. Our rule layers a specific detection on top of it via
`if_sid`, exactly as 002 built on the Sysmon base rule:

- generic (91816, T1082, level 4): "an environment variable was queried"
- specific (100103, T1033, level 10): "the `USERNAME` variable was
  queried — this is identity discovery"

The pattern `\$env:USERNAME` escapes the dollar sign (`\$`) because in
regex `$` means "end of line" — the same class of trap as escaping a
literal dot with `\.`. The `type="pcre2"` attribute is required for the
escape to behave as intended.

The rule is assigned level 10, matching 002: identity discovery is worth
analyst attention but is not proof of compromise on its own.

## Testing

| # | Type | Action | Expected | Observed |
|---|------|--------|----------|----------|
| 1 | Positive | `$env:USERNAME` in PowerShell | 100103 fires, level 10 | Fired, level 10, `scriptBlockText: $env:USERNAME` |
| 2 | Negative | `$env:COMPUTERNAME` in PowerShell | 100103 does **not** fire (generic 91816 may still fire) | No 100103 alert |
| 3 | Negative + regression | `whoami` in PowerShell | 100102 fires, 100103 silent | 100102 fired (incl. the `whoami /all` variant); no 100103 |

Test 2 confirms the rule is scoped to `USERNAME` and does not fire on
every environment-variable query. Test 3 confirms the two detections do
not interfere: the process-based path (100102) and the script-block path
(100103) coexist and fire independently on their respective techniques.

## Lessons Learned

- **A detection gap can live in the data source, not the rule.** No
  amount of tuning on an Event ID 1 rule would ever catch
  `$env:USERNAME`, because the behavior never generates an Event ID 1.
  Choosing the right telemetry source is a prerequisite to writing the
  rule — this is the step above rule syntax.
- **"Not visible" and "not arriving" are different things.** The event
  did not appear in the `wazuh-alerts` index at first, which looked like
  a failure. It was arriving at the manager the whole time; it simply
  had not matched an alert-producing rule yet. Enabling `logall_json`
  and searching the *archives* proved the pipeline was healthy and
  revealed the base rule (91816) to build on. Confirm arrival before
  assuming breakage.
- **Read the base rule from telemetry, don't assume it.** The correct
  `if_sid` (91816) was discovered by inspecting a real event, not
  guessed. Wazuh already had a generic rule for this behavior; layering
  on it is cleaner than writing a standalone rule against the raw 4104.
- **Visibility has a cost.** Within minutes of enabling Script Block
  Logging, the channel filled with unrelated noise — the Wazuh agent's
  own SCA scans run through PowerShell (`secedit ...`), plus routine
  blocks like `prompt` and `$global:?`. In production, turning this on
  is a deliberate trade-off, not a free win.
- **`$` must be escaped in regex.** Like the `\.` lesson from 001, `\$`
  is required because an unescaped `$` is a line-end anchor, not a
  literal dollar sign — and the escape only works under `type="pcre2"`.

## Related

- [002 — User Identity Discovery via whoami](../002-user-identity-discovery-whoami/)
  — the process-based detection this variable-read evades.
