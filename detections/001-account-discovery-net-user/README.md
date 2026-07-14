# Detection 001: Account Discovery via net.exe (T1087)

## 1. Behavior

After gaining access to a machine, attackers often run commands like
`net user` to discover local accounts. This behavior is known as
Account Discovery (MITRE T1087). Detecting it early is important because
it allows defenders to stop the attacker before they can steal data,
move to other systems, or cause serious damage.

## 2. Data Source

The detection uses Sysmon Event ID 1 (Process Creation) events collected on the Windows endpoint. The Wazuh agent forwards these events to the manager for analysis.

| Field | Question it answers |
|---|---|
| parentImage | WHO started it? |
| image | WHAT ran? |
| commandLine | HOW was it used? |

A single field is not enough because it can lead to an excessive number of false alarms by capturing normal activity. For example, matching only `parentImage` would alert on every process started from PowerShell, while matching only `image` could not separate `net user` from the harmless `net use`.

## 3. Detection Rule

```xml
<group name="sysmon_custom">
  <rule id="100101" level="10">
    <if_sid>92033</if_sid>
    <field name="win.eventdata.parentImage">powershell\.exe</field>
    <field name="win.eventdata.image" type="pcre2">net1?\.exe</field>
    <field name="win.eventdata.commandLine" type="pcre2">net1?\.exe.+user</field>
    <description>Account discovery: net user executed via PowerShell</description>
    <mitre><id>T1087</id></mitre>
  </rule>
</group>
```

**Why each line:**

- `parentImage`: Limits the rule to processes started from PowerShell. Without this condition, the rule would fire for `net.exe` started from anywhere, creating noise.
- `image`: The `net1?` pattern covers both `net.exe` and `net1.exe`, because attackers can run `net1 user` directly to evade a rule that only matches `net.exe`. The `?` quantifier requires `type="pcre2"` — Wazuh's default OS_Regex engine does not support it.
- `commandLine`: Looks for the `user` argument to separate account discovery from harmless commands like `net use`.

## 4. Testing

| 1 | `net user` | Alert (rule 100101) | ✅ |
| 2 | `net1 user` | Alert (evasion variant covered) | ✅ |
| 3 | `net use` | **No alert** (negative test) | ✅ |

The negative test is as important as the positive ones: it proves that the rule stays silent on harmless activity like `net use`. A rule that fires on normal behavior creates alert fatigue, and a noisy rule can be more dangerous than no rule at all.

## 5. Lessons Learned

### Bug 1: Silent death by whitespace
The rule never fired and produced no error. I compared the pattern with the real event value character by character and found a leading whitespace after the `>` in the image field. Wazuh matched the literal space, so nothing ever matched. Lesson: XML syntax can be valid while the pattern is dead.

### Bug 2: OS_Regex vs PCRE2
The built-in rule 92033 fired but my rule stayed silent. The `?` quantifier in my pattern is not supported by Wazuh's default OS_Regex engine, so the pattern could never match. Adding `type="pcre2"` to the field fixed it. Lesson: know which regex engine evaluates your pattern.

### Bug 3: Contradicting conditions
`net1 user` did not trigger the rule. I put each condition next to the real event values: the commandLine pattern allowed `net1`, but the image condition still required `net.exe` — and `net.exe` does not appear inside `net1.exe`. One condition silently blocked the other. Fix: aligned both fields to `net1?\.exe`.

### Bug 4: Edit regression caught by re-testing
After fixing Bug 3, `net use` suddenly started alerting — a false positive that did not exist before. Reading the actual file with `cat` showed that my edit had replaced the commandLine condition instead of the old image line, so the "HOW" check was gone. I restored the line and re-ran all three tests. Lesson: re-run the full test suite after every change, and verify the file on disk — the rule matches what is written, not what you intended.

---

*Lab: Wazuh 4.14.5 (Ubuntu) + Windows 11 agent with Sysmon (SwiftOnSecurity config)*
