# Detection Engineering Lab

<!-- Vitrin sayfası: işe alımcının 30 saniyede okuyacağı yer. Kısa tut. -->

Hands-on detection engineering work built on a home SOC lab:
**Wazuh 4.14.5** (manager, Ubuntu) + **Windows 11** endpoint with **Sysmon**
(SwiftOnSecurity config).

Each detection follows a five-step loop:
**behavior → data source → rule → testing (positive + negative + regression) → lessons learned.**

<!-- İstersen buraya kendi cümlenle 1-2 satır ekle: kim olduğun ve neden
     bu repo'yu tuttuğun. Örnek kalıp:
     "I am a cybersecurity student focusing on blue team operations.
     This repo documents my detection rules and — more importantly —
     the debugging process behind them." -->

## Detections

| # | Name | Technique | Status |
|---|---|---|---|
| 001 | [Account Discovery via net.exe](detections/001-account-discovery-net-user/) | T1087 | ✅ Tested |
| 002 | [User Identity Discovery via whoami](detections/002-user-identity-discovery-whoami/) | T1033 | ✅ Tested |
| 003 | [User Identity Discovery via Environment Variable](detections/003-user-identity-discovery-env-var/) | T1033 | ✅ Tested |

## Lab Setup

- **SIEM:** Wazuh 4.14.5 all-in-one (Ubuntu VM, VMware)
- **Endpoint:** Windows 11 VM, Sysmon with SwiftOnSecurity configuration, Wazuh agent
- **Telemetry:** Sysmon Event ID 1 (process creation) and PowerShell
  Script Block Logging (Event ID 4104)
- **Method:** Custom rules in `local_rules.xml`, validated with positive,
  negative, and regression tests before being marked as tested