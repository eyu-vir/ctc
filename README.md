**SOC Automation Pipeline**  
**SOC Analyst**  
 **Prepared by:** Eyuel shimels  
An automated incident-response pipeline that takes a raw security event (an endpoint alert or a suspicious email) and turns it into a triaged, enriched, AI-summarized case, with automatic containment or remediation in several workflows.  
```  
Wazuh → n8n → TheHive → Cortex → Groq AI → Automated Response  
   
```  
  
|  |  |  
| - | - |  
| **Metric** |  **Value** |  
| Independent n8n workflows |  8 |  
| Custom Wazuh detection rules |  19 |  
| Detection surfaces |  2 (endpoint telemetry, email) |  
| Max firewall block lifetime |  24h |  
  
   
Validated against real, live attack traffic against the server, not only staged simulations.  
**Design principle: isolate blast radius.** Small single-purpose workflows fail independently. One giant workflow fails all at once.  
  
---  
**Contents**  
1. [Architecture](#anchor-1 "#anchor-1")  
2. [Environment](#anchor-2 "#anchor-2")  
3. [Detection engine (Wazuh)](#anchor-3 "#anchor-3")  
4. [Workflows](#anchor-4 "#anchor-4")  
5. [Threat-intel enrichment (Cortex)](#anchor-5 "#anchor-5")  
6. [Dashboards](#anchor-6 "#anchor-6")  
7. [Real-world validation](#anchor-7 "#anchor-7")  
8. [Attack simulation library](#anchor-8 "#anchor-8")  
9. [Outstanding items](#anchor-9 "#anchor-9")  
10. [Limitations](#anchor-10 "#anchor-10")  
  
---  
**Architecture**  
  
|  |  |  
| - | - |  
| **Category** |  **Coverage** |  
| Detection sources |  Wazuh (Linux host + Windows endpoint), Wazuh FIM (honeytoken), IMAP inbox |  
| Case management |  TheHive |  
| Enrichment |  Cortex: AbuseIPDB, VirusTotal (IP, domain, URL, file-hash) |  
| AI reasoning |  Groq (cloud LLM): verdicts, risk scoring, campaign narratives |  
| Notification |  Telegram |  
| Response actions |  UFW (Linux), Windows Firewall / netsh, scheduled-task removal, threat-intel proactive blocking |  
  
   
  
---  
**Environment**  
  
|  |  |  
| - | - |  
| **Component** |  **Detail** |  
| Host server |  Ubuntu 24.04 LTS |  
| Windows endpoint |  Sysmon telemetry forwarded via Wazuh agent |  
| Wazuh |  Manager v4.12.0 (native systemd), ports 1514 / 1515 / 55000 |  
| Wazuh agent (Windows) |  v4.12.0, upgraded to match the manager |  
| Sysmon |  SwiftOnSecurity config via ossec.conf eventchannel |  
| n8n |  Docker, port 5678, orchestration for all workflows |  
| TheHive |  v4.1.24, Docker, port 9000, persistent bind-mount volume |  
| Cortex |  Docker, port 9001, 2 analyzers enabled |  
| Cortex Elasticsearch |  Dedicated container, remapped to 9202:9200 |  
| Docker network |  Shared bridge so Cortex and TheHive resolve each other by name |  
| AI provider |  Groq cloud API (local Ollama evaluated, dropped due to host resources) |  
  
   
**Issues resolved during setup**  
- **Agent registration dropping:** fixed by upgrading the Windows agent to match the manager version (v4.12.0).  
- **Port 9200 conflict:** Cortex's Elasticsearch collided with the Wazuh Indexer, remapped to `9202:9200`.  
- **TheHive data loss (x2):** data lived only in the container filesystem, fixed with a persistent bind-mount.  
- **n8n "TheHive 5" node bug:** resource mapper never sends field data, replaced with the plain "TheHive" node.  
- **Cortex analyzers are Process-mode:** required installing Python3, pip and per-analyzer dependencies inside the container, plus the API pattern for enabling analyzers programmatically.  
  
---  
**Detection engine (Wazuh)**  
19 custom rules in `local_rules.xml` (deduplicated after a duplicate-definition bug on rule 100100).  
**Windows**  
  
|  |  |  
| - | - |  
| **Rule** |  **Detects** |  
| 100050 |  Encoded / obfuscated PowerShell (T1027, T1059.001) |  
| 100051 |  PowerShell download cradle |  
| 100052 |  Hidden PowerShell window |  
| 100055 |  Enumeration / recon (whoami, net user, systeminfo) |  
| 100056 |  Registry persistence |  
| 100057 |  Scheduled task creation |  
| 100059 |  Firewall disabled |  
| 100060 |  New local user |  
| 100061 |  User added to administrators |  
| 100062 |  Admin group modification |  
| 100063 |  Base64 detection (general) |  
| 100100 |  Windows brute-force correlation (5 hits / 60s per source IP, T1110) |  
  
   
**Linux / PAM**  
  
|  |  |  
| - | - |  
| **Rule** |  **Detects** |  
| 100011 |  Failed sudo attempt |  
| 100012 |  New Linux user created |  
| 100013 |  SSH root login attempt (classified as Brute Force, not Privilege Escalation) |  
| 100014 |  User added to sudoers / wheel |  
  
   
**Threat-intel integration**  
- 100092 / 100093: VirusTotal integration rules.  
**Validation**  
- `wazuh-logtest` confirmed Sysmon captures process creation correctly, so any gaps were rule or config issues, not telemetry.  
- Rule 100050 confirmed firing live on real obfuscated PowerShell.  
**Built-in Wazuh modules used**  
MITRE ATT&CK dashboard, Vulnerability Detector, Security Configuration Assessment (CIS), and File Integrity Monitoring (also the trigger for Workflow 6).  
  
---  
**Workflows**  
  
|  |  |  |  |  
| - | - | - | - |  
| **#** |  **Workflow** |  **Trigger** |  **One-line purpose** |  
| 1 |  Main Detection & Response |  Webhook from Wazuh |  Classify, enrich, AI verdict, case, notify, contain |  
| 2 |  Proactive Threat-Intel Blocking |  Every 6h |  Block known C2 IPs before they attack |  
| 3 |  Block Expiry Governance |  Every 1h |  No automated block outlives 24h |  
| 4 |  Kill-Chain Campaign Correlator |  Every 15 min |  Link multi-stage attacks from one source |  
| 5 |  Pipeline Health Monitoring |  Every 15 min |  Alert when n8n / TheHive / Cortex / Groq go down |  
| 6 |  Honeytoken Trap |  Wazuh FIM webhook |  Decoy file touched = instant high-severity case |  
| 7 |  Scheduled-Task Auto-Remediation |  Rule 100057 |  Hash the task's binary, check VirusTotal, delete if malicious |  
| 8 |  Phishing Detection via IMAP |  New email |  Domain/URL checks, then full TheHive case lifecycle |  
  
   
**Workflow 1: Main Detection & Response**  
1. **Classify & filter:** rule-ID allowlist drops noise (fixes an earlier flood of 20,000+ alerts), maps to 1 of 13 attack types, extracts source IP.  
2. **Case creation:** structured TheHive alert with severity, tags, observables.  
3. **Enrichment:** Cortex queries AbuseIPDB and VirusTotal in parallel. Alerts without an IP skip this step.  
4. **AI verdict:** Groq produces summary, risk level, recommended action. Composite 0-100 score = rule severity 40% + AbuseIPDB 30% + VirusTotal 30%.  
5. **Notification:** TheHive case updated, Telegram alert sent.  
6. **Containment:** parallel branch checks severity, attack type and allowlist, then inserts a UFW (Linux) or Windows Firewall rule.  
**Safety controls:** hardcoded IP allowlist, containment gated on severity and confirmed attack type, 10-minute dedup window per rule + source.  
**Workflow 2: Proactive Threat-Intel Blocking**  
Pulls the abuse.ch Feodo Tracker feed every 6h, filters out allowlisted and already-blocked IPs, and inserts `ufw deny` rules for the rest. Blocks are logged to the same `blocked_ips.log` used by Workflow 1, so Workflow 3 expires them automatically.  
   
 **Result:** 5 confirmed C2 IPs blocked live.  
**Workflow 3: Block Expiry Governance**  
Hourly `expire_blocks.sh` reads `blocked_ips.log` (`IP,unix_timestamp`), removes UFW rules older than 86400s, and appends to `expiry_audit.log` with a UTC timestamp. One expiry mechanism for every path that can create a block, and every expiry is auditable.  
**Workflow 4: Kill-Chain Campaign Correlator**  
Groups TheHive cases by source over a rolling 1-hour window. Flags a campaign only when a single source hits 2+ distinct attack stages (repeats of one stage are noise). Groq writes a narrative, and a consolidated Campaign case is created in TheHive.  
   
 **Result:** correctly separated a real multi-stage attack from unrelated concurrent activity.  
**Workflow 5: Pipeline Health Monitoring**  
One Code node checks n8n, TheHive, Cortex and Groq with a 5s timeout each and returns `{ statuses, unhealthy, hasFailures, checkedAt }`. Telegram fires only on failure, so a healthy stack is silent.  
   
 **Tested both directions:** stopping Cortex triggered the alert, and restarting it cleared the alert.  
**Workflow 6: Honeytoken Trap**  
A decoy file is watched by Wazuh FIM. Any touch fires a webhook, builds a `honeytoken-triggered` alert, opens a TheHive case that bypasses risk scoring, and sends a distinct Telegram alert. Same principle as commercial deception tools like Thinkst Canary: it catches unknown attacker behavior because only an intruder would touch the asset.  
**Workflow 7: Scheduled-Task Auto-Remediation**  
Parses the task's target executable, computes its SHA256, checks the hash on VirusTotal via Cortex, and if flagged above threshold, deletes the task with `schtasks /delete /tn "<task-name>" /f`. Clean binaries are left alone. This closes the loop on persistence at the endpoint, beyond IP blocking.  
**Workflow 8: Phishing Detection via IMAP**  
A separate detection surface (inbound email) carried through the full TheHive lifecycle:  
   
 parse sender domain and URLs, then VirusTotal domain and URL checks in parallel, merge, then Telegram summary (always), then if suspicious: case, phishing response task checklist, lessons-learned entry, and case closure.  
  
---  
**Threat-intel enrichment (Cortex)**  
- Analyzers: `AbuseIPDB_2_0` and `VirusTotal_GetReport_3_1`, plus VirusTotal file-hash lookups for Workflow 7.  
- Both are Process-mode (plain Python), not Docker-mode.  
- Confirmed on real attack data: IP `45.156.87.91` was flagged by both AbuseIPDB and VirusTotal (20/91 vendors).  
  
---  
**Dashboards**  
Built on Wazuh's OpenSearch dashboards (index pattern `wazuh-alerts-*`). Eight dashboards:  
  
|  |  |  |  
| - | - | - |  
| **#** |  **Dashboard** |  **Approach** |  
| 1 |  Executive / SOC Overview |  Custom: severity pie, attack-type bar, top source IPs, timeline |  
| 2 |  MITRE ATT&CK Coverage |  Native Wazuh module |  
| 3 |  Windows Endpoint Threat |  Custom, scoped to the Windows agent |  
| 4 |  Linux / Auth |  Custom, incl. geo-map (needs GeoIP module) |  
| 5 |  Threat Intel Enrichment |  Presented from TheHive / Cortex data |  
| 6 |  Response / Containment |  Presented from n8n Executions + live `ufw status` |  
| 7 |  Vulnerability & Compliance |  Native Wazuh modules |  
| 8 |  Campaign Correlation |  Presented from TheHive Campaign cases |  
  
   
  
---  
**Real-world validation**  
The server was under genuine external attack during the project:  
- `45.156.87.91`: SSH root login attempts, confirmed malicious by both intel sources, full pipeline run with AI verdict and Telegram alert.  
- `45.148.10.152`: repeated attempts, rule fired 69 times.  
- `209.97.183.43`: direct SSH attempts against the Windows endpoint.  
- Multiple IPs scanning TheHive's exposed API from the internet.  
  
---  
**Attack simulation library**  
Safe, repeatable simulations with documented commands and cleanup steps: Brute Force, Execution (encoded PowerShell), Persistence (scheduled task / new Linux user), Privilege Escalation (new admin account), Reconnaissance (whoami / net user / systeminfo), Defense Evasion (firewall disable / re-enable), Log Tampering (event log clear).  
  
---  
**Outstanding items**  
- Confirm the VirusTotal parallel branch connection on the Workflow 1 canvas  
- Rotate all credentials exposed during build sessions (sudo password, Cortex API keys, TheHive API key)  
- Complete Cortex and TheHive shared Docker network config and generate the TheHive org API key for Cortex  
- Run an end-to-end adversary emulation test (Atomic Red Team) on the Windows endpoint  
  
---  
**Limitations**  
- **Proactive blocking only covers known threats.** Feodo Tracker gives no protection against a novel attacker. Reactive detection (Workflow 1) is the only defense against first-seen attackers.  
- **Single-host deployment.** The whole stack runs on one resource-constrained VM. It is a single point of failure for every workflow, including the health monitor.  
- **Cloud AI dependency.** Local Ollama was impractical, so alert data (IPs, usernames, process details) goes to Groq, a third-party cloud. Fine for a demo, but it needs security review before production use.  
  
---  
**Summary**  
Eight workflows cover the operational loop of a modern SOC: real-time detection and AI-assisted triage, safety-gated containment, proactive defense against known threats, time-boxed automated actions, cross-alert correlation, deception-based detection, self-healing endpoint remediation, health monitoring of the pipeline itself, and a second detection surface carried through the full incident lifecycle.  
Every automated response is safety-gated: allowlisted, severity-gated, throttled and time-boxed.  
