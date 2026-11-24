# sigma2wazuh (P6)

This tool converts a curated set of SigmaHQ rules into Wazuh rules, using pySigma to parse them. The output is installed on the siem (CT 100) as `/var/ossec/etc/rules/sigma_rules.xml`. Built 2026-11-23/24.

## What's converted

Only Sigma rules whose log sources this lab actually sends to Wazuh are included.

| Sigma rules | Wazuh data | Notes |
|---|---|---|
| `windows/builtin/security`, `windows/builtin/system` | DC01, DC02 and the desktop eventchannel (Security, System) | There's no Sysmon or PowerShell/Operational channel yet, so `process_creation` rules are out. |
| `web/webserver_generic` | NPM access logs (decoder `npm-access-fields`) | NPM is a reverse proxy in front of the public sites, so these are inbound webserver logs. |
| `web/proxy_generic` | NPM, user-agent rules only | The URL/TLD/download rules describe outbound browsing and would fire on Nextcloud downloads. |

Network (DNS/firewall) Sigma rules aren't included. That data lives in the syslog collector, not Wazuh, and the anomaly engine covers it.

The current build has 183 Sigma rules, giving 249 Wazuh rules (IDs 101000-101248). 68 were skipped; the reason for each is in `report.md`. Sigma statuses `stable` and `test` are included, plus four experimental AD rules listed in the config.

## How a Sigma rule becomes Wazuh rules

1. pySigma parses the rule and resolves its condition into an AND/OR/NOT tree over field/value tests.
2. The tree is rewritten as an OR of ANDs. Each AND becomes one Wazuh rule, because a Wazuh rule can only AND its conditions. A Sigma rule needing more than 6 Wazuh rules is skipped.
3. All tests on one field inside an AND become a single PCRE2 expression, using lookaheads. Sigma's case-insensitive whole-value matching is kept, and its wildcards are honoured. ORs over one field become one alternation. Negations use `negate="yes"`.
4. Windows field names get Wazuh's eventdata naming: `TargetUserName` becomes `win.eventdata.targetUserName`, and `EventID` becomes `win.system.eventID`. NPM fields map to the NPM decoder's fields: `url`, `protocol` (the HTTP method), `id` (the status), `npm.useragent` and `npm.host`.
5. ATT&CK tags come from the Sigma rule. Sigma already uses ATT&CK v18 IDs (T1685.x) that Wazuh 4.14 doesn't know, so `mitre_map` in the config maps them to the older equivalents.

Anything that can't be mapped or expressed exactly is skipped, never approximated. That covers aggregations, unmapped fields and huge expansions.

## Wazuh rule-tree gotchas found while testing (important if you change the parent)

- **Parent.** Windows Sigma rules use `<if_group>windows</if_group>`, which makes each one a child of every built-in Windows rule. Wazuh never backtracks to a sibling once a child matches, and the built-in grouping rules (60001, then 60103/60104, then 60106...) claim events first. So a Sigma rule hung under 60000 or 60001 never saw most events.
- **Group name.** Wazuh matches `if_group` as a substring of a rule's group list. The Sigma rules must not carry any group containing "windows": with `sigma_windows` they became children of each other, and `wazuh-analysisd -t` never finished. They use `sigma_win`.
- **Static fields.** Fields like `url`, `id`, `protocol` and `srcip` can't go in `<field name=...>`; they need their own tags.
- **logtest limits.** `wazuh-logtest` and the logtest socket can't decode eventchannel events (they come out as `json`). Windows rules were therefore tested by sending synthetic events through the analysisd queue (`test-inject.py`). Those events use computer name `P6-TEST`.

## Site-specific filters

`local_filters` in the config adds extra exclusions to named Sigma rules without editing them. Today it holds one exclusion: the LAN's own global IPv6 (`2001:db8:4a00:1f80::/57`) for the three "logon from public IP" rules. DC logons from LAN hosts arrive from those addresses, and fired 101011 six times in four minutes before the filter.

## Re-running

```
git clone --depth 1 https://github.com/SigmaHQ/sigma.git sigma-repo
pip install pysigma pyyaml
python3 sigma2wazuh.py --config sigma2wazuh.yml --out sigma_rules.xml --report report.md --tests tests.jsonl
```

Then on the siem:

1. Copy the output to `/var/ossec/etc/rules/sigma_rules.xml` (wazuh:wazuh 660).
2. Run `timeout 60 /var/ossec/bin/wazuh-analysisd -t`. It should finish in about a second; if it hangs, check the group names.
3. Restart wazuh-manager.
4. Run `test-inject.py` and confirm the four test alerts.

---

*Published from a home lab. Site identifiers are sanitized: public IPv4 uses the documentation ranges (203.0.113.0/24, 198.51.100.0/24), the delegated IPv6 prefix is `2001:db8::/32`, the ULA prefix is `fd12:3456:789a::/48`, domains are `example.com` / `home.arpa`, MAC addresses, Wi-Fi SSIDs, serials, keys and names are replaced. RFC 1918 addresses are left as they are so the layouts still read. Credentials are never in these files; scripts read them from `agent.env` or similar files that are not published.*

## Disclaimer

This repository is shared **as is**, for reference and learning. It is a personal home-lab project, not a product, and it comes with no support.

- **No warranty.** Everything here (code, configurations, scripts, rules and documentation) is provided without warranty of any kind, express or implied, including fitness for a particular purpose. It may contain bugs, errors or omissions.
- **No commitment to maintain.** The author makes no commitment to fix bugs, answer questions, upgrade or update this repository beyond what is provided here. Any future updates are made purely on a voluntary basis, at the author's sole discretion, and may stop at any time.
- **You are solely responsible.** Any review, adaptation, configuration, testing, deployment or operation of this material is solely the responsibility of the person using it. Bugs, fixes and updates in your environment are yours to handle.
- **No liability.** To the fullest extent permitted by law, the author is not liable for any damages or losses of any kind arising from the use or misuse of this material, including but not limited to outages, data loss, security incidents, lost revenue, damage to hardware or other property, and any physical or digital harm.
- **Test before you trust.** Several scripts change firewalls, routers, DNS, authentication or system services. Read them, adapt them to your network, test them in a lab, and keep backups and a rollback path before running anything in production.

## License

The code and documentation in this repository are released under the [MIT License](LICENSE), an open-source license, unless a file or folder states otherwise.

### Third-party content

`sigma_rules.xml` is generated from detection rules in the [SigmaHQ repository](https://github.com/SigmaHQ/sigma) (commit noted in the file header). Those rules are licensed by their authors under the [Detection Rule License (DRL) 1.1](https://github.com/SigmaHQ/Detection-Rule-License), not under MIT. Each converted rule carries a comment with the original Sigma rule ID and file path; the original authors are credited in those source files. The converter (`sigma2wazuh.py`), its configuration and the documentation are MIT-licensed.
