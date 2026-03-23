# Threat Hunting Incident Report

**Generated at:** 2026-03-23 18:41:40

## Table of Contents

- [Executive Summary](#executive-summary)
- [HIGH Severity Alerts](#high-severity-alerts)
- [MEDIUM Severity Alerts](#medium-severity-alerts)

## Executive Summary

**Total alerts detected:** 4

### Alerts by Severity

| Severity | Count |
| --- | --- |
| HIGH | 2 |
| MEDIUM | 2 |

### Alerts by Rule

| Rule | Count |
| --- | --- |
| Brute Force Followed by Success | 1 |
| Suspicious Process Execution | 2 |
| Rare Outbound Connection | 1 |

## HIGH Severity Alerts

### 1. Possible brute force attack followed by successful login

| Field | Value |
| --- | --- |
| Alert ID | `24b83cc9-1536-409d-8afa-55d63c2fb7c3` |
| Rule | `Brute Force Followed by Success` (`RULE-001`) |
| Severity | `HIGH` |
| User | `adi` |
| Host | `host1` |
| Source IP | `185.24.10.8` |
| First Seen | `2026-03-20 09:00:00` |
| Last Seen | `2026-03-20 09:02:00` |
| Evidence Count | `11` |

#### Description
Detected 10 failed login attempts followed by a successful login within 5 minutes.

#### Recommended Actions
- Review the source IP for suspicious activity.
- Validate whether this login was expected.
- Check for additional suspicious activity on the host.
- Consider resetting the affected user's credentials.

#### Evidence Event IDs
| Event ID |
| --- |
| `9532d16e-6b8d-42cd-b4b2-4d3f22bae82e` |
| `d53f9b4e-f81f-41f3-a216-5a5315ef9bf9` |
| `d5f863be-33eb-450f-b1c7-f58df7914fd5` |
| `ede20770-d745-46cc-88f6-609662ed7ea3` |
| `de8ba4b6-92fc-41ea-a38e-de7a183f5257` |
| `8d517fcd-5100-4259-bae4-94998e80c126` |
| `547cc8ee-417b-47d5-9123-3559bea6b6fa` |
| `d82b0a99-8f78-4384-9620-1ae4329b4a3e` |
| `ca098ca4-bc66-40d1-a95a-289f78fd6493` |
| `485a6805-14fe-4f0c-8ddf-5a5fab783db1` |
| `ddfb9bdf-3d57-4b50-964c-9c41046f8b76` |

---

### 2. Suspicious encoded PowerShell execution detected

| Field | Value |
| --- | --- |
| Alert ID | `2afc2a27-bcc7-4f65-8917-d827798ff2ff` |
| Rule | `Suspicious Process Execution` (`RULE-002`) |
| Severity | `HIGH` |
| User | `adi` |
| Host | `host1` |
| Source IP | `N/A` |
| First Seen | `2026-03-20 09:03:00` |
| Last Seen | `2026-03-20 09:03:00` |
| Evidence Count | `1` |

#### Description
Detected suspicious process execution: process='powershell.exe', parent='explorer.exe', indicators=['-enc'].

#### Recommended Actions
- Review the full command line and execution context.
- Inspect the parent process and child process chain.
- Check whether the command was expected for this user and host.
- Investigate related authentication and network activity around this time.

#### Evidence Event IDs
| Event ID |
| --- |
| `6a6c2c18-6754-4f64-a954-48de06f1edef` |

---

## MEDIUM Severity Alerts

### 1. Suspicious process execution detected

| Field | Value |
| --- | --- |
| Alert ID | `8079efd3-f5f8-47bf-ad6e-2db65ad9998e` |
| Rule | `Suspicious Process Execution` (`RULE-002`) |
| Severity | `MEDIUM` |
| User | `adi` |
| Host | `host1` |
| Source IP | `N/A` |
| First Seen | `2026-03-20 09:04:30` |
| Last Seen | `2026-03-20 09:04:30` |
| Evidence Count | `1` |

#### Description
Detected suspicious process execution: process='cmd.exe', parent='powershell.exe', indicators=['whoami'].

#### Recommended Actions
- Review the full command line and execution context.
- Inspect the parent process and child process chain.
- Check whether the command was expected for this user and host.
- Investigate related authentication and network activity around this time.

#### Evidence Event IDs
| Event ID |
| --- |
| `c890c3d0-220c-44b6-8a93-c67e853cc525` |

---

### 2. Rare outbound network connection detected

| Field | Value |
| --- | --- |
| Alert ID | `a8fe61c2-f045-4102-9a00-f24f9e84b099` |
| Rule | `Rare Outbound Connection` (`RULE-003`) |
| Severity | `MEDIUM` |
| User | `N/A` |
| Host | `host1` |
| Source IP | `10.0.0.5` |
| First Seen | `2026-03-20 09:05:00` |
| Last Seen | `2026-03-20 09:05:00` |
| Evidence Count | `1` |

#### Description
Detected outbound connection from host 'host1' to external IP '185.99.88.77' on uncommon port '4444/TCP'.

#### Recommended Actions
- Review the destination IP and port for known malicious activity.
- Inspect processes running on the source host around this time.
- Check whether this outbound connection is expected for the host.
- Correlate this event with recent authentication or process alerts.

#### Evidence Event IDs
| Event ID |
| --- |
| `e2647f3c-533b-4f07-83f1-3584894367d6` |

---
