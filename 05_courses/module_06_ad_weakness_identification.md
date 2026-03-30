# Module 6: Identifying AD Weaknesses Through Logs

[← Module 5: Attacker Tooling Signatures](./module_05_attacker_tooling_signatures.md) | [Module 7: Threat Hunting Capstone →](./module_07_threat_hunting_capstone.md)

---

## Module Overview

| Attribute | Detail |
|---|---|
| **Estimated Time** | 2 hours |
| **PEAK Phase** | Prepare → Explore → Knowledge |
| **Data Sources** | WinEvent 4624/4625/4662/4668/4769/4728/5136/7045, Sysmon EID 1 |
| **Prerequisites** | [Module 5: Attacker Tooling Signatures](./module_05_attacker_tooling_signatures.md) |

### Learning Objectives

After completing this module you will be able to:

1. Identify AD misconfigurations that enable common attacks using only log evidence.
2. Write SPL queries to surface vulnerable accounts (AS-REP roastable, Kerberoastable) and over-privileged configurations.
3. Detect stale privileged accounts and over-permissive ACLs via log analysis.
4. Build a periodic weakness report using Splunk saved searches.

> **Key mindset shift:** This module is about finding *configurations* that enable attacks — not detecting attacks already in progress. Proactive weakness identification removes attacker leverage before an attack begins.

---

## Weakness 1: Accounts Without Kerberos Pre-Authentication

### What It Is

When `Do not require Kerberos preauthentication` is set on a user account, any requestor can ask for an AS-REP without providing a timestamp encrypted with the account's password. The response is encrypted with the account's hash — available for offline cracking without any credentials.

**Enables:** AS-REP Roasting (T1558.004)

### Log Evidence

```spl
/* Find accounts responding without pre-authentication in the last 30 days */
index=wineventlog EventCode=4768 earliest=-30d
| where PreAuthType="0"
| stats count AS as_req_count,
        min(_time) AS first_seen,
        max(_time) AS last_seen,
        dc(IpAddress) AS unique_requesters
    BY TargetUserName
| eval days_active = round((last_seen - first_seen) / 86400, 0)
| sort - as_req_count
| table TargetUserName, as_req_count, unique_requesters, days_active
```

### Remediation

Enable Kerberos pre-authentication on all user accounts. Only set `DONT_REQUIRE_PREAUTH` when a legacy application genuinely requires it, and document the exception.

---

## Weakness 2: Service Accounts with SPNs and RC4 Encryption

### What It Is

Service accounts with SPNs can be Kerberoasted — any authenticated user can request a TGS for them. If those SPNs use RC4 (legacy) rather than AES encryption, the tickets are fast to crack offline. The presence of RC4 TGS requests in logs indicates either Kerberoasting or legacy clients that haven't been migrated.

**Enables:** Kerberoasting (T1558.003)

### Log Evidence

```spl
/* Service accounts being requested with RC4 encryption — potential Kerberoasting targets */
index=wineventlog EventCode=4769 earliest=-30d
| where TicketEncryptionType="0x17"
| where NOT match(ServiceName, "krbtgt|\\$$")
| stats count AS rc4_requests,
        dc(SubjectUserName) AS unique_requesters,
        min(_time) AS first_seen,
        max(_time) AS last_seen
    BY ServiceName
| eval days_active = round((last_seen - first_seen) / 86400, 0)
| sort - rc4_requests
| table ServiceName, rc4_requests, unique_requesters, days_active
```

```spl
/* Distinguish roasting (burst from single user) vs legacy clients (regular from many users) */
index=wineventlog EventCode=4769 earliest=-7d
| where TicketEncryptionType="0x17"
| where NOT match(ServiceName, "krbtgt|\\$$")
| stats count AS requests, dc(SubjectUserName) AS requesters BY ServiceName, SubjectUserName
| eval roast_indicator = if(requests > 5 AND requesters < 2, "LIKELY ROASTING", "Legacy client")
| sort - requests
```

### Remediation

Configure service accounts for AES256 encryption (`msDS-SupportedEncryptionTypes = 24`). Migrate legacy applications that require RC4. Use Group Managed Service Accounts (gMSA) with auto-rotating 240-character passwords — making even successfully cracked hashes useless.

---

## Weakness 3: Unconstrained Delegation

### What It Is

Hosts configured with unconstrained delegation receive a copy of the TGT of any user who authenticates to them. An attacker who compromises such a host can extract all TGTs that have been cached — including Domain Admin TGTs if any DA has authenticated to that host.

**Enables:** Credential theft, Golden Ticket attacks, Lateral Movement

### Log Evidence

```spl
/* Accounts authenticating to hosts with unconstrained delegation */
/* First identify high-value accounts authenticating to non-DC servers */
index=wineventlog EventCode=4769 earliest=-7d
| where NOT match(ServiceName, "krbtgt|\\$$")
| where match(SubjectUserName, "(?i)admin|svc_|service")
| lookup unconstrained_delegation_hosts hostname as ServiceName OUTPUT has_unconstrained
| where has_unconstrained = "true"
| stats count AS auth_count, dc(SubjectUserName) AS unique_users
    BY ServiceName, has_unconstrained
| sort - auth_count
```

```spl
/* Printer Bug / SpoolSample: forcing DC to authenticate to unconstrained delegation host */
/* Look for DC computer accounts requesting TGS (they shouldn't initiate these) */
index=wineventlog EventCode=4769 earliest=-24h
| where match(SubjectUserName, "\\$$")
| lookup dc_list computername as SubjectUserName OUTPUT is_dc
| where is_dc = "true"
| lookup unconstrained_delegation_hosts hostname as ServiceName OUTPUT has_unconstrained
| where has_unconstrained = "true"
| table _time, SubjectUserName, ServiceName, IpAddress
```

### Remediation

Audit unconstrained delegation objects in AD (`Get-ADComputer -Filter {TrustedForDelegation -eq $true}`). Migrate to constrained delegation (specific SPNs only) or resource-based constrained delegation. Mark sensitive accounts with `Account is sensitive and cannot be delegated`.

---

## Weakness 4: AdminSDHolder ACL Misconfigurations

### What It Is

The AdminSDHolder object controls the ACL template applied to all protected AD groups (Domain Admins, Enterprise Admins, etc.) every 60 minutes via the SDProp process. If an attacker grants themselves write permissions on AdminSDHolder, those permissions propagate to all protected groups automatically — creating persistent privileged access that survives manual remediation attempts on the group objects themselves.

**Enables:** Persistent privilege (T1098), defence evasion

### Log Evidence

```spl
/* Changes to AdminSDHolder object or protected group ACLs */
index=wineventlog EventCode=5136 earliest=-30d
| where match(ObjectDN, "(?i)AdminSDHolder|CN=Domain Admins|CN=Enterprise Admins|CN=Schema Admins")
| where NOT match(SubjectUserName, "\\$$")
| lookup dc_list computername as SubjectUserName OUTPUT is_dc
| where isnull(is_dc)
| stats count, values(AttributeLDAPDisplayName) AS changed_attrs,
        values(AttributeValue) AS new_values
    BY SubjectUserName, ObjectDN
| sort - count
```

```spl
/* Permission changes on sensitive AD objects (EID 4670) */
index=wineventlog EventCode=4670 earliest=-30d
| where match(ObjectName, "(?i)AdminSDHolder|Domain Admins|Enterprise Admins")
| table _time, SubjectUserName, ObjectName, OldSd, NewSd
```

### Remediation

Audit AdminSDHolder permissions (`(Get-Acl "AD:CN=AdminSDHolder,CN=System,...").Access`). Remove all non-administrative write permissions. Monitor EID 5136 on AdminSDHolder as a tier-0 alert.

---

## Weakness 5: Over-Privileged Service Accounts

### What It Is

Service accounts accumulate privileges over time — a DBA service account might be in Domain Admins "temporarily" for a project and never removed. These accounts are high-value Kerberoasting targets because: (a) they have SPNs, (b) they have domain admin or high privilege, and (c) they often have weak passwords set years ago.

**Enables:** Privilege escalation, lateral movement

### Log Evidence

```spl
/* Service accounts with Domain Admin group membership that still log in */
index=wineventlog EventCode=4624 earliest=-30d
| where match(SubjectUserName, "(?i)svc_|service|task|batch|sql|backup|monitor")
| where LogonType IN ("2","3","10")
| stats count AS login_count,
        dc(ComputerName) AS unique_hosts,
        min(_time) AS first_login,
        max(_time) AS last_login
    BY SubjectUserName
| sort - unique_hosts
```

```spl
/* Service accounts (contain 'svc_' pattern) in privileged groups (from group add events) */
index=wineventlog (EventCode=4728 OR EventCode=4732 OR EventCode=4756) earliest=-180d
| where match(MemberName, "(?i)svc_|service|sql|backup")
| where match(GroupName, "(?i)Domain Admins|Enterprise Admin|Schema Admin|Backup Operators")
| stats count, values(GroupName) AS groups_added_to
    BY MemberName, SubjectUserName
| sort - count
```

### Remediation

Apply least-privilege to service accounts. Use gMSA/sMSA where possible. Audit service account group memberships quarterly via PowerShell:
```powershell
Get-ADGroupMember "Domain Admins" | Where-Object {$_.objectClass -eq "user"} |
  Get-ADUser -Properties ServicePrincipalNames, PasswordLastSet |
  Select-Object Name, PasswordLastSet, ServicePrincipalNames
```

---

## Weakness 6: NTLM in Modern Environments

### What It Is

NTLM authentication is vulnerable to Pass-the-Hash and relay attacks. In modern environments, all domain authentication should use Kerberos. NTLM should only appear for: (a) local accounts, (b) IP-based connections where Kerberos cannot be used, (c) legacy applications that haven't been updated.

**Enables:** Pass-the-Hash (T1550.002), NTLM Relay attacks

### Log Evidence

```spl
/* NTLM authentication volume by account — identify accounts using NTLM when they shouldn't */
index=wineventlog EventCode=4624 earliest=-7d
| where AuthenticationPackageName="NTLM"
| where NOT match(SubjectUserName, "ANONYMOUS|\\$$")
| where SubjectDomainName != "NT AUTHORITY"
| stats count AS ntlm_logins,
        dc(ComputerName) AS unique_targets,
        dc(IpAddress) AS unique_sources
    BY SubjectUserName, SubjectDomainName
| sort - ntlm_logins
| head 50
```

```spl
/* NTLM usage trend — are we reducing NTLM over time? */
index=wineventlog EventCode=4624 earliest=-30d
| eval auth_type = if(AuthenticationPackageName="NTLM", "NTLM", "Kerberos/Other")
| timechart span=1d count BY auth_type
```

### Remediation

Block NTLM via GPO (`Network security: Restrict NTLM`). Start with audit mode to identify all NTLM sources before blocking. Use Kerberos delegation for service accounts. Add server names to DNS and use FQDNs to prevent IP-based connections forcing NTLM.

---

## Weakness 7: Stale Privileged Accounts

### What It Is

Accounts in Domain Admins or other privileged groups that have not logged in for 90+ days represent lingering attack surface. Former employees, contractors, or project-specific accounts that were never deprovisioned can be compromised and used without detection if no one monitors activity for those accounts.

**Enables:** Credential reuse, persistence

### Log Evidence

```spl
/* Privileged group members with low recent login activity */
/* Step 1: identify current DA group members from group change events */
index=wineventlog (EventCode=4728 OR EventCode=4732) earliest=-180d
| where match(GroupName, "(?i)Domain Admins|Enterprise Admins|Schema Admins")
| stats count BY MemberName

/* Step 2: join with recent login data */
| join MemberName [
    search index=wineventlog EventCode=4624 earliest=-90d
    | stats max(_time) AS last_login BY SubjectUserName
    | rename SubjectUserName AS MemberName
    ]
| eval days_since_login = round((now() - last_login) / 86400, 0)
| where isnull(last_login) OR days_since_login > 60
| sort - days_since_login
| table MemberName, last_login, days_since_login
```

### Remediation

Implement a periodic privileged account review (quarterly minimum). Disable accounts after 45 days of inactivity; delete after 90 days. Use tiered access model — no-one should have standing Domain Admin access; use just-in-time (JIT) privilege elevation.

---

## Building a Periodic Weakness Report

Save this search in Splunk as a weekly scheduled report to surface the most critical AD weaknesses:

```spl
/* Weekly AD Weakness Summary */
index=wineventlog earliest=-7d
    (EventCode=4768 AND PreAuthType="0")
    OR (EventCode=4769 AND TicketEncryptionType="0x17")
    OR (EventCode=5136 AND match(ObjectDN, "(?i)AdminSDHolder|Domain Admins"))
    OR (EventCode=4624 AND AuthenticationPackageName="NTLM" AND NOT match(SubjectUserName, "\\$$"))
| eval weakness_type = case(
    EventCode=4768 AND PreAuthType="0", "AS-REP Roastable Account",
    EventCode=4769 AND TicketEncryptionType="0x17", "Kerberoastable with RC4",
    EventCode=5136 AND match(ObjectDN, "(?i)AdminSDHolder"), "AdminSDHolder Modified",
    EventCode=4624 AND AuthenticationPackageName="NTLM", "NTLM Authentication",
    true(), "Other"
  )
| stats count BY weakness_type
| sort - count
```

---

## Weakness Summary Table

| Weakness | Attack Enabled | Log Source | Detection Field | Remediation Priority |
|---|---|---|---|---|
| No Kerberos pre-auth | AS-REP Roasting | EID 4768 | `PreAuthType=0` | Critical |
| RC4 SPNs | Kerberoasting | EID 4769 | `TicketEncryptionType=0x17` | High |
| Unconstrained delegation | Credential forwarding | EID 4769 | TGTs to delegation hosts | High |
| AdminSDHolder ACL abuse | Persistent privilege | EID 5136/4670 | Changes to AdminSDHolder DN | Critical |
| Over-privileged svc accounts | High-value Kerberoasting | EID 4624/4728 | DA svc accounts with SPNs | High |
| NTLM in domain | Pass-the-Hash/Relay | EID 4624 | `AuthPackage=NTLM` for domain accounts | Medium |
| Stale privileged accounts | Credential reuse | EID 4624 | Low login frequency + DA membership | Medium |

---

## Module Summary

| Key Concept | Remember |
|---|---|
| Weakness hunting is proactive | Finding misconfigured accounts before attackers do removes attack vectors entirely |
| AS-REP roasting indicator | EID 4768 with `PreAuthType=0` shows the vulnerable account — fix the account, not just the detection |
| Kerberoasting indicator | RC4 TGS volume (EID 4769) is both a weakness signal and an attack signal |
| NTLM volume trending | Track NTLM % over time — it should decrease as you enforce Kerberos |
| AdminSDHolder is silent | Changes propagate every 60 min without obvious events — require active monitoring of EID 5136 on that specific DN |

### Related Detection Use Cases

- [Credential Attacks](../03_detection_use_cases/03_credential_attacks.md) — Kerberoasting and spray detection
- [Privilege Escalation](../03_detection_use_cases/06_privilege_escalation.md) — how weaknesses translate to privilege
- [Insider Threat](../03_detection_use_cases/07_insider_threat.md) — stale account abuse patterns

---

[← Module 5: Attacker Tooling Signatures](./module_05_attacker_tooling_signatures.md) | [Module 7: Threat Hunting Capstone →](./module_07_threat_hunting_capstone.md)
