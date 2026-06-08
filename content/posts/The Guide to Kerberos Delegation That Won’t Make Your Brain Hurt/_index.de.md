---
date: '2026-06-08T13:35:44+06:00'
draft: false
title: 'Kerberos Delegation verständlich erklärt: Der Guide ohne Kopfschmerzen'
---

```

Wenn du dich schon mal ein bisschen mit Active Directory Hacking oder Defense beschäftigt hast, bist du garantiert schon über den Begriff **Kerberos Delegation** gestolpert. In den meisten Lehrbüchern wird das mit wilden Pfeil-Diagrammen und riesigen Textwänden erklärt, sodass es am Ende viel komplizierter aussieht, als es eigentlich ist.

Lass uns den ganzen Corporate-Jargon mal weglassen und ganz entspannt anschauen, was Delegation eigentlich bedeutet, wie es in der Praxis läuft und warum es für Angreifer eine absolute Goldgrube ist.

---

## Das große Ganze: Was ist Delegation überhaupt?

Stell dir deine Lieblings-Website für Hotelbuchungen vor. Du loggst dich ein, suchst ein Zimmer aus und klickst auf "Bezahlen". Um diese Buchung abzuschließen, muss die Website im Hintergrund mit einem Datenbank-Server sprechen, um zu prüfen, ob das Zimmer noch frei ist, und um die Buchung einzutragen.

Die Datenbank sollte dem Webserver aber nicht einfach blind vertrauen. Wenn sie das täte, könnte ein kompromittierter Webserver die Daten *jedes beliebigen* Nutzers manipulieren. Die Datenbank muss also genau wissen, *wer* diese Anfrage gerade stellt.

Anstatt dir jetzt ein zweites Login-Fenster anzuzeigen und dich zu zwingen, dein Passwort noch einmal einzugeben, sagt der Webserver einfach: *"Hey Datenbank, dieser Nutzer hat sich gerade bei mir authentifiziert und mir die Erlaubnis gegeben, in seinem Namen zu handeln."*

Diese Weitergabe deiner Identität – quasi wie eine digitale Vollmacht – nennt man **Delegation**. Im Active Directory gibt es dafür drei verschiedene Varianten.

---

## 1. Unconstrained Delegation: Der Wilde Westen

Das ist die älteste Version der Delegation und aus Sicherheitsaspekten ein absoluter Albtraum.

Wenn ein Administrator das Häkchen für **Unconstrained Delegation** (unbeschränkte Delegation) bei einem Server setzt, sagt er dem Active Directory damit im Grunde: *"Ich vertraue dieser Maschine so sehr, dass sie sich im gesamten Netzwerk gegenüber jedem beliebigen Dienst als jeder beliebige Nutzer ausgeben darf."*

### Wie es funktioniert:

Kerberos nutzt statt Passwörtern digitale Eintrittskarten, sogenannte **Tickets**. Wenn du dich mit einem Server verbindest, bei dem Unconstrained Delegation aktiv ist, packt dein Computer quasi eine Kopie deines Haupt-Ausweises (dein **TGT - Ticket Granting Ticket**) mit in die Sitzung und drückt sie dem Server in die Hand.

Der Server nimmt deinen Ausweis und speichert (cached) ihn direkt in seinem lokalen Arbeitsspeicher (RAM), um ihn später zu nutzen.

> 💥 **Der Traum eines Angreifers:** Wenn es ein Hacker schafft, Admin-Rechte auf einem Server mit Unconstrained Delegation zu bekommen, muss er sich nur noch zurücklehnen und warten. In dem Moment, in dem sich ein Domänen-Administrator (Domain Admin) für eine Routineaufgabe mit diesem Server verbindet, landet dessen mächtiges TGT im Arbeitsspeicher. Der Hacker greift sich das Ticket aus dem RAM und zack – ihm gehört die gesamte Domäne.

---

## 2. Constrained Delegation: Die Whitelist

Microsoft hat ziemlich schnell gemerkt, dass es eine verdammt schlechte Idee ist, wenn Server die Generalschlüssel von allen Nutzern bunkern. Also haben sie **Constrained Delegation** (beschränkte Delegation) eingeführt.

Anstatt dem Webserver zu erlauben, sich überall als du auszugeben, konfiguriert ein Admin hier eine strikte, vorab genehmigte Liste von Backend-Diensten, mit denen der Webserver im Namen der Nutzer sprechen darf.

### Wie es funktioniert:

Der Webserver bekommt jetzt keine Kopie deines Haupt-Ausweises (TGT) mehr. Wenn er stattdessen in deinem Namen mit der Datenbank sprechen muss, wendet er sich an den Domain Controller und sagt: *"Ich brauche ein Service-Ticket für die SQL-Datenbank und ich fordere das im Namen von Alice an."*

Der Domain Controller prüft dann ein spezielles Attribut auf dem Konto des Webservers namens `msDS-AllowedToDelegateTo`. Wenn die Datenbank auf dieser Liste steht, rückt er das Ticket heraus. Der Webserver kann also nur noch dorthin, wo es ihm explizit erlaubt wurde.

---

## 3. Resource-Based Constrained Delegation (RBCD)

Die klassische Constrained Delegation funktioniert zwar gut, sorgt aber für ordentlich Verwaltungsaufwand. Die Liste, wo es hingehen darf, liegt nämlich direkt beim Front-End-Webserver. Wenn das Datenbank-Team jetzt einen neuen Datenbank-Cluster aufbaut, müssen sie erst ein Ticket beim Webserver-Team eröffnen und warten, bis diese die Attribute des Webservers manuell aktualisieren.

**Resource-Based Constrained Delegation (RBCD)** dreht den Spieß komplett um.

Anstatt dass der Webserver auflistet, worauf er zugreifen darf, agiert die Backend-Datenbank selbst wie ein **Türsteher mit einer Gästeliste**. Die Datenbank entscheidet selbst, welche Front-End-Server sich ihr gegenüber als Nutzer ausgeben dürfen. Das verlagert die Kontrolle genau zu dem Team, das auch für den Schutz der Daten verantwortlich ist, was das Netzwerk-Management viel sauberer macht.

---

## Ein Blick unter die Haube: S4U2Self und S4U2Proxy

Damit die beschränkte Delegation überhaupt funktioniert, nutzt das Active Directory im Hintergrund zwei Erweiterungen. Die Namen klingen zwar ziemlich technisch und roboterhaft, aber die Logik dahinter ist schnell verstanden.

### S4U2Proxy (Das Ticket weitergeben)

Das ist der Standardprozess, den wir eben beschrieben haben. Ein Dienst nimmt die Kerberos-Identität eines Nutzers und leitet sie sicher an eine Backend-Ressource weiter.

### S4U2Self (Protokoll-Transition)

Was passiert eigentlich, wenn sich ein Nutzer nicht über Kerberos am Webserver anmeldet, sondern über ein älteres Protokoll wie NTLM oder über ein normales Webformular? Dann hat der Webserver ja gar kein Kerberos-Ticket vom Nutzer, das er an die Datenbank weiterreichen könnte!

Genau hier springt **S4U2Self** mit einem Feature namens **Protocol Transition** (Protokollwechsel) ein:

1. Der Webserver sagt dem Domain Controller: *"Hey, Bob hat sich über NTLM bei mir eingeloggt. Kannst du mir trotzdem ein gültiges Kerberos-Ticket für ihn ausstellen, damit ich damit arbeiten kann?"*
2. Der Domain Controller generiert ein sogenanntes "forwardable" Kerberos-Ticket für Bob und gibt es dem Webserver.

Bei der Konfiguration von Constrained Delegation kann ein Admin zwischen **"Use Kerberos only"** (deaktiviert dieses Feature) und **"Use any authentication protocol"** (aktiviert S4U2Self) wählen.

Wenn ein Hacker ein Dienstkonto übernimmt, das *jedes beliebige Authentisierungsprotokoll* nutzen darf, kann er S4U2Self missbrauchen, um beim Domain Controller einfach so aus dem Nichts ein Ticket für den Administrator anzufordern. Genau so funktionieren die Angriffs-Skripte, die man online findet.

