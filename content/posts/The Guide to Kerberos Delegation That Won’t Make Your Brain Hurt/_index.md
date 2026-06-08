---
date: '2026-06-08T13:35:44+06:00'
draft: false
title: 'The Guide to Kerberos Delegation That Won’t Make Your Brain Hurt'
---


If you’ve dipped your toes into Active Directory hacking or defense, you’ve probably run face-first into the term **Kerberos Delegation**. Most textbooks explain this with maps of arrows and massive walls of text that make it look way more complicated than it actually is.

Let's strip away the corporate jargon and look at what delegation actually means, how it works in the real world, and why it's a goldmine for attackers.

---

## The Big Picture: What is Delegation?

Think of your favorite travel booking website. You log in, pick a hotel, and click pay. To finalize that booking, the website needs to talk to a backend database server to see if rooms are available and modify the records.

The database shouldn't just trust the web server blindly. If it did, a compromised web server could modify *any* user's data. The database needs to know exactly *who* is making the request.

Instead of popping up a second login box and making you type your password again, the web server says: *"Hey database, this user just authenticated with me, and they gave me permission to act on their behalf."*

Passing your identity down the line like a digital power of attorney is called **Delegation**. In Active Directory, it comes in three distinct flavors.

---

## 1. Unconstrained Delegation: The Wild West

This is the oldest version of delegation, and from a security standpoint, it’s an absolute horror show.

When an administrator checks the box for **Unconstrained Delegation** on a server, they are telling Active Directory: *"I trust this machine to impersonate any user to any service, anywhere on the network."*

### How it works:

Kerberos uses digital passes called **Tickets** instead of passwords. When you connect to a server that has Unconstrained Delegation turned on, your computer literally bundles up a copy of your main "ID card" (your **TGT - Ticket Granting Ticket**) and gives it to that server.

The server takes your ID card and caches it directly into its local memory so it can use it later.

> **The Attacker's Dream:** If a hacker manages to gain admin rights on an Unconstrained Delegation server, all they have to do is sit quietly and wait. The moment a Domain Administrator connects to that server for a routine task, their high-privileged TGT is dropped into memory. The hacker scoops it up, and boom—they own the entire domain.

---

## 2. Constrained Delegation: The Approved List

Microsoft quickly realized that letting servers hold onto everyone's master keys was a terrible idea, so they introduced **Constrained Delegation**.

Instead of letting a web server impersonate you everywhere, an admin configures a strict, pre-approved list of backend services that the web server is allowed to talk to.

### How it works:

The web server no longer gets a copy of your master ID card. Instead, when it needs to talk to the database on your behalf, it reaches out to the Domain Controller and says: *"I need a service ticket for the SQL database, and I'm requesting it on behalf of Alice."*

The Domain Controller checks a special attribute on the web server's account called `msDS-AllowedToDelegateTo`. If the database is on that specific list, it hands over the ticket. The web server can only go where it’s explicitly allowed.

---

## 3. Resource-Based Constrained Delegation (RBCD)

Traditional Constrained Delegation works fine, but it creates a massive administrative headache. The front-end web server holds the list of where it can go. If the database team deploys a new database cluster, they have to open a ticket and wait for the web server's admin team to manually update the server's attributes.

**Resource-Based Constrained Delegation (RBCD)** flips the script completely.

Instead of the web server listing what it can access, the backend database acts like a **bouncer with a guest list**. The database itself decides which front-end servers are allowed to impersonate users to it. This shifts control to the team responsible for protecting the data, making network management much cleaner.

---

## Under the Hood: S4U2Self and S4U2Proxy

To make constrained delegation actually work, Active Directory relies on two background extensions. They have weird, robotic-sounding names, but their concepts are pretty straightforward.

### S4U2Proxy (Passing the Ticket)

This is the standard process we just described. A service takes a user's Kerberos identity and safely passes it forward to a backend resource.

### S4U2Self (Protocol Transition)

What happens if a user logs into a web server using an old protocol like NTLM, or via a web form, instead of using Kerberos? The web server doesn't have a Kerberos ticket to pass along to the database!

This is where **S4U2Self** steps in via a feature called **Protocol Transition**:

1. The web server tells the Domain Controller: *"Hey, Bob logged into my site via NTLM. Can you generate a valid Kerberos ticket for him anyway so I can use it?"*
2. The Domain Controller generates a forwardable Kerberos ticket for Bob and hands it to the web server.

When configuring Constrained Delegation, an admin can choose **"Use Kerberos only"** (disabling this feature) or **"Use any authentication protocol"** (enabling S4U2Self).

If a hacker takes over a service account that is allowed to use *any authentication protocol*, they can abuse S4U2Self to ask the domain controller for an administrator's ticket out of thin air. That's exactly how the attack scripts you see online work.

---
