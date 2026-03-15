<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# since i am a newbie in this field explain how to do this with all deep risk mitigation,donts and sources  : Test your MVP by hunting a real bug on a live program yourself. If YOU can find and submit a valid bug using only your tool, it works. , and how to Hunt bugs personally every week. Target: ₹42,000–₹50,000/month from personal bounties in M1–M3.  from where which platforms

This is the most important guide in your entire journey — get this wrong and you get banned, sued, or earn nothing. Here is the complete, honest, first-principles breakdown for a total newbie.

***

## ⚠️ THE SINGLE MOST CRITICAL TRUTH FIRST

**Earning ₹42,000–₹50,000/month in Month 1 as a newbie from bug bounty alone is extremely unlikely.** The realistic timeline is 6–12 months before consistent income.  The **Month 1 ₹42,000 number in our model includes your personal bounty hunting PLUS the assumption that you already have intermediate skills.** This section teaches you how to build those skills safely from zero. If you are a complete newbie, treat M1–M3 as **learning + first small wins** (₹5,000–₹20,000), not ₹50,000. That is not failure — that is the honest roadmap.[^1][^2]

***

## PHASE ZERO — The Legal \& Safety Foundation (Before You Touch Any Target)

These are not optional. Skipping any one of these can result in criminal charges under India's IT Act.[^3][^4]

### 1. Understand What Bug Bounty Legally Means

- **Bug bounty = a company's written permission to test their systems** within a defined scope[^3]
- Without written permission (a live program's policy), testing ANY system = illegal under Section 66 of the IT Act 2000 and the Computer Fraud and Abuse Act (CFAA) internationally[^5]
- Permission is **program-specific** — you cannot test System B because you found a bug in System A
- Permission is **scope-specific** — if they say `*.example.com` is in scope, `api2.example.com` may NOT be


### 2. The 3 Golden Rules (Tattoo These on Your Brain)

- **Rule 1:** Only test what is explicitly listed as IN-SCOPE in the program policy. Read it three times.
- **Rule 2:** Never access, download, or modify real user data — even if you accidentally can. Screenshot the bug, then stop.
- **Rule 3:** Never run automated scanners unless the program EXPLICITLY permits it. Most don't.[^4]

***

## PART 1 — Build Your Skills First (Week 1–8, Non-Negotiable)

*Framework: PortSwigger Web Security Academy — the single best free resource in the world for this*[^6][^7]

### Step 1: Learn How the Web Works (Week 1–2)

You cannot find bugs in systems you don't understand. Master these in order:[^8][^3]

1. **HTTP Protocol:** GET/POST/PUT/DELETE, status codes (200, 301, 403, 404, 500), headers (Authorization, Cookie, Content-Type)
2. **How authentication works:** Sessions, cookies, JWT tokens, OAuth
3. **How APIs work:** REST APIs, JSON responses, endpoints, parameters
4. **JavaScript basics:** Enough to read JS in a browser console and find hidden endpoints
5. **DNS and subdomains:** What `api.example.com` vs `admin.example.com` means

**Free resource:** PortSwigger Web Security Academy — `portswigger.net/web-security` — start with "Getting Started" path[^7][^6]

### Step 2: Install and Learn Your Core Tools (Week 2–3)

| Tool | What It Does | Cost | Install Guide |
| :-- | :-- | :-- | :-- |
| **Burp Suite Community** | Intercept + modify web requests — your main weapon | Free | portswigger.net/burp |
| **Firefox + FoxyProxy** | Route browser through Burp | Free | Standard install |
| **subfinder** | Find subdomains of a target | Free | github.com/projectdiscovery/subfinder |
| **httpx** | Check which subdomains are alive | Free | github.com/projectdiscovery/httpx |
| **nuclei** | Automated vulnerability scanning (use carefully) | Free | github.com/projectdiscovery/nuclei |

**Do NOT install or use:** Metasploit, SQLmap on live targets, automated brute-forcers — until you fully understand what they do and a program explicitly permits them[^4]

### Step 3: Learn 3 Bug Classes Deeply (Week 3–6)

Do NOT try to learn all 100+ vulnerability types. Master these 3 first — they are the most common, easiest to find, and safest for beginners:[^9][^3]

**Bug Class 1: IDOR (Insecure Direct Object Reference)**

- What it is: Changing a number in a URL or request to access someone else's data
- Example: `GET /api/orders/1234` → change to `GET /api/orders/1235` → see another user's order
- Why it's beginner-friendly: No special tool needed, just observation and Burp Repeater
- Where to practice: PortSwigger IDOR labs + OWASP WebGoat[^3]

**Bug Class 2: XSS (Cross-Site Scripting)**

- What it is: Injecting JavaScript code into a website that runs in another user's browser

```
- Example: Typing `<script>alert(1)</script>` in a search box and having it execute
```

- Why it's beginner-friendly: Visible, easy to demonstrate, widely accepted
- Where to practice: PortSwigger XSS labs (35+ free labs)[^6][^7]

**Bug Class 3: Information Disclosure**

- What it is: Finding sensitive data exposed unintentionally (API keys, internal paths, debug info, user data)
- Example: `/robots.txt` reveals admin panel path; `.git` folder exposed; error message shows database type
- Why it's beginner-friendly: Often requires zero exploitation — just observation
- Where to practice: Google Dorking exercises, PortSwigger info disclosure labs[^8][^3]


### Step 4: Practice on Legal Lab Environments ONLY (Week 4–8)

These are systems intentionally built to be hacked — 100% legal:[^10][^3]


| Platform | Cost | What You Practice |
| :-- | :-- | :-- |
| **PortSwigger Web Security Academy** | Free | All web vulns, 200+ labs |
| **HackTheBox (HTB)** | Free tier | Realistic machines |
| **TryHackMe** | Free tier | Guided learning paths |
| **OWASP WebGoat** | Free (local install) | Deliberately vulnerable app |
| **DVWA (Damn Vulnerable Web App)** | Free (local install) | Classic web vulns |

**Minimum before hunting live:** Complete at least 20 PortSwigger labs across IDOR, XSS, and Info Disclosure.[^8][^3]

***

## PART 2 — Platform Selection (Where to Hunt as a Newbie)

### The 5 Platforms Ranked for Beginners in India

**Platform 1: HackerOne (Best for Volume + Learning)**

- 1,950+ programs, largest community (1.5M researchers from 170 countries)[^11]
- Open registration — no vetting, sign up with email immediately[^11]
- Has Hacker101 (free training), Hacktivity (public reports to learn from)
- **Best beginner move:** Start with their free Hacker101 CTF challenges before any live program[^11]

**Platform 2: Bugcrowd (Best for Beginners — Friendliest UX)**

- "AI-powered CrowdMatch" matches you to programs based on your skill level[^11]
- Open registration, no approval needed[^11]
- Has Vulnerability Rating Taxonomy (VRT) — a clear guide to how bugs are classified[^12]
- Large mix of public and private programs[^13]

**Platform 3: Intigriti (Best for Fast Feedback)**

- Excellent triage response times — you learn quickly if your reports are valid[^13]
- Beginner-friendly onboarding and clear scoping[^13]
- Strong European programs — less competition than HackerOne for same targets[^1]

**Platform 4: BugBase (Best for India-Specific Programs)**

- Indian platform with Indian companies — easier to understand product context[^14]
- Compliant with ISO 29147 — programs are professionally managed[^14]
- Less competition than global platforms — higher chance of unique findings[^5]

**Platform 5: YesWeHack (Best for Expanding Later)**

- Growing platform, competitive bounties, community-focused[^15][^1]
- Good for Month 3+ once you have your first valid reports[^1]


### ❌ Do NOT Start Here as a Newbie

- **Google VRP, Meta, Apple, Microsoft** — thousands of elite researchers competing. You will find nothing and get discouraged.[^9]
- **Immunefi (Web3/Crypto)** — requires deep blockchain knowledge, not beginner-friendly[^1]
- **Synack** — invite-only, requires proven track record[^1]

***

## PART 3 — How to Choose Your First Target (The Most Important Decision)

### The GRAIN Method for Program Selection[^16][^3]

Use this exact filter — check every box before starting:

**G — Green scope (clear, explicit, wide)**

- ✅ "All assets under `*.example.com` are in scope"
- ❌ "Only `www.example.com/contact` is in scope" — too narrow

**R — Recent activity (program is responsive)**

- Check: When was the last public report resolved? If >6 months ago, skip.
- Check: Average response time listed on HackerOne — target <7 days

**A — Avoid huge programs (less competition)**

- Companies with 10,000+ reports resolved = extremely saturated
- Target: programs with 100–500 lifetime reports[^3]

**I — Indian or growing tech company (you understand the product)**

- You understand a food delivery app or fintech app better than a US defense contractor
- Understanding the product = understanding where the bugs are

**N — No automated scanner restriction (or explicit permission)**

- Read policy carefully: "no automated tools" = hands-only manual testing only
- "Automated scanning permitted within rate limits" = you can use nuclei/subfinder


### 5 Actual Program Types Perfect for Indian Newbies

1. **Indian SaaS startups on BugBase** — less competition, you understand the product
2. **VDP (Vulnerability Disclosure Programs) on HackerOne** — no money, but no pressure, hall of fame credit, builds experience[^3]
3. **E-commerce platforms** with wide scope — lots of IDOR opportunities in order/cart APIs
4. **EdTech platforms** — growing category, often underfunded security teams, many accessible bugs
5. **Fintech apps (carefully scoped)** — high bounties but read scope extremely carefully[^5]

***

## PART 4 — The Actual Hunt: Step-by-Step Methodology

*This is the exact process that generates valid reports. Do not skip steps.*[^17][^3]

### Step 1: Read the Program Policy (30 minutes minimum)

Before touching ANY tool, read and note:

- Exactly which domains/apps are IN scope (make a list)
- Exactly which are OUT of scope (payment systems, third-party services usually out)
- Forbidden techniques (no DoS, no automated scanners, no social engineering)
- Payout table (P1 Critical → P5 Informational, typical amounts)
- Disclosure timeline (how long before you can publish)


### Step 2: Passive Recon — Learn Without Touching (2–3 hours)

**Do NOT make any requests to the target yet.** Gather intelligence passively:[^18][^3]

```bash
# Find subdomains passively (no requests to target)
subfinder -d example.com -silent -o subdomains.txt

# Check which are alive (this DOES make requests — only after reading policy)
cat subdomains.txt | httpx -silent -o alive_hosts.txt

# Look at public JS files for hidden endpoints
# In browser: visit target, open DevTools → Sources → look for .js files
```

**Also do:**

- Google: `site:example.com filetype:pdf` — find exposed documents
- Google: `site:example.com inurl:api` — find API endpoints
- Check `example.com/robots.txt` — lists paths companies don't want indexed
- Check `example.com/.git` — if accessible, entire source code is exposed (big find)


### Step 3: Manual Testing — The IDOR Checklist (Your First Real Hunt)

Pick one authenticated feature (account settings, order history, user profile). In Burp Suite:[^18][^3]

```
1. Create Account A and Account B (use two browser profiles)
2. Log into Account A, perform an action (place order, save address, view invoice)
3. Capture the request in Burp → note any IDs (user_id=123, order_id=456)
4. Send to Burp Repeater
5. Change the ID to Account B's ID (user_id=124, order_id=457)
6. Send the request — are you seeing Account B's data?
7. If YES → valid IDOR. Stop testing. Document immediately.
```


### Step 4: Document the Bug Immediately (Evidence Collection)

The moment you find something, stop exploiting and start documenting:[^19][^3]

- Screenshot the vulnerable request in Burp (request + response)
- Screenshot the impact (what data was exposed)
- Note exact URL, parameter name, HTTP method
- Note both accounts used (Account A ID, Account B ID)
- Record a short screen video if possible (massively helps triage)

**Critical:** Do NOT access more than 2–3 test accounts' data. Do NOT download real user data. One example proving the concept is enough.[^4]

### Step 5: Write the Report (The Difference Between ₹0 and ₹10,000)

This template gets reports accepted. Fill in every single field:[^19][^3]

```
TITLE: [IDOR] Authenticated user can access other users' [data type] 
via [parameter name]

SEVERITY: P3 Medium (CVSS 6.5) or P2 High (CVSS 8.0) depending on data sensitivity

DESCRIPTION:
A logged-in user can access other users' [invoices/orders/personal data] by 
manipulating the [order_id] parameter in the [GET /api/orders/{id}] endpoint. 
This allows horizontal privilege escalation between user accounts.

STEPS TO REPRODUCE:
1. Create two accounts: test1@gmail.com (Account A) and test2@gmail.com (Account B)
2. Log in as Account A. Place an order. Note the order ID (e.g., 12345)
3. Send GET /api/orders/12345 — you see Account A's order data ✓
4. Now change the ID to Account B's order ID (12346)
5. Send GET /api/orders/12346 — you see Account B's data despite being Account A

PROOF OF CONCEPT:
[Screenshot of Burp request showing the parameter change]
[Screenshot of the response showing Account B's data]

IMPACT:
Any authenticated user can access any other user's complete order history, 
including delivery addresses and payment method details. This violates user 
privacy and may constitute a data breach under India's DPDPA 2023.

REMEDIATION:
Implement server-side authorization checks: verify that the authenticated 
user's ID matches the resource owner's ID before returning data.
```


***

## PART 5 — Deep Risk Mitigation: The 15 Commandments

### Legal Risks

**1. NEVER test out-of-scope assets.** If `payments.example.com` is out of scope and you find a bug there, you cannot report it through the program. Email their security team directly at `security@example.com` as a responsible disclosure.[^4][^3]

**2. NEVER cause service disruption.** No brute force at high rates, no flood of requests, no DoS attempts. Even unintentional disruption can trigger legal action. Use Burp Intruder with a 1-second delay minimum.[^4]

**3. NEVER access production user data.** If you accidentally see real user emails, phone numbers, or payment data — close it, do not copy it, do not download it. Just screenshot the vulnerability concept with test data.[^3]

**4. NEVER disclose a bug publicly before the program's defined embargo period.** Most programs require 90 days of silence before you can publish a writeup. Publishing early = banned + potential legal action.[^19]

**5. ALWAYS keep records of your permission.** Screenshot the program's policy page with date. Keep the Hackerone/Bugcrowd URL. If anyone ever questions you, this is your proof of authorization.

### Platform/Account Risks

**6. NEVER create fake or multiple personal accounts on platforms.** One HackerOne account per person — creating multiple to farm reputation is a permanent ban.[^4]

**7. NEVER submit duplicate bugs.** Before submitting, search HackerOne Hacktivity and program's past reports for the same issue. Duplicates hurt your reputation score.[^9]

**8. NEVER submit low-quality or unverified reports.** "This MIGHT be vulnerable" is an automatic N/A (Not Applicable). Only submit what you can fully reproduce with steps. Every N/A lowers your reputation score, which gates you out of better programs.[^9][^3]

**9. NEVER harass triage teams.** If a report is closed as N/A and you disagree, ask once politely with additional evidence. Never argue, never send repeated follow-ups, never be rude. Triage teams have memory.[^4]

**10. NEVER use someone else's writeup techniques on the same target.** If a public writeup shows IDOR at `/api/users/{id}`, that exact bug is already patched and reported. Learn the technique, apply it to different endpoints.

### Technical Risks

**11. ALWAYS rate-limit your tools.** In ffuf: use `-t 1` (1 thread). In Burp Intruder: set 1-second delay. In nuclei: use `-rate-limit 10`. Aggressive scanning = IP ban + program ban + potential legal complaint.[^4]

**12. NEVER run nuclei or automated scanners without explicit program permission.** Even if you think it's "just checking," it looks like an attack from the server's perspective.[^3][^4]

**13. ALWAYS test in off-peak hours.** 2–6 AM IST is when traffic is lowest. Your testing has less chance of impacting real users. Shows professionalism and reduces disruption risk.[^4]

**14. NEVER store target data on public GitHub repos.** Your recon results, target URLs, screenshots — all private. One accidental public push with a company's internal paths = legal letter.[^3]

**15. ALWAYS use a VPN during testing** (ProtonVPN free tier is fine) — not for anonymity, but to separate your testing IP from your personal browsing. It also prevents accidental testing from home IP if you have saved credentials open.

***

## PART 6 — Realistic Earnings Timeline (Honest Numbers)

| Month | Your Status | Realistic Earnings | What You're Doing |
| :-- | :-- | :-- | :-- |
| **M1** | Learning + first VDP | ₹0–₹5,000 | PortSwigger labs, first VDP report (no money, Hall of Fame) |
| **M2** | First valid paid report | ₹5,000–₹15,000 | 1–2 P3/P4 bugs on small programs |
| **M3** | Finding rhythm | ₹10,000–₹30,000 | Consistent P3 bugs, first P2 attempt |
| **M4–M6** | Skill compounding | ₹20,000–₹60,000 | P2/P3 consistent, first P1 attempt |
| **M7–M12** | Intermediate | ₹50,000–₹1,50,000 | P1/P2 bugs, private program invitations |
| **M12+** | Proficient | ₹1,00,000–₹5,00,000+ | Private programs, high-paying targets |

**Reality check from Reddit:** A friend of one commenter earned \$24,000 total in Year 2 — nothing in Year 1. The ₹42,000/month M1 figure in our business model assumes you are building toward this over 3–6 months, not earning it on Day 1.[^2][^20]

***

## PART 7 — Your Free Learning Stack (Zero Cost)

**Week 1–2: Foundation**

- PortSwigger Web Security Academy — `portswigger.net/web-security` (free, 200+ labs)[^7][^6]
- Read: OWASP Top 10 (2021) — `owasp.org/Top10`

**Week 3–4: Tools**

- Burp Suite Community Edition — free, install today[^18]
- TryHackMe "Jr Penetration Tester" path — free tier available[^3]

**Week 5–6: Vulnerability Deep Dive**

- HackerOne Hacker101 — free CTF and training[^11]
- Read 50 public HackerOne Hacktivity reports (IDOR + XSS only at first)[^3]

**Week 7–8: First Live Hunt**

- HackerOne VDP programs (start here — no money but safe to learn)[^11]
- BugBase India programs (less competition)[^14]

**Ongoing: Stay Current**

- Intigriti's 31 tips blog — `intigriti.com/blog`[^17]
- Netlas.io blog — bug bounty roadmap articles[^3]
- r/bugbounty on Reddit — real community, real income reports[^2]

***

## PART 8 — How to TEST YOUR MVP With Your Own Hunting

Once you have 4–6 weeks of practice, here is how your tool testing and your personal hunting merge:[^21][^22]

1. **Pick a VDP program with wide scope** (no payment, low pressure)
2. **Run your tool's recon pipeline on it** (subfinder → httpx → attack surface map)
3. **Review what the tool surfaces** — does it find the right subdomains? Does it flag the right endpoints?
4. **Manually verify one hypothesis the tool generates** — open Burp, test the endpoint the AI suggested
5. **If the bug is valid:** Your MVP works. Submit the report manually (human gate). Note the time saved.
6. **If the bug is invalid:** Feed this back as training data — "AI suggested X, but X was already patched" → this improves your acceptance graph

This is both your product validation AND your personal skill development in one session. The tool and your skills grow together.[^21][^1]

***

> **Final Honest Advice:** The ₹42,000/month target is absolutely achievable — but in Month 4–6, not Month 1. The fastest path there is: 6 weeks of daily PortSwigger labs → first VDP submission → first paid P3 bug → compound from there. Every bug you find makes the next one faster. Every accepted report sharpens your tool's acceptance graph. There is no shortcut past the 6-week learning investment — but there is no ceiling either once you have it.[^2][^5][^3]
<span style="display:none">[^23][^24][^25][^26][^27][^28][^29][^30][^31][^32][^33][^34][^35][^36][^37][^38][^39][^40]</span>

<div align="center">⁂</div>

[^1]: https://dev.to/krlz/bug-bounty-hunting-guide-2026-from-zero-to-paid-security-researcher-5c82

[^2]: https://www.reddit.com/r/bugbounty/comments/1p7vy66/how_realistic_is_earning_3kmonth_from_bug_bounty/

[^3]: https://netlas.io/blog/bug_bounty_roadmap/

[^4]: https://osintteam.blog/avoid-these-5-bug-bounty-mistakes-or-get-banned-b274fa78f7e9

[^5]: https://www.cryptus.in/hackingnews/definitive-guide-to-bug-bounty-hunting-in-2026/

[^6]: https://portswigger.net/web-security/getting-started

[^7]: https://portswigger.net/web-security

[^8]: https://osintteam.blog/starting-bug-bounty-with-zero-knowledge-heres-the-exact-roadmap-to-your-first-valid-report-774e4d923289

[^9]: https://cybersecuritywriteups.com/5-beginner-mistakes-killing-your-bug-bounty-success-fix-them-now-4ad55128d1a9

[^10]: https://github.com/onyxwizard/portswigger-academy

[^11]: https://www.stationx.net/bug-bounty-programs-for-beginners/

[^12]: https://www.bugcrowd.com/bug-bounty-list/

[^13]: https://www.cloudsek.com/knowledge-base/best-bug-bounty-platforms

[^14]: https://bugbase.ai

[^15]: https://www.youtube.com/watch?v=oFxcG7yerG4

[^16]: https://infosecwriteups.com/give-me-5-minutes-and-ill-fix-your-bug-bounty-strategy-the-2025-blueprint-1262cb57589b

[^17]: https://www.intigriti.com/blog/business-insights/31-bite-sized-tips-techniques-and-bug-bounty-resources-to-kick-off-2026

[^18]: https://www.eicta.iitk.ac.in/knowledge-hub/ethical-hacking/15-top-bug-bounty-tools-to-become-pro-bug-hunter

[^19]: https://arxiv.org/pdf/2409.07670.pdf

[^20]: https://osintteam.blog/reality-of-bug-bounty-2025-c920bf9944fb

[^21]: https://arxiv.org/html/2504.06017v1

[^22]: https://shannon-ai.com/bug-bounty-ai

[^23]: http://arxiv.org/pdf/2304.00077.pdf

[^24]: http://arxiv.org/pdf/2403.09484.pdf

[^25]: http://thesai.org/Downloads/Volume15No4/Paper_30-Optimizing_Bug_Bounty_Programs_for_Efficient_Malware.pdf

[^26]: https://zenodo.org/record/5091567/files/Blockchain-based Bug Bounty Framework.pdf

[^27]: https://www.mdpi.com/2079-9292/10/1/62/pdf

[^28]: https://arxiv.org/abs/2305.16615v1

[^29]: https://www.coursera.org/in/articles/bug-bounty

[^30]: https://www.youtube.com/watch?v=ZutwWm2FQp0

[^31]: https://www.hackerone.com/bug-bounty-programs

[^32]: https://cybersapiens.com.au/best-bug-bounty-hunting-course-in-india/

[^33]: https://github.com/bobby-lin/study-bug-bounty

[^34]: https://arxiv.org/pdf/1904.02724.pdf

[^35]: https://www.tandfonline.com/doi/pdf/10.1080/13600834.2022.2088062?needAccess=true

[^36]: http://arxiv.org/pdf/2501.17748.pdf

[^37]: https://dx.plos.org/10.1371/journal.pcbi.1010540

[^38]: https://www.reddit.com/r/netsecstudents/comments/1rbl8ja/getting_into_bug_bounty_in_2026_whats_the_smart/

[^39]: https://www.linkedin.com/posts/aditi-patil0907_800dayscybersec-day720-cybersecurity-activity-7421977699469975553-1xRV

[^40]: https://www.youtube.com/watch?v=07__k7jh-EY

