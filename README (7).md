# HTB Writeups

Penetration-test reports for retired **Hack The Box** machines — full exploitation chains, from reconnaissance to root.

Each writeup documents the complete methodology: real commands and output, the reasoning behind every step, the dead ends, and a chain summary. All flags, credentials and hashes are redacted; the methodology is complete, the values are not.

> Written by **Leandro Ancona** — Offensive Security Practitioner, eJPT Certified. · *SEL — Sentiti Libero*

---

## Machines

| Machine | OS | Difficulty | Key techniques | Writeup |
|---|---|:---:|---|:---:|
| [Cobblestone](./cobblestone) | Linux | Insane | Second-order SQLi, Twig SSTI, Cobbler CVE-2024-47533, Cheetah RCE | [Read](./cobblestone) |
| [Voleur](./voleur) | Windows | Medium | Targeted Kerberoasting, AD Recycle Bin, DPAPI, NTDS dump | [Read](./voleur) |
| [Checkpoint](./checkpoint) | Windows | Medium | AD Recycle Bin, malicious VS Code extension, BadSuccessor, Volatility | [Read](./checkpoint) |
| [Odori](./odori) | Linux | Medium | BitLocker crack, mRemoteNG forensics, forged `.pyc` | [Read](./odori) |
| [Titanic](./titanic) | Linux | Easy | Path traversal, Gitea DB exfil, CVE-2024-41817 loader hijack | [Read](./titanic) |
| [Dog](./dog) | Linux | Easy | Exposed `.git`, Backdrop module RCE, `sudo bee eval` | [Read](./dog) |
| [Nexus](./nexus) | Linux | Easy | Git history leak, Krayin RCE, forged Git tree path traversal | [Read](./nexus) |
| [Nocturnal](./nocturnal) | Linux | Easy | IDOR, command-injection blacklist bypass, ISPConfig CVE-2023-46818 | [Read](./nocturnal) |
| [Reset](./reset) | Linux | Easy | Password-reset leak, log poisoning, r-services trust, `sudo nano` | [Read](./reset) |
| [WingData](./wingdata) | Linux | Easy | Wing FTP CVE-2025-47812, hashcat, `tarfile` CVE-2025-4517 | [Read](./wingdata) |
| [Manage](./manage) | Linux | Easy | Unauthenticated JMX, backup + TOTP, `sudo adduser` | [Read](./manage) |
| [Beep](./beep) | Linux | Easy | vtiger LFI (CVE-2010-3910), FreePBX RCE, `sudo nmap` | [Read](./beep) |
| [Legacy](./legacy) | Windows | Easy | MS08-067 (CVE-2008-4250) → SYSTEM | [Read](./legacy) |

---

## About

These are training exercises on retired machines from the Hack The Box platform, an authorised environment for offensive-security practice. Writeups are published only after a machine is officially retired, with flags and credentials redacted per community practice.

Each report is available as a GitHub-rendered Markdown file and as a styled PDF in the same folder.

`#HackTheBox` · `#PenetrationTesting` · `#OffensiveSecurity` · `#OSCP`
