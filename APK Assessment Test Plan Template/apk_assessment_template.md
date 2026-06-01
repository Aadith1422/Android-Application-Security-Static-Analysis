# APK Security Assessment — Test Plan Template

**Assessment ID:** `APK-YYYY-MM-DD-XXX`  
**Assessor:**  
**Date Started:**  
**Date Completed:**  
**App Name:**  
**Package Name:**  
**Version (versionName / versionCode):**  
**APK SHA-256:**  

---

## Table of Contents

1. [Scope & Objectives](#1-scope--objectives)
2. [Environment Setup](#2-environment-setup)
3. [APK Acquisition](#3-apk-acquisition)
4. [Unpacking & Decompilation](#4-unpacking--decompilation)
5. [Manifest Review](#5-manifest-review)
6. [Code & Strings Analysis](#6-code--strings-analysis)
7. [Resource Inspection](#7-resource-inspection)
8. [Dynamic Analysis](#8-dynamic-analysis)
9. [Authentication & Authorization Testing](#9-authentication--authorization-testing)
10. [Network Communication Testing](#10-network-communication-testing)
11. [Cryptography Review](#11-cryptography-review)
12. [Data Storage Review](#12-data-storage-review)
13. [Platform Interaction Testing](#13-platform-interaction-testing)
14. [Findings Summary](#14-findings-summary)
15. [Risk Rating Reference](#15-risk-rating-reference)
16. [Sign-Off](#16-sign-off)

---

## 1. Scope & Objectives

### 1.1 Assessment Goals

- [ ] Identify security vulnerabilities in the APK binary
- [ ] Review authentication and authorization mechanisms
- [ ] Assess data storage and communication security
- [ ] Verify compliance with OWASP Mobile Top 10
- [ ] Document all findings with evidence and remediation guidance

### 1.2 In Scope

| Item | Details |
|---|---|
| APK file | |
| Backend API endpoints | |
| Third-party SDKs | |
| Deep link handlers | |

### 1.3 Out of Scope

| Item | Reason |
|---|---|
| | |
| | |

### 1.4 Testing Type

- [ ] Black-box (no source code access)
- [ ] White-box (full source code provided)
- [ ] Grey-box (partial documentation provided)

---

## 2. Environment Setup

### 2.1 Tooling Checklist

| Tool | Version | Purpose | Installed |
|---|---|---|---|
| `adb` | | Device interaction | [ ] |
| `apktool` | | APK decode / smali | [ ] |
| `jadx` | | Java decompilation | [ ] |
| `MobSF` | | Automated analysis | [ ] |
| `Burp Suite` | | Traffic interception | [ ] |
| `Frida` | | Runtime hooking | [ ] |
| `objection` | | Runtime exploration | [ ] |
| `semgrep` | | Static code scanning | [ ] |
| `sqlite3` | | Database inspection | [ ] |
| `keytool` | | Certificate analysis | [ ] |
| `strings` | | Binary string extraction | [ ] |

### 2.2 Test Device

| Property | Value |
|---|---|
| Device model | |
| Android version | |
| Rooted | Yes / No |
| Frida server running | Yes / No |
| Proxy configured | Yes / No |
| CA certificate installed | Yes / No |

### 2.3 Working Directory Structure

```
assessment/
├── apk/
│   └── target.apk
├── decoded/          ← apktool output
├── decompiled/       ← jadx output
├── traffic/          ← Burp captures
├── screenshots/      ← evidence
└── report/
```

---

## 3. APK Acquisition

### 3.1 Acquisition Method

- [ ] `adb pull` from connected device
- [ ] Google Play via `gplaycli`
- [ ] Provided by client
- [ ] Extracted from device backup
- [ ] Other: _______________

### 3.2 Acquisition Steps

```bash
# Document exact commands used:


```

### 3.3 Integrity Verification

| Check | Value |
|---|---|
| File size | |
| SHA-256 hash | |
| File type (`file myapp.apk`) | |
| ZIP validity (`unzip -t`) | |

### 3.4 Notes

> _Document any issues encountered during acquisition._

---

## 4. Unpacking & Decompilation

### 4.1 Apktool Decode

```bash
apktool d target.apk -o decoded/
```

- [ ] Completed successfully
- [ ] AndroidManifest.xml decoded (human-readable)
- [ ] Resources decoded
- [ ] Smali output generated

**Errors / Notes:**

### 4.2 JADX Decompilation

```bash
jadx target.apk -d decompiled/
```

- [ ] Completed successfully
- [ ] Java source files generated
- [ ] Package structure visible

**Decompilation success rate (estimate):** _______%  
**Errors / Notes:**

### 4.3 APK Structure Notes

| Component | Present | Notes |
|---|---|---|
| `classes.dex` | [ ] | |
| `classes2.dex` (multidex) | [ ] | |
| `resources.arsc` | [ ] | |
| `lib/` (native .so) | [ ] | |
| `assets/` | [ ] | |
| `META-INF/` | [ ] | |

### 4.4 Signing Certificate

```bash
keytool -printcert -file META-INF/CERT.RSA
```

| Property | Value | Status |
|---|---|---|
| Issuer | | |
| Signature algorithm | | ✅ / ❌ |
| Key size | | ✅ / ❌ |
| Valid from | | |
| Valid until | | |
| Debug certificate? | Yes / No | ✅ / ❌ |

---

## 5. Manifest Review

**File:** `decoded/AndroidManifest.xml`

### 5.1 Application Flags

| Flag | Value Found | Expected | Status |
|---|---|---|---|
| `android:debuggable` | | `false` | ✅ / ❌ |
| `android:allowBackup` | | `false` | ✅ / ❌ |
| `android:usesCleartextTraffic` | | `false` | ✅ / ❌ |
| `android:networkSecurityConfig` | | Present | ✅ / ❌ |
| `android:targetSdkVersion` | | ≥ 33 | ✅ / ❌ |

### 5.2 Permissions Audit

List all declared permissions and assess necessity:

| Permission | Sensitive | Justified | Notes |
|---|---|---|---|
| | [ ] | [ ] | |
| | [ ] | [ ] | |
| | [ ] | [ ] | |

**Over-privileged?** Yes / No  
**Notes:**

### 5.3 Exported Components

#### Activities

| Activity Name | Exported | Permission Required | Risk | Notes |
|---|---|---|---|---|
| | | | Low/Med/High | |
| | | | | |

#### Services

| Service Name | Exported | Permission Required | Risk | Notes |
|---|---|---|---|---|
| | | | | |

#### Broadcast Receivers

| Receiver Name | Exported | Permission Required | Risk | Notes |
|---|---|---|---|---|
| | | | | |

#### Content Providers

| Provider Name | Exported | Read Permission | Write Permission | Risk |
|---|---|---|---|---|
| | | | | |

### 5.4 Deep Links / Intent Filters

| Activity | Scheme | Host | Path | Type | Risk |
|---|---|---|---|---|---|
| | | | | Custom/AppLink | |

**Vulnerable to scheme hijacking?** Yes / No  
**Notes:**

### 5.5 Manifest Findings

| # | Finding | Severity | Location |
|---|---|---|---|
| 1 | | | |
| 2 | | | |

---

## 6. Code & Strings Analysis

### 6.1 Secret Hunting — grep Results

Run each search and document findings:

```bash
# Working directory: decompiled/sources/
```

| Pattern Searched | Command | Findings |
|---|---|---|
| API keys | `grep -r "api_key\|apikey" . -i` | |
| Passwords | `grep -r "password\|passwd\|pwd" . -i` | |
| Tokens | `grep -r "token\|bearer\|secret" . -i` | |
| AWS keys | `grep -r "AKIA" .` | |
| Google keys | `grep -r "AIza" .` | |
| HTTP URLs | `grep -r "http://" .` | |
| Staging URLs | `grep -r "staging\|dev\.\|localhost" . -i` | |
| Weak crypto | `grep -r "MD5\|SHA1\|DES\|AES/ECB" . -i` | |
| Log statements | `grep -r "Log\.d\|Log\.e\|Log\.v" .` | |
| Random (insecure) | `grep -r "new Random()" .` | |

### 6.2 Binary String Extraction

```bash
strings decoded/classes.dex | grep -E "https?://"
strings decoded/classes.dex | grep -E "[A-Za-z0-9+/]{32,}"
```

**Findings:**

### 6.3 Native Library Analysis

| Library | Suspicious Strings Found | Notes |
|---|---|---|
| | | |

### 6.4 MobSF Automated Scan

- [ ] MobSF scan completed
- [ ] Report exported

**MobSF Security Score:** _______ / 100  
**Critical findings from MobSF:**

### 6.5 Code Analysis Findings

| # | Finding | File | Line | Severity |
|---|---|---|---|---|
| 1 | | | | |
| 2 | | | | |

---

## 7. Resource Inspection

### 7.1 strings.xml Review

**File:** `decoded/res/values/strings.xml`

- [ ] Reviewed for hardcoded API keys
- [ ] Reviewed for hardcoded endpoints
- [ ] Reviewed for internal URLs (staging/dev)
- [ ] Reviewed for feature flags / hidden features

**Findings:**

### 7.2 Network Security Config

**File:** `decoded/res/xml/network_security_config.xml`

| Check | Value Found | Status |
|---|---|---|
| Cleartext traffic permitted | | ✅ / ❌ |
| User certificates trusted | | ✅ / ❌ |
| Certificate pinning configured | | ✅ / ❌ |
| Pinned domains | | |

**Config snippet (paste relevant section):**

```xml

```

### 7.3 Assets Directory

```bash
ls -la decoded/assets/
```

| File Found | Type | Risk | Notes |
|---|---|---|---|
| | | Low/Med/High | |
| | | | |

- [ ] SQLite databases inspected
- [ ] JSON/XML config files reviewed
- [ ] Bundled certificates reviewed
- [ ] JavaScript files reviewed (hybrid apps)

### 7.4 File Provider Paths

**File:** `decoded/res/xml/file_paths.xml`

- [ ] No overly broad path exposure (e.g. `path="."`)
- [ ] Sensitive directories not exposed

**Findings:**

### 7.5 Resource Findings

| # | Finding | File | Severity |
|---|---|---|---|
| 1 | | | |
| 2 | | | |

---

## 8. Dynamic Analysis

### 8.1 Frida / Objection Setup

```bash
# Start objection
objection -g com.example.app explore
```

- [ ] Frida attached successfully
- [ ] Objection connected

### 8.2 Runtime Checks

| Test | Command / Method | Result | Status |
|---|---|---|---|
| Root detection present | `android root simulate` | | ✅ / ❌ |
| Root detection bypassable | Frida hook | | ✅ / ❌ |
| SSL pinning present | Traffic interception | | ✅ / ❌ |
| SSL pinning bypassable | `android sslpinning disable` | | ✅ / ❌ |
| Debugger detection | Attach debugger | | ✅ / ❌ |
| Emulator detection | Run in emulator | | ✅ / ❌ |

### 8.3 Logcat Analysis

```bash
adb logcat | grep -i "com.example.app"
```

- [ ] PII found in logs
- [ ] Tokens/credentials found in logs
- [ ] Sensitive URLs found in logs
- [ ] Error messages revealing internals

**Findings:**

### 8.4 File System Analysis (Post-Launch)

```bash
adb shell run-as com.example.app ls -la /data/data/com.example.app/
```

| Location | Files Found | Sensitive Data | Notes |
|---|---|---|---|
| `shared_prefs/` | | [ ] | |
| `databases/` | | [ ] | |
| `files/` | | [ ] | |
| `cache/` | | [ ] | |
| External storage | | [ ] | |

### 8.5 Dynamic Findings

| # | Finding | Severity | Evidence |
|---|---|---|---|
| 1 | | | |
| 2 | | | |

---

## 9. Authentication & Authorization Testing

### 9.1 Authentication Mechanisms

| Mechanism | Implemented | Secure | Notes |
|---|---|---|---|
| Username / password | [ ] | [ ] | |
| Biometric | [ ] | [ ] | |
| OAuth 2.0 | [ ] | [ ] | |
| JWT | [ ] | [ ] | |
| Certificate-based | [ ] | [ ] | |

### 9.2 Authentication Test Cases

| Test | Result | Notes |
|---|---|---|
| Brute force protection (5+ attempts) | Pass / Fail | |
| Account lockout enforced | Pass / Fail | |
| Weak password accepted | Pass / Fail | |
| Token stored securely (Keystore) | Pass / Fail | |
| Token expires appropriately | Pass / Fail | |
| Token revoked on logout | Pass / Fail | |
| Biometric bound to Keystore key | Pass / Fail | |
| Re-auth required for sensitive actions | Pass / Fail | |

### 9.3 Authorization Test Cases

| Test | Result | Notes |
|---|---|---|
| IDOR — access other users' resources | Pass / Fail | |
| Privilege escalation via param tampering | Pass / Fail | |
| Client-side role check only | Pass / Fail | |
| Exported components require auth | Pass / Fail | |
| Deep link enforces auth state | Pass / Fail | |

### 9.4 Auth/Authz Findings

| # | Finding | Severity | OWASP Ref |
|---|---|---|---|
| 1 | | | M3 |
| 2 | | | |

---

## 10. Network Communication Testing

### 10.1 Traffic Capture Setup

- [ ] Burp Suite proxy configured
- [ ] Device proxy set to Burp
- [ ] Burp CA installed on device
- [ ] Traffic successfully intercepted

### 10.2 Communication Tests

| Test | Result | Notes |
|---|---|---|
| All traffic uses HTTPS | Pass / Fail | |
| HTTP traffic observed | Pass / Fail | |
| Certificate validation enabled | Pass / Fail | |
| Certificate pinning active | Pass / Fail | |
| TLS version ≥ 1.2 | Pass / Fail | |
| Sensitive data in URL params | Pass / Fail | |
| Sensitive data in response bodies | Pass / Fail | |
| Security headers present | Pass / Fail | |
| Tokens in HTTP headers (not URL) | Pass / Fail | |

### 10.3 Captured Endpoints

| Endpoint | Method | Auth Required | Sensitive Data | Notes |
|---|---|---|---|---|
| | | [ ] | [ ] | |
| | | [ ] | [ ] | |

### 10.4 Network Findings

| # | Finding | Severity | Endpoint |
|---|---|---|---|
| 1 | | | |
| 2 | | | |

---

## 11. Cryptography Review

### 11.1 Algorithms Found

| Algorithm | Location | Usage | Status |
|---|---|---|---|
| | | Encryption/Hashing/KDF | ✅ / ❌ |
| | | | |

### 11.2 Cryptography Checklist

| Check | Status | Notes |
|---|---|---|
| No MD5 / SHA-1 used for security | ✅ / ❌ | |
| No DES / 3DES / RC4 | ✅ / ❌ | |
| No AES-ECB mode | ✅ / ❌ | |
| IVs are randomly generated | ✅ / ❌ | |
| GCM or CBC+HMAC used | ✅ / ❌ | |
| Keys stored in Android Keystore | ✅ / ❌ | |
| No hardcoded keys | ✅ / ❌ | |
| PBKDF2 / Argon2 for password KDF | ✅ / ❌ | |
| Sufficient iteration count (≥ 310,000) | ✅ / ❌ | |
| Cryptographic RNG used (`SecureRandom`) | ✅ / ❌ | |

### 11.3 Crypto Findings

| # | Finding | Severity | Location |
|---|---|---|---|
| 1 | | | |
| 2 | | | |

---

## 12. Data Storage Review

### 12.1 Storage Locations Tested

| Location | Data Found | Sensitive | Encrypted | Notes |
|---|---|---|---|---|
| SharedPreferences | | [ ] | [ ] | |
| SQLite databases | | [ ] | [ ] | |
| Internal files (`filesDir`) | | [ ] | [ ] | |
| External storage | | [ ] | [ ] | |
| Cache directory | | [ ] | [ ] | |
| Keystore | | [ ] | N/A | |
| Clipboard | | [ ] | N/A | |
| Logs / Logcat | | [ ] | N/A | |
| Crash reports | | [ ] | N/A | |

### 12.2 Storage Checklist

| Check | Status | Notes |
|---|---|---|
| Auth tokens in Keystore (not SharedPrefs) | ✅ / ❌ | |
| No PII in SharedPreferences | ✅ / ❌ | |
| No sensitive data in external storage | ✅ / ❌ | |
| SQLite databases encrypted (SQLCipher) | ✅ / ❌ | |
| No sensitive data in cache | ✅ / ❌ | |
| Backup excluded (`allowBackup=false`) | ✅ / ❌ | |
| FLAG_SECURE on sensitive screens | ✅ / ❌ | |
| Sensitive data cleared from clipboard | ✅ / ❌ | |

### 12.3 Storage Findings

| # | Finding | Severity | Location |
|---|---|---|---|
| 1 | | | |
| 2 | | | |

---

## 13. Platform Interaction Testing

### 13.1 Intent Security

| Test | Result | Notes |
|---|---|---|
| Exported activities require auth | Pass / Fail | |
| No sensitive data in Intent extras | Pass / Fail | |
| Implicit intents used safely | Pass / Fail | |
| Deep link input validated | Pass / Fail | |

### 13.2 WebView Testing

| Check | Status | Notes |
|---|---|---|
| JavaScript enabled (justified?) | ✅ / ❌ | |
| `addJavascriptInterface` present | ✅ / ❌ | |
| File access disabled | ✅ / ❌ | |
| Only trusted URLs loaded | ✅ / ❌ | |
| No user-supplied URL loaded | ✅ / ❌ | |

### 13.3 Screenshot / Screen Recording

| Check | Status | Notes |
|---|---|---|
| `FLAG_SECURE` on sensitive activities | ✅ / ❌ | |
| App switcher blurs sensitive content | ✅ / ❌ | |

### 13.4 Platform Findings

| # | Finding | Severity | Component |
|---|---|---|---|
| 1 | | | |
| 2 | | | |

---

## 14. Findings Summary

### 14.1 All Findings

| ID | Title | Severity | OWASP Category | Status |
|---|---|---|---|---|
| F-01 | | Critical | | Open |
| F-02 | | High | | Open |
| F-03 | | Medium | | Open |
| F-04 | | Low | | Open |
| F-05 | | Info | | Open |

### 14.2 Severity Distribution

| Severity | Count |
|---|---|
| Critical | |
| High | |
| Medium | |
| Low | |
| Informational | |
| **Total** | |

### 14.3 OWASP Mobile Top 10 Coverage

| OWASP ID | Category | Tested | Finding |
|---|---|---|---|
| M1 | Improper Credential Usage | [ ] | |
| M2 | Inadequate Supply Chain Security | [ ] | |
| M3 | Insecure Auth & Authorization | [ ] | |
| M4 | Insufficient Input Validation | [ ] | |
| M5 | Insecure Communication | [ ] | |
| M6 | Inadequate Privacy Controls | [ ] | |
| M7 | Insufficient Binary Protections | [ ] | |
| M8 | Security Misconfiguration | [ ] | |
| M9 | Insecure Data Storage | [ ] | |
| M10 | Insufficient Cryptography | [ ] | |

### 14.4 Finding Detail Template

> Copy this block for each finding:

---

#### F-XX — [Finding Title]

**Severity:** Critical / High / Medium / Low / Informational  
**OWASP Category:** M1–M10  
**CWE:** CWE-XXX  

**Description:**  
_What the vulnerability is and why it matters._

**Location:**  
_File name, class, method, line number, or endpoint._

**Evidence:**  
```
Paste relevant code snippet, log output, or screenshot reference here.
```

**Impact:**  
_What an attacker can achieve by exploiting this._

**Remediation:**  
_Specific, actionable fix with code example where possible._

**References:**  
- OWASP Mobile Top 10
- CWE link

---

---

## 15. Risk Rating Reference

| Severity | CVSS Range | Description | Example |
|---|---|---|---|
| **Critical** | 9.0 – 10.0 | Direct account takeover or full data breach possible | Hardcoded admin credentials |
| **High** | 7.0 – 8.9 | Significant data exposure or auth bypass | Disabled SSL validation |
| **Medium** | 4.0 – 6.9 | Limited data exposure or requires user interaction | Weak hashing algorithm |
| **Low** | 1.0 – 3.9 | Minor exposure, hard to exploit | Verbose error messages |
| **Informational** | N/A | Best practice gap, no direct exploitability | Missing security headers |

---

## 16. Sign-Off

### 16.1 Assessment Summary

**Overall Security Posture:** Poor / Needs Improvement / Acceptable / Good  
**Recommended Action:** Block release / Fix critical before release / Fix before next release / Monitor  

**Summary Statement:**  
> _2–3 sentence executive summary of the assessment findings._

### 16.2 Assessor Sign-Off

| Field | Value |
|---|---|
| Assessor name | |
| Date completed | |
| Tools version | |
| Hours spent | |

### 16.3 Review Sign-Off (if applicable)

| Field | Value |
|---|---|
| Reviewer name | |
| Date reviewed | |
| Approved | Yes / No |

### 16.4 Re-test Record

| Finding ID | Fixed By | Fix Date | Re-tested By | Re-test Date | Result |
|---|---|---|---|---|---|
| F-01 | | | | | Pass / Fail |
| F-02 | | | | | Pass / Fail |

---

*Template version 1.0 — Based on OWASP Mobile Top 10 (2024) and OWASP MSTG*
