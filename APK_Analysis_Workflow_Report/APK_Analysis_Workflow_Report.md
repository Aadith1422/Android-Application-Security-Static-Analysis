# APK Analysis — Full Workflow Report
**Target APK:** `DIVA.apk` (Damn Insecure and Vulnerable App)  
**Package:** `jakhar.aseem.diva`  
**Analyst:** Aadith  
**Date:** 2026-05-30  
**Working Directory:** `~/mobile-static-analysis/`

---

## Table of Contents
1. [Lab Environment Setup](#1-lab-environment-setup)
2. [Step 1 — Obtain the APK](#2-step-1--obtain-the-apk)
3. [Step 2 — Verify APK Signature & Check for Tampering](#3-step-2--verify-apk-signature--check-for-tampering)
4. [Step 3 — Decompile with apktool & jadx](#4-step-3--decompile-with-apktool--jadx)
5. [Step 4 — Inspect AndroidManifest.xml & Resources](#5-step-4--inspect-androidmanifestxml--resources)
6. [Step 5 — Search Code for Insecure Patterns & Sensitive Strings](#6-step-5--search-code-for-insecure-patterns--sensitive-strings)
7. [Step 6 — Patch APK (Smali) & Re-sign for Dynamic Testing](#7-step-6--patch-apk-smali--re-sign-for-dynamic-testing)
8. [Findings Summary](#8-findings-summary)

---

## 1. Lab Environment Setup

### Tools Verified

```bash
java -version
adb version
apktool --version
jadx --version
```

**Screenshot — Tool version verification:**

![tool versions](Screenshots/Screenshot%20from%202026-05-30%2013-55-47.png)

| Tool | Version | Purpose |
|---|---|---|
| **OpenJDK** | 21.0.11 (2026-04-21) | Java runtime for apktool, keytool, apksigner |
| **ADB** | 1.0.41 / 34.0.4-debian | Android Debug Bridge — device communication |
| **apktool** | 2.7.0-dirty | APK decode/rebuild, Smali access |
| **jadx** | 1.5.1 | DEX → Java decompiler |

**Additional tools used (installed separately):**

| Tool | Purpose |
|---|---|
| **Burp Suite** | HTTP/S proxy for traffic interception |
| **Frida** | Dynamic instrumentation framework |
| **Objection** | Frida-based runtime exploration toolkit |
| **MobSF** | Automated mobile security scanning |
| **keytool / apksigner** | APK signing and certificate inspection |

---

## 2. Step 1 — Obtain the APK

### Working Directory Setup

```bash
cd ~/mobile-static-analysis
ls
```

**Screenshot — Working directory with DIVA.apk present:**

![working directory](Screenshots/Screenshot%20from%202026-05-30%2013-56-44.png)

The working directory contains:
- `DIVA/` — previously decoded APK directory (from apktool)
- `DIVA.apk` — original APK file ready for analysis

> **Note:** The APK was obtained directly as a file. Alternatively, an APK can be pulled from a connected device using:
> ```bash
> adb shell pm path jakhar.aseem.diva
> adb pull /data/app/jakhar.aseem.diva-1/base.apk DIVA.apk
> ```

---

## 3. Step 2 — Verify APK Signature & Check for Tampering

APK signature verification confirms the APK has not been tampered with and identifies the signing entity. Two tools were used: `keytool` (certificate inspection) and `apksigner` (scheme verification).

### 3.1 Certificate Inspection with keytool

```bash
keytool -printcert -jarfile DIVA.apk
```

**Screenshot — APK certificate details:**

![keytool printcert output](Screenshots/Screenshot%20from%202026-05-30%2013-57-04.png)

**Certificate findings:**

| Field | Value |
|---|---|
| **Signer** | #1 |
| **Owner** | CN=Android Debug, O=Android, C=US |
| **Issuer** | CN=Android Debug, O=Android, C=US |
| **Serial Number** | 218330df |
| **Valid From** | Mon Nov 02 2015 |
| **Valid Until** | Wed Oct 25 2045 |
| **SHA1 Fingerprint** | AE:4E:AD:5A:EA:BA:4E:9E:4F:C9:28:E7:C7:F7:FD:45:9F:00:80:31 |
| **SHA256 Fingerprint** | 35:D7:F7:AD:35:DF:B8:26:B7:0F:A4:B7:31:87:ED:47:85:40:E3:2C:8B:8C:56:53:B8:65:68:02:9F:CD:58:40 |
| **Signature Algorithm** | SHA256withRSA |
| **Key Algorithm** | 2048-bit RSA |
| **Version** | 3 |

> **Finding:** The APK is signed with an **Android Debug key** (self-signed, CN=Android Debug). This is the default debug keystore, confirming the APK was never signed for production release. Debug-signed APKs should never be distributed publicly.

---

## 4. Step 3 — Decompile with apktool & jadx

### 4.1 apktool — Decode Resources & Smali

```bash
apktool -f d DIVA.apk
```

The `-f` flag forces a clean re-decode, overwriting any previous output.

**Screenshot — apktool decode output:**

![apktool decode](Screenshots/Screenshot%20from%202026-05-30%2013-57-57.png)

apktool successfully performed all decode stages:
- Loaded resource table and framework
- Decoded `AndroidManifest.xml` with resources
- Decoded file-resources and values XMLs
- Baksmaled `classes.dex` → Smali bytecode
- Copied assets, libs, and unknown files

### 4.2 jadx — Decompile DEX to Java Source

jadx was launched in GUI mode to browse decompiled Java source interactively.

**Screenshot — jadx-gui with DIVA.apk loaded:**

![jadx gui](Screenshots/Screenshot%20from%202026-05-30%2013-58-13.png)

The jadx project tree exposes:
- **Inputs** → raw files and scripts
- **Source code** → `android.support.*` + `jakhar.aseem.diva.*`
- **Resources** → decoded XML layouts and values
- **APK signature** → certificate information
- **Summary** → decompilation statistics and warnings

### 4.3 strings — Raw String Extraction from Binary

```bash
strings DIVA.apk | head -50
```

**Screenshot — strings output from DIVA.apk:**

![strings output](Screenshots/Screenshot%20from%202026-05-30%2013-59-03.png)

The `strings` command extracts all printable character sequences directly from the binary. Output includes embedded resource paths such as `res/anim/abc_fade_in.xml`, `res/anim/abc_popup_enter.xml`, and obfuscated short strings from the DEX section. This technique is useful for a quick first pass to spot hardcoded URLs, keys, or credentials without needing full decompilation.

---

## 5. Step 4 — Inspect AndroidManifest.xml & Resources

### 5.1 Permissions

```bash
grep uses-permission DIVA/AndroidManifest.xml
```

### 5.2 Exported Components & Intent Filters

```bash
grep exported DIVA/AndroidManifest.xml
grep -n "intent-filter" DIVA/AndroidManifest.xml
```

**Screenshot — Manifest inspection (permissions, exported components, intent-filters):**

![manifest inspection](Screenshots/Screenshot%20from%202026-05-30%2013-58-48.png)

**Permissions declared:**

| Permission | Risk |
|---|---|
| `WRITE_EXTERNAL_STORAGE` | High — write files to SD card |
| `READ_EXTERNAL_STORAGE` | High — read all SD card files |
| `INTERNET` | Medium — outbound network access |

**Exported component found:**
```xml
<provider
  android:authorities="jakhar.aseem.diva.provider.notesprovider"
  android:enabled="true"
  android:exported="true"
  android:name="jakhar.aseem.diva.NoteProvider"/>
```
> Any third-party app can freely query the `NoteProvider` content provider — no permission required.

**Intent filters** found at lines 7, 22, and 29 — three activities registered to receive external intents without visible input validation.

### 5.3 Resource File Enumeration

```bash
find DIVA/res -type f | head -20
```

**Screenshot — Resource files listing:**

![resource files](Screenshots/Screenshot%20from%202026-05-30%2014-01-04.png)

The `res/` directory contains drawable assets across multiple density buckets (`xxxhdpi`, `hdpi`, `v4`, `v23`) and localised `strings.xml` files for numerous locales (es-rUS, pt-rBR, si-rLK, kk-rKZ, hr, am, in, etc.). These were scanned for embedded sensitive values.

---

## 6. Step 5 — Search Code for Insecure Patterns & Sensitive Strings

### 6.1 Sensitive Strings in resources/strings.xml

```bash
grep -i "http\|password\|api" DIVA/res/values/strings.xml
```

**Screenshot — Sensitive string search in resources:**

![sensitive strings grep](Screenshots/Screenshot%20from%202026-05-30%2014-01-39.png)

Matches found in `strings.xml`:

| String Name | Content / Significance |
|---|---|
| `aci1_intro` | References accessing **API credentials** from outside the app |
| `aci1_view` | Label: "VIEW API CREDENTIALS" |
| `aci2_intro` | References **Tveeter API** credentials and a vendor PIN bypass |
| `aci2_view` | Label: "VIEW TVEETER API CREDENTIALS" |
| `apic2_enter` | "Enter PIN received from Tveeter" |
| `apic2_label` | "Tveeter API Credentials" |
| `apic_label` | "Vendor API Credentials" |
| `ids1_password` | "Enter 3rd party service **password**" |

> **Finding:** The strings resource file exposes UI labels that directly describe the vulnerable API credential and insecure data storage challenges, confirming that credential handling flows are present in the app.

### 6.2 Smali Bytecode — SQLInjectionActivity Inspection

The Smali file for `SQLInjectionActivity` was opened directly to review the raw bytecode before patching.

```
DIVA/smali/jakhar/aseem/diva/SQLInjectionActivity.smali
```

**Screenshot — SQLInjectionActivity.smali (class header & onCreate):**

![smali class header](Screenshots/Screenshot%20from%202026-05-30%2014-04-18.png)

Key Smali observations:
- Class declared as `Ljakhar/aseem/diva/SQLInjectionActivity;`
- Extends `Landroid/support/v7/app/AppCompatActivity;`
- Private field `mDB` of type `Landroid/database/sqlite/SQLiteDatabase;`
- `onCreate` opens database named `"sqli"` via `openOrCreateDatabase`

**Screenshot — Raw SQL query string in Smali (before patch):**

![smali before patch](Screenshots/Screenshot%20from%202026-05-30%2014-06-15.png)

The vulnerable `const-string` instruction at line 39 holds the injectable query:
```smali
const-string v6, "SELECT * FROM sqliuser WHERE user = \'"
```
User input is concatenated directly via `StringBuilder.append()` calls — classic SQL injection in bytecode form.

---

## 7. Step 6 — Patch APK (Smali) & Re-sign for Dynamic Testing

This step demonstrates how to modify Smali bytecode, rebuild the APK, generate a signing key, and verify the re-signed package — a common technique to disable root checks, certificate pinning, or other runtime defences.

### 7.1 Edit Smali — Patch the SQL Query

The raw SQL string in `SQLInjectionActivity.smali` was edited using `nano` to replace the injectable query prefix with a fixed, non-injectable string:

**Before patch:**
```smali
const-string v6, "SELECT * FROM sqliuser WHERE user = \'"
```

**After patch:**
```smali
const-string v6, "SELECT * FROM sqliuser WHERE user = 'PATCHED"
```

**Screenshot — Smali file after patch (PATCHED string visible):**

![smali after patch](Screenshots/Screenshot%20from%202026-05-30%2014-12-01.png)

The `*` marker in the nano title bar confirms unsaved changes, and the patched string `'PATCHED"` is visible at the `const-string v6` instruction. This effectively hard-codes a non-injectable query, demonstrating that Smali-level modification works.

### 7.2 Rebuild APK with apktool

```bash
apktool b DIVA -o DIVA_patched.apk
```

**Screenshot — apktool rebuild output:**

![apktool rebuild](Screenshots/Screenshot%20from%202026-05-30%2014-12-22.png)

apktool rebuild process:
- Checked for source/resource changes
- Smaled the Smali folder back into `classes.dex`
- Built resources and copied libs
- Output: **`DIVA_patched.apk`** (1.5 MB)

> **Note:** A warning appeared: `aapt: brut.common.BrutException: Could not extract resource: /prebuilt/linux/aapt_64 (defaulting to $PATH binary)` — apktool fell back to the system `aapt`, which is acceptable for this lab exercise.

### 7.3 Generate a Test Signing Keystore

To install the patched APK on a device or emulator, it must be signed. A new RSA keystore was generated:

```bash
keytool -genkeypair -v -keystore test.keystore \
  -alias test -keyalg RSA -keysize 2048 -validity 10000
```

**Screenshot — keytool keystore generation + patched APK file size:**

![keytool keystore generation](Screenshots/Screenshot%20from%202026-05-30%2014-15-28.png)

Keystore certificate details entered:

| Field | Value |
|---|---|
| First & Last Name | Unknown |
| Organisational Unit | Security |
| Organisation | Lab |
| City / Locality | Test |
| State / Province | Test |
| Country Code | IN |

Generated: **2,048-bit RSA key pair** with a **SHA384withRSA** self-signed certificate valid for 10,000 days. Stored in `test.keystore`.

### 7.4 Sign & Verify the Patched APK

```bash
apksigner sign --ks test.keystore DIVA_patched.apk
apksigner verify --verbose DIVA_patched.apk
```

**Screenshot — apksigner sign & verify output:**

![apksigner verify](Screenshots/Screenshot%20from%202026-05-30%2014-16-21.png)

**Verification results:**

| Scheme | Result |
|---|---|
| v1 (JAR signing) | ✅ true |
| v2 (APK Signature Scheme v2) | ✅ true |
| v3 (APK Signature Scheme v3) | ✅ true |
| v4 (APK Signature Scheme v4) | ❌ false (not generated — acceptable) |
| SourceStamp | false |
| Number of signers | 1 |

> **Result:** The patched APK is successfully re-signed and verified on schemes v1, v2, and v3. It is now ready for installation on an emulator or rooted test device for dynamic analysis with Frida/Objection.

---

## 8. Findings Summary

### Complete Workflow Checklist

| Step | Action | Status | Tool Used |
|---|---|---|---|
| 1 | Verify lab tools (Java, ADB, apktool, jadx) | ✅ Done | Terminal |
| 2 | Obtain APK in working directory | ✅ Done | ADB / manual |
| 3a | Inspect APK certificate | ✅ Done | keytool |
| 3b | Confirm APK is debug-signed | ✅ Done | keytool |
| 4a | Decode APK with apktool | ✅ Done | apktool 2.7.0 |
| 4b | Decompile to Java with jadx | ✅ Done | jadx 1.5.1 |
| 4c | Extract raw strings from binary | ✅ Done | strings |
| 5a | Inspect permissions in manifest | ✅ Done | grep |
| 5b | Find exported components | ✅ Done | grep |
| 5c | Locate intent filters | ✅ Done | grep |
| 5d | Enumerate resource files | ✅ Done | find |
| 5e | Search strings.xml for API/password refs | ✅ Done | grep |
| 5f | Review Smali for SQL injection | ✅ Done | nano |
| 6a | Patch Smali (modify SQL query string) | ✅ Done | nano |
| 6b | Rebuild patched APK | ✅ Done | apktool |
| 6c | Generate test signing keystore | ✅ Done | keytool |
| 6d | Sign & verify patched APK | ✅ Done | apksigner |

### Key Security Findings

| # | Finding | Location | Severity |
|---|---|---|---|
| F-01 | APK signed with **debug key** — not production-safe | APK certificate | 🟠 High |
| F-02 | Exported `NoteProvider` with no read permission | `AndroidManifest.xml` | 🔴 Critical |
| F-03 | Broad external storage permissions declared | `AndroidManifest.xml` | 🟠 High |
| F-04 | API credential labels exposed in `strings.xml` | `res/values/strings.xml` | 🟡 Medium |
| F-05 | SQL injection via string concat in Smali | `SQLInjectionActivity.smali:39` | 🔴 Critical |
| F-06 | Smali bytecode successfully patched & re-signed | `DIVA_patched.apk` | ℹ️ Info |

### Patch Demonstration Summary

The Smali-level patch proved that:
1. `apktool` can fully decode and rebuild a working APK from bytecode.
2. Individual `const-string` instructions — including SQL queries, flag checks, and API keys — can be surgically modified without recompiling Java source.
3. The rebuilt APK passes v1/v2/v3 signature verification after re-signing with a custom keystore.
4. This technique can be used to **disable SSL pinning checks**, **bypass root detection**, or **remove licence validation** in apps during dynamic analysis labs.

---

*Report generated from static analysis and APK patching workflow performed on 2026-05-30.*
