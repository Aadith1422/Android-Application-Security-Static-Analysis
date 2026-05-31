# APK Static Analysis Report
**Target APK:** `DIVA.apk` (Damn Insecure and Vulnerable App)  
**Package:** `jakhar.aseem.diva`  
**Analyst:** Aadith  
**Date:** 2026-05-30  
**Tools Used:** apktool, jadx, grep, strings

---

## Table of Contents
1. [Tools & Environment Setup](#1-tools--environment-setup)
2. [AndroidManifest.xml Analysis](#2-androidmanifestxml-analysis)
3. [Resource & Embedded Secret Inspection](#3-resource--embedded-secret-inspection)
4. [Decompiled Code — Sensitive Pattern Search](#4-decompiled-code--sensitive-pattern-search)
5. [Findings Summary & Risk Table](#5-findings-summary--risk-table)

---

## 1. Tools & Environment Setup

### 1.1 apktool — Decode APK Resources & Manifest

`apktool` was used to decode the APK, extracting the human-readable `AndroidManifest.xml`, resource files (layouts, values, drawables), and Smali bytecode.

```bash
apktool d DIVA.apk
```

**Screenshot — apktool decoding DIVA.apk:**

![apktool decode output](Screenshots/Screenshot%20from%202026-05-30%2011-52-44.png)

The decode produced the following directory structure inside the `DIVA/` folder:

| Output Item | Description |
|---|---|
| `AndroidManifest.xml` | Human-readable manifest |
| `res/` | Decoded layout & resource files |
| `smali/` | Disassembled Dalvik bytecode |
| `apktool.yml` | Metadata for re-packing |
| `lib/`, `original/` | Native libs & original META-INF |

### 1.2 jadx — Decompile DEX to Java Source

**jadx** (Java Decompiler for Android) was used to convert `classes.dex` back into readable Java source. The decompiled source was explored through the jadx-gui interface.

**Screenshot — jadx-gui with DIVA.apk loaded (project tree):**

![jadx gui loaded](Screenshots/Screenshot%20from%202026-05-30%2012-02-45.png)

The left-hand panel shows the full project tree:
- **Inputs** → raw APK files & scripts
- **Source code** → `android.support.*` and `jakhar.aseem.diva.*` packages
- **Resources** → decoded XML resources
- **APK signature** → signing certificate info
- **Summary** → overall stats

---

## 2. AndroidManifest.xml Analysis

All manifest analysis was performed on the file at `DIVA/AndroidManifest.xml` (extracted by apktool).

### 2.1 Permissions Declared

```bash
grep uses-permission DIVA/AndroidManifest.xml
```

**Screenshot — Permission grep results:**

![permissions grep](Screenshots/Screenshot%20from%202026-05-30%2011-55-36.png)

**Permissions found:**

| Permission | Risk Level | Notes |
|---|---|---|
| `android.permission.WRITE_EXTERNAL_STORAGE` | HIGH | Can write arbitrary files to SD card |
| `android.permission.READ_EXTERNAL_STORAGE` | HIGH | Can read all files on SD card |
| `android.permission.INTERNET` | MEDIUM | Allows outbound network connections |

> **Finding:** The app requests broad external storage permissions. Combined with insecure data storage vulnerabilities, this could allow an attacker or malicious app to read credentials saved to external storage.

### 2.2 Exported Components

```bash
grep exported DIVA/AndroidManifest.xml
```

**Screenshot — Exported component grep:**

![exported component grep](Screenshots/Screenshot%20from%202026-05-30%2011-55-52.png)

**Finding:** The `NoteProvider` content provider is explicitly exported with `android:exported="true"`:

```xml
<provider
  android:authorities="jakhar.aseem.diva.provider.notesprovider"
  android:enabled="true"
  android:exported="true"
  android:name="jakhar.aseem.diva.NoteProvider"/>
```

> **Risk:** Any app on the device can query `jakhar.aseem.diva.provider.notesprovider` without any permission requirement, exposing all notes data stored in the content provider.

### 2.3 Intent Filters

```bash
grep -n "intent-filter" DIVA/AndroidManifest.xml
```

**Screenshot — Intent filter locations in manifest:**

![intent filter grep](Screenshots/Screenshot%20from%202026-05-30%2011-56-08.png)

Intent filters were found at lines **7, 10, 22, 25, 29, and 32**, indicating multiple activities are registered to receive external intents. These should each be reviewed for improper input validation on incoming Intent data.

---

## 3. Resource & Embedded Secret Inspection

### 3.1 Hardcoded Credentials in SQLite Database Setup

**File:** `jakhar/aseem/diva/SQLInjectionActivity.java`  
**Lines:** 24–26

**Screenshot — Hardcoded credentials in SQLInjectionActivity (jadx):**

![hardcoded credentials SQLInjectionActivity](Screenshots/Screenshot%20from%202026-05-30%2012-12-13.png)

The decompiled code reveals plaintext credentials hardcoded directly into SQL `INSERT` statements:

```java
this.mDB.execSQL("INSERT INTO sqliuser VALUES ('admin', 'passwd123', '1234567812345678');");
this.mDB.execSQL("INSERT INTO sqliuser VALUES ('diva', 'p@ssword', '1111222233334444');");
this.mDB.execSQL("INSERT INTO sqliuser VALUES ('john', 'password123', '5555666677778888');");
```

> **Critical Finding:** Credit card numbers, usernames, and passwords are hardcoded in plain text in the source. This is a direct secret leakage vulnerability.

### 3.2 Insecure HTTP URL

**File:** `jakhar/aseem/diva/APICreds2Activity.java`  
**Method:** `onCreate(Bundle)`

**Screenshot — Insecure HTTP URL search in jadx:**

![insecure http search](Screenshots/Screenshot%20from%202026-05-30%2012-07-15.png)

A search for `http://` in the decompiled code returned one result: a reference to `http://payatu.c...` (full URL truncated in the screenshot). This URL uses plain HTTP rather than HTTPS, making all communication susceptible to man-in-the-middle (MitM) interception.

> **Finding:** Insecure HTTP endpoint used in `APICreds2Activity`. All traffic to this endpoint is unencrypted.

---

## 4. Decompiled Code — Sensitive Pattern Search

All searches below were performed using jadx's built-in **Text Search** (`Tools → Text Search`) with **Code** scope enabled and case-insensitive matching.

### 4.1 WebView Usage — JavaScript Enabled

**Search term:** `WebView`  
**Results:** 3 matches in `InputValidation2URISchemeActivity`

**Screenshot — WebView text search results:**

![webview search results](Screenshots/Screenshot%20from%202026-05-30%2012-07-01.png)

**Screenshot — WebView code with JavaScript enabled:**

![webview javascript enabled code](Screenshots/Screenshot%20from%202026-05-30%2012-08-47.png)

**File:** `jakhar/aseem/diva/InputValidation2URISchemeActivity.java`  
**Lines:** 17–19, 25, 27

```java
// Line 17-19
WebView wview = (WebView) findViewById(R.id.ivi2wview);
WebSettings wset = wview.getSettings();
wset.setJavaScriptEnabled(true);   // ← DANGEROUS

// Line 25-27 (get() method)
WebView wview = (WebView) findViewById(R.id.ivi2wview);
wview.loadUrl(uriText.getText().toString());  // ← User-controlled URL
```

> **Critical Finding:** JavaScript is enabled on a WebView that loads a **user-controlled URL** directly without sanitisation. This enables Cross-Site Scripting (XSS), JavaScript injection, and potentially allows attackers to exfiltrate data using `javascript:` scheme URIs or load malicious pages.

### 4.2 SQLite Usage

**Search term:** `SQLite`  
**Results:** 15 matches across multiple classes

**Screenshot — SQLite text search results:**

![sqlite search results](Screenshots/Screenshot%20from%202026-05-30%2012-09-49.png)

SQLite usage was found in:

| Class | Usage |
|---|---|
| `InsecureDataStorage2Activity` | `openOrCreateDatabase`, credential storage |
| `NoteProvider` | `SQLiteOpenHelper`, `SQLiteQueryBuilder` |
| `NoteProvider.DBHelper` | `SQLiteOpenHelper` subclass |
| `SQLInjectionActivity` | Direct `rawQuery` with user input |

### 4.3 SQL Injection — Raw Query with User Input

**File:** `jakhar/aseem/diva/SQLInjectionActivity.java`  
**Line:** 39

**Screenshot — SQLInjectionActivity full source (jadx):**

![sql injection activity](Screenshots/Screenshot%20from%202026-05-30%2012-12-13.png)

```java
Cursor cr = this.mDB.rawQuery(
    "SELECT * FROM sqliuser WHERE user = '" + srchtxt.getText().toString() + "'",
    null
);
```

> **Critical Finding:** Raw SQL string concatenation with unvalidated user input. Classic SQL injection — an attacker can inject `' OR '1'='1` to dump all records including credit card numbers and passwords.

### 4.4 Insecure Data Storage — SQLite Credential Storage

**File:** `jakhar/aseem/diva/InsecureDataStorage2Activity.java`  
**Lines:** 22–23, 36**

**Screenshot — InsecureDataStorage2Activity (jadx):**

![insecure data storage 2](Screenshots/Screenshot%20from%202026-05-30%2012-28-36.png)

```java
// Line 22-23: Database created with no encryption
this.mDB = openOrCreateDatabase("ids2", 0, null);
this.mDB.execSQL("CREATE TABLE IF NOT EXISTS myuser(user VARCHAR, password VARCHAR);");

// Line 36: Plaintext insert of credentials
this.mDB.execSQL("INSERT INTO myuser VALUES ('" + usr.getText().toString() + "', '" + pwd.getText().toString() + "');");
```

> **Finding:** User credentials are stored in an unencrypted SQLite database (`ids2`). On rooted devices or via ADB backup, this file is trivially readable.

### 4.5 Password References

**Search term:** `password`  
**Results:** 40 matches

**Screenshot — Password search results:**

![password search results](Screenshots/Screenshot%20from%202026-05-30%2012-06-24.png)

Multiple password-related methods are spread across accessibility and app classes. The most critical are in `SQLInjectionActivity` and `InsecureDataStorage2Activity` (covered above).

### 4.6 Token References

**Search term:** `token`  
**Results:** 50+ matches

**Screenshot — Token search results:**

![token search results](Screenshots/Screenshot%20from%202026-05-30%2012-09-34.png)

Most token references are in `android.support.*` media/notification libraries (standard Android support code). No custom app-level token handling with hardcoded secrets was found in the app package itself.

### 4.7 Weak Cryptography — MD5 / SHA1

**Search term:** `MD5` → **0 results**  
**Search term:** `SHA1` → **0 results**

**Screenshot — MD5 search (no results):**

![md5 search no results](Screenshots/Screenshot%20from%202026-05-30%2012-06-35.png)

**Screenshot — SHA1 search (no results):**

![sha1 search no results](Screenshots/Screenshot%20from%202026-05-30%2012-06-52.png)

> **Note:** No explicit use of MD5 or SHA1 was found in application code. The app does not appear to implement custom hashing; it stores passwords in plaintext instead, which is equally insecure.

---

## 5. Findings Summary & Risk Table

| # | Finding | File / Location | Severity | CWE |
|---|---|---|---|---|
| F-01 | Exported `NoteProvider` with no permission | `AndroidManifest.xml` | 🔴 **Critical** | CWE-926 |
| F-02 | SQL Injection via `rawQuery` | `SQLInjectionActivity.java:39` | 🔴 **Critical** | CWE-89 |
| F-03 | Hardcoded credentials & credit card numbers | `SQLInjectionActivity.java:24–26` | 🔴 **Critical** | CWE-798 |
| F-04 | WebView with JS enabled loading user-controlled URL | `InputValidation2URISchemeActivity.java:17–27` | 🔴 **Critical** | CWE-79 |
| F-05 | Plaintext credential storage in unencrypted SQLite | `InsecureDataStorage2Activity.java:22–36` | 🟠 **High** | CWE-312 |
| F-06 | Insecure HTTP endpoint (no TLS) | `APICreds2Activity.java` | 🟠 **High** | CWE-319 |
| F-07 | Broad external storage permissions declared | `AndroidManifest.xml` | 🟡 **Medium** | CWE-276 |
| F-08 | Multiple intent-filters without input validation | `AndroidManifest.xml:7,22,29` | 🟡 **Medium** | CWE-20 |

### Key Takeaways

- DIVA is intentionally vulnerable and demonstrates **7 of the OWASP Mobile Top 10** categories in a single APK.
- Static analysis with **apktool + jadx + grep** was sufficient to uncover all major vulnerabilities without executing the app.
- The most impactful findings (**SQL injection**, **exported content provider**, **WebView JS injection**) could be chained for full data exfiltration on a real device.
- Automated tools like **MobSF** would flag most of these automatically; manual jadx review adds depth by confirming exploitability at the code level.

---

*Report generated from static analysis of DIVA.apk on 2026-05-30.*
