# SSL Pinning — Concept, Implementations & Bypass Techniques

---

| Field | Details |
|---|---|
| **Topic** | SSL/TLS Pinning — Understanding & Bypass |
| **Analysis Type** | Conceptual + Practical Lab Study |
| **Tools Covered** | Frida, Objection, apktool, smali, Burp Suite |
| **Analyst** | aadith |
| **Date** | 2026-05-31 |

---

## Table of Contents

1. [What is SSL Pinning?](#1-what-is-ssl-pinning)
2. [Why Apps Use SSL Pinning](#2-why-apps-use-ssl-pinning)
3. [Common Pinning Implementations](#3-common-pinning-implementations)
4. [SSL Pinning Bypass Techniques](#4-ssl-pinning-bypass-techniques)
5. [Tool-by-Tool Bypass Guide](#5-tool-by-tool-bypass-guide)
6. [Detecting SSL Pinning in Code](#6-detecting-ssl-pinning-in-code)
7. [Summary Table](#7-summary-table)

---

## 1. What is SSL Pinning?

SSL Pinning (also called **Certificate Pinning** or **TLS Pinning**) is a security technique used in mobile applications to **hardcode a specific server certificate or public key** directly into the app. Instead of relying solely on the device's trusted CA (Certificate Authority) store, the app validates the server's certificate against its own pinned copy.

### Normal TLS Handshake (Without Pinning)

```
Client (App)                        Server
     |                                 |
     |------- ClientHello ------------>|
     |<------ ServerHello + Cert ------|
     |                                 |
     | Validates cert against          |
     | device's CA store               |
     |                                 |
     |===== Encrypted Channel =========|
```

### TLS Handshake With Pinning

```
Client (App)                        Server
     |                                 |
     |------- ClientHello ------------>|
     |<------ ServerHello + Cert ------|
     |                                 |
     | 1. Validates cert against CA    |
     | 2. Also checks cert/pubkey      |
     |    against HARDCODED pin        |
     |    inside the app               |
     |    ✅ Match → Connection OK      |
     |    ❌ Mismatch → ABORT          |
     |                                 |
     |===== Encrypted Channel =========|
```

### What Happens During a MITM Attack Without Pinning

```
Attacker (Burp Suite / Proxy)
         ↕
     App trusts Burp's CA
     (installed on device)
         ↕
     All traffic visible
     to attacker ✅
```

### What Happens During a MITM Attack With Pinning

```
Attacker (Burp Suite / Proxy)
         ↕
     App checks Burp's cert
     → Does NOT match pinned cert
     → Connection REJECTED ❌
     → Attacker sees nothing
```

---

## 2. Why Apps Use SSL Pinning

Banking apps, payment apps, and security-sensitive apps implement SSL pinning to defend against the following threats:

| Threat | Without Pinning | With Pinning |
|---|---|---|
| **MITM via rogue CA** | Vulnerable | Protected |
| **Burp Suite interception** | Easy | Blocked |
| **Compromised CA** | Vulnerable | Protected |
| **Corporate/ISP proxy inspection** | Vulnerable | Protected |
| **Malware on device trusting fake CA** | Vulnerable | Protected |
| **Traffic analysis by researcher** | Easy | Blocked |

### Real-World Use Cases

- **Banking apps** — prevent credential and OTP interception
- **Payment apps** (PhonePe, GPay) — protect transaction data
- **Healthcare apps** — protect patient data in transit
- **Government apps** — prevent surveillance/modification
- **Auth apps** — protect token exchange flows

---

## 3. Common Pinning Implementations

### 3.1 Certificate Pinning

The entire server certificate (DER-encoded) or its hash is embedded in the app. The app compares the server's presented certificate byte-by-byte or hash-by-hash.

**Android Implementation (Java):**

```java
// In OkHttpClient or custom TrustManager
public void checkServerTrusted(X509Certificate[] chain, String authType)
        throws CertificateException {
    // Get the server's certificate
    X509Certificate serverCert = chain[0];
    
    // Compare with pinned certificate bytes
    byte[] pinnedCert = loadPinnedCertFromAssets(); // hardcoded/bundled cert
    
    if (!Arrays.equals(serverCert.getEncoded(), pinnedCert)) {
        throw new CertificateException("Certificate pinning failure!");
    }
}
```

**Pros:** Simple to implement  
**Cons:** Certificate rotations break the app — requires app update every time cert expires

---

### 3.2 Public Key Pinning (SPKI Pinning)

Instead of pinning the full certificate, only the **Subject Public Key Info (SPKI)** hash (usually SHA-256 base64) is pinned. More flexible since the public key can survive certificate renewals.

**Android Implementation:**

```java
// Extract and compare public key hash
MessageDigest md = MessageDigest.getInstance("SHA-256");
byte[] pubKeyBytes = chain[0].getPublicKey().getEncoded();
byte[] pubKeyHash = md.digest(pubKeyBytes);
String pinned = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

if (!Base64.encodeToString(pubKeyHash, Base64.NO_WRAP).equals(pinnedHash)) {
    throw new CertificateException("Public key pinning failure!");
}
```

---

### 3.3 OkHttp CertificatePinner

The most common pinning implementation in Android apps. OkHttp provides a built-in `CertificatePinner` class.

```java
// Build OkHttpClient with certificate pinning
CertificatePinner certificatePinner = new CertificatePinner.Builder()
    .add("api.mybank.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
    .add("api.mybank.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
    .build();

OkHttpClient client = new OkHttpClient.Builder()
    .certificatePinner(certificatePinner)
    .build();
```

**Detection in jadx-gui:**

```
Search: "CertificatePinner"
Search: "sha256/"
Search: "certificatePinner"
```

---

### 3.4 Network Security Config (Android 7+)

Android 7.0+ supports declarative pinning via `network_security_config.xml` — no Java code required.

```xml
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api.mybank.com</domain>
        <pin-set expiration="2027-01-01">
            <pin digest="SHA-256">AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=</pin>
            <pin digest="SHA-256">BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

**Linked in AndroidManifest.xml:**

```xml
<application
    android:networkSecurityConfig="@xml/network_security_config"
    ...>
```

**Detection:** Check `Decompiled/res/xml/network_security_config.xml` after apktool decompilation.

---

### 3.5 TrustManager Override

Some apps implement a custom `X509TrustManager` that performs manual certificate validation.

```java
TrustManager[] trustManagers = new TrustManager[]{
    new X509TrustManager() {
        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            // Custom pinning logic here
            validatePin(chain[0]);
        }
        // ...
    }
};
SSLContext sslContext = SSLContext.getInstance("TLS");
sslContext.init(null, trustManagers, null);
```

---

### 3.6 Trustkit / Third-Party Libraries

Some apps use third-party pinning libraries:

| Library | Detection String |
|---|---|
| TrustKit (iOS/Android) | `TrustKit`, `TSKConfiguration` |
| Appcelerator | `PinningTrustManager` |
| AndroidPinning | `PinnedSSLSocketFactory` |
| Retrofit + OkHttp | `CertificatePinner`, `sha256/` |

---

## 4. SSL Pinning Bypass Techniques

### Overview of Bypass Methods

```
SSL Pinning Bypass
├── 1. Frida Script (Runtime Hook)
├── 2. Objection Framework (Frida wrapper)
├── 3. APK Patching (smali modification)
├── 4. Network Security Config Patch
├── 5. Xposed Framework (rooted device)
└── 6. Custom TrustManager Injection
```

---

### 4.1 Prerequisites

| Requirement | Purpose |
|---|---|
| Rooted Android device or emulator | Required for Frida/Objection |
| ADB installed and device connected | Deploy tools and apps |
| Burp Suite (proxy) | Intercept decrypted traffic |
| Frida server on device | Runtime instrumentation |
| Python + frida-tools | Run Frida scripts from PC |
| apktool + smali knowledge | APK-level patching |

**Lab Setup:**

```bash
# Install frida-tools on host
pip install frida-tools

# Check connected device
adb devices

# Push frida-server to device (match version to host frida)
adb push frida-server-16.x.x-android-x86 /data/local/tmp/frida-server
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

# Verify frida is running
frida-ps -U
```

---

## 5. Tool-by-Tool Bypass Guide

### 5.1 Bypass Using Frida Script

Frida hooks into the running app process and overrides SSL pinning methods at runtime.

**Step 1 — Start Frida server on device:**

```bash
adb shell "/data/local/tmp/frida-server &"
```

**Step 2 — Use the universal SSL Pinning bypass script:**

```javascript
// ssl_bypass.js — Universal SSL Pinning Bypass for Android

Java.perform(function() {

    // ── 1. Bypass OkHttp CertificatePinner ──────────────────────────
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List')
            .implementation = function(hostname, peerCertificates) {
            console.log('[+] OkHttp CertificatePinner bypassed for: ' + hostname);
            return; // Skip pinning check
        };
    } catch(e) { console.log('[-] OkHttp CertificatePinner not found'); }

    // ── 2. Bypass X509TrustManager ──────────────────────────────────
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');

        var TrustManager = Java.registerClass({
            name: 'com.custom.TrustManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function(chain, authType) {},
                checkServerTrusted: function(chain, authType) {
                    console.log('[+] checkServerTrusted bypassed');
                },
                getAcceptedIssuers: function() { return []; }
            }
        });

        var TrustManagers = [TrustManager.$new()];
        var sslContext = SSLContext.getInstance('TLS');
        sslContext.init(null, TrustManagers, null);
        console.log('[+] X509TrustManager hooked');
    } catch(e) { console.log('[-] TrustManager error: ' + e); }

    // ── 3. Bypass SSLPeerUnverifiedException ────────────────────────
    try {
        var SSLPeerUnverifiedException = Java.use('javax.net.ssl.SSLPeerUnverifiedException');
        SSLPeerUnverifiedException.$init.implementation = function(msg) {
            console.log('[+] SSLPeerUnverifiedException suppressed');
        };
    } catch(e) {}

    // ── 4. Bypass Android Network Security Config ────────────────────
    try {
        var NetworkSecurityConfig = Java.use(
            'android.security.net.config.NetworkSecurityConfig');
        NetworkSecurityConfig.getPins.implementation = function() {
            console.log('[+] NetworkSecurityConfig pins bypassed');
            return Java.use('java.util.HashSet').$new();
        };
    } catch(e) {}

    console.log('[*] SSL Pinning bypass script loaded successfully');
});
```

**Step 3 — Inject script into running app:**

```bash
# Attach to running app by package name
frida -U -l ssl_bypass.js -n com.target.app

# OR spawn the app with the script
frida -U -l ssl_bypass.js -f com.target.app --no-pause
```

**Step 4 — Verify bypass:**

```bash
# Set device proxy to Burp Suite (e.g., 192.168.1.x:8080)
# Trigger network actions in the app
# → Traffic should now appear in Burp Suite
```

---

### 5.2 Bypass Using Objection (Frida Wrapper)

Objection is a runtime mobile exploration toolkit built on top of Frida. It makes SSL pinning bypass a **one-liner**.

**Installation:**

```bash
pip install objection
```

**Usage:**

```bash
# Ensure frida-server is running on device

# Launch app with objection
objection -g com.target.app explore

# Once in the objection shell, disable SSL pinning:
android sslpinning disable
```

**Output expected:**

```
(com.target.app) on (Android: 11) [usb] # android sslpinning disable
(agent) Custom TrustManager ready, overriding SSLContext
(agent) OkHTTP 3.x CertificatePinner.check() called. Not throwing exception.
(agent) Bypassing TrustManagerImpl
```

**All intercepted traffic now flows through Burp Suite.**

---

### 5.3 Bypass via APK Patching (smali Method)

This method modifies the decompiled smali bytecode of the APK to remove or neutralize pinning checks — **does not require a rooted device**.

**Step 1 — Decompile the APK:**

```bash
apktool d target_app.apk -o target_decompiled
```

**Step 2 — Locate pinning logic in smali:**

```bash
# Search for CertificatePinner
grep -r "CertificatePinner" target_decompiled/smali/

# Search for check() method
grep -r "check" target_decompiled/smali/okhttp3/

# Search for TrustManager
grep -r "checkServerTrusted" target_decompiled/smali/
```

**Step 3 — Edit smali to bypass:**

Original smali (pinning check throws exception on mismatch):

```smali
.method public check(Ljava/lang/String;Ljava/util/List;)V
    .locals 3
    
    invoke-virtual {p0, p1, p2}, Lokhttp3/CertificatePinner;->check(...)V
    
    # Throws SSLPeerUnverifiedException if pin doesn't match
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    throw-exception
    
    return-void
.end method
```

Patched smali (immediately return — skip all checks):

```smali
.method public check(Ljava/lang/String;Ljava/util/List;)V
    .locals 0
    
    return-void    # ← Just return immediately, skip ALL pinning logic
    
.end method
```

**Step 4 — Patch Network Security Config (if present):**

```bash
# Edit res/xml/network_security_config.xml
nano target_decompiled/res/xml/network_security_config.xml
```

Change:

```xml
<pin-set expiration="2027-01-01">
    <pin digest="SHA-256">AAAA...=</pin>
</pin-set>
```

To (remove pin-set entirely, allow all):

```xml
<domain-config cleartextTrafficPermitted="true">
    <domain includeSubdomains="true">api.target.com</domain>
    <trust-anchors>
        <certificates src="system"/>
        <certificates src="user"/>   <!-- Trust user-installed CAs like Burp -->
    </trust-anchors>
</domain-config>
```

**Step 5 — Repackage and sign the APK:**

```bash
# Rebuild the APK
apktool b target_decompiled -o target_patched.apk

# Generate a new signing key (if not already done)
keytool -genkey -v -keystore my_key.jks -alias myalias \
        -keyalg RSA -keysize 2048 -validity 10000

# Sign the patched APK
jarsigner -verbose -sigalg SHA256withRSA -digestalg SHA-256 \
          -keystore my_key.jks target_patched.apk myalias

# Zipalign for optimization
zipalign -v 4 target_patched.apk target_patched_aligned.apk

# Install on device
adb install target_patched_aligned.apk
```

---

### 5.4 Bypass via Network Security Config Patch Only

If the app uses only `network_security_config.xml` for pinning (no code-level pinning), simply editing that XML after apktool decompile and rebuilding is sufficient.

```bash
apktool d app.apk -o app_dec

# Edit network_security_config.xml to trust user CAs
vim app_dec/res/xml/network_security_config.xml

apktool b app_dec -o app_patched.apk
# Sign and install...
```

---

### 5.5 Bypass Using Xposed Framework

On rooted devices with Xposed installed, modules like **TrustMeAlready** or **JustTrustMe** automatically disable SSL pinning for all apps.

```
Install Xposed Framework (rooted device)
    ↓
Install module: JustTrustMe or TrustMeAlready
    ↓
Enable module in Xposed Manager
    ↓
Reboot device
    ↓
All SSL pinning in all apps bypassed globally
```

| Xposed Module | What it hooks |
|---|---|
| **JustTrustMe** | OkHttp, HttpsURLConnection, TrustManager, Volley |
| **TrustMeAlready** | Most common Android SSL APIs |
| **SSLUnpinning** | OkHttp 2/3, Appcelerator, conscrypt |

---

## 6. Detecting SSL Pinning in Code

### 6.1 Static Detection — jadx-gui Searches

After decompiling with jadx-gui, search for the following strings:

| Search String | Indicates |
|---|---|
| `CertificatePinner` | OkHttp pinning |
| `sha256/` | OkHttp / Retrofit pin hash |
| `checkServerTrusted` | Custom TrustManager |
| `X509TrustManager` | Custom TrustManager |
| `SSLContext.init` | Custom SSL context |
| `PinnedSSLSocketFactory` | AndroidPinning library |
| `TrustKit` | TrustKit library |
| `network_security_config` | Declarative pinning |
| `getAcceptedIssuers` | Custom TrustManager |
| `SSLPeerUnverifiedException` | Pinning failure handler |
| `KeyStore` | Certificate stored in app |
| `.bks` / `.p12` / `.cer` | Bundled certificate files |

---

### 6.2 Static Detection — Manifest & Resources

```bash
# Check for network_security_config reference
grep "networkSecurityConfig" Decompiled/AndroidManifest.xml

# Check for bundled certificate files
find Decompiled/ -name "*.cer" -o -name "*.crt" -o \
     -name "*.pem" -o -name "*.bks" -o -name "*.p12"

# Read network_security_config.xml
cat Decompiled/res/xml/network_security_config.xml
```

---

### 6.3 Dynamic Detection — Runtime Behaviour

| Behaviour | Meaning |
|---|---|
| App works normally without proxy | Baseline confirmed |
| App crashes or shows error with proxy set | Pinning likely active |
| `javax.net.ssl.SSLPeerUnverifiedException` in logcat | Pinning rejection |
| `Certificate pinning failure!` in logcat | OkHttp pinning rejection |
| No traffic in Burp with proxy set | Pinning blocking interception |

```bash
# Watch logcat for pinning-related errors
adb logcat | grep -i "ssl\|pin\|certificate\|trust"
```

---

### 6.4 Detection Flow Diagram

```
Start Analysis
      |
      ▼
Decompile APK (apktool + jadx)
      |
      ├──► Check AndroidManifest.xml
      │         └── networkSecurityConfig present? ──► YES → Check XML pins
      │
      ├──► Search "CertificatePinner" in source
      │         └── Found? ──► YES → OkHttp pinning confirmed
      │
      ├──► Search "checkServerTrusted" in source
      │         └── Found? ──► YES → Custom TrustManager pinning
      │
      ├──► Find .cer/.bks/.p12 files in assets/res
      │         └── Found? ──► YES → Bundled certificate pinning
      │
      ├──► Set device proxy → Burp Suite
      │         └── App rejects connection? ──► YES → Runtime pinning confirmed
      │
      └──► Check logcat for SSL errors
                └── SSLPeerUnverifiedException? ──► YES → Pinning active
```

---

## 7. Summary Table

### Bypass Methods Comparison

| Method | Root Required | Complexity | Leaves Traces | Works On |
|---|---|---|---|---|
| **Frida Script** | ✅ Yes | Medium | No | All pinning types |
| **Objection** | ✅ Yes | Low (one-liner) | No | All pinning types |
| **smali APK Patch** | ❌ No | High | In APK | Code-level pinning |
| **NSC XML Patch** | ❌ No | Low | In APK | NSC-only pinning |
| **Xposed Module** | ✅ Yes | Low | In system | All apps globally |

---

### Detection Methods Comparison

| Method | Stage | Tool | What it Finds |
|---|---|---|---|
| jadx search | Static | jadx-gui | CertificatePinner, TrustManager |
| Manifest grep | Static | grep / apktool | networkSecurityConfig |
| Asset search | Static | find / grep | .cer, .bks, .p12 files |
| Proxy test | Dynamic | Burp Suite | Runtime rejection |
| Logcat analysis | Dynamic | adb logcat | SSLPeerUnverifiedException |
| Frida tracing | Dynamic | Frida | Live method calls |

---

### Pinning Types vs Detection & Bypass

| Pinning Type | Detection | Bypass Method |
|---|---|---|
| OkHttp CertificatePinner | Search `CertificatePinner`, `sha256/` | Frida hook `check()`, Objection, smali patch |
| Custom TrustManager | Search `checkServerTrusted`, `X509TrustManager` | Frida hook TrustManager, Objection |
| Network Security Config | Check `network_security_config.xml` | Edit XML, re-sign APK |
| Bundled Certificate | Find `.cer`/`.bks` in assets | Replace cert or hook validation |
| TrustKit library | Search `TrustKit`, `TSKConfiguration` | Frida hook TrustKit internals |
| Xposed-resistant pinning | Native code (`.so` libs) | Frida native hooks, LD_PRELOAD |

---

### Key Takeaways

| # | Takeaway |
|---|---|
| 1 | SSL Pinning prevents MITM by hardcoding the expected server cert/key in the app |
| 2 | OkHttp `CertificatePinner` is the most common Android implementation |
| 3 | `network_security_config.xml` allows declarative pinning without code |
| 4 | Frida + Objection is the fastest bypass method on rooted devices |
| 5 | smali patching bypasses pinning without root but requires re-signing |
| 6 | Detection is done via both static (jadx, grep) and dynamic (logcat, Burp) analysis |
| 7 | Apps can layer multiple pinning methods — all must be bypassed |

---

*This report was produced as part of a controlled lab study on SSL/TLS pinning bypass techniques. All techniques described are for authorized security testing and educational purposes only.*