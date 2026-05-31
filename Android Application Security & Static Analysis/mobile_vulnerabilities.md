# Mobile-Specific Security Vulnerabilities

A comprehensive reference of mobile security vulnerabilities, with examples and real-world implications.

---

## 1. Insecure Data Storage

### Description
Sensitive data stored in plaintext or weakly protected locations on the device.

### Vulnerable Locations
- SharedPreferences (Android) / NSUserDefaults (iOS)
- SQLite databases without encryption
- External storage (SD cards)
- Log files and crash reports
- Application caches and temp files

### Example — Android SharedPreferences
```java
// VULNERABLE: Storing credentials in plaintext
SharedPreferences prefs = getSharedPreferences("user_data", MODE_PRIVATE);
prefs.edit().putString("password", userPassword).apply();
// Stored at: /data/data/com.example.app/shared_prefs/user_data.xml
```

### Example — iOS NSUserDefaults
```swift
// VULNERABLE: Token stored unencrypted in plist
UserDefaults.standard.set(authToken, forKey: "auth_token")
// Stored at: Library/Preferences/com.example.app.plist (unencrypted)
```

### Real-World Implications
- **2019 — Twitter for Android**: User private tweets and DMs were found stored in device logs accessible to other apps with log-read permission.
- **Banking apps**: Multiple banking apps were found storing PINs, session tokens, and account numbers in SQLite databases without encryption, readable on rooted devices.
- **2021 — TikTok**: Clipboard content (including passwords) was logged and accessible via device storage.

---

## 2. Insecure Communication (Man-in-the-Middle)

### Description
Data transmitted without proper TLS/SSL, with certificate validation disabled, or over HTTP.

### Example — Disabled Certificate Validation (Android)
```java
// VULNERABLE: Accepting all certificates
TrustManager[] trustAllCerts = new TrustManager[]{
    new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}
        public X509Certificate[] getAcceptedIssuers() { return null; }
    }
};
SSLContext sc = SSLContext.getInstance("SSL");
sc.init(null, trustAllCerts, new SecureRandom());
```

### Example — iOS ATS Bypass
```xml
<!-- VULNERABLE: Info.plist disabling App Transport Security -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>
</dict>
```

### Real-World Implications
- **2014 — Fandango & Credit Karma**: FTC fined both companies for disabling SSL certificate validation, exposing millions of users to MitM attacks over public Wi-Fi.
- **2015 — Superfish (Lenovo)**: Pre-installed adware used a self-signed root CA to intercept HTTPS traffic on Android devices.
- **Banking trojans**: Attackers on the same Wi-Fi network can intercept login sessions of apps with improper TLS.

---

## 3. Insecure Authentication & Authorization

### Description
Weak authentication mechanisms, missing server-side checks, or improper session management.

### Example — Client-Side Authentication Bypass
```javascript
// VULNERABLE: React Native app checking auth only on device
if (this.state.isAdmin === true) {   // Value manipulated via Frida/runtime hooking
    this.renderAdminPanel();
}
```

### Example — Missing Authorization Check (iOS)
```swift
// VULNERABLE: Deep link bypasses login check
func application(_ app: UIApplication, open url: URL, ...) {
    if url.host == "reset-password" {
        // Goes directly to reset screen — no auth token verified
        showResetPasswordScreen(token: url.queryParameters["token"])
    }
}
```

### Real-World Implications
- **2012 — Instagram**: An API authorization flaw allowed attackers to take over any account by manipulating OAuth tokens, exposing 6 million user accounts.
- **2019 — Venmo**: A missing server-side authorization check allowed enumeration of all public transaction data through the mobile API.
- **Ride-sharing apps**: Exploited deep-link authentication bypasses allowed users to access ride history and personal details of other accounts.

---

## 4. Insufficient Cryptography

### Description
Use of weak algorithms, hardcoded keys, or improper key management.

### Example — Hardcoded Encryption Key
```java
// VULNERABLE: Key baked into source code
private static final String SECRET_KEY = "myHardcodedKey123";

public String encrypt(String data) {
    SecretKeySpec keySpec = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // ECB mode is insecure
    cipher.init(Cipher.ENCRYPT_MODE, keySpec);
    return Base64.encodeToString(cipher.doFinal(data.getBytes()), Base64.DEFAULT);
}
```

### Example — Weak Hashing for Password Storage
```swift
// VULNERABLE: MD5 for password hashing
let passwordHash = MD5(password + "salt123")
```

### Real-World Implications
- **2013 — Adobe**: 130 million passwords stored with 3DES in ECB mode and identical hints exposed the actual passwords through pattern analysis.
- **Reverse-engineered APKs**: Security researchers routinely extract hardcoded API keys and encryption keys from decompiled Android APKs (using jadx or apktool), gaining access to backend systems.
- **2020 — Zoom**: Found using ECB mode AES encryption for video streams, which leaks structural information from the plaintext.

---

## 5. Improper Platform Usage

### Description
Misuse of platform features such as intents, permissions, clipboard, WebView, or keychain.

### Example — Exported Activities (Android)
```xml
<!-- VULNERABLE: Activity accessible to other apps -->
<activity android:name=".AdminActivity" android:exported="true">
    <!-- No permission required — any app can launch this -->
</activity>
```

### Example — JavaScript Injection via WebView
```java
// VULNERABLE: WebView with JavaScript enabled loading untrusted content
WebView webView = findViewById(R.id.webView);
webView.getSettings().setJavaScriptEnabled(true);
webView.addJavascriptInterface(new DataBridge(), "NativeBridge");
webView.loadUrl(url); // url from untrusted source
```

### Example — Sensitive Data in Clipboard
```swift
// VULNERABLE: Password auto-filled and copied to system clipboard
UIPasteboard.general.string = generatedPassword
// Any app can now read UIPasteboard.general.string
```

### Real-World Implications
- **2019 — Strandhogg (Android)**: Exploited task affinity to hijack foreground Activities of banking apps, overlaying fake login screens — affected over 500 apps.
- **2020 — iOS Clipboard snooping**: Dozens of apps including LinkedIn, Reddit, and TikTok were caught reading clipboard contents (which often contain passwords) every few keystrokes.
- **2021 — WhatsApp WebView CVE**: A remote code execution vulnerability via malicious video file was enabled by insecure WebView configuration.

---

## 6. Code Tampering & Reverse Engineering

### Description
Lack of protections against app repackaging, runtime manipulation, or binary analysis.

### Example — No Root/Jailbreak Detection
```kotlin
// MISSING: No check for rooted/jailbroken environment
// Attacker uses Frida to hook and modify:
fun processPayment(amount: Double): Boolean {
    return apiService.charge(amount)  // Hooked to always return true
}
```

### Example — Debug Build in Production
```xml
<!-- VULNERABLE: AndroidManifest.xml with debug flag -->
<application android:debuggable="true" ...>
```

### Real-World Implications
- **Pokemon Go (2016)**: Within days of launch, the APK was decompiled, modified to enable auto-catching, and repackaged. Millions used the modified version.
- **Mobile banking trojans**: Attackers repackage popular apps with embedded banking trojans (e.g., BankBot, Cerberus), distributing through third-party stores. These targeted over 200 banking apps globally.
- **In-app purchase fraud**: Modified APKs intercept purchase confirmation calls, marking items as "purchased" without payment — causing millions in losses for developers.

---

## 7. Excessive Permissions

### Description
Requesting permissions beyond what the app needs, increasing attack surface.

### Example — Over-permissioned Android App
```xml
<!-- VULNERABLE: Flashlight app requesting unnecessary permissions -->
<uses-permission android:name="android.permission.READ_CONTACTS"/>
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/>
<uses-permission android:name="android.permission.READ_CALL_LOG"/>
<uses-permission android:name="android.permission.RECORD_AUDIO"/>
<!-- A flashlight needs NONE of these -->
```

### Real-World Implications
- **2013 — Brightest Flashlight (Android)**: The FTC took action after the app collected and sold precise location data and device identifiers. It had been downloaded 50 million times.
- **2021 — Grindr**: Location data collected via the app was sold to third-party brokers, later used to identify and out a Catholic priest.
- **Spyware campaigns**: Stalkerware apps abuse contact, location, microphone, and SMS permissions to conduct covert surveillance — disproportionately targeting domestic abuse victims.

---

## 8. Insecure Inter-Process Communication (IPC)

### Description
Insecure use of Intents, Content Providers, Broadcasts, or XPC services that expose data to other apps.

### Example — Unprotected Content Provider
```xml
<!-- VULNERABLE: Content Provider with no read/write permissions defined -->
<provider
    android:name=".UserDataProvider"
    android:authorities="com.example.app.provider"
    android:exported="true"/>
    <!-- No android:readPermission or android:writePermission -->
```

### Example — Implicit Intent with Sensitive Data
```java
// VULNERABLE: Broadcasting sensitive data via implicit intent
Intent intent = new Intent("com.example.ACTION_LOGIN_SUCCESS");
intent.putExtra("auth_token", token);
sendBroadcast(intent); // Any app with matching receiver can intercept this
```

### Real-World Implications
- **2019 — WhatsApp CVE-2019-3568**: A buffer overflow via a crafted RTP packet exploited IPC between audio/video processing components, enabling remote code execution without user interaction — used by NSO Group's Pegasus spyware.
- **Android Content Provider leaks**: Researchers found thousands of apps on Google Play with exported Content Providers exposing PII, messages, and media files to any installed app.

---

## 9. Improper Session Management

### Description
Long-lived tokens, tokens stored insecurely, or missing token invalidation on logout.

### Example — Token Never Expires
```python
# VULNERABLE: Backend issues JWT with no expiry
payload = {"user_id": user.id, "role": user.role}
token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")  # No exp claim
```

### Example — Token Persists After Logout (iOS)
```swift
// VULNERABLE: Logout only clears local state, not the token
func logout() {
    self.currentUser = nil
    // Token still valid on server; still stored in Keychain
}
```

### Real-World Implications
- **2018 — Facebook**: A session token vulnerability exposed 50 million accounts. Tokens had no expiry and remained valid even after password changes or logout.
- **Stolen device scenarios**: If session tokens are stored in plaintext and never invalidated, a stolen unlocked phone gives permanent account access even after the user changes their password.

---

## 10. Sensitive Data Exposure via Backups & Logs

### Description
Sensitive data leaking through iOS/Android backups, logcat, or crash reports.

### Example — Android Backup Enabled
```xml
<!-- VULNERABLE: Backup includes app's private data -->
<application android:allowBackup="true" ...>
    <!-- All SharedPreferences, databases, files backed up to Google Drive
         or accessible via adb backup on non-encrypted devices -->
```

### Example — Logging Sensitive Data
```java
// VULNERABLE: Credentials written to logcat
Log.d("AUTH", "Login attempt: user=" + username + " pass=" + password);
// Readable via: adb logcat | grep AUTH
```

### Real-World Implications
- **2014 — Snapchat**: 4.6 million phone numbers and usernames were harvested via the API. Logs and backup data exposed additional metadata.
- **Many iOS apps**: Security researchers using iPhone backups (via iTunes on a computer) extracted plaintext passwords, tokens, and private messages from apps that didn't set `NSFileProtectionComplete` on sensitive files.
- **Firebase misconfiguration (2018)**: Over 2,000 iOS and Android apps were found exposing millions of records — including medical data and banking info — through misconfigured Firebase real-time databases, often discovered via crash logs and debug endpoints left in production builds.

---

## Summary Table

| # | Vulnerability | Platform | Severity |
|---|---------------|----------|----------|
| 1 | Insecure Data Storage | Android / iOS | Critical |
| 2 | Insecure Communication (MitM) | Android / iOS | Critical |
| 3 | Insecure Authentication & Authorization | Android / iOS | Critical |
| 4 | Insufficient Cryptography | Android / iOS | High |
| 5 | Improper Platform Usage | Android / iOS | High |
| 6 | Code Tampering & Reverse Engineering | Android | High |
| 7 | Excessive Permissions | Android / iOS | Medium–High |
| 8 | Insecure IPC | Android / iOS | High |
| 9 | Improper Session Management | Android / iOS | Critical |
| 10 | Sensitive Data in Backups & Logs | Android / iOS | Medium–High |

---

## References

- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [Apple iOS Security Guide](https://support.apple.com/guide/security/welcome/web)
- [NIST Mobile Device Security Guidelines (SP 800-124)](https://csrc.nist.gov/publications/detail/sp/800-124/rev-2/final)
