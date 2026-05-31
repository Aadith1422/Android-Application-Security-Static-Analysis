# Android Static Testing Checklist

A structured checklist for Android static analysis security reviews. Each item is tagged by severity: 🔴 Critical · 🟠 High · 🔵 Medium

---

## 1. AndroidManifest.xml

- [ ] 🔴 `android:debuggable="true"` is absent or false in release build
- [ ] 🔴 `android:allowBackup` is set to false for sensitive apps
- [ ] 🔴 Exported activities, services, and receivers require explicit permissions
- [ ] 🟠 `android:usesCleartextTraffic` is false; `network_security_config` enforces HTTPS
- [ ] 🟠 Permissions declared match only what the app genuinely needs

---

## 2. Data Storage

- [ ] 🔴 SharedPreferences does not store passwords, tokens, or PII in plaintext
- [ ] 🟠 SQLite databases containing sensitive data use SQLCipher or equivalent encryption
- [ ] 🟠 Files written to external storage do not include private data
- [ ] 🔴 Sensitive fields are stored in Android Keystore, not hardcoded
- [ ] 🟠 `Log.d` / `Log.v` calls do not output credentials, tokens, or PII

---

## 3. Cryptography

- [ ] 🔴 No hardcoded encryption keys, IVs, or salts in source or resources
- [ ] 🟠 AES uses CBC or GCM mode — ECB mode is absent
- [ ] 🟠 Password hashing uses bcrypt, Argon2, or PBKDF2 — not MD5 or SHA-1
- [ ] 🔵 Random values use `SecureRandom`, not `java.util.Random`

---

## 4. Network & TLS

- [ ] 🔴 `TrustManager` does not accept all certificates (no override of `checkServerTrusted`)
- [ ] 🔴 `HostnameVerifier` is not overridden to return true for all hosts
- [ ] 🟠 Certificate pinning is implemented for high-value endpoints
- [ ] 🟠 HTTP URLs are absent from the codebase and network config

---

## 5. IPC & Intents

- [ ] 🔴 Content Providers set explicit `readPermission` and `writePermission`
- [ ] 🟠 Implicit broadcasts do not carry sensitive payloads
- [ ] 🟠 Deep-link handlers validate and sanitize all incoming parameters
- [ ] 🟠 WebView has `setJavaScriptEnabled(false)` unless JS is strictly required
- [ ] 🔴 `addJavascriptInterface` is absent or restricted to trusted content origins

---

## 6. Authentication & Sessions

- [ ] 🔴 Authentication decisions are enforced server-side, not only on the client
- [ ] 🟠 JWT or session tokens have an expiry (`exp` claim / TTL)
- [ ] 🟠 Tokens are stored in `EncryptedSharedPreferences` or Keystore — not in plain files
- [ ] 🟠 Logout clears local state and invalidates the server-side session

---

## 7. Code Hygiene

- [ ] 🔵 ProGuard / R8 minification and obfuscation are enabled in release builds
- [ ] 🔵 Root / emulator detection is implemented for apps handling sensitive data
- [ ] 🟠 No third-party SDKs with known CVEs are included
- [ ] 🟠 Sensitive strings are not present in `res/values/strings.xml` or `BuildConfig`

---

## Severity Legend

| Tag | Meaning |
|-----|---------|
| 🔴 Critical | Exploitable with direct impact; must fix before release |
| 🟠 High | Significant risk; fix before release |
| 🔵 Medium | Recommended hardening; address in next cycle |

---

## References

- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [Android Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [Android Network Security Configuration](https://developer.android.com/training/articles/security-config)
- [Android Keystore System](https://developer.android.com/training/articles/keystore)
