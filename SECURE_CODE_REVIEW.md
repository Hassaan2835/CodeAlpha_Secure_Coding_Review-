# 🔒 Secure Code Review Report

**Application:** CodeAlpha Phishing Awareness & Cybersecurity Training  
**Language / Stack:** HTML5, Vanilla CSS, Vanilla JavaScript (Client-Side SPA)  
**Review Date:** July 20, 2026  
**Methodology:** Manual code inspection + static pattern analysis (grep-based scanning for dangerous sinks, inline handlers, CSP gaps, storage/network calls, and input handling)  
**Auditor:** Antigravity Secure Code Review Agent

---

## Executive Summary

The **Phishing Awareness Training** application is a client-side single-page app consisting of three source files:

| File | Lines | Purpose |
|------|-------|---------|
| [index.html](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/index.html) | 604 | Structure, layout, all 4 training modules |
| [app.js](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/app.js) | 858 | Application logic, state management, quiz engine, certificate renderer |
| [styles.css](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/styles.css) | 1763 | Full design system & responsive styles |

The audit identified **8 security vulnerabilities** across 3 severity levels. While the app has no server-side component (reducing the attack surface), several client-side issues could lead to **XSS injection**, **content spoofing**, and **integrity bypass** attacks.

### Severity Distribution

| Severity | Count | Description |
|----------|-------|-------------|
| 🔴 **HIGH** | 2 | Exploitable DOM-XSS via unsanitized user input |
| 🟠 **MEDIUM** | 3 | Missing security headers, inline handlers, client-side state tampering |
| 🟡 **LOW** | 3 | Information disclosure, accessibility issues, no SRI on external resources |

---

## Findings

### 🔴 FINDING 1: DOM-Based Cross-Site Scripting (XSS) via Certificate Name Input

**Severity:** HIGH  
**CWE:** [CWE-79](https://cwe.mitre.org/data/definitions/79.html) — Improper Neutralization of Input During Web Page Generation  
**OWASP:** A7:2017 — Cross-Site Scripting (XSS)

#### Vulnerable Code

The user enters their name in the certificate input ([index.html:562](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/index.html#L562)):
```html
<input type="text" id="cert-user-name" placeholder="John Doe" class="cert-input">
```

This value is stored **without any sanitization** ([app.js:611](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/app.js#L611)):
```javascript
state.userName = nameInput.value.trim();
```

Then injected directly into an SVG template literal via `innerHTML` ([app.js:826](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/app.js#L826)):
```javascript
// Inside renderCertificate():
<text ...>${state.userName.toUpperCase()}</text>
```

And rendered into the DOM at ([app.js:856](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/app.js#L856)):
```javascript
certContainer.innerHTML = svgCert;
```

#### Attack Scenario

A user (or a shared link with pre-filled URL parameters) could inject:
```
<img src=x onerror="alert(document.cookie)">
```

Since `innerHTML` parses and executes HTML, this creates a **DOM-XSS** vulnerability. While the current app doesn't use cookies or authentication, in a production deployment this could be used for:
- Session hijacking
- Phishing within the training app itself (ironic!)
- Keylogging via injected scripts

#### Remediation

```diff
- certContainer.innerHTML = svgCert;
+ // Option A: Use textContent for user data in SVG
+ const nameElement = document.createElementNS("http://www.w3.org/2000/svg", "text");
+ nameElement.textContent = state.userName.toUpperCase();

+ // Option B: Sanitize before template insertion
+ function escapeHTML(str) {
+     const div = document.createElement('div');
+     div.textContent = str;
+     return div.innerHTML;
+ }
+ const safeName = escapeHTML(state.userName.toUpperCase());
+ // Then use: ${safeName} in the template literal
```

---

### 🔴 FINDING 2: Multiple `innerHTML` Assignments with Embedded HTML Markup

**Severity:** HIGH  
**CWE:** [CWE-79](https://cwe.mitre.org/data/definitions/79.html) — Improper Neutralization of Input During Web Page Generation

#### Vulnerable Locations

The application uses `innerHTML` **9 times** to inject dynamic content:

| Line | File | Context | Risk |
|------|------|---------|------|
| [411](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/app.js#L411) | app.js | `details.innerHTML = emailRedFlags[flagId].text` | Medium — data source is internal object, but pattern is unsafe |
| [450](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/app.js#L450) | app.js | Verdict feedback (correct) | Low — static template |
| [469](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/app.js#L469) | app.js | Verdict feedback (incorrect) | Low — static template |
| [550](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/app.js#L550) | app.js | Site verdict correct feedback | Low — static template |
| [571](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/app.js#L571) | app.js | Site verdict incorrect feedback | Low — static template |
| [673](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/app.js#L673) | app.js | `optionsContainer.innerHTML = ""` | Safe — clearing content |
| [678](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/app.js#L678) | app.js | `btn.innerHTML = opt.text` | Medium — quiz option text from internal data |
| [742](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/app.js#L742) | app.js | Score badge SVG injection | Medium — contains interpolated JS state |
| [856](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/app.js#L856) | app.js | Full SVG certificate with user name | **HIGH — user input injected** |

While most assignments use static templates from internal data, the **pattern itself is a security anti-pattern**. If any of these data sources are later modified to include user-controllable data (e.g., quiz loaded from a server API), the entire pattern becomes exploitable without code changes.

#### Remediation

```javascript
// BEST PRACTICE: Replace innerHTML with safe DOM APIs

// Instead of:
btn.innerHTML = opt.text;

// Use:
btn.textContent = opt.text;

// For complex DOM structures, use document.createElement:
const h5 = document.createElement('h5');
h5.textContent = '✓ VERDICT CORRECT';
feedbackBox.appendChild(h5);

// Or use a sanitization library like DOMPurify:
// feedbackBox.innerHTML = DOMPurify.sanitize(htmlString);
```

---

### 🟠 FINDING 3: Missing Content Security Policy (CSP) Headers

**Severity:** MEDIUM  
**CWE:** [CWE-1021](https://cwe.mitre.org/data/definitions/1021.html) — Improper Restriction of Rendered UI Layers

#### Issue

No `Content-Security-Policy` meta tag or HTTP header is present in [index.html](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/index.html). This means:
- Injected scripts from XSS attacks will execute unrestricted
- External resources can be loaded from any origin
- Inline styles and scripts are permitted (even though none are currently used directly)

#### Remediation

Add a CSP meta tag to the `<head>` section:

```diff
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
+ <meta http-equiv="Content-Security-Policy" 
+       content="default-src 'self'; 
+              script-src 'self'; 
+              style-src 'self' https://fonts.googleapis.com; 
+              font-src 'self' https://fonts.gstatic.com;
+              img-src 'self' data:;
+              connect-src 'none';
+              frame-src 'none';
+              object-src 'none';">
```

> [!TIP]
> For deployment behind a web server, also set these via HTTP headers: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, and `Referrer-Policy: strict-origin-when-cross-origin`.

---

### 🟠 FINDING 4: Inline Event Handler in HTML

**Severity:** MEDIUM  
**CWE:** [CWE-79](https://cwe.mitre.org/data/definitions/79.html)

#### Vulnerable Code

[index.html:330](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/index.html#L330):
```html
<a href="#" class="email-btn-link hotspot" id="hs-link" data-ref="link-flag" onclick="return false;">
```

#### Issue

Inline event handlers (`onclick`, `onerror`, etc.) are flagged by strict CSP policies and violate the principle of separating behavior from markup. While `return false` is benign, this pattern:
1. Requires `unsafe-inline` in CSP script-src, weakening security
2. Sets a precedent for mixing JS into HTML attributes
3. Can be exploited if the attribute value were dynamically generated

#### Remediation

```diff
- <a href="#" class="email-btn-link hotspot" id="hs-link" data-ref="link-flag" onclick="return false;">
+ <a href="#" class="email-btn-link hotspot" id="hs-link" data-ref="link-flag">
```

```javascript
// In app.js setupEmailInspector():
const emailLink = document.getElementById('hs-link');
if (emailLink) {
    emailLink.addEventListener('click', (e) => e.preventDefault());
}
```

---

### 🟠 FINDING 5: Client-Side State Tampering — All Security Controls Are Bypassable

**Severity:** MEDIUM  
**CWE:** [CWE-602](https://cwe.mitre.org/data/definitions/602.html) — Client-Side Enforcement of Server-Side Security

#### Issue

The entire training progression system is controlled by a client-side JavaScript object ([app.js:3-35](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/app.js#L3-L35)):

```javascript
const state = {
    unlockedModules: {
        dashboard: true,
        basics: true,
        email: false,      // ← Trivially changeable
        websites: false,
        quiz: false,
        certificate: false
    },
    ...
};
```

Any user can open the browser DevTools console and execute:
```javascript
// Skip all training, unlock everything, and generate a fake certificate:
state.unlockedModules.email = true;
state.unlockedModules.websites = true;
state.unlockedModules.quiz = true;
state.completedModules.quiz = true;
state.quizScore = 5;
state.userName = "Fake Person";
renderCertificate();
```

This means:
- Training completion can be faked
- Certificates can be generated without completing any module
- Quiz scores can be inflated

#### Remediation

> [!IMPORTANT]
> For a training platform where certificates carry professional weight, server-side validation is essential.

```javascript
// Option A: Server-side validation (recommended for production)
// - Store progress in a backend database
// - Validate quiz answers server-side
// - Sign certificates with a server-side key

// Option B: Client-side hardening (for demo/prototype)
// - Wrap state in a closure to prevent console access
// - Use Object.freeze() on sensitive config
// - Add integrity checksums to state transitions

const AppState = (() => {
    const _state = Object.seal({ /* ... */ });
    return {
        getProgress: () => ({ ...state }),
        completeModule: (moduleId) => {
            // Validate prerequisite completion before unlocking
            if (!_validatePrerequisites(moduleId)) {
                throw new Error('Prerequisites not met');
            }
            _state.completedModules[moduleId] = true;
        }
    };
})();
```

---

### 🟡 FINDING 6: No Subresource Integrity (SRI) on External Resources

**Severity:** LOW  
**CWE:** [CWE-829](https://cwe.mitre.org/data/definitions/829.html) — Inclusion of Functionality from Untrusted Control Sphere

#### Vulnerable Code

[index.html:9-11](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/index.html#L9-L11):
```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=Space+Grotesk:wght@400;500;600;700&display=swap" rel="stylesheet">
```

#### Issue

Google Fonts are loaded from a third-party CDN without `integrity` attributes. If the CDN were compromised (supply-chain attack), malicious CSS could be injected, potentially:
- Exfiltrating form data via CSS attribute selectors and `url()` background fetches
- Defacing the application
- Performing UI redressing attacks

#### Remediation

```diff
- <link href="https://fonts.googleapis.com/css2?family=Inter..." rel="stylesheet">
+ <link href="https://fonts.googleapis.com/css2?family=Inter..." 
+       rel="stylesheet"
+       integrity="sha384-<hash>"
+       crossorigin="anonymous">
```

> [!NOTE]
> Google Fonts CDN dynamically generates CSS, making traditional SRI difficult. As an alternative, **self-host the fonts** by downloading them and serving from your own origin.

---

### 🟡 FINDING 7: Certificate Input Lacks Client-Side Validation

**Severity:** LOW  
**CWE:** [CWE-20](https://cwe.mitre.org/data/definitions/20.html) — Improper Input Validation

#### Vulnerable Code

[index.html:562](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/index.html#L562):
```html
<input type="text" id="cert-user-name" placeholder="John Doe" class="cert-input">
```

[app.js:610-611](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/app.js#L610-L611):
```javascript
if (nameInput && nameInput.value.trim() !== "") {
    state.userName = nameInput.value.trim();
```

#### Issue

The input field has:
- No `maxlength` attribute — users could enter extremely long strings causing layout overflow
- No `pattern` attribute — allows special characters, HTML tags, and control characters
- No `required` attribute
- Only a basic emptiness check in JS — no character set validation

#### Remediation

```diff
- <input type="text" id="cert-user-name" placeholder="John Doe" class="cert-input">
+ <input type="text" id="cert-user-name" placeholder="John Doe" class="cert-input"
+        maxlength="100" 
+        pattern="[A-Za-z\s\-\.\']+"
+        required
+        autocomplete="name"
+        title="Please enter a valid name (letters, spaces, hyphens, periods)">
```

```javascript
// Enhanced validation in app.js:
const nameRegex = /^[A-Za-z\s\-\.']{2,100}$/;
if (nameInput && nameRegex.test(nameInput.value.trim())) {
    state.userName = nameInput.value.trim();
} else {
    alert("Please enter a valid name (2-100 characters, letters and spaces only).");
    return;
}
```

---

### 🟡 FINDING 8: Global State Object Exposed in Window Scope

**Severity:** LOW  
**CWE:** [CWE-200](https://cwe.mitre.org/data/definitions/200.html) — Exposure of Sensitive Information

#### Vulnerable Code

[app.js:3](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/app.js#L3):
```javascript
const state = { ... };
```

[app.js:38](file:///c:/Users/Administrator/Desktop/Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/app.js#L38):
```javascript
const quizQuestions = [ ... ];
```

#### Issue

All application state, quiz answers (including which options are `correct: true`), and internal functions are globally accessible. A trainee can:
1. Open DevTools → Console
2. Type `quizQuestions` to see all correct answers
3. Type `state` to see/modify all progress

#### Remediation

```javascript
// Wrap entire application in an IIFE to prevent global leakage:
;(() => {
    'use strict';
    
    const state = { ... };
    const quizQuestions = [ ... ];
    
    // All functions defined here are now private
    function initElements() { ... }
    // ...
    
    document.addEventListener("DOMContentLoaded", () => { ... });
})();
```

---

## Summary of Recommendations

### Immediate Actions (Must Fix)

| # | Action | Finding |
|---|--------|---------|
| 1 | **Sanitize all user input** before inserting into DOM via `innerHTML` | F1, F2 |
| 2 | **Replace `innerHTML`** with `textContent` / DOM APIs wherever possible | F2 |
| 3 | **Add Content Security Policy** meta tag to `index.html` | F3 |

### Short-Term Improvements

| # | Action | Finding |
|---|--------|---------|
| 4 | Remove inline `onclick` handler and use `addEventListener` | F4 |
| 5 | Add input validation (`maxlength`, `pattern`) to certificate name field | F7 |
| 6 | Wrap code in an IIFE to prevent global scope leakage | F8 |

### Long-Term / Production Hardening

| # | Action | Finding |
|---|--------|---------|
| 7 | Self-host fonts or add SRI hashes to external resources | F6 |
| 8 | Implement server-side state management and certificate signing | F5 |
| 9 | Add automated SAST (static analysis) to CI/CD pipeline (e.g., ESLint security plugin, Semgrep) | General |

---

## Secure Coding Best Practices Applied to This Project

### 1. Input Validation & Output Encoding
- **Never trust user input.** Always validate on both client and server side.
- Use `textContent` instead of `innerHTML` when injecting text-only data.
- Use parameterized templates or sanitization libraries (DOMPurify) for rich content.

### 2. Content Security Policy
- Always define a CSP that restricts script sources to `'self'`.
- Avoid `unsafe-inline` and `unsafe-eval` directives.
- Use `nonce`-based or `hash`-based CSP for unavoidable inline scripts.

### 3. Principle of Least Privilege
- Keep sensitive data (quiz answers, state) private using closures or ES modules.
- Expose only the minimum necessary API surface.

### 4. Defense in Depth
- Security headers (CSP, X-Frame-Options, HSTS) provide layers of protection.
- Client-side validation is for UX; server-side validation is for security.

### 5. Supply Chain Security
- Pin external dependency versions.
- Use SRI or self-hosting for third-party resources.
- Audit external dependencies regularly.

---

> [!IMPORTANT]
> **Overall Assessment:** The application demonstrates good separation of concerns and clean code structure. The primary risks are **DOM-XSS through the certificate name field** and the **absence of Content Security Policy headers**. Fixing these two issues would significantly improve the security posture of the application.

---

*Report generated by Antigravity Secure Code Review Agent — July 2026*
