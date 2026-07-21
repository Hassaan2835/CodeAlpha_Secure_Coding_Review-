# 🔒 CodeAlpha Secure Coding Review — Task 3

## Project Overview

This repository contains a **comprehensive security audit** of the [CodeAlpha Phishing Awareness & Cybersecurity Training](../Cyber%20Security%20Task%202/CodeAlpha_Phishing_Awareness_Training/) web application.

## Application Under Review

- **Language:** JavaScript (HTML5 + CSS3 + Vanilla JS)
- **Type:** Client-side Single-Page Application (SPA)
- **Purpose:** Interactive phishing awareness training with email inspector, website spotter, and certification quiz

## Audit Methodology

| Method | Tool / Approach |
|--------|-----------------|
| Manual Code Inspection | Line-by-line review of all 3 source files (~3,225 LOC) |
| Static Pattern Analysis | `grep`-based scans for `innerHTML`, `eval`, `document.write`, inline event handlers, storage/network APIs, CSP headers |
| OWASP Mapping | Findings mapped to OWASP Top 10 and CWE identifiers |
| Remediation Verification | Remediated code provided with diff-formatted fixes |

## Key Findings Summary

| Severity | ID | Vulnerability | CWE |
|----------|----|---------------|-----|
| 🔴 HIGH | F1 | DOM-XSS via certificate name (unsanitized `innerHTML`) | CWE-79 |
| 🔴 HIGH | F2 | 9× `innerHTML` assignments (unsafe sink pattern) | CWE-79 |
| 🟠 MEDIUM | F3 | No Content Security Policy | CWE-1021 |
| 🟠 MEDIUM | F4 | Inline `onclick` event handler | CWE-79 |
| 🟠 MEDIUM | F5 | Client-side state tampering (bypasses training) | CWE-602 |
| 🟡 LOW | F6 | No SRI on external Google Fonts | CWE-829 |
| 🟡 LOW | F7 | Certificate input missing validation | CWE-20 |
| 🟡 LOW | F8 | Global scope exposure of state & quiz answers | CWE-200 |

## Repository Contents

```
📁 CodeAlpha_Secure_Coding_Review-/
├── README.md                  ← This file
├── SECURE_CODE_REVIEW.md      ← Full detailed audit report
└── remediated/
    ├── index.html             ← Hardened HTML with CSP, SRI, input validation
    └── app.js                 ← Hardened JS with XSS fixes, IIFE, sanitization
```

## How to Apply Fixes

The `remediated/` directory contains the patched source files. To apply:

```bash
# Copy remediated files over originals
cp remediated/index.html ../Cyber\ Security\ Task\ 2/CodeAlpha_Phishing_Awareness_Training/index.html
cp remediated/app.js ../Cyber\ Security\ Task\ 2/CodeAlpha_Phishing_Awareness_Training/app.js
```

## Secure Coding Best Practices

1. **Never use `innerHTML` with user-controlled data** — Use `textContent` or `DOM APIs`
2. **Always define a Content Security Policy** — Blocks unauthorized script execution
3. **Validate all input** — Both client-side (UX) and server-side (security)
4. **Encapsulate application state** — Use IIFE/modules to prevent global leakage
5. **Use Subresource Integrity** — Verify external resource integrity with `integrity` attributes

---

*CodeAlpha Cybersecurity Internship — Task 3: Secure Coding Review*