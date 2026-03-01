# isXSS-Burp

A Burp Suite extension that automatically detects reflected XSS vulnerabilities by passively monitoring traffic and testing which special characters are reflected in HTML responses.

## How it works

For each request with parameters, the extension:
1. Replaces parameter values with `ggg2"ggg3>ggg4<`
2. Sends modified request variants in the background
3. Checks which characters (`"`, `>`, `<`) are reflected unencoded in **HTML responses only**
4. Detects dangerous DOM sinks (href, event handlers, script contexts, etc.)
5. Reports findings in a table with side-by-side request/response viewers

## Features

### Injection Coverage
- ✅ Tests GET and POST requests
- ✅ Injects into all query/body parameters (all-at-once or per-parameter mode)
- ✅ Injects into 1 random cookie per request (with exclusion list and session cookie avoidance)
- ✅ Injects into 1 random non-essential header per request
- ✅ Always injects into high-value reflection headers: `User-Agent`, `Referer`, `X-Forwarded-For`, `X-Real-IP`, `Origin`, `X-Forwarded-Host`
- ✅ Detects and injects into JSON-encoded parameter values (GET, POST, and cookies)
- ✅ Detects and injects into Base64-encoded parameter values (standard and URL-safe)
- ✅ Injects into URL hash fragments (full fragment and key=value fragment variants)
- ✅ Tests double URL-encoded payload variants for WAF bypass (`ggg2%22ggg3%3Eggg4%3C`)
- ✅ Injects into nested `key=value` parameter values

### Detection
- ✅ Detects reflected characters: `"`, `>`, `<` in HTML response body
- ✅ Identifies DOM XSS sinks:
  - `href` attribute injection
  - Event handlers (`onclick`, `onload`, `onerror`, etc.)
  - Dangerous `src`/`data` attributes (`<script src>`, `<iframe src>`, `<embed src>`, `<object data>`)
  - Script execution contexts (`<script>` block content)
  - JS execution sinks (`eval`, `setTimeout`, `setInterval`)
  - DOM write sinks (`innerHTML`, `outerHTML`, `document.write`)
  - Navigation sinks (`location`, `window.open`)
  - Form action injection
- ✅ HTML-context only — ignores JavaScript, CSS, and other non-HTML response types
- ✅ Optional JSON response findings (off by default)

### Noise Reduction
- ✅ Path-level deduplication — skips re-testing the same endpoint with different query parameters
- ✅ Blocklist of 25+ analytics, tracking, and ad-serving domains (Google, Facebook, Hotjar, Segment, etc.)
- ✅ Scope filter — restrict testing to glob patterns (e.g. `*.example.com`)

### UI
- ✅ Settings dialog to toggle all features on/off
- ✅ Cookie exclusion text field and session cookie preference toggle
- ✅ Side-by-side request/response viewer for each finding
- ✅ Finding count statistics and Clear Results button
- ✅ Tooltips on JSON findings with remediation guidance

<img width="3456" height="2168" alt="image" src="https://github.com/user-attachments/assets/74a70497-4059-4569-aab8-2951ce44e594" />

