# isXSS-Burp

A Burp Suite extension that automatically detects reflected XSS vulnerabilities by testing which special characters are reflected in responses.

## How it works

For each request with parameters, the plugin:
1. Replaces parameter values with `ggg2"ggg3>ggg4<`
2. Sends the modified request in the background
3. Checks which characters (`"`, `>`, `<`) are reflected unencoded
4. Detects dangerous DOM sinks (href, onclick, script contexts, etc.)
5. Reports findings with request/response viewers

## Features

- ✅ Tests GET and POST requests
- ✅ Detects reflected characters: `"`, `>`, `<`
- ✅ Identifies DOM XSS sinks (href, event handlers, script contexts, etc.)
- ✅ Checks response headers for reflections
- ✅ Avoids duplicate testing
- ✅ Side-by-side request/response view
- ✅ Clean UI with statistics and filtering

<img width="3456" height="2168" alt="image" src="https://github.com/user-attachments/assets/74a70497-4059-4569-aab8-2951ce44e594" />
