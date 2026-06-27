# MuteMaster Agent Skills

Elite offensive security skills for Claude Code. Built for bug bounty hunters, penetration testers, and security researchers.

## Install

```bash
npx -y skills add Zaphh-Tech/agent-skills --skill mutemaster-hunt --agent claude-code
```

## Skills

### `mutemaster-hunt`

The complete MuteMaster bug bounty hunting methodology — encoded as a Claude Code skill that activates automatically on any security task.

**Covers:**
- Full attack loop: recon → fuzz → auth bypass → chain → report
- OWASP Top 10 (2021) + API Top 10 (2023) with exact attack instincts
- Zero-Day Steroid Mode — edge-case fuzzing, protocol smuggling, WAF bypass
- Prototype pollution (client + server-side Node.js RCE)
- Web cache poisoning / web cache deception
- CORS exploitation — null origin, regex bypass, unicode dot
- Subdomain takeover → supply chain JS injection
- OAuth 2.0 — consent phishing, device code flow abuse, DPoP bypass
- JWT attacks — alg:none, RS256→HS256, jku hijack, jwk embed
- GraphQL — introspection, field-level BOLA, query batching rate-limit bypass
- AI/LLM bugs — direct + indirect prompt injection, agent exploitation
- Web3 — 60-second triage, $625M bug class templates, cross-chain exploits, Uniswap V4 hooks
- All tools: subfinder, nuclei, sqlmap, dalfox, jwt_tool, cast, forge, slither

**Rules:**
- Critical and High only — never wastes time on Low/Med
- Every finding ships with a weaponized PoC (curl or Python)
- CVSS 9.0+ bar
- Auto-triggers on any offensive security context

## Legal

Only use on systems you have explicit written authorization to test. Unauthorized scanning is illegal.

## License

MIT
