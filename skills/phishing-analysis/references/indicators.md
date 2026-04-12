# Phishing Indicators Checklist

## Header-Based Indicators

### Authentication Failures
- [ ] SPF fails or softfails
- [ ] DKIM signature invalid or missing
- [ ] DMARC fails alignment
- [ ] Multiple authentication failures

### Sender Anomalies
- [ ] From address uses lookalike domain
- [ ] Reply-To differs from From
- [ ] Return-Path mismatch
- [ ] Display name impersonates known entity
- [ ] Encoded display name hiding true content

### Routing Red Flags
- [ ] Unusual geographic routing
- [ ] Anonymous/privacy relays in chain
- [ ] IP doesn't match claimed sending domain
- [ ] Missing or malformed Received headers

### Metadata Issues
- [ ] Missing Message-ID
- [ ] Message-ID domain mismatch
- [ ] Unusual X-Mailer value
- [ ] Timestamp anomalies

## Content-Based Indicators

### Urgency Signals
- [ ] "Immediate action required"
- [ ] "Account will be suspended"
- [ ] "Within 24/48 hours"
- [ ] "Failure to respond will result in..."
- [ ] "Last warning"
- [ ] "Final notice"

### Authority Impersonation
- [ ] Claims to be from CEO/executive
- [ ] IT department impersonation
- [ ] HR/payroll impersonation
- [ ] Legal/compliance threats
- [ ] Government agency claims
- [ ] Bank/financial institution

### Fear Triggers
- [ ] Account compromise claims
- [ ] Unauthorized access alerts
- [ ] Payment/invoice disputes
- [ ] Legal action threats
- [ ] Data breach notifications
- [ ] Password expiration warnings

### Reward Triggers
- [ ] Prize/lottery winnings
- [ ] Inheritance notifications
- [ ] Refund claims
- [ ] Job offers
- [ ] Investment opportunities

### Language Issues
- [ ] Grammatical errors
- [ ] Spelling mistakes
- [ ] Awkward phrasing
- [ ] Inconsistent tone
- [ ] Machine translation artifacts
- [ ] Missing personalization (generic greeting)

### Visual Deception
- [ ] Blurry or distorted logos
- [ ] Outdated branding
- [ ] Inconsistent formatting
- [ ] Poor HTML rendering
- [ ] Mixed fonts/styles

## Link-Based Indicators

### Domain Manipulation
- [ ] Subdomain abuse: `legitimate.com.attacker.xyz`
- [ ] Typosquatting: `amaz0n.com`, `paypa1.com`
- [ ] Homograph attack: Cyrillic/Greek characters
- [ ] Extra TLDs: `company.com.secure.net`
- [ ] Hyphen insertion: `pay-pal.com`

### URL Obfuscation
- [ ] URL shorteners (bit.ly, tinyurl)
- [ ] IP address instead of domain
- [ ] Hexadecimal encoding
- [ ] Double encoding
- [ ] Data URIs
- [ ] JavaScript in links

### Link-Text Mismatch
- [ ] Displayed URL differs from actual href
- [ ] "Click here" hiding malicious URL
- [ ] Button with mismatched link
- [ ] Legitimate domain in anchor, malicious in href

### Redirect Patterns
- [ ] Multiple redirects
- [ ] Open redirect abuse
- [ ] URL parameter manipulation
- [ ] Tracking parameters unusual

## Attachment Indicators

### Dangerous File Types
- [ ] Executable files (.exe, .scr, .bat, .cmd)
- [ ] Script files (.ps1, .vbs, .js, .wsf)
- [ ] Macro documents (.docm, .xlsm)
- [ ] Archive with executables
- [ ] ISO/IMG disk images
- [ ] LNK shortcut files
- [ ] HTA applications

### File Deception
- [ ] Double extension: `invoice.pdf.exe`
- [ ] Long filename hiding extension
- [ ] Right-to-left override character
- [ ] Extension doesn't match content
- [ ] Password-protected (evasion attempt)
- [ ] Unexpected archive format

### Content Characteristics
- [ ] Request to enable macros
- [ ] "Document protected" lure
- [ ] Empty/minimal visible content
- [ ] Embedded links in documents
- [ ] Suspicious VBA/macro code

## Behavioral Indicators

### Request Patterns
- [ ] Requests credentials
- [ ] Asks for MFA codes
- [ ] Requests financial information
- [ ] Asks for personal data
- [ ] Requests software installation
- [ ] Asks to call a number

### Process Manipulation
- [ ] Requests to bypass security
- [ ] Asks to ignore warnings
- [ ] Suggests unusual procedures
- [ ] Requests off-channel communication
- [ ] Gift card payment requests

## Red Team Indicators

Signs this may be a security awareness test:

### Infrastructure Clues
- [ ] Links to internal domains
- [ ] Known phishing simulation platforms
- [ ] Company security team infrastructure
- [ ] Tracking pixels from awareness tools

### Timing Clues
- [ ] During security awareness month
- [ ] After security training announcement
- [ ] Following security incidents
- [ ] Predictable testing schedule

### Content Clues
- [ ] Slightly obvious mistakes
- [ ] Training-related themes
- [ ] References to security policies
- [ ] Unusual sender within IT/Security

## Risk Scoring Guide

### Critical (Immediate Threat)
- Credential harvesting active
- Malware delivery confirmed
- Targeted spear-phishing
- BEC (Business Email Compromise)

### High
- Multiple high-confidence indicators
- Active malicious infrastructure
- Sophisticated social engineering
- Targeted to sensitive personnel

### Medium
- Several moderate indicators
- Generic phishing campaign
- Limited targeting
- Known threat patterns

### Low
- Few weak indicators
- Possible false positive
- Spam rather than phishing
- Minimal risk exposure

## Quick Reference Matrix

| Indicator Type | Weight | Notes |
|----------------|--------|-------|
| Auth failures | High | Multiple failures = very suspicious |
| Sender mismatch | High | Reply-To differs = strong indicator |
| Urgency language | Medium | Common but not definitive |
| Link mismatch | High | Strongest content indicator |
| Dangerous attachment | Critical | Immediate threat |
| Credential request | Critical | Primary phishing goal |
| Grammar errors | Low | Unreliable alone |
| Generic greeting | Low | Common in mass campaigns |
