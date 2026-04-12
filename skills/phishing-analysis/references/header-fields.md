# Email Header Fields Reference

## Authentication Headers

### Authentication-Results
Contains aggregated authentication check results.
```
Authentication-Results: mx.example.com;
    spf=pass smtp.mailfrom=sender@example.com;
    dkim=pass header.d=example.com header.s=selector1;
    dmarc=pass (policy=reject) header.from=example.com
```

### Received-SPF
SPF check result for the sending server.
```
Received-SPF: pass (example.com: domain of sender@example.com designates 192.0.2.1 as permitted sender)
```

**Possible Values:**
- `pass` - Authorized sender
- `fail` - Unauthorized sender (hard fail)
- `softfail` - Unauthorized but domain in transition
- `neutral` - No assertion
- `none` - No SPF record
- `temperror` - Temporary error
- `permerror` - Permanent error (malformed record)

### DKIM-Signature
Digital signature for message integrity.
```
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
    d=example.com; s=selector1;
    h=from:to:subject:date:message-id;
    bh=base64_body_hash;
    b=base64_signature
```

**Key Fields:**
- `d=` Domain that signed
- `s=` Selector for DNS lookup
- `h=` Headers included in signature
- `bh=` Body hash
- `b=` Signature

## Routing Headers

### Received
Added by each mail server in the delivery chain. Read from bottom (oldest) to top (newest).

```
Received: from mail.sender.com (mail.sender.com [192.0.2.1])
    by mx.receiver.com (Postfix) with ESMTPS id ABC123
    for <recipient@receiver.com>; Mon, 1 Jan 2024 12:00:00 +0000 (UTC)
```

**Analysis Points:**
- IP address vs hostname consistency
- Geographic routing anomalies
- Unexpected relay servers
- Time delays between hops

### X-Originating-IP
Client IP that submitted the message (webmail, Outlook).
```
X-Originating-IP: [192.0.2.100]
```

### X-Sender-IP
Similar to X-Originating-IP, added by some providers.

## Sender Headers

### From
Display name and email address shown to recipient.
```
From: "John Smith" <john.smith@company.com>
From: =?UTF-8?B?encoded_name?= <sender@domain.com>
```

**Red Flags:**
- Display name mimics trusted entity
- Email domain doesn't match display name
- Encoded names hiding true content

### Reply-To
Address for replies (often different in phishing).
```
Reply-To: attacker@malicious.com
```

**Red Flag:** Reply-To differs from From address without legitimate reason.

### Return-Path
Envelope sender, used for bounces.
```
Return-Path: <bounces@sender.com>
```

### Sender
The actual sender if different from From.
```
Sender: secretary@company.com
```

## Message Identification

### Message-ID
Unique identifier for the message.
```
Message-ID: <unique-id@mail.sender.com>
```

**Red Flags:**
- Missing Message-ID
- Domain in Message-ID doesn't match sender
- Malformed format

### Date
When message was composed.
```
Date: Mon, 1 Jan 2024 12:00:00 +0000
```

**Analysis:**
- Compare with Received header timestamps
- Check timezone consistency with sender location

### Subject
Message subject line.
```
Subject: Urgent: Your account has been compromised
Subject: =?UTF-8?Q?encoded_subject?=
```

## Content Headers

### Content-Type
MIME type and encoding.
```
Content-Type: multipart/mixed; boundary="boundary_string"
Content-Type: text/html; charset="UTF-8"
```

### Content-Transfer-Encoding
How content is encoded.
```
Content-Transfer-Encoding: base64
Content-Transfer-Encoding: quoted-printable
```

### Content-Disposition
How to handle attachments.
```
Content-Disposition: attachment; filename="document.pdf"
Content-Disposition: inline
```

## Client Headers

### X-Mailer / User-Agent
Email client used.
```
X-Mailer: Microsoft Outlook 16.0
User-Agent: Mozilla Thunderbird 91.0
```

**Analysis:**
- Inconsistent with claimed sender's organization
- Outdated or unusual clients
- Mismatch with typical behavior

### X-Priority / Importance
Message priority.
```
X-Priority: 1 (Highest)
Importance: High
```

**Red Flag:** High priority often used in phishing for urgency.

## Security Headers

### X-Spam-Status
Spam filter results.
```
X-Spam-Status: No, score=-2.0 required=5.0 tests=BAYES_00,DKIM_SIGNED
```

### X-Virus-Scanned
Antivirus scan results.
```
X-Virus-Scanned: ClamAV
```

## Common Phishing Header Patterns

### Pattern 1: Authentication Failures
```
Authentication-Results: spf=fail; dkim=fail; dmarc=fail
```

### Pattern 2: Sender Mismatch
```
From: "IT Department" <support@company.com>
Reply-To: helpdesk@suspicious-domain.xyz
Return-Path: <random@another-domain.com>
```

### Pattern 3: Suspicious Routing
```
Received: from unknown (HELO mail.legitimate.com) (185.xx.xx.xx)
    by suspicious-relay.xyz
```

### Pattern 4: Encoded Headers
```
From: =?UTF-8?B?TWljcm9zb2Z0IFN1cHBvcnQ=?= <attacker@phishing.com>
Subject: =?UTF-8?Q?=E2=9A=A0_Security_Alert?=
```

## Header Analysis Checklist

- [ ] All authentication checks (SPF/DKIM/DMARC) pass
- [ ] From domain matches organization claimed
- [ ] Reply-To matches From (or has legitimate reason)
- [ ] Return-Path is consistent
- [ ] Message-ID domain is consistent
- [ ] Received chain is logical
- [ ] X-Originating-IP is expected
- [ ] Date/timezone is reasonable
- [ ] X-Mailer is consistent with sender
- [ ] No suspicious encoding in display names
