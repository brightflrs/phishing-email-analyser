/*
 * Phishing Email Analyser - analysis engine
 *
 * Everything in this file runs inside the visitor's web browser.
 * - It makes NO network requests (no fetch, no XMLHttpRequest, no external scripts).
 * - It stores nothing and sends nothing anywhere.
 * - Every rule is listed in the RULES array below, with its points value,
 *   so the score can always be explained and checked.
 *
 * This is an educational triage tool. It identifies warning signs. It does NOT
 * determine whether an email is malicious.
 */
(function () {
  'use strict';

  // ---------------------------------------------------------------------------
  // Reference lists (small, deliberately simple, and easy to edit)
  // ---------------------------------------------------------------------------

  // Link shorteners hide the real destination.
  var SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 'tiny.cc', 'lnkd.in'
  ];

  // Domain endings that are cheap or frequently abused in phishing campaigns.
  // Being on this list is a warning sign, not proof of anything.
  var SUSPICIOUS_TLDS = [
    'zip', 'mov', 'top', 'xyz', 'click', 'gq', 'tk', 'ml', 'cf', 'ga',
    'icu', 'monster', 'cam', 'rest', 'loan', 'work'
  ];

  // Well-known brands and the domains they officially use.
  // "token" is the word we look for inside a link or sender name.
  // Check the official list against each company's own website before relying on it.
  var MS_DOMAINS = ['microsoft.com', 'office.com', 'office365.com', 'live.com',
    'outlook.com', 'microsoftonline.com', 'sharepoint.com'];
  var BRANDS = [
    { name: 'Microsoft', token: 'microsoft', official: MS_DOMAINS },
    { name: 'Microsoft 365', token: 'm365', official: MS_DOMAINS },
    { name: 'Office 365', token: 'office365', official: MS_DOMAINS },
    { name: 'PayPal', token: 'paypal', official: ['paypal.com'] },
    { name: 'Apple', token: 'apple', official: ['apple.com', 'icloud.com'] },
    { name: 'Amazon', token: 'amazon', official: ['amazon.com'] },
    { name: 'DHL', token: 'dhl', official: ['dhl.com'] },
    { name: 'FedEx', token: 'fedex', official: ['fedex.com'] },
    { name: 'GCash', token: 'gcash', official: ['gcash.com'] },
    { name: 'BDO', token: 'bdo', official: ['bdo.com.ph'] },
    { name: 'BPI', token: 'bpi', official: ['bpi.com.ph'] }
  ];

  var EXEC_EXT = ['exe', 'scr', 'bat', 'cmd', 'pif', 'js', 'jse', 'vbs', 'vbe',
    'wsf', 'wsh', 'ps1', 'msi', 'jar', 'lnk', 'hta', 'dll', 'reg', 'apk'];
  var MACRO_EXT = ['docm', 'xlsm', 'pptm', 'xlam', 'dotm', 'xltm'];
  var ARCHIVE_EXT = ['zip', 'rar', '7z', 'iso', 'img', 'gz', 'cab'];
  var DOC_EXT = ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'txt',
    'rtf', 'jpg', 'jpeg', 'png', 'htm', 'html'];

  // ---------------------------------------------------------------------------
  // Phrase patterns
  // ---------------------------------------------------------------------------

  var URGENCY_RE = /\b(urgent(ly)?|immediately|act now|right away|(within|in) \d+ hours?|within 24 hours|final (notice|warning|reminder)|last warning|expires? (today|soon|in \d+)|time[- ]sensitive|asap|as soon as possible|do not delay|don'?t delay|today only|respond (now|today)|before (the )?end of (the )?day|before (end of day|close of business))\b/gi;
  var SUSPEND_RE = /\b(account|mailbox|access|profile|subscription)\b[^.\n]{0,60}\b(suspend(ed)?|locked|disabled|deactivated|terminated|closed|closure|restricted|removed|deleted|blocked)\b|\b(suspend(ed)?|locked|disabled|deactivated|terminated|closure|closed|restricted|removed|blocked)\b[^.\n]{0,60}\b(account|mailbox|access|profile|subscription)\b/gi;
  var PASSWORD_RE = /\b(enter|confirm|verify|provide|send|reply with|re-?enter|submit|share|type|update|log ?in with|sign ?in with)\b[^.\n]{0,25}?\b(your\s+)?(password|passcode|login details|login credentials|credentials)\b/gi;
  var MFA_CODE_RE = /\b(verification|security|one[- ]time|otp|mfa|2fa|authentication|sign[- ]?in|login|access|confirmation|validation|authenticator)\s+(codes?|pins?|passcodes?|tokens?)\b/gi;
  var MFA_ASK_RE = /\b(share|send|provide|enter|reply|give|type|submit|forward|read out|input|confirm)\b/i;
  var MFA_APPROVE_RE = /\b(approve|accept|allow)\b[^.\n]{0,30}\b(sign[- ]?in|login)\b[^.\n]{0,15}\b(request|attempt|notification|prompt)?\b/gi;
  var CRED_RE = /\b(verify|confirm|validate|update|re-?activate|restore|secure|unlock)\s+(your\s+)?(account|identity|details|information|credentials|billing|payment method|login|mailbox|profile)\b/gi;
  var CLICK_RE = /\b(click (here|below|the link|this link)|follow (the )?link|use the link|link below|sign in below|log in below|tap here)\b/i;
  var GIFT_RE = /\b(gift cards?|itunes cards?|google play cards?|steam cards?|apple gift cards?|bitcoin|crypto(currency)?|western union|moneygram|wire transfer)\b/gi;
  var PAY_RE = /\b(pay|payment|transfer|send|remit|settle)\b[^.\n]{0,60}?\b(now|today|immediately|urgent(ly)?|asap|within \d+ (hours?|days?)|by (end of day|tonight|tomorrow))\b/gi;
  var FEE_RE = /\b(fee|charge|customs duty|redelivery)\b[^.\n]{0,40}(php|usd|eur|gbp|\u20b1|\$|\u20ac|\u00a3)\s?[\d,.]+/gi;
  var BANK_CHANGE_RE1 = /\b(change[ds]?|updated?|new|different|modif(y|ied))\b[^.\n]{0,40}\b(bank|iban|sort code|routing|swift|account number)\b/gi;
  var BANK_CHANGE_RE2 = /\b(bank|iban|sort code|routing|swift|account number)\b[^.\n]{0,30}\b(change[ds]?|updated?|new|different|modified)\b/gi;
  var MACRO_RE = /\benable (editing|content|macros?|the content|this content)\b|\bmacros? (must|needs to|should) be enabled\b|\b(enable|allow) macros?\b/gi;
  var INVOICE_RE = /\b(invoice|overdue|payment due|remittance|purchase order|past due|outstanding balance|statement of account)\b/gi;
  var BRAND_BODY_RE = /\b(microsoft|microsoft 365|office 365|outlook|onedrive|sharepoint|paypal|apple id|icloud|amazon|netflix|dhl|fedex|gcash|bdo|bpi)\b/gi;
  var AUTHORITY_RE = /\b(it (department|support|helpdesk|service desk|team)|help ?desk|security (team|department|centre|center)|hr|human resources|finance (department|team)|accounts payable|ceo|cfo|managing director|management team)\b/gi;
  var GENERIC_GREETING_RE = /\bdear (valued )?(customer|user|client|account holder|member|applicant|employee|sir\/madam|sir or madam)\b/gi;
  var SECRECY_RE = /\b(keep (this|it|the matter) (confidential|between us|private|quiet|to yourself)|don'?t tell|do not tell|don'?t mention|do not mention|discreet(ly)?|between (you and me|us))\b/gi;
  var URL_IN_TEXT_RE = /(?:https?:\/\/|www\.)[^\s<>"'`)\]]+/gi;
  var ATTACH_TOKEN_RE = /[\w\-]+(?:\.[\w\-]+)*\.[A-Za-z0-9]{1,5}\b/g;

  // ---------------------------------------------------------------------------
  // Small helpers
  // ---------------------------------------------------------------------------

  function matchAll(re, text) {
    var flags = re.flags.indexOf('g') >= 0 ? re.flags : re.flags + 'g';
    var r = new RegExp(re.source, flags);
    var out = [];
    var m;
    while ((m = r.exec(text)) !== null) {
      out.push({ text: m[0], index: m.index });
      if (m[0].length === 0) { r.lastIndex++; }
    }
    return out;
  }

  // True if a negation word (never, do not, don't...) sits just before this position.
  // Stops "We will never ask for your password" from being flagged as a password request.
  function isNegated(text, index) {
    var before = text.slice(Math.max(0, index - 40), index).toLowerCase();
    return /\b(never|not|don'?t|do not|won'?t|will not|no need to|avoid|nobody|cannot)\b/.test(before);
  }

  function clip(s, n) {
    s = String(s).replace(/\s+/g, ' ').trim();
    n = n || 110;
    return s.length > n ? s.slice(0, n - 1) + '\u2026' : s;
  }

  function unique(arr) {
    return arr.filter(function (v, i) { return arr.indexOf(v) === i; });
  }

  function uniqueMatchTexts(matches) {
    var seen = {};
    var out = [];
    matches.forEach(function (m) {
      var t = clip(m.text, 80);
      var key = t.toLowerCase();
      if (!seen[key]) { seen[key] = true; out.push(t); }
    });
    return out;
  }

  function sameDomain(a, b) {
    if (!a || !b) { return false; }
    return a === b || a.endsWith('.' + b) || b.endsWith('.' + a);
  }

  function isOfficial(host, officialList) {
    return officialList.some(function (d) { return host === d || host.endsWith('.' + d); });
  }

  function normaliseLabel(s) {
    // Turns look-alike characters back into letters: "micros0ft" -> "microsoft"
    return s.toLowerCase().replace(/0/g, 'o').replace(/1/g, 'l');
  }

  function tokensOf(s) {
    return normaliseLabel(s).split(/[^a-z0-9]+/).filter(Boolean);
  }

  function tokenMatchesBrand(tok, brand) {
    if (tok === brand.token) { return true; }
    // Allow longer words that start with the brand name, e.g. "microsoftonline"
    return brand.token.length >= 5 && tok.indexOf(brand.token) === 0 && tok.length - brand.token.length <= 10;
  }

  // Names of brands whose word appears inside a host name (e.g. "micros0ft-login.example").
  // Returns only brands that are NOT officially used by that host.
  function brandImpersonation(host) {
    var tokens = tokensOf(host);
    var found = [];
    BRANDS.forEach(function (brand) {
      var appears = tokens.some(function (t) { return tokenMatchesBrand(t, brand); });
      if (appears && !isOfficial(host, brand.official)) { found.push(brand.name); }
    });
    return unique(found);
  }

  // Names of brands whose word appears in free text, such as a display name ("Microsoft 365 Support").
  function brandWordsIn(text) {
    var tokens = tokensOf(text);
    return unique(BRANDS.filter(function (brand) {
      return tokens.some(function (t) { return tokenMatchesBrand(t, brand); });
    }).map(function (b) { return b.name; }));
  }

  // ---------------------------------------------------------------------------
  // Parsing: email headers, links, attachments
  // ---------------------------------------------------------------------------

  // Splits pasted text into "headers" (From:, Subject:, ...) and "body".
  function splitHeaders(raw) {
    var lines = raw.split('\n');
    var headers = {};
    var lastKey = null;
    var seenHeader = false;
    var i = 0;
    for (; i < lines.length; i++) {
      var line = lines[i];
      if (line.trim() === '') {
        if (seenHeader) { i++; }
        break;
      }
      if (/^\s/.test(line) && lastKey) {
        headers[lastKey] += ' ' + line.trim(); // folded (multi-line) header
        continue;
      }
      var m = /^([A-Za-z][A-Za-z0-9-]*):\s*(.*)$/.exec(line);
      if (!m) { break; }
      lastKey = m[1].toLowerCase();
      seenHeader = true;
      headers[lastKey] = headers[lastKey] ? headers[lastKey] + ' | ' + m[2].trim() : m[2].trim();
    }
    var hasHeaders = seenHeader && !!(headers.from || headers.subject || headers['reply-to'] ||
      headers['return-path'] || headers['authentication-results'] || headers['received-spf']);
    var body = hasHeaders ? lines.slice(i).join('\n') : raw;
    return { headers: hasHeaders ? headers : null, hasHeaders: hasHeaders, body: body };
  }

  function parseAddress(value) {
    if (!value) { return null; }
    var angle = /<([^>]+)>/.exec(value);
    var addr = angle ? angle[1] : ((/[^\s<>"',;]+@[^\s<>"',;]+/.exec(value)) || [null])[0];
    if (!addr) { return null; }
    addr = addr.trim().toLowerCase();
    var at = addr.lastIndexOf('@');
    var name = angle ? value.slice(0, angle.index).replace(/["']/g, '').trim() : '';
    return {
      address: addr,
      domain: at >= 0 ? addr.slice(at + 1).replace(/[>\s]/g, '') : '',
      name: name
    };
  }

  function parseAuth(headers) {
    var res = { spf: null, dkim: null, dmarc: null };
    var ar = headers['authentication-results'] || '';
    ['spf', 'dkim', 'dmarc'].forEach(function (k) {
      var m = new RegExp('\\b' + k + '=(\\w+)', 'i').exec(ar);
      if (m) { res[k] = m[1].toLowerCase(); }
    });
    var rs = headers['received-spf'];
    if (!res.spf && rs) {
      var m2 = /^\s*(\w+)/.exec(rs);
      if (m2) { res.spf = m2[1].toLowerCase(); }
    }
    return res;
  }

  function makeLink(raw, source, shown) {
    var clean = raw.replace(/[.,;:!?]+$/, '');
    var hasScheme = /^https?:\/\//i.test(clean);
    var url = hasScheme ? clean : 'http://' + clean;
    var rest = url.replace(/^https?:\/\//i, '');
    var authority = rest.split(/[\/?#]/)[0];
    var userinfo = authority.indexOf('@') >= 0;
    var hostPort = userinfo ? authority.slice(authority.lastIndexOf('@') + 1) : authority;
    var host;
    if (hostPort.charAt(0) === '[') {
      host = hostPort.slice(0, hostPort.indexOf(']') + 1).toLowerCase();
    } else {
      host = hostPort.replace(/:\d+$/, '').replace(/\.$/, '').toLowerCase();
    }
    var labels = host.split('.');
    return {
      raw: clip(clean, 120),
      source: source,            // 'link' = inside an HTML anchor, 'text' = plain text
      shown: shown ? clip(shown, 120) : null,
      host: host,
      http: /^http:\/\//i.test(clean),
      userinfo: userinfo,
      isIp: /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.charAt(0) === '[',
      shortener: SHORTENERS.some(function (s) { return host === s || host.endsWith('.' + s); }),
      badTld: SUSPICIOUS_TLDS.indexOf(labels[labels.length - 1]) >= 0,
      punycode: host.indexOf('xn--') >= 0,
      tooManyParts: labels.length >= 5 || (host.match(/-/g) || []).length >= 3,
      lookalikeBrands: brandImpersonation(host)
    };
  }

  function extractLinks(body) {
    var links = [];
    var anchorRe = /<a\b[^>]*\bhref\s*=\s*["']([^"']+)["'][^>]*>([\s\S]*?)<\/a\s*>/gi;
    var m;
    while ((m = anchorRe.exec(body)) !== null) {
      var shown = m[2].replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim();
      links.push(makeLink(m[1].trim(), 'link', shown));
    }
    var plain = body.replace(anchorRe, ' ');
    matchAll(URL_IN_TEXT_RE, plain).forEach(function (u) {
      links.push(makeLink(u.text, 'text', null));
    });
    return links;
  }

  var KNOWN_EXT = EXEC_EXT.concat(MACRO_EXT, ARCHIVE_EXT, DOC_EXT);

  function findAttachments(body) {
    var noUrls = body.replace(URL_IN_TEXT_RE, ' ');
    var names = matchAll(ATTACH_TOKEN_RE, noUrls).map(function (m) { return m.text; });
    var result = [];
    names.forEach(function (name) {
      var parts = name.split('.');
      var ext = parts[parts.length - 1].toLowerCase();
      if (KNOWN_EXT.indexOf(ext) >= 0) {
        result.push({ name: name, ext: ext, parts: parts.map(function (p) { return p.toLowerCase(); }) });
      }
    });
    // Remove duplicates by name
    var seen = {};
    return result.filter(function (a) {
      if (seen[a.name]) { return false; }
      seen[a.name] = true;
      return true;
    });
  }

  // ---------------------------------------------------------------------------
  // Scoring rules
  // Each rule: id, title, points (negative = reassuring), description, check(ctx).
  // check() returns an array of evidence strings. An empty array means "not triggered".
  // ---------------------------------------------------------------------------

  function firstEvidence(matches, prefix) {
    return uniqueMatchTexts(matches).map(function (t) { return (prefix || '') + '\u201c' + t + '\u201d'; });
  }

  var RULES = [
    // ----- Pressure and manipulation -----
    {
      id: 'urgency', title: 'Urgency or pressure language', points: 12,
      description: 'Phrases that push you to act quickly, such as "urgent", "immediately", "within 24 hours", or "act now".',
      check: function (ctx) {
        return firstEvidence(matchAll(URGENCY_RE, ctx.body));
      }
    },
    {
      id: 'suspension', title: 'Threat of account suspension or closure', points: 15,
      description: 'Warnings that an account, mailbox or service will be suspended, locked, closed or deleted.',
      check: function (ctx) {
        return firstEvidence(matchAll(SUSPEND_RE, ctx.body));
      }
    },
    {
      id: 'generic-greeting', title: 'Generic greeting', points: 8,
      description: 'Addresses you as "Dear customer" or "Dear user" instead of by name. Legitimate services usually use your name.',
      check: function (ctx) {
        return firstEvidence(matchAll(GENERIC_GREETING_RE, ctx.body));
      }
    },
    {
      id: 'secrecy', title: 'Asks you to keep the message secret', points: 15,
      description: 'Requests to keep something confidential or not tell colleagues. Secrecy is a common tactic to stop you checking with others.',
      check: function (ctx) {
        return firstEvidence(matchAll(SECRECY_RE, ctx.body));
      }
    },
    {
      id: 'authority', title: 'Claims to be an internal authority', points: 10,
      description: 'Pretends to come from IT, HR, finance, a security team, or a senior executive.',
      check: function (ctx) {
        return firstEvidence(matchAll(AUTHORITY_RE, ctx.body));
      }
    },
    {
      id: 'brand-mention', title: 'Mentions a well-known brand', points: 10,
      description: 'Names a major brand or service. Scammers often impersonate brands. This is only a prompt to check, not proof.',
      check: function (ctx) {
        return firstEvidence(matchAll(BRAND_BODY_RE, ctx.body));
      }
    },

    // ----- Requests for sensitive information -----
    {
      id: 'password-request', title: 'Requests your password or login credentials', points: 25,
      description: 'Asks you to enter, confirm, verify or send your password or login details. Genuine organisations do not ask for your password by email.',
      check: function (ctx) {
        return firstEvidence(matchAll(PASSWORD_RE, ctx.body).filter(function (m) {
          return !isNegated(ctx.body, m.index);
        }));
      }
    },
    {
      id: 'mfa-request', title: 'Requests a verification or MFA code', points: 25,
      description: 'Asks you to share a one-time code, PIN or verification code. Codes are meant only for you to type into the official site.',
      check: function (ctx) {
        var out = [];
        matchAll(MFA_CODE_RE, ctx.body).forEach(function (m) {
          if (isNegated(ctx.body, m.index)) { return; }
          var win = ctx.body.slice(Math.max(0, m.index - 120), m.index + m.text.length + 120);
          if (MFA_ASK_RE.test(win) && !/\b(never|do not|don'?t)\s+(share|give|send|provide|disclose)\b/i.test(win)) {
            out.push('\u201c' + clip(m.text, 60) + '\u201d appears near a request to share or enter it');
          }
        });
        return unique(out);
      }
    },
    {
      id: 'approve-signin', title: 'Asks you to approve a sign-in request', points: 15,
      description: 'Asks you to approve a sign-in or login prompt. Approving requests you did not start can give attackers access.',
      check: function (ctx) {
        return firstEvidence(matchAll(MFA_APPROVE_RE, ctx.body).filter(function (m) {
          return !isNegated(ctx.body, m.index);
        }));
      }
    },
    {
      id: 'credential-harvest', title: 'Asks you to "verify" or "confirm" your account via a link', points: 15,
      description: 'Uses verify, confirm, validate or update language about your account, details or identity, together with a link or "click here".',
      check: function (ctx) {
        var matches = matchAll(CRED_RE, ctx.body).filter(function (m) { return !isNegated(ctx.body, m.index); });
        if (matches.length === 0) { return []; }
        if (ctx.links.length > 0 || CLICK_RE.test(ctx.body)) {
          return firstEvidence(matches);
        }
        return [];
      }
    },
    {
      id: 'gift-card-crypto', title: 'Asks for gift cards, crypto or wire transfers', points: 25,
      description: 'Requests payment by gift card, cryptocurrency or wire or money-transfer services. These are almost never used by legitimate businesses for urgent requests.',
      check: function (ctx) {
        return firstEvidence(matchAll(GIFT_RE, ctx.body));
      }
    },
    {
      id: 'payment-demand', title: 'Demands an immediate payment or fee', points: 15,
      description: 'Asks you to pay now, today, within a short deadline, or to pay a small fee to release a delivery or account.',
      check: function (ctx) {
        return firstEvidence(matchAll(PAY_RE, ctx.body).concat(matchAll(FEE_RE, ctx.body)));
      }
    },
    {
      id: 'bank-change', title: 'Asks you to change bank or payment details', points: 25,
      description: 'Says bank, IBAN or account details have changed, or asks you to send money to a new account. This is a classic business email compromise (BEC) technique.',
      check: function (ctx) {
        return firstEvidence(matchAll(BANK_CHANGE_RE1, ctx.body).concat(matchAll(BANK_CHANGE_RE2, ctx.body)));
      }
    },
    {
      id: 'invoice', title: 'Unexpected invoice or overdue-payment language', points: 10,
      description: 'Mentions invoices, overdue balances, remittance or purchase orders. Check against your own records before acting.',
      check: function (ctx) {
        return firstEvidence(matchAll(INVOICE_RE, ctx.body));
      }
    },

    // ----- Attachments and files -----
    {
      id: 'exec-attachment', title: 'Executable or script attachment', points: 30,
      description: 'A file name ending in a program or script type (such as .exe, .scr, .js, .vbs or .ps1). These can run code on your computer.',
      check: function (ctx) {
        return ctx.attachments.filter(function (a) { return EXEC_EXT.indexOf(a.ext) >= 0; })
          .map(function (a) { return a.name; });
      }
    },
    {
      id: 'macro-attachment', title: 'Macro-enabled Office file', points: 20,
      description: 'Word, Excel or PowerPoint files that can run macros (such as .docm or .xlsm). Macros are a common way to deliver malware.',
      check: function (ctx) {
        return ctx.attachments.filter(function (a) { return MACRO_EXT.indexOf(a.ext) >= 0; })
          .map(function (a) { return a.name; });
      }
    },
    {
      id: 'macro-request', title: 'Asks you to enable macros or content', points: 25,
      description: 'Asks you to click "Enable Editing" or "Enable Content" to view a document. This is a common malware trick.',
      check: function (ctx) {
        return firstEvidence(matchAll(MACRO_RE, ctx.body));
      }
    },
    {
      id: 'double-extension', title: 'Disguised file name (double extension or hidden text trick)', points: 30,
      description: 'A file that looks like a document (for example "invoice.pdf.exe") but really ends in a program type. Some files also use invisible characters to hide the real ending.',
      check: function (ctx) {
        var out = [];
        ctx.attachments.forEach(function (a) {
          var p = a.parts;
          if (p.length >= 3 && DOC_EXT.indexOf(p[p.length - 2]) >= 0 && EXEC_EXT.indexOf(a.ext) >= 0) {
            out.push(a.name + ' (looks like a document but ends in .' + a.ext + ')');
          }
        });
        if (ctx.raw.indexOf('\u202e') >= 0) {
          out.push('Contains a hidden right-to-left character that can disguise a file extension');
        }
        return out;
      }
    },
    {
      id: 'archive-attachment', title: 'Compressed or disk-image attachment', points: 10,
      description: 'Zip, RAR, ISO or IMG files can hide other files that security filters may not inspect. Be cautious.',
      check: function (ctx) {
        return ctx.attachments.filter(function (a) { return ARCHIVE_EXT.indexOf(a.ext) >= 0; })
          .map(function (a) { return a.name; });
      }
    },

    // ----- Links -----
    {
      id: 'raw-ip', title: 'Link uses a raw IP address', points: 30,
      description: 'A link that points to a number such as 192.0.2.10 instead of a named website. Legitimate services almost always use domain names.',
      check: function (ctx) {
        return ctx.links.filter(function (l) { return l.isIp; }).map(function (l) { return l.raw; });
      }
    },
    {
      id: 'userinfo-trick', title: 'Link contains a fake "@" trick', points: 30,
      description: 'A link like "https://paypal.com@evil.example" shows one name but actually goes to the part after the "@".',
      check: function (ctx) {
        return ctx.links.filter(function (l) { return l.userinfo; }).map(function (l) {
          return l.raw + ' (real destination: ' + l.host + ')';
        });
      }
    },
    {
      id: 'shortener', title: 'Shortened link', points: 20,
      description: 'Link shorteners such as bit.ly hide the real destination. You cannot see where the link goes before clicking.',
      check: function (ctx) {
        return ctx.links.filter(function (l) { return l.shortener; }).map(function (l) { return l.raw; });
      }
    },
    {
      id: 'bad-tld', title: 'Domain ending often abused in scams', points: 15,
      description: 'Domains ending in endings such as .zip, .top, .xyz or .click are cheap and frequently used by scammers. This is a warning sign, not proof.',
      check: function (ctx) {
        return ctx.links.filter(function (l) { return l.badTld; }).map(function (l) { return l.host; });
      }
    },
    {
      id: 'lookalike', title: 'Domain imitates a well-known brand', points: 25,
      description: 'The link contains a brand name (such as "microsoft") but the domain is not one that brand officially uses.',
      check: function (ctx) {
        var out = [];
        ctx.links.forEach(function (l) {
          if (l.lookalikeBrands.length) {
            out.push(l.host + ' imitates ' + l.lookalikeBrands.join(', '));
          }
        });
        return unique(out);
      }
    },
    {
      id: 'complex-domain', title: 'Unusually complex domain', points: 10,
      description: 'Very long chains of sub-domains or many hyphens are often used to make a web address look official.',
      check: function (ctx) {
        return ctx.links.filter(function (l) { return l.tooManyParts && !l.isIp; }).map(function (l) { return l.host; });
      }
    },
    {
      id: 'http-link', title: 'Link is not encrypted (http, not https)', points: 10,
      description: 'Links starting with http:// do not use an encrypted connection. Legitimate sign-in pages should use https://.',
      check: function (ctx) {
        return ctx.links.filter(function (l) { return l.http; }).map(function (l) { return l.raw; });
      }
    },
    {
      id: 'punycode', title: 'Internationalised look-alike domain', points: 20,
      description: 'Domains containing "xn--" can use characters that look almost identical to ordinary letters.',
      check: function (ctx) {
        return ctx.links.filter(function (l) { return l.punycode; }).map(function (l) { return l.host; });
      }
    },
    {
      id: 'misleading-text', title: 'Link text does not match where the link goes', points: 30,
      description: 'The visible text shows one website but the link actually goes to a different one. This is one of the most common phishing tricks.',
      check: function (ctx) {
        var out = [];
        ctx.links.forEach(function (l) {
          if (l.source !== 'link' || !l.shown) { return; }
          var m = /([a-z0-9-]+\.)+[a-z]{2,}/i.exec(l.shown);
          if (!m) { return; }
          var shownHost = makeLink(m[0], 'text', null).host;
          if (!sameDomain(shownHost, l.host)) {
            out.push('Shows "' + clip(l.shown, 60) + '" but points to ' + l.host);
          }
        });
        return out;
      }
    },

    // ----- Email headers (only checked if headers were pasted) -----
    {
      id: 'reply-to', title: 'Reply-To address is a different domain from the sender', points: 25,
      description: 'Replies would go to a different organisation from the one that appears to have sent the email.',
      check: function (ctx) {
        var h = ctx.headers; if (!h) { return []; }
        if (ctx.replyTo && ctx.from && !sameDomain(ctx.replyTo.domain, ctx.from.domain)) {
          return ['From domain: ' + ctx.from.domain + ' | Reply-To domain: ' + ctx.replyTo.domain];
        }
        return [];
      }
    },
    {
      id: 'display-name', title: 'Sender display name claims a brand the address does not match', points: 20,
      description: 'The name shown in the From line (for example "Microsoft 365") does not match the real sending domain.',
      check: function (ctx) {
        if (!ctx.headers || !ctx.from || !ctx.from.name) { return []; }
        var brands = brandWordsIn(ctx.from.name).filter(function (name) {
          return BRANDS.some(function (b) { return b.name === name && !isOfficial(ctx.from.domain, b.official); });
        });
        return brands.length ? ['Display name "' + clip(ctx.from.name, 60) + '" but sent from ' + ctx.from.domain] : [];
      }
    },
    {
      id: 'return-path', title: 'Return-Path domain differs from the sender', points: 5,
      description: 'The technical bounce address is on a different domain. This is often normal for newsletters, so it carries a small weight.',
      check: function (ctx) {
        if (!ctx.headers || !ctx.returnPath || !ctx.from) { return []; }
        return sameDomain(ctx.returnPath.domain, ctx.from.domain) ? [] :
          ['From domain: ' + ctx.from.domain + ' | Return-Path domain: ' + ctx.returnPath.domain];
      }
    },
    {
      id: 'spf-fail', title: 'SPF check failed', points: 15,
      description: 'SPF checks whether the sending server is allowed to send for the domain. A failure means the sender could not be confirmed this way.',
      check: function (ctx) {
        if (!ctx.auth) { return []; }
        return (ctx.auth.spf === 'fail' || ctx.auth.spf === 'softfail') ? ['SPF result: ' + ctx.auth.spf] : [];
      }
    },
    {
      id: 'dkim-fail', title: 'DKIM check failed', points: 15,
      description: 'DKIM checks a digital signature that proves the message was not altered and came from the claimed domain. A failure is a warning sign.',
      check: function (ctx) {
        if (!ctx.auth) { return []; }
        return ctx.auth.dkim === 'fail' ? ['DKIM result: fail'] : [];
      }
    },
    {
      id: 'dmarc-fail', title: 'DMARC check failed', points: 20,
      description: 'DMARC combines SPF and DKIM with the sender domain. A failure means the domain\'s own policy was not satisfied.',
      check: function (ctx) {
        if (!ctx.auth) { return []; }
        return ctx.auth.dmarc === 'fail' ? ['DMARC result: fail'] : [];
      }
    },

    // ----- Reassuring signs (these LOWER the score) -----
    {
      id: 'spf-pass', title: 'SPF check passed', points: -5,
      description: 'Reassuring: the sending server was authorised for the domain.',
      check: function (ctx) {
        return ctx.auth && ctx.auth.spf === 'pass' ? ['SPF result: pass'] : [];
      }
    },
    {
      id: 'dkim-pass', title: 'DKIM check passed', points: -5,
      description: 'Reassuring: the digital signature matches the claimed domain.',
      check: function (ctx) {
        return ctx.auth && ctx.auth.dkim === 'pass' ? ['DKIM result: pass'] : [];
      }
    },
    {
      id: 'dmarc-pass', title: 'DMARC check passed', points: -10,
      description: 'Reassuring: the sender domain\'s authentication policy was satisfied.',
      check: function (ctx) {
        return ctx.auth && ctx.auth.dmarc === 'pass' ? ['DMARC result: pass'] : [];
      }
    }
  ];

  // ---------------------------------------------------------------------------
  // Scoring and recommendations
  // ---------------------------------------------------------------------------

  var BANDS = { high: 60, suspicious: 25 };

  function bandFor(score) {
    if (score >= BANDS.high) { return { key: 'high', label: 'High Risk' }; }
    if (score >= BANDS.suspicious) { return { key: 'suspicious', label: 'Suspicious' }; }
    return { key: 'low', label: 'Low Risk' };
  }

  function buildRecommendations(band, findingIds) {
    var recs = [];
    var has = function (id) { return findingIds.indexOf(id) >= 0; };

    if (band.key === 'high') {
      recs.push('Treat this message as dangerous until proven otherwise. Do not reply, click links, or open attachments.');
    } else if (band.key === 'suspicious') {
      recs.push('Treat this message as unverified. Do not act on its requests until you have checked them through another channel.');
    } else {
      recs.push('No strong warning signs were found. Stay alert anyway: a clean result does not prove the email is safe.');
    }

    if (has('password-request') || has('mfa-request') || has('approve-signin') || has('credential-harvest')) {
      recs.push('Never type your password or a verification code into a page reached from an email. Go to the service yourself by typing its address or using its official app.');
    }
    if (has('bank-change') || has('gift-card-crypto') || has('payment-demand') || has('invoice')) {
      recs.push('Do not send any money or change payment details based on this message. Confirm the request by phone, using a number you already have, not one from the email.');
    }
    if (has('exec-attachment') || has('macro-attachment') || has('macro-request') || has('double-extension')) {
      recs.push('Do not open any attachments. Do not enable macros or content. Use a file you requested yourself, or ask your IT team to check the file.');
    }
    if (has('raw-ip') || has('userinfo-trick') || has('shortener') || has('lookalike') ||
        has('misleading-text') || has('bad-tld') || has('punycode')) {
      recs.push('Do not click the links. To see where a link really goes on a computer, hover your mouse over it and read the address shown in the corner of the browser. Better still, type the official address yourself.');
    }
    if (has('reply-to') || has('display-name') || has('spf-fail') || has('dkim-fail') || has('dmarc-fail')) {
      recs.push('The sender could not be properly verified. Do not reply. Contact the person or company using contact details you already trust.');
    }
    recs.push('Verify important messages independently. Use the organisation\'s official website, official app, or a phone number you already know, not one given in the email.');
    recs.push('If you have already clicked a link or entered information: change that password right away, turn on multi-factor authentication, review recent sign-in activity, and report it to your IT team or the service provider.');
    if (band.key !== 'low') {
      recs.push('Report the message to your organisation\'s IT or security team, or to the email provider\'s "report phishing" option, then delete it.');
    }
    return recs;
  }

  // ---------------------------------------------------------------------------
  // Main entry point
  // ---------------------------------------------------------------------------

  function analyseEmail(input) {
    var raw = String(input || '').replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    var parts = splitHeaders(raw);
    var headers = parts.headers || {};
    var ctx = {
      raw: raw,
      body: parts.body,
      headers: parts.headers,
      hasHeaders: parts.hasHeaders,
      from: null,
      replyTo: null,
      returnPath: null,
      auth: null,
      links: extractLinks(parts.body),
      attachments: findAttachments(parts.body)
    };
    if (parts.hasHeaders) {
      ctx.from = parseAddress(headers.from);
      ctx.replyTo = parseAddress(headers['reply-to']);
      ctx.returnPath = parseAddress(headers['return-path']);
      ctx.auth = parseAuth(headers);
    }

    var findings = [];
    var reassurance = [];
    var total = 0;

    RULES.forEach(function (rule) {
      var evidence = rule.check(ctx) || [];
      if (evidence.length === 0) { return; }
      var item = {
        id: rule.id,
        title: rule.title,
        points: rule.points,
        explanation: rule.description,
        evidence: evidence.slice(0, 5),
        moreCount: Math.max(0, evidence.length - 5)
      };
      total += rule.points;
      if (rule.points < 0) { reassurance.push(item); } else { findings.push(item); }
    });

    var score = Math.max(0, Math.min(100, total));
    var band = bandFor(score);

    findings.sort(function (a, b) { return b.points - a.points; });

    var notes = [];
    var wordCount = (raw.match(/\S+/g) || []).length;
    if (wordCount < 8) {
      notes.push('Very little text was pasted. The result may be incomplete.');
    }
    if (!parts.hasHeaders) {
      notes.push('No email headers were pasted, so the sender checks (Reply-To, SPF, DKIM, DMARC) were skipped. Pasting the full headers gives a more complete picture.');
    }
    if (ctx.links.length === 0) {
      notes.push('No links were found in the text.');
    }

    return {
      score: score,
      rawTotal: total,
      band: band,
      findings: findings,
      reassurance: reassurance,
      links: ctx.links.map(function (l) {
        var flags = [];
        if (l.isIp) { flags.push('Raw IP address'); }
        if (l.userinfo) { flags.push('Fake "@" trick'); }
        if (l.shortener) { flags.push('Shortened link'); }
        if (l.badTld) { flags.push('Scam-associated ending'); }
        if (l.lookalikeBrands.length) { flags.push('Imitates ' + l.lookalikeBrands.join(', ')); }
        if (l.http) { flags.push('Not encrypted (http)'); }
        if (l.punycode) { flags.push('Look-alike characters'); }
        if (l.tooManyParts) { flags.push('Complex domain'); }
        return { host: l.host, raw: l.raw, shown: l.shown, source: l.source, flags: flags };
      }),
      attachments: ctx.attachments.map(function (a) { return a.name; }),
      headerSummary: parts.hasHeaders ? {
        from: ctx.from ? ctx.from.address : '(not found)',
        replyTo: ctx.replyTo ? ctx.replyTo.address : '(not present)',
        returnPath: ctx.returnPath ? ctx.returnPath.address : '(not present)',
        spf: ctx.auth.spf || '(not found)',
        dkim: ctx.auth.dkim || '(not found)',
        dmarc: ctx.auth.dmarc || '(not found)'
      } : null,
      notes: notes,
      recommendations: buildRecommendations(band, findings.map(function (f) { return f.id; }))
    };
  }

  // Plain-English catalogue of every rule, used to show the scoring table on the page.
  function ruleCatalogue() {
    return RULES.map(function (r) {
      return { id: r.id, title: r.title, points: r.points, description: r.description };
    });
  }

  var api = {
    analyseEmail: analyseEmail,
    ruleCatalogue: ruleCatalogue,
    bands: { high: 60, suspicious: 25 }
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = api;
  } else {
    window.PhishingAnalyser = api;
  }
})();
