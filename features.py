"""Interpretable phishing signals.

Everything here works on *strings only*. No URL is ever fetched or opened.
`analyse_signals()` returns a vector of numeric features (for the model) plus a
list of human-readable signals (for the explanation shown to the user).
"""
import re
import unicodedata
from urllib.parse import urlparse

import config as C

# --------------------------------------------------------------------------- text normalisation
_ZW = dict.fromkeys(map(ord, "​‌‍⁠﻿"), None)
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_SPACED = re.compile(r"\b(?:[A-Za-z][ .\-_]){3,}[A-Za-z]\b")      # "p a s s w o r d"


def normalise_text(text: str) -> str:
    """De-obfuscate common evasion tricks (zero-width chars, homoglyphs, spaced letters, leetspeak)."""
    t = unicodedata.normalize("NFKC", text).translate(_ZW)
    t = _SPACED.sub(lambda m: re.sub(r"[ .\-_]", "", m.group(0)), t)
    # leetspeak only inside words that mix letters and digits/symbols (avoid wrecking real numbers/URLs)
    def _unleet(m):
        w = m.group(0)
        return w.translate(_LEET) if re.search(r"[A-Za-z]", w) and re.search(r"[0-9@$]", w) else w
    parts = re.split(r"(https?://\S+|www\.\S+)", t)               # leave URLs untouched
    parts = [p if i % 2 else re.sub(r"\b[\w@$]{4,}\b", _unleet, p) for i, p in enumerate(parts)]
    return "".join(parts)


# --------------------------------------------------------------------------- lexicons
URGENCY = re.compile(
    r"\b(urgent(ly)?|immediate(ly)?|right now|asap|act now|at once|without delay|hurry|"
    r"within \d+ ?(hours?|hrs?|minutes?|mins?|days?)|in \d+ ?(hours?|hrs?|minutes?|mins?)|"
    r"expires? (today|soon|in)|about to expire|last (chance|warning|call)|final (notice|warning|call)|"
    r"before midnight|today only|limited (time|seats)|by \d{1,2} ?(am|pm)|tonight|"
    r"turant|abhi|jaldi|foran)\b", re.I)
THREAT = re.compile(
    r"(suspen\w+|deactivat\w+|\bblock(ed)?\b|terminat\w+|frozen|\bfreeze\b|disabled?|permanent(ly)?|"
    r"legal action|disciplinary|penalt\w+|lose (access|your)|will be (closed|deleted|removed|disconnected)|"
    r"band ho|locked|hold on your)", re.I)
CRED_TERMS = re.compile(
    r"(password|passcode|\botp\b|one[- ]time (password|code)|\bpin\b|cvv|login (details|credentials|id)|"
    r"credentials|username|registration (number|no)|reg\.? ?no|date of birth|\bdob\b|aadhaa?r|\bpan\b|"
    r"bank details|account (number|no)|a/c no|card (number|details)|net ?banking|security (code|answer)|"
    r"6[- ]digit code|passbook)", re.I)
REQUEST_VERBS = re.compile(
    r"\b(verify|confirm|enter|share|send|provide|submit|update|re-?authenticate|sign ?in|log ?in|"
    r"re-?login|fill|reply|bhejo|daalo|dalke|dalo)\b", re.I)
SAFE_WARNING = re.compile(
    r"((do not|don'?t|never|dont) (share|disclose|give|tell|reveal)|never ask|will never ask|"
    r"not share (it|this)|no action (is )?(needed|required)|ignore (this|the) (message|email|sms) if|"
    r"ignore if already|if (this )?(wasn'?t|was not) you)", re.I)
LURE = re.compile(
    r"(refund|scholarship|congratulations|you (have )?(won|been selected)|prize|lottery|reward|cashback|"
    r"free (gift|recharge|wi-?fi)|stipend|earn (rs|₹)|per day|work from home|gift cards?|"
    r"processing fee|registration fee|deposit|claim|shortlisted)", re.I)
AUTHORITY = re.compile(
    r"\b(registrar|dean|hod|proctor|exam cell|controller of examinations|it (services|support|helpdesk|desk)|"
    r"vice chancellor|administrator|security team|helpdesk)\b", re.I)
ASK_REPLY = re.compile(
    r"\b(reply|respond|send|forward|share) (with |me |us |back )?(your |the )?(\w+ ){0,3}"
    r"(password|otp|pin|code|codes|details|credentials)\b", re.I)
PAYMENT = re.compile(
    r"(\bupi\b|gpay|paytm|phonepe|gift cards?|account below|a/c no|transfer of|courier charges|redelivery|"
    r"processing fee|registration fee|refundable deposit|confirmation amount|advance (fee|payment))", re.I)
ATTACH = re.compile(r"(enable (macros|content|editing)|open (the )?attach\w+|open (the )?(file|document) (attached|below)|"
                    r"see (the )?attached (invoice|document)|\.(exe|apk|scr|zip|docm)\b)", re.I)
BRAND_IN_TEXT = re.compile(r"\b(vit|vtop|vellore institute)\b", re.I)
# QR codes hide the link from every text check; scanning one to *receive* money or to log in is a scam pattern
QR = re.compile(r"\b(qr(?: ?code)?|scan (?:the |this )?(?:code|barcode))\b", re.I)
QR_ACTION = re.compile(r"(receive|claim|refund|cashback|reward|prize|\bwon\b|log ?in|sign ?in|verify|password|credentials|"
                       r"\bpin\b|unlock|re-?authenticate|kyc)", re.I)
# call-back scams: no link at all, the attack moves to a phone call
MOBILE = re.compile(r"(?<!\d)(?:\+?91[\s-]?)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")
LANDLINE = re.compile(r"(?<!\d)(?:0\d{2,4}[\s-]?\d{6,8}|1800[\s-]?\d{3}[\s-]?\d{4})(?!\d)")
CALL_VERB = re.compile(r"\b(call|ring|dial|contact|whatsapp|helpline|customer care)\b", re.I)
URL_RE = re.compile(
    r"(?<![@\w.\-])((?:https?://|www\.)[^\s<>\"')]+|"
    r"(?:[a-z0-9\-]+\.)+(?:com|in|net|org|xyz|top|cc|icu|click|online|site|live|link|info|biz|co|ly|gle|"
    r"tk|ml|ga|cf|gq|buzz|help|ac\.in|edu\.in|edu)(?:/[^\s<>\"')]*)?)", re.I)


# --------------------------------------------------------------------------- helpers
def _registered_domain(host: str) -> str:
    labels = host.lower().strip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in C.MULTI_PART_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.lower()


def _norm_label(s: str) -> str:
    return s.lower().translate(str.maketrans("10358", "ioesb")).replace("-", "").replace("rn", "m")


def _lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def is_official(host: str) -> bool:
    return _registered_domain(host) in C.OFFICIAL_DOMAINS


def _impersonates_brand(host: str) -> bool:
    """Host imitates the institution without being official (v1t.ac.in, vit-login.xyz, ...)."""
    if is_official(host):
        return False
    reg = _registered_domain(host)
    label = reg.split(".")[0]
    n = _norm_label(label)
    if any(b in n for b in C.BRAND_TOKENS):
        return True
    return len(n) <= 5 and min(_lev(n, b) for b in C.BRAND_TOKENS) <= 1


def _subdomain_trick(host: str) -> bool:
    """official-looking name used as a subdomain of someone else's domain."""
    h = host.lower()
    return (not is_official(h)) and any(o in h or o.replace(".", "-") in h for o in C.OFFICIAL_DOMAINS)


def analyse_url(raw: str) -> dict:
    url = raw.rstrip(".,;:!?)")
    p = urlparse(url if "://" in url else "http://" + url)
    host = (p.hostname or "").lower()
    reg = _registered_domain(host)
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    flags = {}
    flags["ip_host"] = bool(re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", host))
    flags["shortener"] = reg in C.SHORTENERS
    flags["form_host"] = host in C.FORM_HOSTS or reg in C.FORM_HOSTS
    flags["official"] = is_official(host)
    flags["brand_lookalike"] = _impersonates_brand(host)
    flags["subdomain_trick"] = _subdomain_trick(host)
    flags["bad_tld"] = tld in C.SUSPICIOUS_TLDS and not flags["official"]
    flags["hyphen_keyword"] = bool(re.search(
        r"-(login|verify|secure|portal|update|account|support|helpdesk|student|alert|pay|unlock)|"
        r"(login|verify|secure|update|support)-", host)) and not flags["official"]
    flags["plain_http"] = p.scheme == "http" and not flags["official"]
    flags["punycode"] = "xn--" in host
    flags["userinfo"] = "@" in (p.netloc or "")
    weights = {"ip_host": .9, "shortener": .6, "brand_lookalike": .95, "subdomain_trick": 1.0,
               "bad_tld": .5, "hyphen_keyword": .4, "plain_http": .2, "punycode": .8,
               "userinfo": .8, "form_host": .25}
    risk = 1.0
    for k, w in weights.items():
        if flags.get(k):
            risk *= (1 - w)
    flags["risk"] = round(1 - risk, 3)
    return {"url": url, "host": host, "registered": reg, "flags": flags}


def defang(url: str) -> str:
    """Make a link non-clickable for display: https://a.b -> hxxps://a[.]b"""
    u = re.sub(r"^http", "hxxp", url, flags=re.I)
    return re.sub(r"\.", "[.]", u)


def parse_sender(sender: str) -> dict:
    s = (sender or "").strip()
    out = {"raw": s, "present": bool(s), "email": "", "domain": "", "display": "", "phone": False}
    if not s:
        return out
    m = re.search(r"([\w.+\-]+)@([\w\-]+(?:\.[\w\-]+)+)", s)
    if m:
        out["email"] = m.group(0).lower()
        out["domain"] = m.group(2).lower()
        out["display"] = s[:m.start()].strip(' <"\'')
    elif re.fullmatch(r"\+?[\d\s\-]{10,15}", s):
        out["phone"] = True
    else:
        out["display"] = s
    return out


# --------------------------------------------------------------------------- main entry
FEATURE_NAMES = [
    "urgency", "threat", "cred_request", "cred_safe", "lure", "authority", "reply_with_secret",
    "payment_request", "attachment_lure", "qr_lure", "callback_lure",
    "no_links", "link_risk_max", "link_lookalike", "link_subdomain_trick", "link_shortener",
    "link_ip", "link_bad_tld", "link_all_official", "link_form_host",
    "sender_present", "sender_official", "sender_freemail", "sender_mismatch", "sender_lookalike",
    "reply_to_differs", "body_claims_brand_nonofficial_sender", "caps_ratio", "exclaim",
]


# Email-structure signals. The training data is plain text, so these have no learned weight;
# model.explain() turns them into a minimum risk label instead.
RULE_FEATURES = ["link_text_mismatch", "link_text_fakes_official", "auth_fail", "auth_spoofs_official", "auth_pass"]


def _call_number(full: str) -> float:
    """1.0 = asks you to call a mobile number, 0.4 = a landline/toll-free number (what real offices use)."""
    best = 0.0
    for rx, val in ((MOBILE, 1.0), (LANDLINE, 0.4)):
        for m in rx.finditer(full):
            if CALL_VERB.search(full[max(0, m.start() - 60): m.end() + 15]):
                best = max(best, val)
    return best


def analyse_html_links(html_links, sig_add):
    """Compare what each link *shows* with where it really *goes*. Returns (features, analysed hrefs)."""
    f = {"link_text_mismatch": 0.0, "link_text_fakes_official": 0.0}
    hrefs = []
    for ln in html_links or []:
        href, shown = (ln.get("href") or "").strip(), (ln.get("text") or "").strip()
        if not re.match(r"(https?:)?//|www\.", href, re.I):
            continue                                  # mailto:, tel:, #anchors carry no web destination
        target = analyse_url(href.lstrip("/") if href.startswith("//") else href)
        if not target["host"]:
            continue
        hrefs.append(target)
        dest = defang(target["url"])
        m = URL_RE.search(shown)
        if m:
            shown_url = analyse_url(m.group(1))
            if shown_url["registered"] and shown_url["registered"] != target["registered"]:
                fakes = shown_url["flags"]["official"] and not target["flags"]["official"]
                f["link_text_mismatch"] = 1.0
                f["link_text_fakes_official"] = max(f["link_text_fakes_official"], float(fakes))
                sig_add("link_text_mismatch", 1.0 if fakes else 0.9, "Link text shows one address but goes to another",
                        f"The link shows '{defang(shown_url['url'])}' but really leads to {dest} "
                        f"({target['registered']}).")
        elif BRAND_IN_TEXT.search(shown) and not target["flags"]["official"]:
            f["link_text_mismatch"] = max(f["link_text_mismatch"], 0.7)
            sig_add("link_text_mismatch", 0.7, "Button names the college but goes elsewhere",
                    f"The button '{shown[:60]}' leads to {dest} ({target['registered']}), not an official college domain.")
    return f, hrefs


def analyse_auth(auth, sender_domain, sig_add):
    """SPF/DKIM/DMARC verdicts written by the receiving mail server (from the .eml headers)."""
    f = {"auth_fail": 0.0, "auth_spoofs_official": 0.0, "auth_pass": 0.0}
    if not auth:
        return f
    bad = {"fail", "softfail", "permerror"}
    spf, dkim, dmarc = auth.get("spf", ""), auth.get("dkim", ""), auth.get("dmarc", "")
    official = bool(sender_domain) and _registered_domain(sender_domain) in C.OFFICIAL_DOMAINS
    failed = dmarc in bad or (spf in bad and dkim in bad | {"none", ""})
    summary = ", ".join(f"{k.upper()}={v}" for k, v in auth.items())
    if failed:
        f["auth_fail"] = 1.0
        f["auth_spoofs_official"] = float(official)
        if official:
            sig_add("auth_spoofs_official", 1.0, "Forged college sender address",
                    f"The mail server could not verify that this really came from {sender_domain} ({summary}). "
                    "Someone is using the college's address without permission.")
        else:
            sig_add("auth_fail", 0.8, "Sender failed email authentication",
                    f"Your mail server could not confirm the sender is who it claims to be ({summary}).")
    elif dmarc == "pass" or (spf == "pass" and dkim == "pass"):
        f["auth_pass"] = 1.0
        sig_add("auth_pass", 0.5 if official else 0.3, "Sender passed email authentication",
                f"{summary}. This confirms the sending domain{' is official' if official else ''}, not that the content is safe "
                "(a hacked real account also passes).", kind="safe")
    return f


def analyse_signals(text: str, sender: str = "", subject: str = "", reply_to: str = "",
                    html_links=None, auth=None):
    """Return (feature_dict, signals, urls) where signals is a list of dicts:
    {id, strength(0..1), title, detail, kind: 'risk'|'safe'}.
    html_links: [{"text", "href"}] from an HTML email; auth: {"spf","dkim","dmarc"} verdicts. Both optional."""
    full = f"{subject}\n{text}".strip()
    full = normalise_text(full)
    f = dict.fromkeys(FEATURE_NAMES + RULE_FEATURES, 0.0)
    sig = []

    def add(id_, strength, title, detail, kind="risk"):
        sig.append({"id": id_, "strength": round(float(strength), 3), "title": title,
                    "detail": detail, "kind": kind})

    # ---- language signals
    u = [m.group(0) for m in URGENCY.finditer(full)]
    f["urgency"] = min(1.0, len(u) / 2)
    if u:
        add("urgency", f["urgency"], "Pressure / urgency language",
            "Rushes you to act: " + ", ".join(sorted({x.lower() for x in u})[:4]))
    t = [m.group(0) for m in THREAT.finditer(full)]
    f["threat"] = min(1.0, len(t) / 2)
    if t:
        add("threat", f["threat"], "Threat of losing access / penalty",
            "Threatening words: " + ", ".join(sorted({x.lower() for x in t})[:4]))

    creds = [m.group(0) for m in CRED_TERMS.finditer(full)]
    safe = bool(SAFE_WARNING.search(full))
    f["cred_safe"] = float(safe)
    if creds:
        near_request = False
        for m in CRED_TERMS.finditer(full):
            ctx = full[max(0, m.start() - 70): m.end() + 70]
            if REQUEST_VERBS.search(ctx):
                near_request = True
                break
        base = 1.0 if near_request else 0.3
        f["cred_request"] = base * (0.25 if safe else 1.0)
        if f["cred_request"] >= 0.25 and not safe:
            add("cred_request", f["cred_request"], "Asks for sensitive information",
                "Mentions " + ", ".join(sorted({x.lower() for x in creds})[:4]) +
                (" together with a request to submit it" if near_request else ""))
    if safe:
        add("cred_safe", 0.5, "Contains a 'do not share / no action needed' warning",
            "Genuine security messages usually warn you not to share codes.", kind="safe")
    ask = [m for m in ASK_REPLY.finditer(full)
           if not re.search(r"(not|never|n't|dont)\s*$", full[max(0, m.start() - 12):m.start()].lower())]
    if ask:
        f["reply_with_secret"] = 1.0
        add("reply_with_secret", 1.0, "Asks you to reply/send secrets directly",
            "Legitimate IT teams never ask you to send passwords or OTPs by message.")

    lure = [m.group(0) for m in LURE.finditer(full)]
    f["lure"] = min(1.0, len(lure) / 2)
    if lure:
        add("lure", f["lure"], "Reward / money / job lure", "Bait words: " + ", ".join(sorted({x.lower() for x in lure})[:4]))
    pay = [m.group(0) for m in PAYMENT.finditer(full)]
    if pay:
        f["payment_request"] = min(1.0, len(pay) / 2 + 0.3)
        add("payment_request", f["payment_request"], "Asks you to pay or transfer money",
            "Payment wording: " + ", ".join(sorted({x.lower() for x in pay})[:3]) + ". Official fees are paid on the official portal, never to a person or UPI number.")
    if ATTACH.search(full):
        f["attachment_lure"] = 1.0
        add("attachment_lure", 0.9, "Pushes you to open an attachment / enable macros",
            "Unexpected attachments and 'enable macros/content' prompts are a malware route.")
    qr = [m for m in QR.finditer(full)]
    if qr:
        acts = {a.group(0).lower() for m in qr
                for a in QR_ACTION.finditer(full[max(0, m.start() - 80): m.end() + 80])}
        f["qr_lure"] = 1.0 if acts else 0.3
        if acts:
            add("qr_lure", 0.9, "Asks you to scan a QR code to claim money or log in",
                f"QR code together with: {', '.join(sorted(acts)[:3])}. A QR code hides its link from you, and you never "
                "need to scan a code or enter a UPI PIN to *receive* money.")
    f["callback_lure"] = _call_number(full)
    if f["callback_lure"] >= 1.0:
        pressure = f["urgency"] or f["threat"] or f["lure"]
        add("callback_lure", 0.85 if pressure else 0.5, "Asks you to call a mobile number",
            "Call-back scams have no link: they move you to a phone call where they can pressure you. "
            "Call only the number listed on the official website or card.")
    if AUTHORITY.search(full):
        f["authority"] = 1.0
        add("authority", 0.4, "Invokes an authority figure/office",
            "Impersonating the registrar, dean or IT desk is a common pretext (weak signal alone).")

    letters = [c for c in full if c.isalpha()]
    if letters:
        f["caps_ratio"] = min(1.0, (sum(c.isupper() for c in letters) / len(letters)) * 2)
    f["exclaim"] = min(1.0, full.count("!") / 3)

    # ---- links (string analysis only; never fetched)
    urls = [analyse_url(m.group(1)) for m in URL_RE.finditer(full)]
    hf, hrefs = analyse_html_links(html_links, add)
    f.update(hf)
    urls += hrefs                     # real destinations of HTML links count like any other link
    seen, uniq = set(), []
    for x in urls:
        if x["url"] not in seen:
            seen.add(x["url"]); uniq.append(x)
    urls = uniq
    f["no_links"] = float(len(urls) == 0)
    if urls:
        f["link_risk_max"] = max(x["flags"]["risk"] for x in urls)
        f["link_lookalike"] = float(any(x["flags"]["brand_lookalike"] for x in urls))
        f["link_subdomain_trick"] = float(any(x["flags"]["subdomain_trick"] for x in urls))
        f["link_shortener"] = float(any(x["flags"]["shortener"] for x in urls))
        f["link_ip"] = float(any(x["flags"]["ip_host"] for x in urls))
        f["link_bad_tld"] = float(any(x["flags"]["bad_tld"] for x in urls))
        f["link_form_host"] = float(any(x["flags"]["form_host"] for x in urls))
        f["link_all_official"] = float(all(x["flags"]["official"] for x in urls))
        for x in urls:
            fl = x["flags"]
            d = defang(x["url"])
            if fl["subdomain_trick"]:
                add("link_subdomain_trick", 1.0, "Official name hidden inside a fake domain",
                    f"{d} uses the college name as a subdomain of {x['registered']}, which is not official.")
            elif fl["brand_lookalike"]:
                add("link_lookalike", 0.95, "Look-alike of the official domain",
                    f"{d} imitates the college name, but its actual domain is {x['registered']} - not an official college domain.")
            if fl["ip_host"]:
                add("link_ip", 0.9, "Link points to a raw IP address", f"{d} - real portals use domain names.")
            if fl["shortener"]:
                add("link_shortener", 0.6, "Shortened link hides the destination", f"{d} - you cannot see where it leads.")
            if fl["bad_tld"] and not fl["brand_lookalike"]:
                add("link_bad_tld", 0.5, "Unusual domain ending", f"{d} uses a '.{x['host'].rsplit('.',1)[-1]}' domain often used in scams.")
            if fl["hyphen_keyword"] and not fl["brand_lookalike"]:
                add("link_hyphen", 0.4, "Domain stuffed with login/verify keywords", f"{d}")
            if fl["plain_http"]:
                add("link_http", 0.2, "Link is not HTTPS", f"{d}")
            if fl["form_host"]:
                add("link_form", 0.25, "Link goes to a generic form host",
                    f"{d} - fine for surveys, but never type your password into a form.")
            if fl["official"]:
                add("link_official", 0.5, "Link goes to an official college domain", f"{d} ({x['registered']})", kind="safe")
        if not any(s["id"].startswith("link") and s["kind"] == "risk" for s in sig):
            pass

    # ---- sender
    sd = parse_sender(sender)
    f["sender_present"] = float(sd["present"])
    claims = bool(re.search(r"\b(vit|vtop|registrar|dean|exam|coe|it (support|services|desk)|helpdesk|"
                            r"placement|admin|alerts?|noreply|hostel|library)\b",
                            (sd["display"] + " " + sd["domain"].split(".")[0]).replace("-", " "), re.I))
    if sd["domain"]:
        reg = _registered_domain(sd["domain"])
        official = reg in C.OFFICIAL_DOMAINS
        f["sender_official"] = float(official)
        f["sender_freemail"] = float(reg in C.FREE_MAIL)
        look = _impersonates_brand(sd["domain"]) or _subdomain_trick(sd["domain"])
        f["sender_lookalike"] = float(look)
        f["sender_mismatch"] = float(claims and not official)
        if look:
            add("sender_lookalike", 1.0, "Sender domain imitates the college",
                f"'{sd['email']}' is not from an official domain ({', '.join(sorted(C.OFFICIAL_DOMAINS)[:3])}...).")
        elif claims and reg in C.FREE_MAIL:
            add("sender_mismatch", 0.85, "Official-sounding name from a free mail account",
                f"Display name '{sd['display']}' but the address is {sd['email']}.")
        elif claims and not official:
            add("sender_mismatch", 0.7, "Sender name does not match sender domain",
                f"'{sd['display'] or sd['email']}' is sent from {sd['domain']}, not an official domain.")
        elif official:
            add("sender_official", 0.4, "Sender address uses an official domain",
                f"{sd['email']} - note: sender addresses can be spoofed, so still check the content.", kind="safe")
        body_brand = bool(BRAND_IN_TEXT.search(full))
        f["body_claims_brand_nonofficial_sender"] = float(body_brand and not official)
    if reply_to:
        rd = parse_sender(reply_to)["domain"]
        if rd and sd["domain"] and _registered_domain(rd) != _registered_domain(sd["domain"]):
            f["reply_to_differs"] = 1.0
            add("reply_to_differs", 0.9, "Reply-To address differs from the sender",
                f"Replies would go to {rd}, not {sd['domain']}.")
    f.update(analyse_auth(auth, sd["domain"], add))

    sig.sort(key=lambda s: (s["kind"] == "safe", -s["strength"]))
    return f, sig, urls


def feature_vector(f: dict):
    return [f[n] for n in FEATURE_NAMES]
