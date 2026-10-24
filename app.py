"""PhishGuard web UI.   python app.py   ->  http://127.0.0.1:5000

Privacy / safety design
  * Messages are analysed in memory and never stored or logged.
  * Links are analysed as text only. They are never fetched, resolved or opened, and are
    displayed "defanged" (hxxp://example[.]com) and non-clickable.
"""
import re
from email import policy
from email.parser import BytesParser
from html import unescape

from flask import Flask, jsonify, render_template_string, request

import data_gen
from model import PhishModel

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
MODEL = PhishModel("hybrid").fit(data_gen.load())

SAMPLES = {
    "Phishing: account suspension": {
        "sender": "VIT IT Support <support@vit-helpdesk.xyz>", "subject": "Account suspension notice",
        "text": "Dear Student, your VIT account will be suspended within 24 hours unless you verify your password. Click http://vit-verify.top/login now."},
    "Phishing: polite, no urgency": {
        "sender": "IT Desk <itdesk@vit-mail.online>", "subject": "",
        "text": "Hi, this is Ramesh from the VIT IT desk. We are migrating mailboxes this weekend. Kindly sign in at your earliest convenience so your mail is carried over: https://vit-mailmigration.online/signin"},
    "Phishing: UPI / no link": {
        "sender": "+91 9123456780", "subject": "",
        "text": "Quick favour: I'm stuck at the airport and my card is blocked. Could you do a UPI transfer of 5000 to me? I'll return it tonight. Sent from Dr. Kumar's number"},
    "Legit: urgent exam notice": {
        "sender": "COE <coe@vit.ac.in>", "subject": "Exam rescheduled",
        "text": "URGENT: Exam on Machine Learning rescheduled to tomorrow 9 AM due to weather. Please check https://vtop.vit.ac.in."},
    "Legit: genuine OTP": {
        "sender": "", "subject": "",
        "text": "OTP 482913 for VTOP login. Never share this OTP with anyone, including VIT staff."},
}

ADVICE = {
    "do_not": ["Do not click links, open attachments, scan QR codes or call numbers in the message.",
               "Do not reply, and never send a password, OTP, PIN or card details to anyone by message or call.",
               "Do not forward the message to friends 'as a warning' - report it instead."],
    "if_clicked": ["If you typed a password: open the real portal by typing its address yourself, change the password now, and sign out of all devices.",
                   "If you shared card/bank/UPI details: call your bank immediately and report on 1930 (National Cyber Crime Helpline).",
                   "Tell your campus IT helpdesk what happened - speed matters, and you will not be blamed."],
    "report": ["Take a screenshot (with the sender and time visible) before deleting.",
               "Report to your campus IT / cyber-security cell using the official contact on the college website.",
               "Email: use 'Report phishing' in your mail app. WhatsApp/SMS: block and report the sender.",
               "India: file at cybercrime.gov.in (or call 1930). Suspicious calls/SMS can also be reported via Sanchar Saathi (Chakshu)."],
    "verify": ["Check the sender address and the full link domain - the real college domains end in vit.ac.in / vitap.ac.in etc.",
               "Verify through a second channel: type the portal address yourself, or ask the department in person.",
               "Genuine staff never ask for your password or OTP."],
}


def parse_eml(raw: bytes):
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    body = ""
    part = msg.get_body(preferencelist=("plain", "html"))
    if part:
        body = part.get_content()
        if part.get_content_type() == "text/html":
            body = unescape(re.sub(r"<[^>]+>", " ", body))
    return {"sender": str(msg.get("From", "")), "subject": str(msg.get("Subject", "")),
            "reply_to": str(msg.get("Reply-To", "")), "text": re.sub(r"\s+\n", "\n", body).strip()[:5000]}


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhishGuard - message checker</title>
<style>
:root{--bg:#f6f7f9;--card:#fff;--ink:#16202b;--mute:#5d6b7a;--line:#e1e5ea;--acc:#1f5fbf;--hi:#c0392b;--hib:#fdecea;--med:#a66a00;--medb:#fff4de;--lo:#1e7a46;--lob:#e6f5ec}
@media (prefers-color-scheme:dark){:root{--bg:#10151b;--card:#18202a;--ink:#e8edf2;--mute:#9fb0c1;--line:#2a3542;--acc:#6aa5ff;--hi:#ff8a7a;--hib:#3a1d1a;--med:#f2b24c;--medb:#3a2c10;--lo:#6fd69a;--lob:#12301f}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1080px;margin:0 auto;padding:20px 16px 48px}
h1{font-size:1.5rem;margin:0 0 4px}.sub{color:var(--mute);margin:0 0 18px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:820px){.grid{grid-template-columns:1fr}}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px}
label{display:block;font-size:.85rem;color:var(--mute);margin:10px 0 4px}
textarea,input[type=text],select{width:100%;padding:9px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--ink);font:inherit}
textarea{min-height:150px;resize:vertical}
button{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:10px 18px;font:inherit;font-weight:600;cursor:pointer;margin-top:14px}
button.ghost{background:transparent;color:var(--acc);border:1px solid var(--line);font-weight:500}
.badge{display:inline-block;padding:6px 14px;border-radius:999px;font-weight:700;letter-spacing:.04em}
.HIGH{background:var(--hib);color:var(--hi)}.MEDIUM{background:var(--medb);color:var(--med)}.LOW{background:var(--lob);color:var(--lo)}
.bar{height:8px;background:var(--line);border-radius:6px;overflow:hidden;margin:10px 0 2px}.bar>i{display:block;height:100%}
.sig{border-top:1px solid var(--line);padding:10px 0}.sig:first-of-type{border-top:0}.sig>b{display:block}.sig span{color:var(--mute);font-size:.92rem}
code{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:1px 6px;word-break:break-all;font-size:.88rem}
h2{font-size:1.02rem;margin:0 0 8px}ul{margin:6px 0 0;padding-left:20px}li{margin:4px 0}
.note{font-size:.85rem;color:var(--mute)}.safe b{color:var(--lo)}
</style></head><body><div class="wrap">
<h1>PhishGuard</h1><p class="sub">Paste a suspicious email, SMS or WhatsApp message. Nothing is stored and no link is ever opened.</p>
<div class="grid">
<form class="card" method="post" enctype="multipart/form-data" action="/">
  <label for="sample">Try an example</label>
  <select id="sample" onchange="loadSample(this.value)"><option value="">- choose -</option>{% for k in samples %}<option>{{k}}</option>{% endfor %}</select>
  <label for="text">Message text</label><textarea id="text" name="text" required>{{ form.text }}</textarea>
  <label for="sender">Sender (email address, phone number or name - optional)</label><input type="text" id="sender" name="sender" value="{{ form.sender }}">
  <label for="subject">Subject (optional)</label><input type="text" id="subject" name="subject" value="{{ form.subject }}">
  <label for="reply_to">Reply-To address (optional)</label><input type="text" id="reply_to" name="reply_to" value="{{ form.reply_to }}">
  <label for="eml">...or upload a saved email (.eml)</label><input type="file" id="eml" name="eml" accept=".eml">
  <button type="submit">Analyse message</button>
</form>
<div>
{% if r %}
<div class="card">
  <span class="badge {{ r.label }}">{{ r.label }} RISK</span>
  <span class="note"> &nbsp;phishing probability {{ (r.probability*100)|round|int }}%</span>
  <div class="bar"><i style="width:{{ (r.probability*100)|round|int }}%;background:{{ {'HIGH':'var(--hi)','MEDIUM':'var(--med)','LOW':'var(--lo)'}[r.label] }}"></i></div>
  {% if r.floor_applied %}<p class="note">Raised to MEDIUM because a look-alike link or sender was detected, even though the text looks calm.</p>{% endif %}
  <p class="note">This is a prompt to review, not a verdict. When unsure, verify through the official portal.</p>
</div>
<div class="card" style="margin-top:16px"><h2>Why - strongest signals</h2>
  {% for s in r.top_signals %}<div class="sig"><b>{{ s.title }}</b><span>{{ s.detail }}</span></div>
  {% else %}<p class="note">No strong warning signals found.</p>{% endfor %}
  {% if r.phrases %}<div class="sig"><b>Phrases the text model weighed</b><span>{% for p in r.phrases %}<code>{{ p[0] }}</code> {% endfor %}</span></div>{% endif %}
  {% if r.reassuring_signals %}<div class="sig safe"><b>Reassuring signals</b>{% for s in r.reassuring_signals %}<span>- {{ s.title }}: {{ s.detail }}<br></span>{% endfor %}</div>{% endif %}
</div>
{% if r.links %}<div class="card" style="margin-top:16px"><h2>Links found (defanged, not clickable, never visited)</h2>
  {% for l in r.links %}<div class="sig"><code>{{ l.display }}</code><br><span>actual domain: <b>{{ l.registered }}</b> - {{ 'official college domain' if l.official else 'NOT an official college domain' }} - link risk {{ (l.risk*100)|round|int }}%</span></div>{% endfor %}</div>{% endif %}
{% else %}
<div class="card"><h2>How it works</h2><ul><li>Reads urgency, threats, requests for passwords/OTPs, money and attachment lures.</li><li>Inspects link domains as text: look-alikes, shorteners, IP addresses, odd endings.</li><li>Compares sender name and domain when available (email) - phone/WhatsApp senders have fewer checks.</li><li>A hybrid text-and-signal model gives the risk label; the strongest reasons are listed.</li></ul></div>
{% endif %}
</div></div>
<div class="grid" style="margin-top:16px">
 <div class="card"><h2>{{ 'Before you do anything' }}</h2><ul>{% for a in advice.do_not %}<li>{{a}}</li>{% endfor %}</ul><h2 style="margin-top:14px">Check it safely</h2><ul>{% for a in advice.verify %}<li>{{a}}</li>{% endfor %}</ul></div>
 <div class="card"><h2>If you already clicked or replied</h2><ul>{% for a in advice.if_clicked %}<li>{{a}}</li>{% endfor %}</ul><h2 style="margin-top:14px">How to report</h2><ul>{% for a in advice.report %}<li>{{a}}</li>{% endfor %}</ul></div>
</div></div>
<script>
const S={{ samples|tojson }};
function loadSample(k){if(!S[k])return;for(const f of ['text','sender','subject']){document.getElementById(f).value=S[k][f]||'';}}
</script></body></html>"""


@app.route("/", methods=["GET", "POST"])
def index():
    form = {"text": "", "sender": "", "subject": "", "reply_to": ""}
    result = None
    if request.method == "POST":
        f = request.files.get("eml")
        if f and f.filename:
            form.update(parse_eml(f.read()))
        else:
            for k in form:
                form[k] = request.form.get(k, "")[:5000]
        if form["text"].strip():
            result = MODEL.explain(form["text"], form["sender"], form["subject"], form["reply_to"])
    return render_template_string(PAGE, form=form, r=result, samples=SAMPLES, advice=ADVICE)


@app.route("/api/analyse", methods=["POST"])
def api():
    d = request.get_json(force=True, silent=True) or {}
    r = MODEL.explain(d.get("text", ""), d.get("sender", ""), d.get("subject", ""), d.get("reply_to", ""))
    r.pop("features", None)
    return jsonify(r)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
