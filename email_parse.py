"""Email structure that plain text loses: real link targets and the mail server's SPF/DKIM/DMARC verdict.

Everything here works on strings only. No link is fetched, no DNS lookup is made.
"""
import re
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser

_BLOCK = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "table", "section"}


class _Html(HTMLParser):
    """Collects visible text plus every <a href> with the text the reader actually sees for it."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.text, self.links = [], []
        self._skip = 0           # inside <script>/<style>
        self._a = None           # link currently open: {"href", "text"}

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("script", "style"):
            self._skip += 1
        elif tag in _BLOCK:
            self.text.append("\n")
        if tag == "a" and a.get("href"):
            self._a = {"href": a["href"].strip(), "text": ""}
        elif tag == "img" and self._a is not None and a.get("alt"):
            self._a["text"] += " " + a["alt"]          # image buttons: the alt text is what "shows"

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self._skip = max(0, self._skip - 1)
        elif tag == "a" and self._a is not None:
            self._a["text"] = re.sub(r"\s+", " ", self._a["text"]).strip()
            self.links.append(self._a)
            self._a = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text.append(data)
        if self._a is not None:
            self._a["text"] += data


def html_to_text_and_links(html: str):
    """Return (visible_text, [{"text": shown text, "href": real target}, ...])."""
    p = _Html()
    p.feed(html or "")
    p.close()
    text = re.sub(r"[ \t\r\f\v]+", " ", "".join(p.text))
    text = re.sub(r"\n\s*\n+", "\n", text).strip()
    return text, p.links


_AUTH = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)


def parse_auth_results(header: str) -> dict:
    """Pull spf/dkim/dmarc verdicts out of an Authentication-Results header.
    Returns e.g. {"spf": "pass", "dkim": "fail", "dmarc": "fail"}; missing methods are omitted.
    When a method appears more than once (several DKIM signatures), a 'pass' wins."""
    out = {}
    for method, result in _AUTH.findall(header or ""):
        m, r = method.lower(), result.lower()
        if out.get(m) != "pass":
            out[m] = r
    return out


def parse_eml(raw: bytes) -> dict:
    msg = BytesParser(policy=policy.default).parsebytes(raw)
    text, links = "", []
    html_part = msg.get_body(preferencelist=("html",))
    plain_part = msg.get_body(preferencelist=("plain",))
    if html_part is not None:
        text, links = html_to_text_and_links(html_part.get_content())
    if plain_part is not None and not text:
        text = plain_part.get_content()
    # Headers are prepended in transit, so the first Authentication-Results is the one written by
    # the user's own mail server. Lower ones could have been written by the sender and are ignored.
    auth_hdr = (msg.get_all("Authentication-Results") or [""])[0]
    auth = parse_auth_results(str(auth_hdr))
    if "spf" not in auth:
        spf = str(msg.get("Received-SPF", "")).split(" ", 1)[0].lower()
        if spf:
            auth["spf"] = spf
    return {"sender": str(msg.get("From", "")), "subject": str(msg.get("Subject", "")),
            "reply_to": str(msg.get("Reply-To", "")), "text": re.sub(r"\s+\n", "\n", text).strip()[:5000],
            "links": links[:50], "auth": auth}
