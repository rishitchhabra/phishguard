"""Hybrid phishing detector: TF-IDF text model + interpretable signal features, one logistic regression.

modes:  'ml'     -> TF-IDF only
        'rules'  -> hand-built signals only (still learned weights, fully interpretable)
        'hybrid' -> both (default)
"""
import re
import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

import config as C
import features as F

_URL = re.compile(r"(https?://\S+|www\.\S+|\b(?:[a-z0-9\-]+\.)+(?:com|in|net|org|xyz|top|cc|icu|click|online|site|live|link|ly|gle|ml|help)\S*)", re.I)


_STOP = {"num", "bignum", "your", "you", "to", "the", "is", "of", "and", "a", "in", "for", "on", "be", "or",
         "will", "your", "has", "have", "this", "that", "with", "at", "by", "an", "it", "vit", "we"}


def prep_text(text: str, subject: str = "", normalise: bool = True) -> str:
    t = f"{subject} {text}".strip()
    if normalise:
        t = F.normalise_text(t)
    t = _URL.sub(" urltoken ", t.lower())            # URLs are judged by the rule layer, not memorised
    t = re.sub(r"\d{4,}", " bignum ", t)
    t = re.sub(r"\d+", " num ", t)
    return t


class PhishModel:
    def __init__(self, mode="hybrid", normalise=True, C_reg=3.0, dense_scale=None):
        self.mode, self.normalise, self.C_reg = mode, normalise, C_reg
        self.dense_scale = C.DENSE_SCALE if dense_scale is None else dense_scale
        self.vec = TfidfVectorizer(ngram_range=(1, 2), min_df=2, sublinear_tf=True)
        self.clf = LogisticRegression(C=C_reg, max_iter=2000, class_weight="balanced", random_state=C.SEED)

    # -- feature construction
    def _dense(self, rows):
        out = []
        for r in rows:
            f, _, _ = F.analyse_signals(r["text"], r.get("sender", ""), r.get("subject", ""),
                                        html_links=r.get("links"), auth=r.get("auth")) if self.normalise \
                else self._no_norm(r)
            out.append(F.feature_vector(f))
        return np.array(out) * self.dense_scale

    def _no_norm(self, r):
        # evaluation helper: run signals without de-obfuscation (to measure the benefit of normalisation)
        orig = F.normalise_text
        F.normalise_text = lambda x: x
        try:
            return F.analyse_signals(r["text"], r.get("sender", ""), r.get("subject", ""))
        finally:
            F.normalise_text = orig

    def _X(self, rows, fit=False):
        parts = []
        if self.mode in ("ml", "hybrid"):
            docs = [prep_text(r["text"], r.get("subject", ""), self.normalise) for r in rows]
            parts.append(self.vec.fit_transform(docs) if fit else self.vec.transform(docs))
        if self.mode in ("rules", "hybrid"):
            parts.append(csr_matrix(self._dense(rows)))
        return hstack(parts).tocsr() if len(parts) > 1 else parts[0]

    def fit(self, rows):
        y = [r["label"] for r in rows]
        self.clf.fit(self._X(rows, fit=True), y)
        return self

    def predict_proba(self, rows):
        return self.clf.predict_proba(self._X(rows))[:, 1]

    # -- explanation
    def explain(self, text, sender="", subject="", reply_to="", links=None, auth=None, topn=5):
        row = {"text": text, "sender": sender, "subject": subject, "links": links, "auth": auth}
        feats, signals, urls = F.analyse_signals(text, sender, subject, reply_to, html_links=links, auth=auth)
        p = float(self.predict_proba([row])[0])
        coef = self.clf.coef_[0]
        n_txt = len(self.vec.vocabulary_) if self.mode in ("ml", "hybrid") else 0
        # contribution of each hand-built feature to the log-odds
        contrib = {}
        if self.mode in ("rules", "hybrid"):
            for i, name in enumerate(F.FEATURE_NAMES):
                contrib[name] = coef[n_txt + i] * feats[name] * self.dense_scale
        # strongest phrases from the text model
        phrases = []
        if self.mode in ("ml", "hybrid"):
            x = self.vec.transform([prep_text(text, subject, self.normalise)])
            inv = {v: k for k, v in self.vec.vocabulary_.items()}
            for j, v in zip(x.indices, x.data):
                c = coef[j] * v
                w = inv[j]
                if c > 0.12 and "token" not in w and not set(w.split()) <= _STOP:
                    phrases.append((inv[j], float(c)))
            phrases.sort(key=lambda t: -t[1])
        # hard safety floor: never show 'Low' when a look-alike link/sender is present
        floor, floor_reasons = None, []
        if (feats["link_lookalike"] or feats["link_subdomain_trick"] or feats["sender_lookalike"]
                or feats["reply_to_differs"] or feats["link_ip"]):
            floor = "MEDIUM"; floor_reasons.append("a look-alike link or sender was detected")
        # email-structure rules (no training data for these, see features.RULE_FEATURES)
        if feats["link_text_mismatch"] or feats["auth_fail"]:
            floor = "MEDIUM"
            floor_reasons.append("a link hides its real destination" if feats["link_text_mismatch"]
                                 else "the sender failed email authentication")
        if feats["link_text_fakes_official"] or feats["auth_spoofs_official"]:
            floor = "HIGH"
            floor_reasons.append("an official college address is faked" if feats["auth_spoofs_official"]
                                 else "a link pretends to be an official college address")
        label = risk_label(p, floor)
        risk_sigs = [s for s in signals if s["kind"] == "risk"]
        safe_sigs = [s for s in signals if s["kind"] == "safe"]
        # rank by learned contribution when available, else by signal strength
        id2feat = {"urgency": "urgency", "threat": "threat", "cred_request": "cred_request", "lure": "lure",
                   "authority": "authority", "payment_request": "payment_request", "attachment_lure": "attachment_lure", "reply_with_secret": "reply_with_secret",
                   "link_lookalike": "link_lookalike", "link_subdomain_trick": "link_subdomain_trick",
                   "link_shortener": "link_shortener", "link_ip": "link_ip", "link_bad_tld": "link_bad_tld",
                   "sender_lookalike": "sender_lookalike", "sender_mismatch": "sender_mismatch",
                   "reply_to_differs": "reply_to_differs", "link_form": "link_form_host",
                   "qr_lure": "qr_lure", "callback_lure": "callback_lure"}
        for s in risk_sigs:
            if s["id"] in F.RULE_FEATURES:            # no learned weight: rank by rule strength alone
                s["score"] = s["strength"]
                continue
            c = contrib.get(id2feat.get(s["id"], ""), 0.0)
            s["score"] = 0.5 * min(max(c, 0.0), 3.0) / 3.0 + 0.5 * s["strength"]
        risk_sigs.sort(key=lambda s: -s["score"])
        return {"probability": round(p, 3), "label": label,
                "floor_applied": label != risk_label(p), "floor_reasons": floor_reasons,
                "top_signals": risk_sigs[:topn], "reassuring_signals": safe_sigs, "phrases": phrases[:6],
                "links": [{"display": F.defang(u["url"]), "host": u["host"], "registered": u["registered"],
                           "risk": u["flags"]["risk"], "official": u["flags"]["official"]} for u in urls],
                "features": feats}


def risk_label(p, floor=None):
    """floor: None, 'MEDIUM' or 'HIGH' - the lowest label rule-based evidence allows."""
    if p >= C.HIGH_MIN or floor == "HIGH":
        return "HIGH"
    if p >= C.LOW_MAX or floor:
        return "MEDIUM"
    return "LOW"
