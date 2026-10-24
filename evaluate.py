"""Evaluation suite. Run:  python evaluate.py [--public data/sms_public.tsv]

Experiments
  A  random 70/30 split                 (optimistic: templates repeat across the split)
  B  leave-families-out (GroupKFold)    (tests unseen message *styles*)
  C  hand-written challenge set         (tests unseen *wording*, hard negatives)
  D  adversarial evasion + mitigation   (de-obfuscation on/off)
  E  threshold analysis, confusion matrices, error review
  F  optional: train on a public dataset -> test on campus messages
"""
import argparse
import json
import random
import re
import sys
from pathlib import Path

import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import precision_recall_curve
from sklearn.model_selection import GroupKFold, train_test_split

import challenge_set
import config as C
import data_gen
from model import PhishModel

OUT = Path("results"); OUT.mkdir(exist_ok=True)
MODES = ["ml", "rules", "hybrid"]
NAMES = {"ml": "Text only (TF-IDF)", "rules": "Signals only", "hybrid": "Hybrid"}


def metrics(y, p, thr=0.5):
    y = np.asarray(y); pred = (np.asarray(p) >= thr).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return dict(precision=round(prec, 3), recall=round(rec, 3), f1=round(f1, 3),
                accuracy=round((tp + tn) / len(y), 3), tn=tn, fp=fp, fn=fn, tp=tp, n=int(len(y)))


def labels(rows):
    return [r["label"] for r in rows]


def row(m):
    return f"| {m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | {m['accuracy']:.3f} | {m['tp']} / {m['fp']} / {m['fn']} / {m['tn']} |"


# ---------------------------------------------------------------- adversarial transforms
URG = re.compile(r"\b(urgent(ly)?|immediate(ly)?|right now|asap|now|within \d+ ?\w+|in \d+ ?\w+|before midnight|today|"
                 r"limited seats|alert|notice)\b[:!]?", re.I)
THR = re.compile(r"(suspen\w+|deactivat\w+|blocked?|terminat\w+|frozen|permanent(ly)?|locked)", re.I)
KEYS = ["password", "verify", "account", "login", "otp", "credentials", "suspended", "click"]


def t_strip(t, s):      # remove pressure and threat words, add a polite opener
    t = THR.sub("updated", URG.sub("", t))
    return "Hello, hope you are doing well. " + re.sub(r"\s+", " ", t).strip(), s


def t_obfuscate(t, s):  # spaced letters / zero-width / leetspeak inside key terms
    def spaced(m): return " ".join(m.group(0))
    def zw(m): return "​".join(m.group(0))
    def leet(m): return m.group(0).translate(str.maketrans("aeios", "43105"))
    fns = [spaced, zw, leet]
    k = [0]
    def rep(m):
        k[0] += 1
        return fns[k[0] % 3](m)
    return re.sub("|".join(KEYS), rep, t, flags=re.I), s


def t_nolink(t, s):     # remove the link entirely ("see link in bio" style / reply-based scam)
    return re.sub(r"(https?://\S+|www\.\S+|\b\S+\.(xyz|top|cc|icu|click|online|site|live|link|com|in|ly)\S*)", "", t), s


def t_cleansender(t, s):  # attacker uses a plain phone number / hides the sender
    return t, ""


TRANSFORMS = {"strip pressure words": t_strip, "obfuscate keywords": t_obfuscate,
              "remove link": t_nolink, "hide sender": t_cleansender}


def apply(rows, fn):
    out = []
    for r in rows:
        t, s = fn(r["text"], r["sender"])
        out.append({**r, "text": t, "sender": s})
    return out


# ---------------------------------------------------------------- main
def main(public=None):
    rows = data_gen.load()
    chal = challenge_set.rows()
    res = {"dataset": {"n": len(rows), "phishing": sum(labels(rows)), "legit": len(rows) - sum(labels(rows)),
                       "families": len({r["family"] for r in rows}), "challenge_n": len(chal)}}
    md = []

    # ---------- A. random split
    idx = np.arange(len(rows))
    tr, te = train_test_split(idx, test_size=0.3, stratify=labels(rows), random_state=C.SEED)
    train, test = [rows[i] for i in tr], [rows[i] for i in te]
    A = {}
    for m in MODES:
        mdl = PhishModel(m).fit(train)
        A[m] = metrics(labels(test), mdl.predict_proba(test))
    res["A_random_split"] = A

    # ---------- B. leave-families-out
    groups = [r["family"] for r in rows]
    y = np.array(labels(rows))
    oof = {m: np.zeros(len(rows)) for m in MODES}
    gkf = GroupKFold(n_splits=6)
    for trn, tst in gkf.split(idx, y, groups):
        trr, tsr = [rows[i] for i in trn], [rows[i] for i in tst]
        for m in MODES:
            oof[m][tst] = PhishModel(m).fit(trr).predict_proba(tsr)
    B = {m: metrics(y, oof[m]) for m in MODES}
    res["B_unseen_families"] = B
    per_family = {}
    for fam in sorted(set(groups)):
        ix = [i for i, g in enumerate(groups) if g == fam]
        pred = (oof["hybrid"][ix] >= .5).astype(int)
        per_family[fam] = round(float((pred == y[ix]).mean()), 3)
    res["B_per_family_accuracy_hybrid"] = per_family

    # ---------- C. challenge set (train on everything synthetic)
    full = {m: PhishModel(m).fit(rows) for m in MODES}
    cp = {m: full[m].predict_proba(chal) for m in MODES}
    Cm = {m: metrics(labels(chal), cp[m]) for m in MODES}
    res["C_challenge"] = Cm

    # ---------- D. adversarial evasion, with / without de-obfuscation
    ph_test = [r for r in test if r["label"] == 1]
    ph_chal = [r for r in chal if r["label"] == 1]
    plain = PhishModel("hybrid", normalise=False).fit(train)
    robust = PhishModel("hybrid", normalise=True).fit(train)
    D = {"baseline (unmodified)": {"no normalisation": metrics([1] * len(ph_test), plain.predict_proba(ph_test))["recall"],
                                   "with normalisation": metrics([1] * len(ph_test), robust.predict_proba(ph_test))["recall"]}}
    for name, fn in TRANSFORMS.items():
        adv = apply(ph_test, fn)
        D[name] = {"no normalisation": metrics([1] * len(adv), plain.predict_proba(adv))["recall"],
                   "with normalisation": metrics([1] * len(adv), robust.predict_proba(adv))["recall"]}
    # same on the hand-written phishing messages
    Dc = {"baseline (unmodified)": {"no normalisation": metrics([1] * len(ph_chal), plain.predict_proba(ph_chal))["recall"],
                                    "with normalisation": metrics([1] * len(ph_chal), robust.predict_proba(ph_chal))["recall"]}}
    for name, fn in TRANSFORMS.items():
        adv = apply(ph_chal, fn)
        Dc[name] = {"no normalisation": metrics([1] * len(adv), plain.predict_proba(adv))["recall"],
                    "with normalisation": metrics([1] * len(adv), robust.predict_proba(adv))["recall"]}
    res["D_adversarial_recall_synthetic"] = D
    res["D_adversarial_recall_handwritten"] = Dc

    # ---------- E. thresholds & errors
    prec, rec, thr = precision_recall_curve(y, oof["hybrid"])
    cprec, crec, cthr = precision_recall_curve(labels(chal), cp["hybrid"])
    sweep = {}
    for t in (0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8):
        sweep[str(t)] = {"unseen_families": metrics(y, oof["hybrid"], t), "challenge": metrics(labels(chal), cp["hybrid"], t)}
    res["E_threshold_sweep_hybrid"] = {k: {"B_prec": v["unseen_families"]["precision"], "B_rec": v["unseen_families"]["recall"],
                                           "C_prec": v["challenge"]["precision"], "C_rec": v["challenge"]["recall"]} for k, v in sweep.items()}
    errs = []
    for r, p in zip(chal, cp["hybrid"]):
        if (p >= .5) != bool(r["label"]):
            errs.append({"truth": "phishing" if r["label"] else "legit", "p": round(float(p), 2), "sender": r["sender"], "text": r["text"][:140]})
    res["E_challenge_errors_hybrid"] = errs
    fam_errs = {}
    for i, (r, p) in enumerate(zip(rows, oof["hybrid"])):
        if (p >= .5) != bool(r["label"]):
            fam_errs[r["family"]] = fam_errs.get(r["family"], 0) + 1
    res["E_unseen_family_errors_by_family"] = fam_errs

    # ---------- F. public data transfer (optional)
    if public and Path(public).exists():
        pub = []
        for line in open(public, encoding="utf-8", errors="ignore"):
            if "\t" in line:
                lab, txt = line.rstrip("\n").split("\t", 1)
                pub.append({"text": txt, "sender": "", "subject": "", "label": int(lab.lower().startswith("spam")), "family": "pub"})
        mp = PhishModel("hybrid").fit(pub)
        res["F_public_to_campus"] = {"train_n": len(pub), "campus_all": metrics(y, mp.predict_proba(rows)),
                                     "challenge": metrics(labels(chal), mp.predict_proba(chal))}

    json.dump(res, open(OUT / "metrics.json", "w"), indent=1)

    # ---------------------------------------------------------------- figures
    plt.rcParams.update({"font.size": 10, "axes.spines.top": False, "axes.spines.right": False})
    # 1 confusion matrices
    fig, axs = plt.subplots(1, 2, figsize=(9, 3.9))
    for ax, (title, m) in zip(axs, [("Unseen message families\n(hybrid, 6-fold group CV)", B["hybrid"]),
                                    ("Hand-written challenge set\n(hybrid)", Cm["hybrid"])]):
        cm = np.array([[m["tn"], m["fp"]], [m["fn"], m["tp"]]])
        ax.imshow(cm, cmap="Blues", vmin=0, vmax=cm.max() * 1.3)
        for (i, j), v in np.ndenumerate(cm):
            ax.text(j, i, str(v), ha="center", va="center", fontsize=16, color="white" if v > cm.max() * .55 else "black")
        ax.set_xticks([0, 1], ["Legit", "Phishing"]); ax.set_yticks([0, 1], ["Legit", "Phishing"])
        ax.set_xlabel("Predicted"); ax.set_ylabel("Actual"); ax.set_title(title, fontsize=10)
        ax.spines[:].set_visible(False)
    plt.tight_layout(); plt.savefig(OUT / "confusion_matrices.png", dpi=160); plt.close()

    # 2 ablation bars
    fig, ax = plt.subplots(figsize=(8, 3.8))
    groups_ = [("Random split\n(optimistic)", A), ("Unseen families", B), ("Challenge set", Cm)]
    w = 0.26
    cols = {"ml": "#9aa5b1", "rules": "#c9a227", "hybrid": "#1f5fbf"}
    for k, mname in enumerate(MODES):
        vals = [g[1][mname]["f1"] for g in groups_]
        xs = np.arange(len(groups_)) + (k - 1) * w
        ax.bar(xs, vals, w, label=NAMES[mname], color=cols[mname])
        for x, v in zip(xs, vals):
            ax.text(x, v + .01, f"{v:.2f}", ha="center", fontsize=8)
    ax.set_xticks(range(len(groups_)), [g[0] for g in groups_]); ax.set_ylim(0, 1.1); ax.set_ylabel("F1 (phishing class)")
    ax.legend(frameon=False, loc="lower left"); ax.set_title("Same models, increasingly honest tests")
    plt.tight_layout(); plt.savefig(OUT / "ablation.png", dpi=160); plt.close()

    # 3 threshold curve
    fig, axs = plt.subplots(1, 2, figsize=(9, 3.6), sharey=True)
    for ax, (t, pr, rc, th) in zip(axs, [("Unseen families", prec, rec, thr), ("Challenge set", cprec, crec, cthr)]):
        ax.plot(th, pr[:-1], label="Precision", color="#1f5fbf"); ax.plot(th, rc[:-1], label="Recall", color="#d1495b")
        ax.axvline(0.5, ls=":", color="grey"); ax.set_xlabel("Decision threshold"); ax.set_title(t, fontsize=10)
        ax.set_ylim(0, 1.03)
    axs[0].legend(frameon=False, loc="lower left"); axs[0].set_ylabel("score")
    plt.tight_layout(); plt.savefig(OUT / "threshold_curve.png", dpi=160); plt.close()

    # 4 adversarial recall
    fig, ax = plt.subplots(figsize=(8.5, 3.8))
    names = list(Dc.keys()); xs = np.arange(len(names))
    ax.bar(xs - .2, [Dc[n]["no normalisation"] for n in names], .4, label="No de-obfuscation", color="#9aa5b1")
    ax.bar(xs + .2, [Dc[n]["with normalisation"] for n in names], .4, label="With de-obfuscation", color="#1f5fbf")
    for x, n in zip(xs, names):
        ax.text(x - .2, Dc[n]["no normalisation"] + .01, f"{Dc[n]['no normalisation']:.2f}", ha="center", fontsize=8)
        ax.text(x + .2, Dc[n]["with normalisation"] + .01, f"{Dc[n]['with normalisation']:.2f}", ha="center", fontsize=8)
    ax.set_xticks(xs, [n.replace(" (", "\n(") for n in names], fontsize=8); ax.set_ylim(0, 1.1); ax.set_ylabel("Recall on hand-written phishing")
    ax.legend(frameon=False, loc="lower left"); ax.set_title("Evasion attempts vs recall")
    plt.tight_layout(); plt.savefig(OUT / "adversarial.png", dpi=160); plt.close()

    # ---------------------------------------------------------------- markdown report
    def table(d):
        s = "| Model | Precision | Recall | F1 | Accuracy | TP / FP / FN / TN |\n|---|---|---|---|---|---|\n"
        for m in MODES:
            s += f"| {NAMES[m]} " + row(d[m]) + "\n"
        return s
    md.append(f"# Evaluation results\n\nDataset: {res['dataset']['n']} campus-style messages ({res['dataset']['phishing']} phishing, "
              f"{res['dataset']['legit']} legitimate, {res['dataset']['families']} template families) + {len(chal)} hand-written challenge messages.\n"
              "Phishing is the positive class. Threshold 0.5.\n")
    md.append("## A. Random 70/30 split (optimistic)\nTemplates repeat across train and test, so this over-states real performance.\n\n" + table(A))
    md.append("## B. Unseen message families (6-fold group CV)\nWhole families (e.g. 'fee refund', 'exam notice') are held out.\n\n" + table(B))
    md.append("## C. Hand-written challenge set (trained on all generated data)\nWording never seen in training; includes urgent-but-genuine messages, genuine OTPs and a security-awareness notice.\n\n" + table(Cm))
    md.append("## D. Evasion test: recall on phishing after attacker edits\n\n| Attack | Synthetic: no de-obf. | Synthetic: with | Hand-written: no de-obf. | Hand-written: with |\n|---|---|---|---|---|\n" +
              "\n".join(f"| {n} | {D[n]['no normalisation']:.2f} | {D[n]['with normalisation']:.2f} | {Dc[n]['no normalisation']:.2f} | {Dc[n]['with normalisation']:.2f} |" for n in D) + "\n")
    md.append("## E. Threshold sweep (hybrid)\n\n| Threshold | Unseen-families precision | recall | Challenge precision | recall |\n|---|---|---|---|---|\n" +
              "\n".join(f"| {k} | {v['B_prec']} | {v['B_rec']} | {v['C_prec']} | {v['C_rec']} |" for k, v in res["E_threshold_sweep_hybrid"].items()) + "\n")
    md.append("### Errors on the challenge set (hybrid, threshold 0.5)\n\n| Truth | P(phish) | Sender | Message |\n|---|---|---|---|\n" +
              "\n".join(f"| {e['truth']} | {e['p']} | {e['sender'] or '-'} | {e['text']} |" for e in errs) + "\n")
    md.append("### Per-family accuracy when the family is unseen (hybrid)\n\n" + "\n".join(f"- {k}: {v}" for k, v in per_family.items()) + "\n")
    if "F_public_to_campus" in res:
        f = res["F_public_to_campus"]
        md.append(f"## F. Public data -> campus messages\nTrained on {f['train_n']} public messages. Campus: P={f['campus_all']['precision']} R={f['campus_all']['recall']}; challenge: P={f['challenge']['precision']} R={f['challenge']['recall']}\n")
    (OUT / "report.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))


if __name__ == "__main__":
    ap = argparse.ArgumentParser(); ap.add_argument("--public", default="data/sms_public.tsv")
    main(ap.parse_args().public)
