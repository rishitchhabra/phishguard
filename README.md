# PhishGuard - AI phishing-awareness tool (Question 5)

Scenario: on 16 Oct 2026 students received "your VIT account will be suspended unless you click now" messages.
PhishGuard analyses message text (plus optional sender/subject), gives a **risk label (LOW / MEDIUM / HIGH)**,
explains the **strongest signals**, and **never opens links**. It is decision support: it flags messages for the
user to review, it does not block anything.

## Run it
```bash
pip install -r requirements.txt
python data_gen.py      # builds data/vit_messages.csv  (campus dataset)
python evaluate.py      # metrics + figures -> results/
python app.py           # web UI at http://127.0.0.1:5000
```
API: `POST /api/analyse` with JSON `{"text": "...", "sender": "...", "subject": "...", "reply_to": "..."}`.

## Which platforms does it work on?
It is platform-independent: it analyses **text + optional sender**, so the same engine covers all channels.

| Channel | How you use it | Sender checks |
|---|---|---|
| Email | paste, or upload a saved `.eml` | full: display name vs domain, look-alike domain, Reply-To mismatch |
| WhatsApp / SMS / Telegram | paste or share the text | limited (phone number / name only) |
| Future | Gmail add-on, browser extension, "forward to bot" | - |

WhatsApp offers no legitimate API for reading a person's messages (and auto-reading them would be a privacy problem),
so the user submits the suspicious message themselves.

## Method
1. **Dataset** (`data_gen.py`, `challenge_set.py`): 1,768 campus-style messages (1,031 phishing / 737 legitimate) from
   20 template families, with parameterised slots, mixed senders, channels, Hinglish and **hard negatives** (genuine
   urgent exam notices, genuine OTPs, genuine security-awareness mails, bank alerts). Plus **60 hand-written challenge
   messages** (30 phishing / 30 legitimate) that share no templates with the generator.
   Public datasets (SMS Spam Collection, Nazario) could not be downloaded from the build sandbox; `evaluate.py --public file.tsv`
   (label<TAB>text) runs a public-to-campus transfer test when you have the file.
2. **Signals** (`features.py`): urgency, threats, requests for credentials (with "never share" negation), reward/job lures,
   payment/UPI requests, attachment lures, authority impersonation; link analysis (look-alike of the official domain,
   official name as a subdomain of another site, shorteners, IP hosts, odd TLDs, keyword-stuffed hosts, plain HTTP, form hosts);
   sender analysis (official-sounding name from Gmail, look-alike domain, Reply-To mismatch).
   Text is **de-obfuscated** first (zero-width characters, `p a s s w o r d`, leetspeak).
3. **Model** (`model.py`): TF-IDF (1-2 grams, URLs masked) + signal features -> one logistic regression
   (class-balanced). Because it is linear, each signal's contribution to the score can be read off for the explanation.
   A safety floor lifts the label to at least MEDIUM when a look-alike link/sender or raw-IP link is present.
4. **Safety**: links are parsed as strings only, shown defanged (`hxxp://x[.]com`), non-clickable, never fetched;
   messages are not stored or logged.

## Results (`results/report.md`, `results/*.png`)
Phishing = positive class, threshold 0.5.

| Test | What it measures | Hybrid P | R | F1 |
|---|---|---|---|---|
| A. Random 70/30 split | optimistic (templates leak) | 1.000 | 0.987 | 0.994 |
| B. Unseen message families (6-fold group CV) | new *styles* | 0.928 | 0.891 | 0.909 |
| C. Hand-written challenge set | new *wording* + hard negatives | 0.935 | 0.967 | 0.951 |

Honest reading:
* **The random split is misleading.** The text-only model scores 1.000 there because the same templates appear in train and
  test. Under unseen families it drops to F1 0.82. Always report the harder tests.
* **Hybrid vs signals-only:** hybrid is best on the challenge set (F1 0.951 vs 0.935 vs 0.889 text-only) and has the best
  precision on unseen families, but signals-only is marginally better on unseen-family F1 (0.915 vs 0.909). The signals carry most of the generalisation.
* **Challenge-set v1 -> v2.** First run (v1, `results/report_v1.md`): hybrid F1 0.877, recall 0.833; link-free scams (UPI transfer, gift cards, macros attachments) were missed.
  I then added payment and attachment signals and matching training families (v2). **Caveat:** I added them after seeing the v1 errors,
  so the v2 challenge numbers are optimistic - a fresh untouched test set is needed for a clean estimate.
* **Evasion:** removing pressure words or hiding the sender barely matters (the model does not depend on urgency words).
  Keyword obfuscation cut recall 0.97 -> 0.93 on hand-written phishing; de-obfuscation restores it to 0.97.
  **Removing the link is the real weakness**: recall falls to 0.63 (0.77 on synthetic). Link-free scams rely on text alone.
* **Threshold:** raising it trades recall for precision; for awareness tooling a missed phish is costlier than a false alarm,
  so 0.4-0.5 is a reasonable operating point (see `threshold_curve.png`).

## Known limitations
* Synthetic data is cleaner than real campaigns; a real, consented sample of reported messages would be the best next step.
* Remaining challenge-set errors: a phone-call scam text ("electricity bill ... call now") was missed, and a genuine bank debit alert and an ambiguous family message were rated risky.
  Unseen *legit event* messages ("Congratulations, you are selected...") are often misjudged (per-family accuracy 0.39 when held out).
* Sender checks cannot verify SPF/DKIM; an official-looking address can be spoofed, so "official sender" is only mildly reassuring.
* Image-only phishing, QR-code phishing and voice calls are out of scope.
* `OFFICIAL_DOMAINS` in `config.py` must be confirmed against the college's real domains.

## Safe advice for reporting suspicious messages
Shown in the UI. Summary: do not click, reply or forward; verify via the official portal typed by hand; screenshot as evidence;
report to campus IT, use "Report phishing" in the mail app, block/report on WhatsApp/SMS; in India use cybercrime.gov.in / 1930
(and Sanchar Saathi - Chakshu for suspicious calls/SMS); if you entered a password change it immediately from the real portal, and call your bank if card/UPI details were shared.

## Files
`config.py` settings - `features.py` signals - `model.py` hybrid model + explanations - `data_gen.py` dataset - `challenge_set.py` hand-written test -
`evaluate.py` experiments - `app.py` web UI/API - `results/` metrics, report, figures, UI screenshot.
# phishguard
