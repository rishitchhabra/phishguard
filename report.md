# Evaluation results

Dataset: 1768 campus-style messages (1031 phishing, 737 legitimate, 20 template families) + 60 hand-written challenge messages.
Phishing is the positive class. Threshold 0.5.

## A. Random 70/30 split (optimistic)
Templates repeat across train and test, so this over-states real performance.

| Model | Precision | Recall | F1 | Accuracy | TP / FP / FN / TN |
|---|---|---|---|---|---|
| Text only (TF-IDF) | 1.000 | 1.000 | 1.000 | 1.000 | 310 / 0 / 0 / 221 |
| Signals only | 1.000 | 0.968 | 0.984 | 0.981 | 300 / 0 / 10 / 221 |
| Hybrid | 1.000 | 0.987 | 0.994 | 0.992 | 306 / 0 / 4 / 221 |

## B. Unseen message families (6-fold group CV)
Whole families (e.g. 'fee refund', 'exam notice') are held out.

| Model | Precision | Recall | F1 | Accuracy | TP / FP / FN / TN |
|---|---|---|---|---|---|
| Text only (TF-IDF) | 0.813 | 0.827 | 0.820 | 0.788 | 853 / 196 / 178 / 541 |
| Signals only | 0.920 | 0.911 | 0.915 | 0.902 | 939 / 82 / 92 / 655 |
| Hybrid | 0.928 | 0.891 | 0.909 | 0.896 | 919 / 71 / 112 / 666 |

## C. Hand-written challenge set (trained on all generated data)
Wording never seen in training; includes urgent-but-genuine messages, genuine OTPs and a security-awareness notice.

| Model | Precision | Recall | F1 | Accuracy | TP / FP / FN / TN |
|---|---|---|---|---|---|
| Text only (TF-IDF) | 0.848 | 0.933 | 0.889 | 0.883 | 28 / 5 / 2 / 25 |
| Signals only | 0.906 | 0.967 | 0.935 | 0.933 | 29 / 3 / 1 / 27 |
| Hybrid | 0.935 | 0.967 | 0.951 | 0.950 | 29 / 2 / 1 / 28 |

## D. Evasion test: recall on phishing after attacker edits

| Attack | Synthetic: no de-obf. | Synthetic: with | Hand-written: no de-obf. | Hand-written: with |
|---|---|---|---|---|
| baseline (unmodified) | 0.99 | 0.99 | 0.97 | 0.97 |
| strip pressure words | 0.99 | 0.99 | 0.97 | 0.97 |
| obfuscate keywords | 0.96 | 0.99 | 0.93 | 0.97 |
| remove link | 0.77 | 0.77 | 0.63 | 0.63 |
| hide sender | 0.99 | 0.99 | 0.97 | 0.97 |

## E. Threshold sweep (hybrid)

| Threshold | Unseen-families precision | recall | Challenge precision | recall |
|---|---|---|---|---|
| 0.2 | 0.908 | 0.937 | 0.879 | 0.967 |
| 0.3 | 0.911 | 0.923 | 0.906 | 0.967 |
| 0.4 | 0.922 | 0.906 | 0.935 | 0.967 |
| 0.5 | 0.928 | 0.891 | 0.935 | 0.967 |
| 0.6 | 0.928 | 0.877 | 0.935 | 0.967 |
| 0.7 | 0.927 | 0.85 | 0.966 | 0.933 |
| 0.8 | 0.925 | 0.822 | 0.964 | 0.9 |

### Errors on the challenge set (hybrid, threshold 0.5)

| Truth | P(phish) | Sender | Message |
|---|---|---|---|
| phishing | 0.09 | +91 9871112233 | Sir, your electricity bill is not updated. Power will be disconnected tonight 9:30 pm. Call 9871112233 immediately |
| legit | 0.94 | HDFC Bank <alerts@hdfcbank.net> | HDFC Bank: Rs 2,300 debited at SWIGGY on 22-Oct. Not you? Call the number on your card or block it via NetBanking at hdfcbank.com |
| legit | 0.68 | +91 9811122334 | Beta, I'm sending your pocket money. Send me your new account number tonight. |

### Per-family accuracy when the family is unseen (hybrid)

- legit_admin: 1.0
- legit_events: 0.389
- legit_exam_notice: 1.0
- legit_fee: 1.0
- legit_otp_security: 0.979
- legit_personal: 1.0
- legit_services: 0.969
- legit_timetable: 1.0
- phish_attachment: 0.321
- phish_exam: 0.985
- phish_generic: 1.0
- phish_hinglish: 0.989
- phish_impersonation: 0.865
- phish_job: 0.989
- phish_money: 0.725
- phish_password: 1.0
- phish_refund: 1.0
- phish_storage_wifi: 0.92
- phish_subtle: 0.932
- phish_suspension: 0.991
