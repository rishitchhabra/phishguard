# Evaluation results

Dataset: 1571 campus-style messages (837 phishing, 734 legitimate, 18 template families) + 60 hand-written challenge messages.
Phishing is the positive class. Threshold 0.5.

## A. Random 70/30 split (optimistic)
Templates repeat across train and test, so this over-states real performance.

| Model | Precision | Recall | F1 | Accuracy | TP / FP / FN / TN |
|---|---|---|---|---|---|
| Text only (TF-IDF) | 1.000 | 1.000 | 1.000 | 1.000 | 251 / 0 / 0 / 221 |
| Signals only | 1.000 | 0.952 | 0.976 | 0.975 | 239 / 0 / 12 / 221 |
| Hybrid | 1.000 | 0.972 | 0.986 | 0.985 | 244 / 0 / 7 / 221 |

## B. Unseen message families (6-fold group CV)
Whole families (e.g. 'fee refund', 'exam notice') are held out.

| Model | Precision | Recall | F1 | Accuracy | TP / FP / FN / TN |
|---|---|---|---|---|---|
| Text only (TF-IDF) | 0.861 | 0.927 | 0.893 | 0.882 | 776 / 125 / 61 / 609 |
| Signals only | 0.903 | 0.932 | 0.917 | 0.910 | 780 / 84 / 57 / 650 |
| Hybrid | 0.922 | 0.949 | 0.935 | 0.930 | 794 / 67 / 43 / 667 |

## C. Hand-written challenge set (trained on all generated data)
Wording never seen in training; includes urgent-but-genuine messages, genuine OTPs and a security-awareness notice.

| Model | Precision | Recall | F1 | Accuracy | TP / FP / FN / TN |
|---|---|---|---|---|---|
| Text only (TF-IDF) | 0.889 | 0.800 | 0.842 | 0.850 | 24 / 3 / 6 / 27 |
| Signals only | 0.862 | 0.833 | 0.847 | 0.850 | 25 / 4 / 5 / 26 |
| Hybrid | 0.926 | 0.833 | 0.877 | 0.883 | 25 / 2 / 5 / 28 |

## D. Evasion test: recall on phishing after attacker edits

| Attack | Synthetic: no de-obf. | Synthetic: with | Hand-written: no de-obf. | Hand-written: with |
|---|---|---|---|---|
| baseline (unmodified) | 0.97 | 0.97 | 0.80 | 0.80 |
| strip pressure words | 0.96 | 0.96 | 0.80 | 0.80 |
| obfuscate keywords | 0.94 | 0.97 | 0.77 | 0.80 |
| remove link | 0.63 | 0.63 | 0.40 | 0.40 |
| hide sender | 0.98 | 0.98 | 0.87 | 0.87 |

## E. Threshold sweep (hybrid)

| Threshold | Unseen-families precision | recall | Challenge precision | recall |
|---|---|---|---|---|
| 0.2 | 0.889 | 0.971 | 0.839 | 0.867 |
| 0.3 | 0.912 | 0.964 | 0.839 | 0.867 |
| 0.4 | 0.912 | 0.952 | 0.929 | 0.867 |
| 0.5 | 0.922 | 0.949 | 0.926 | 0.833 |
| 0.6 | 0.922 | 0.94 | 0.92 | 0.767 |
| 0.7 | 0.921 | 0.932 | 0.92 | 0.767 |
| 0.8 | 0.92 | 0.925 | 0.958 | 0.767 |

### Errors on the challenge set (hybrid, threshold 0.5)

| Truth | P(phish) | Sender | Message |
|---|---|---|---|
| phishing | 0.11 | +91 9123456780 | Quick favour: I'm stuck at the airport and my card is blocked. Could you do a UPI transfer of 5000? I'll return it tonight. Sent from Dr. Ku |
| phishing | 0.09 | - | Dear applicant, your hostel allotment is confirmed. Pay the confirmation amount of Rs 12,000 to the account below within 2 days or your seat |
| phishing | 0.49 | +91 9988776655 | From the Office of the Registrar: your degree certificate is ready. Courier charges Rs 350 payable via UPI to 9812345678 |
| phishing | 0.0 | - | Please find the attached invoice for your records. Open the attachment and enable macros to view the content. |
| phishing | 0.13 | +91 9871112233 | Sir, your electricity bill is not updated. Power will be disconnected tonight 9:30 pm. Call 9871112233 immediately |
| legit | 0.98 | HDFC Bank <alerts@hdfcbank.net> | HDFC Bank: Rs 2,300 debited at SWIGGY on 22-Oct. Not you? Call the number on your card or block it via NetBanking at hdfcbank.com |
| legit | 0.8 | +91 9811122334 | Beta, I'm sending your pocket money. Send me your new account number tonight. |

### Per-family accuracy when the family is unseen (hybrid)

- legit_admin: 1.0
- legit_events: 0.394
- legit_exam_notice: 1.0
- legit_fee: 1.0
- legit_otp_security: 1.0
- legit_personal: 1.0
- legit_services: 0.989
- legit_timetable: 1.0
- phish_exam: 0.985
- phish_generic: 0.977
- phish_hinglish: 0.976
- phish_impersonation: 0.722
- phish_job: 0.989
- phish_password: 1.0
- phish_refund: 1.0
- phish_storage_wifi: 0.977
- phish_subtle: 0.852
- phish_suspension: 1.0
