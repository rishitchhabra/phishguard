"""Builds the labelled campus dataset (legitimate vs phishing) from parameterised templates.

Each message belongs to a template *family* (e.g. 'phish_suspension', 'legit_exam_notice').
Families are used for group-held-out evaluation so the model is tested on message styles it
never saw in training. Hard negatives (genuine-but-urgent, genuine OTP, genuine security
awareness mails) are deliberately included.

Run:  python data_gen.py            -> data/vit_messages.csv
"""
import csv
import random
import string
from pathlib import Path

import config as C

R = random.Random(C.SEED)
NAMES = ["Arjun", "Priya", "Rahul", "Sneha", "Karthik", "Ananya", "Vikram", "Divya", "Rohan", "Meera"]
FAC = ["Rao", "Iyer", "Sharma", "Menon", "Gupta", "Nair", "Reddy"]
UNI = ["VIT", "VIT", "VIT University", "Vellore Institute of Technology", "VIT-AP", "VIT Chennai", "VIT Bhopal"]
PORTAL = ["VTOP", "VTOP", "VIT student portal", "VIT LMS", "VIT mail", "Moodle"]
DEADLINE = ["within 24 hours", "in 2 hours", "today", "by 5 PM today", "immediately", "before midnight",
            "within 12 hours", "in 30 minutes", "within 48 hours"]
SUBJECT = ["Operating Systems", "DBMS", "Machine Learning", "Data Structures", "Physics", "Maths", "Networks"]
COMPANY = ["Infosys", "TCS", "Google", "Amazon", "Deloitte", "Zoho", "Wipro", "Microsoft"]
CLUB = ["Robotics Club", "Coding Club", "Music Club", "Photography Club", "Entrepreneurship Cell"]
TOPIC = ["Cloud Computing", "Generative AI", "Cyber Security", "Resume Building", "Startups"]
DAYS = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"]
DATES = ["25 Oct", "28 Oct", "30 Oct", "2 Nov", "5 Nov", "10 Nov"]
TERM = ["Winter", "Fall", "Summer"]


def rid(n=6):
    return "".join(R.choice(string.ascii_letters + string.digits) for _ in range(n))


def amt():
    return R.choice(["12,000", "25,000", "40,000", "5,000", "1,85,000", "8,500", "60,000"])


def small():
    return R.choice(["99", "150", "299", "499", "50"])


def phone():
    return "+91 " + R.choice("6789") + "".join(R.choice(string.digits) for _ in range(9))


def phish_url():
    kind = R.choice(["hyph", "hyph", "look", "sub", "short", "ip", "form", "tld", "plain"])
    kw = R.choice(["login", "verify", "secure", "portal", "update", "student", "vtop", "helpdesk"])
    tld = R.choice(["xyz", "top", "cc", "icu", "click", "online", "site", "live", "link", "com", "in"])
    path = R.choice(["", "/login", "/verify", f"/auth?id={R.randint(1000,9999)}", f"/{rid(5)}"])
    sch = R.choice(["https://", "https://", "http://", ""])
    if kind == "hyph":
        return f"{sch}vit-{kw}.{tld}{path}"
    if kind == "look":
        return f"{sch}{R.choice(['v1t.ac.in','vlt.ac.in','vitt.ac.in','vit-ac.in','vtop-vit.in','vitap-portal.com'])}{path}"
    if kind == "sub":
        return f"{sch}vit.ac.in.{kw}-id.{tld}{path}"
    if kind == "short":
        return R.choice(["bit.ly/", "tinyurl.com/", "cutt.ly/", "rb.gy/"]) + rid(6)
    if kind == "ip":
        return f"http://{R.randint(11,223)}.{R.randint(1,250)}.{R.randint(1,250)}.{R.randint(2,250)}/vit{path}"
    if kind == "form":
        return f"https://forms.gle/{rid(10)}"
    if kind == "tld":
        return f"{sch}{R.choice(['student','account','mail','exam'])}-{R.choice(['vit','vtop'])}.{tld}{path}"
    return f"{sch}{R.choice(['vtop','vit'])}{R.choice(['','-'])}{kw}.com{path}"


def legit_url():
    return R.choice(["https://vtop.vit.ac.in", "https://vit.ac.in/students", "https://vitap.ac.in/exams",
                     "https://vtop.vitap.ac.in", "https://vitbhopal.ac.in/notices", "https://lms.vit.ac.in",
                     "https://vit.ac.in/fees", "vtop.vit.ac.in", "https://chennai.vit.ac.in/placements"])


def gform():
    return R.choice([f"https://forms.gle/{rid(10)}", f"https://docs.google.com/forms/d/{rid(14)}"])


def fill(t, **kw):
    d = dict(uni=R.choice(UNI), portal=R.choice(PORTAL), user=R.choice(["Student", "Dear Student", f"Dear {R.choice(NAMES)}", "Dear User", "Hello"]),
             deadline=R.choice(DEADLINE), amt=amt(), small=small(), name=R.choice(NAMES), fac=R.choice(FAC),
             company=R.choice(COMPANY), subject=R.choice(SUBJECT), club=R.choice(CLUB), topic=R.choice(TOPIC),
             day=R.choice(DAYS), date=R.choice(DATES), term=R.choice(TERM), otp=R.randint(100000, 999999),
             pct=R.randint(60, 74), acct=R.randint(1000, 9999), url=phish_url(), lurl=legit_url(), gform=gform(), phone_=phone()[4:])
    d.update(kw)
    return t.format(**d)


# --------------------------------------------------------------------------- phishing families
PHISH = {
 "phish_suspension": [
  "Dear {user}, your {uni} account will be suspended {deadline} unless you verify. Click {url} now.",
  "URGENT: {uni} IT Services has detected unusual activity on your {portal} account. Your access will be blocked {deadline}. Verify at {url}",
  "Your {portal} account has been flagged and will be deactivated. To keep it active, confirm your login details here: {url}",
  "NOTICE: Failure to update your {uni} account {deadline} will result in permanent suspension. Update now {url}",
  "{uni} Alert! Account suspended. Re-activate {deadline}: {url}",
  "Your {uni} student account is scheduled for termination. Click here to cancel the request: {url}"],
 "phish_password": [
  "Your {uni} password expires {deadline}. Click {url} to keep your current password.",
  "Security alert: password for {portal} must be changed {deadline}. Log in with your registration number and password at {url}",
  "Dear {user}, your mailbox is full and your password is about to expire. Reply with your username and password to avoid losing access.",
  "We detected a login to your {portal} from a new device. Confirm your password at {url} or your account will be locked."],
 "phish_refund": [
  "Congratulations! You are eligible for a {uni} fee refund of Rs {amt}. Claim by entering your bank details at {url}",
  "{uni} scholarship of Rs {amt} approved for you. To receive the amount confirm your registration number, DOB and account number: {url}",
  "Your caution deposit refund of Rs {amt} is on hold. Pay Rs {small} processing fee {deadline} via {url}"],
 "phish_job": [
  "Selected for internship at {company}! Stipend Rs {amt}/month. Pay registration fee Rs {small} to confirm your seat: {url}",
  "{company} is hiring {uni} students. Limited seats. Submit your {portal} login and resume at {url} {deadline}",
  "Work from home job for students, earn Rs {amt} daily. Send your Aadhaar and bank details. {url}",
  "You are shortlisted for a {company} campus drive. Complete the assessment here with your university login: {url}"],
 "phish_impersonation": [
  "This is the {uni} Registrar office. Your attendance record has an issue. Share the OTP you receive to resolve it {deadline}.",
  "Hi, I'm Prof. {fac}, I'm in a meeting and can't talk. Please buy 3 Amazon gift cards of Rs 2000 and send me the codes. I will reimburse you today.",
  "Dean's office: your hall ticket is on hold. Send your {portal} username and password to the exam cell {deadline} to release it.",
  "Hello, I'm calling from the {uni} IT helpdesk. We need your OTP to reverse an incorrect fee charge."],
 "phish_storage_wifi": [
  "{uni} Wi-Fi access expires {deadline}. Re-authenticate your device at {url} to stay connected.",
  "Your {uni} email storage is 99% full. Upgrade now to avoid losing incoming mail: {url}",
  "Your Office 365 licence from {uni} is expiring. Sign in {deadline} to renew: {url}",
  "Your {portal} quota is exceeded. Login again to restore access: {url}"],
 "phish_exam": [
  "Your {uni} exam results are out. Login to view: {url}. Verify your identity with your date of birth and password.",
  "Hall ticket for the upcoming exams is ready. Download at {url} (use your {portal} password).",
  "Exam malpractice case registered against your registration number. Respond {deadline} at {url} to avoid disciplinary action."],
 "phish_generic": [
  "Your bank account will be blocked today. Update KYC at {url} immediately.",
  "Parcel could not be delivered. Pay Rs {small} redelivery fee: {url}",
  "Dear customer, your PAN is not linked. Account will be frozen. Click {url} to update.",
  "UPI alert: Rs {amt} credited by mistake, please return by clicking {url} and entering your UPI PIN."],
 "phish_hinglish": [
  "Aapka {uni} account turant band ho jayega. Abhi verify karein: {url}",
  "{uni} se urgent message: apna password aur OTP abhi bhejo warna account block ho jayega.",
  "Aapka scholarship approve ho gaya hai. Paise lene ke liye apni bank details yahan daalo: {url}",
  "Jaldi karo! Aapka {portal} login expire ho raha hai. Yahan click karein {url}"],
 "phish_attachment": [
  "Dear {user}, the revised {term} fee structure is in the attached document. Open the file and enable editing to view it.",
  "{uni} payroll/scholarship statement attached. Please open the attachment and enable content to see your entry.",
  "Your {subject} marks sheet is attached (marks.docm). Enable macros to display the table.",
  "Invoice #{acct} attached. Download and open the zip archive to review the charges."],
 "phish_money": [
  "Hi {name}, it's Prof. {fac}. I'm travelling and my card is not working. Can you UPI Rs {small}00 to me now? I'll return it by evening.",
  "{uni} hostel seat release: transfer the confirmation amount of Rs {amt} to the account below or the seat is cancelled. A/c no {acct}{acct}",
  "Your certificate courier is held. Courier charges Rs {small} payable via UPI to {phone_} to release it.",
  "Congratulations, you won a {company} voucher! Pay Rs {small} processing fee by GPay to claim it.",
  "Your exam fee payment bounced. Please pay again by UPI to {phone_}, otherwise the hall ticket will not be issued."],
 "phish_subtle": [
  "Hello {name}, as part of a routine security review, kindly confirm your {portal} credentials at {url} at your convenience.",
  "We noticed a new sign-in to your {uni} account from another device. If this wasn't you, review activity at {url}.",
  "Please complete the mandatory student satisfaction survey and sign in with your {portal} account: {url}",
  "Your {uni} email will move to a new system. Sign in at {url} so your messages are carried over."],
 "phish_qr": [
  "Congratulations! You won a {company} cashback of Rs {amt}. Scan the QR code sent to you and enter your UPI PIN to receive the money.",
  "{uni} Wi-Fi upgrade: scan the attached QR code and sign in with your {portal} password to keep access {deadline}.",
  "Your {uni} fee refund of Rs {amt} is ready. Scan this QR in GPay to receive it {deadline}.",
  "Attendance verification pending. Scan the QR code below and log in with your {portal} credentials or you will be marked absent.",
  "Your {portal} account is locked. Scan the QR with your phone camera to unlock and verify your identity."],
 "phish_callback": [
  "Your SIM card will be blocked {deadline} due to incomplete KYC. Call customer care at {phone_} now.",
  "{uni} Exam Cell: discrepancy found in your hall ticket. Call {phone_} {deadline} to avoid cancellation.",
  "Your bank account is temporarily frozen. To reactivate, call our officer on {phone_} and keep your debit card ready.",
  "Courier alert: a parcel booked in your name contains illegal items. Contact {phone_} immediately to avoid legal action.",
  "Scholarship of Rs {amt} sanctioned in your name. Call {phone_} to claim it before it lapses."],
}

# --------------------------------------------------------------------------- legitimate families
LEGIT = {
 "legit_timetable": [
  "Dear students, the timetable for the {term} semester is available on {portal}: {lurl}.",
  "The {subject} class scheduled for tomorrow is cancelled. Revised schedule will be shared on {portal}.",
  "Reminder: {subject} assignment is due {day}. Submit through {portal} ({lurl}).",
  "Guest lecture on {topic} on {day} at 3 PM in the auditorium. Attendance will be marked."],
 "legit_fee": [
  "Your fee payment of Rs {amt} has been received. Receipt is available on {portal}. Thank you.",
  "Reminder: last date for tuition fee payment is {date}. Pay through the official portal {lurl}. Ignore if already paid.",
  "Hostel fee receipt for {term} semester is attached. No action required.",
  "Your caution deposit refund of Rs {amt} has been credited to your registered bank account. No action required."],
 "legit_exam_notice": [
  "Important: CAT-1 exam seating arrangement is published on {portal}. Report 15 minutes early with your ID card.",
  "URGENT: Exam on {subject} rescheduled to tomorrow 9 AM due to weather. Please check {lurl}.",
  "Last date to register for the make-up exam is today 5 PM. Register at {lurl}.",
  "Hall tickets for the end-semester exams are available. Login to {portal} and download them. Carry a printed copy."],
 "legit_otp_security": [
  "Your OTP for {portal} login is {otp}. Do not share it with anyone. VIT never asks for your OTP.",
  "You requested a password reset for your {uni} account. Use the link {lurl} to reset it. If you didn't request this, ignore this message.",
  "{otp} is your verification code for {portal}. Valid for 10 minutes. Don't share this code.",
  "Your password was changed successfully. If this wasn't you, visit the IT helpdesk in person. We will never ask for your password over message.",
  "Security awareness: beware of messages claiming your account will be suspended unless you click a link. Report them to the IT team."],
 "legit_events": [
  "Placement drive: {company} will visit campus on {date}. Eligible students should register on {portal} {lurl} before {date}.",
  "{club} recruitment is open. Fill the form at {gform}. Last date {date}.",
  "Workshop on {topic} this {day} at the Technology Tower. Free for all students. Register: {gform}",
  "Congratulations! You have been selected for the {club} core team. Orientation on {day} at 5 PM in the seminar hall.",
  "Final call! Registration for the hackathon closes tonight at midnight: {gform}"],
 "legit_personal": [
  "Hey are you coming to the lab today? Prof said viva might happen",
  "Can you send me the notes for {subject}? I missed the last class",
  "Bro urgent, I forgot my ID card, can you tell the guard I'm with you?",
  "Where r u? Mess closes in 10 minutes hurry up",
  "Did you submit the {subject} record? Deadline is tonight!!",
  "Happy birthday! Party at 8 pm, don't be late",
  "Please share the Google Meet link for tomorrow's group discussion",
  "Mom: beta, did you eat? Send me a message when you reach the hostel."],
 "legit_services": [
  "Rs {amt} debited from your A/c XX{acct} on {date}. If not done by you, call the number on the back of your card.",
  "Your order has been shipped and will arrive by {day}. Track in the official app.",
  "Your Amazon package was delivered to the hostel front desk.",
  "Your Zoom meeting starts in 10 minutes. Passcode: {otp}",
  "Your Uber ride receipt: Rs {small}. Thanks for riding."],
 "legit_admin": [
  "Dear students, the library will remain closed on {day} for maintenance. Books due will be extended.",
  "Your attendance in {subject} is {pct}%. Minimum 75% required. Please contact your faculty advisor.",
  "The mess committee meeting is on {day} at 5 PM. Student representatives please attend.",
  "Hostel inspection will be conducted tomorrow. Keep your rooms tidy.",
  "Notice: students with attendance below 75% will be debarred from the end-semester exam. Check your attendance on {portal}.",
  "Your library fine of Rs {small} is pending. Pay at the library counter before returning books.",
  "Your {portal} account will be temporarily unavailable on {day} for scheduled maintenance 2-4 AM. No action needed."],
 # hard negatives for the QR / call-back signals: genuine messages that also mention QR codes and phone numbers
 "legit_qr_contact": [
  "Show the QR code on your e-ticket at the entry gate for the {club} event on {day}.",
  "Attendance for the {topic} workshop will be taken by scanning the QR code displayed in the hall. No login needed.",
  "Canteen now accepts UPI: scan the counter QR to pay and show the receipt to collect your order.",
  "For queries about the {company} interview on {date}, contact the Placement Cell on 0416-224{acct} between 9 AM and 5 PM.",
  "Medical emergency? Call the campus health centre at 0416-220{acct} (24x7).",
  "Lost and found: a blue bag was found near the library. Call {name} on {phone_} if it's yours.",
  "Hostel fee queries: call the hostel office at 0416-220{acct} or visit in person. Pay only on {lurl}."],
}

SUBJ_P = ["Action Required: Verify your account", "Account suspension notice", "Password expiry", "Urgent: confirm your details",
          "Your mailbox is full", "Scholarship approved", "Security alert", ""]
SUBJ_L = ["Timetable update", "Fee receipt", "Exam notice", "Event invitation", "Reminder", "Notice", "", ""]


def sender_phish():
    k = R.random()
    if k < .30:
        return ""
    if k < .45:
        return R.choice(["VIT Admin <vitadmin@gmail.com>", "VIT Registrar <registrar.vit@gmail.com>", "Exam Cell <examcell.vit@yahoo.com>"])
    if k < .65:
        d = R.choice(["vit-helpdesk.xyz", "vit-support.online", "v1t.ac.in", "vitap-portal.com", "vit.ac.in.secure-id.top", "vtop-alerts.cc"])
        return f"{R.choice(['VIT IT Support','Registrar','VIT Alerts','Exam Cell'])} <{R.choice(['support','noreply','admin','alerts'])}@{d}>"
    if k < .80:
        return phone()
    if k < .90:
        return R.choice(["Registrar <registrar@vit.ac.in>", "VIT IT <it@vitstudent.ac.in>"])   # spoofed/compromised official
    return f"{R.choice(NAMES)} <{R.choice(NAMES).lower()}{R.randint(10,99)}@gmail.com>"


def sender_legit():
    k = R.random()
    if k < .35:
        return ""
    if k < .65:
        return R.choice(["VIT Registrar <registrar@vit.ac.in>", "Exam Cell <coe@vit.ac.in>", "VTOP <noreply@vtop.vit.ac.in>",
                         "Placement Cell <placement@vitap.ac.in>", f"Dr. {R.choice(FAC)} <{R.choice(FAC).lower()}@vit.ac.in>",
                         "Hostel Office <hostel@vitbhopal.ac.in>", "Library <library@vit.ac.in>"])
    if k < .85:
        return phone()
    if k < .93:
        return R.choice(["Coding Club <vitcodingclub@gmail.com>", "Robotics Club <robotics.vit@gmail.com>"])
    return R.choice(["Amazon <shipment-tracking@amazon.in>", "HDFC Bank <alerts@hdfcbank.net>", "Zoom <no-reply@zoom.us>"])


def build(n_per_template=22):
    rows = []
    for label, fams, sfun, subj in ((1, PHISH, sender_phish, SUBJ_P), (0, LEGIT, sender_legit, SUBJ_L)):
        for fam, temps in fams.items():
            for ti, t in enumerate(temps):
                for _ in range(n_per_template if len(temps) < 6 else n_per_template - 4):
                    msg = fill(t)
                    s = sfun()
                    is_mail = "@" in s and R.random() < .8
                    rows.append({"text": msg, "sender": s, "subject": R.choice(subj) if is_mail else "",
                                 "channel": "email" if is_mail else R.choice(["sms", "whatsapp"]),
                                 "label": label, "family": fam, "template": f"{fam}#{ti}", "source": "synthetic"})
    # exact duplicates add nothing and would leak across splits
    seen, out = set(), []
    for r in rows:
        k = (r["text"], r["sender"])
        if k not in seen:
            seen.add(k); out.append(r)
    R.shuffle(out)
    return out


def save(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        w.writeheader(); w.writerows(rows)


def load(path="data/vit_messages.csv"):
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:
        r["label"] = int(r["label"])
    return rows


if __name__ == "__main__":
    Path("data").mkdir(exist_ok=True)
    rows = build()
    save(rows, "data/vit_messages.csv")
    n1 = sum(r["label"] for r in rows)
    print(f"wrote {len(rows)} messages: {n1} phishing, {len(rows)-n1} legitimate, "
          f"{len({r['family'] for r in rows})} families, {len({r['template'] for r in rows})} templates")
