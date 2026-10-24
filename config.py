"""Central configuration. Edit OFFICIAL_DOMAINS to match your institution."""

# Registered domains treated as "official". Verify these against your campus IT notices.
OFFICIAL_DOMAINS = {
    "vit.ac.in", "vitap.ac.in", "vitbhopal.ac.in", "vitchennai.ac.in",
    "vitstudent.ac.in", "vitapstudent.ac.in",
}
BRAND_TOKENS = ("vit", "vtop")           # strings an attacker will imitate

FREE_MAIL = {"gmail.com", "yahoo.com", "yahoo.in", "outlook.com", "hotmail.com",
             "proton.me", "protonmail.com", "rediffmail.com", "ymail.com", "icloud.com"}

SHORTENERS = {"bit.ly", "tinyurl.com", "cutt.ly", "t.co", "goo.gl", "is.gd", "rb.gy",
              "shorturl.at", "ow.ly", "rebrand.ly", "tiny.cc", "t.ly", "shorturl.com"}

# Form/doc hosts: often legitimate, but also used to harvest credentials -> weak signal only
FORM_HOSTS = {"forms.gle", "docs.google.com", "forms.office.com", "typeform.com"}

SUSPICIOUS_TLDS = {"xyz", "top", "cc", "icu", "click", "online", "site", "live", "link",
                   "buzz", "tk", "ml", "ga", "cf", "gq", "help", "info", "biz", "work",
                   "rest", "monster", "club", "support"}

MULTI_PART_TLDS = {"ac.in", "co.in", "edu.in", "gov.in", "org.in", "net.in", "co.uk",
                   "com.au", "ac.uk"}

# Risk label thresholds on the model probability
LOW_MAX = 0.30
HIGH_MIN = 0.70

DENSE_SCALE = 2.5     # weight of hand-built signals relative to TF-IDF in the hybrid model
SEED = 42
