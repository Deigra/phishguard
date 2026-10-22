"""PhishGuard - a beginner-friendly, rule-based phishing URL checker.

It looks at a URL, applies simple rules, adds up "risk points" (0 to 100),
and explains every warning in plain English.

IMPORTANT: this is a heuristic (rule-of-thumb) tool. It cannot prove that
a website is safe or malicious. See README.md for its limitations.
"""

import ipaddress
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Settings (kept at the top so they are easy to find and change)
# ---------------------------------------------------------------------------

ALLOWED_SCHEMES = ("http", "https")
MAX_INPUT_LENGTH = 2048

# Words that phishing pages often use to pressure people into typing secrets.
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "password", "account", "secure",
    "update", "confirm", "banking", "wallet", "billing", "suspended",
]

# Link shorteners hide the real destination of a link.
SHORTENER_DOMAINS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly")

# Risk points added by each rule.
POINTS_NO_HTTPS = 15
POINTS_IP_HOST = 35
POINTS_PER_KEYWORD = 10
MAX_KEYWORD_POINTS = 30
POINTS_LONG_URL = 10
POINTS_MANY_SUBDOMAINS = 15
POINTS_AT_SYMBOL = 20
POINTS_MANY_HYPHENS = 10
POINTS_PUNYCODE = 10
POINTS_ODD_PORT = 10
POINTS_EMBEDDED_URL = 10
POINTS_SHORTENER = 10

# Limits used by the rules.
LONG_URL_LENGTH = 75      # longer than this is "unusually long"
SUBDOMAIN_LIMIT = 3       # this many subdomains or more is suspicious
HYPHEN_LIMIT = 3          # this many hyphens in the host name or more

# Score ranges for the final label.
LOW_MAX = 29              # 0-29   = Low
MEDIUM_MAX = 59           # 30-59  = Medium, 60-100 = High


# ---------------------------------------------------------------------------
# Part 1: validate the input
# ---------------------------------------------------------------------------

def validate_url(raw_url):
    """Check a user-entered URL.

    Returns a tuple of three things:
        (is_valid, parsed_url_or_None, message)

    It never crashes on bad input. Instead it returns is_valid=False
    together with a clear message that explains the problem.
    """
    # 1. The input must be text (not None, a number, etc.).
    if not isinstance(raw_url, str):
        return False, None, "Input must be text."

    # Remove spaces/newlines at the start and end.
    url = raw_url.strip()

    # 2. The input must not be empty.
    if not url:
        return False, None, "Please enter a URL (the input was empty)."

    # 3. The input must not be huge.
    if len(url) > MAX_INPUT_LENGTH:
        return False, None, "That URL is too long to analyze (over 2048 characters)."

    # 4. A URL cannot contain spaces, tabs or newlines inside it.
    if any(ch.isspace() for ch in url):
        return False, None, "A URL cannot contain spaces."

    # 5. Split the URL into parts. Some broken URLs make Python raise a
    #    ValueError, so we catch it instead of letting the program crash.
    try:
        parsed = urlparse(url)
        parsed.port  # reading the port can raise ValueError if it is invalid
    except ValueError:
        return False, None, "That URL is malformed (for example, a bad port or brackets)."

    # 6. The URL must start with http:// or https://
    if parsed.scheme.lower() not in ALLOWED_SCHEMES:
        return False, None, "The URL must start with http:// or https://"

    # 7. There must be a website name (hostname) after the scheme.
    if not parsed.hostname:
        return False, None, "The URL has no website name (hostname)."

    return True, parsed, "The URL looks valid."


# ---------------------------------------------------------------------------
# Part 2: the rules. Each check returns either None (nothing suspicious)
# or a small dictionary: {"points": ..., "message": ...}
# ---------------------------------------------------------------------------

def is_ip_address(hostname):
    """True if the host name is an IP address such as 192.168.1.1."""
    # A host name made only of digits (like 3232235777) is also an IP
    # address written in a disguised form that browsers still accept.
    if hostname.isdigit():
        return True
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def check_https(parsed):
    if parsed.scheme.lower() == "http":
        return {
            "points": POINTS_NO_HTTPS,
            "message": "Uses HTTP instead of HTTPS, so data sent to this "
                       "site is not encrypted.",
        }
    return None


def check_ip_address(hostname):
    if is_ip_address(hostname):
        return {
            "points": POINTS_IP_HOST,
            "message": "The host name is an IP address ("
                       + hostname + ") instead of a normal website name. "
                       "Legitimate sites rarely do this.",
        }
    return None


def check_keywords(parsed):
    # Look for the keywords in the host name, path and query only.
    text = (parsed.hostname + parsed.path + " " + parsed.query).lower()
    found = [word for word in SUSPICIOUS_KEYWORDS if word in text]
    if found:
        points = min(len(found) * POINTS_PER_KEYWORD, MAX_KEYWORD_POINTS)
        return {
            "points": points,
            "message": "Contains suspicious keyword(s): "
                       + ", ".join(found) + ".",
        }
    return None


def check_long_url(url):
    if len(url) > LONG_URL_LENGTH:
        return {
            "points": POINTS_LONG_URL,
            "message": "The URL is unusually long (" + str(len(url))
                       + " characters). Long URLs can hide the real destination.",
        }
    return None


def check_at_symbol(parsed):
    # Browsers ignore everything before an "@" in the website part of a URL,
    # so https://paypal.com@evil.com really goes to evil.com.
    if "@" in parsed.netloc:
        return {
            "points": POINTS_AT_SYMBOL,
            "message": "Contains an '@' symbol before the host name. Text before "
                       "the '@' is ignored by browsers, so it can disguise "
                       "the real website.",
        }
    return None


def check_odd_port(parsed):
    port = parsed.port
    if port is not None and port not in (80, 443):
        return {
            "points": POINTS_ODD_PORT,
            "message": "Uses an unusual port number (" + str(port)
                       + "). Normal websites use the default ports.",
        }
    return None


def check_embedded_url(parsed):
    # A second http:// or https:// hidden in the path or query often means
    # a redirect to somewhere else.
    tail = (parsed.path + "?" + parsed.query).lower()
    if "http://" in tail or "https://" in tail:
        return {
            "points": POINTS_EMBEDDED_URL,
            "message": "Another web address is hidden inside the URL, which "
                       "may be a redirect to a different site.",
        }
    return None


def check_subdomains(hostname):
    # Assume the last two parts are the main domain (example.com), so
    # everything before that is a subdomain. Not perfect: see README.
    labels = hostname.rstrip(".").split(".")
    subdomain_count = len(labels) - 2
    if subdomain_count >= SUBDOMAIN_LIMIT:
        return {
            "points": POINTS_MANY_SUBDOMAINS,
            "message": "Has " + str(subdomain_count) + " subdomains. Attackers "
                       "stack subdomains to make a fake site look official.",
        }
    return None


def check_hyphens(hostname):
    # Ignore the "xn--" marker so punycode is not counted twice
    # (it has its own rule below).
    hyphen_count = hostname.replace("xn--", "").count("-")
    if hyphen_count >= HYPHEN_LIMIT:
        return {
            "points": POINTS_MANY_HYPHENS,
            "message": "The host name contains many hyphens ("
                       + str(hyphen_count) + "), a common pattern in "
                       "fake look-alike domains.",
        }
    return None


def check_punycode(hostname):
    # "xn--" marks a domain written with special (non-English) characters.
    # Attackers use look-alike letters to imitate real sites.
    if any(label.startswith("xn--") for label in hostname.split(".")):
        return {
            "points": POINTS_PUNYCODE,
            "message": "The domain uses special encoded characters (xn--), "
                       "which can imitate a real website with look-alike letters.",
        }
    return None


def check_shortener(hostname):
    for domain in SHORTENER_DOMAINS:
        if hostname == domain or hostname.endswith("." + domain):
            return {
                "points": POINTS_SHORTENER,
                "message": "Uses a link shortener (" + domain + "), which hides "
                           "the real destination.",
            }
    return None


# ---------------------------------------------------------------------------
# Part 3: combine the rules into one score
# ---------------------------------------------------------------------------

def classify_score(score):
    """Turn a number from 0-100 into the label Low, Medium or High."""
    if score <= LOW_MAX:
        return "Low"
    if score <= MEDIUM_MAX:
        return "Medium"
    return "High"


def analyze_url(raw_url):
    """Analyze a URL and return a dictionary with the results.

    Keys: valid, message, hostname, score, level, reasons
    For invalid input, valid is False, score and level are None.
    """
    is_valid, parsed, message = validate_url(raw_url)
    if not is_valid:
        return {
            "valid": False, "message": message, "hostname": None,
            "score": None, "level": None, "reasons": [],
        }

    url = raw_url.strip()
    hostname = parsed.hostname

    # Rules that make sense for every URL.
    findings = [
        check_https(parsed),
        check_ip_address(hostname),
        check_keywords(parsed),
        check_long_url(url),
        check_at_symbol(parsed),
        check_odd_port(parsed),
        check_embedded_url(parsed),
    ]

    # Rules about domain names only make sense when the host is a name,
    # not an IP address.
    if not is_ip_address(hostname):
        findings += [
            check_subdomains(hostname),
            check_hyphens(hostname),
            check_punycode(hostname),
            check_shortener(hostname),
        ]

    # Keep only the rules that actually fired (the ones that are not None).
    reasons = [finding for finding in findings if finding is not None]

    # Add up the points, but never go above 100.
    score = min(sum(reason["points"] for reason in reasons), 100)

    return {
        "valid": True, "message": message, "hostname": hostname,
        "score": score, "level": classify_score(score), "reasons": reasons,
    }


# ---------------------------------------------------------------------------
# Part 4: show the results to the user
# ---------------------------------------------------------------------------

def format_report(result):
    """Turn the result dictionary into text that is easy to read."""
    if not result["valid"]:
        return "  Invalid input: " + result["message"]

    lines = [
        "  Host name  : " + result["hostname"],
        "  Risk score : " + str(result["score"]) + " / 100",
        "  Risk level : " + result["level"].upper(),
    ]

    if result["reasons"]:
        lines.append("  Warnings:")
        for reason in result["reasons"]:
            lines.append("    +" + str(reason["points"]) + "  " + reason["message"])
    else:
        lines.append("  No warning signs were found by these rules.")

    lines.append("  Note: this is an estimate from simple rules. It cannot prove")
    lines.append("  a site is safe or malicious. Verify important links yourself.")
    return "\n".join(lines)


def main():
    """Ask the user for URLs in a loop until they type quit."""
    print("PhishGuard - Phishing URL Detector")
    print("Type a URL to check it, or type 'quit' to exit.")
    print()

    while True:
        try:
            raw_url = input("Enter URL: ")
        except (EOFError, KeyboardInterrupt):
            # Ctrl+C or Ctrl+Z should end the program politely.
            print()
            print("Goodbye!")
            break

        if raw_url.strip().lower() in ("quit", "exit", "q"):
            print("Goodbye!")
            break

        print(format_report(analyze_url(raw_url)))
        print()


# This line means: run main() only when the file is run directly
# (python phishguard.py), not when another file imports it.
if __name__ == "__main__":
    main()