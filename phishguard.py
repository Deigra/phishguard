"""PhishGuard - a beginner-friendly, rule-based phishing URL checker.

Step 3: check that the user's input is a usable URL and split it into parts.
"""

from urllib.parse import urlparse

# Only these "schemes" (the part before ://) are accepted.
ALLOWED_SCHEMES = ("http", "https")

# Refuse absurdly large input so the program stays fast and safe.
MAX_INPUT_LENGTH = 2048


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

        is_valid, parsed, message = validate_url(raw_url)

        if not is_valid:
            print(f"  Invalid input: {message}")
            print()
            continue

        print("  Valid URL!")
        print(f"  Scheme  : {parsed.scheme}")
        print(f"  Hostname: {parsed.hostname}")
        print(f"  Path    : {parsed.path or '/'}")
        print(f"  Query   : {parsed.query or '(none)'}")
        print()


# This line means: run main() only when the file is run directly
# (python phishguard.py), not when another file imports it.
if __name__ == "__main__":
    main()