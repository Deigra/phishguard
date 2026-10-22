# PhishGuard - Phishing URL Detector

PhishGuard is a beginner-friendly command-line tool that checks a web address (URL) against a set of simple, rule-based tests and gives it a **risk score from 0 to 100**, a **Low / Medium / High** label, and a plain-English reason for every warning.

It is written in pure Python using only the standard library. It never visits the URL, sends no data anywhere, and needs no internet connection.

> **Important:** PhishGuard is an educational heuristic tool. It cannot prove that a website is safe or malicious. See [Limitations](#limitations-and-false-positives).

## Features

- Validates user input (empty, malformed, wrong scheme, spaces, bad ports) without crashing
- Detects HTTP vs HTTPS
- Detects IP addresses used as host names (including disguised numeric forms)
- Looks for suspicious keywords such as `login`, `verify`, `password`, `account`
- Flags unusually long URLs and excessive subdomains
- Flags suspicious structure: `@` symbols, unusual ports, many hyphens, look-alike (punycode) domains, link shorteners, and web addresses hidden inside a URL
- Shows the score, the label and a clear reason for every warning
- 43 automated unit tests using Python's built-in `unittest`

## Project structure

```
phishguard/
  phishguard.py        main application (validation, rules, scoring, command-line interface)
  test_phishguard.py   automated unit tests
  README.md            this file
  .gitignore           files Git should ignore (Python cache, environments)
```

## How it works

1. **Validate** - `validate_url()` checks the input and splits the URL into parts (scheme, host name, path, query) using Python's `urllib.parse`.
2. **Apply rules** - each rule is a small function that returns `None` (nothing found) or a result with points and a message.
3. **Score** - `analyze_url()` adds up the points and caps the total at 100.
4. **Report** - `format_report()` prints the score, label and reasons.

## Setup (Windows)

Requirements: Python 3 (developed and tested with Python 3.14 on Windows) and Git. There is nothing to install: no third-party packages are used.

```powershell
git clone https://github.com/Deigra/phishguard.git
cd phishguard
git switch feature/phishguard-detector
python --version
```

## Usage

```powershell
python phishguard.py
```

Type a URL (including `http://` or `https://`) and press Enter. Type `quit` to exit.

Example session:

```
Enter URL: http://192.168.1.1/login
  Host name  : 192.168.1.1
  Risk score : 60 / 100
  Risk level : HIGH
  Warnings:
    +15  Uses HTTP instead of HTTPS, so data sent to this site is not encrypted.
    +35  The host name is an IP address (192.168.1.1) instead of a normal website name. Legitimate sites rarely do this.
    +10  Contains suspicious keyword(s): login.
  Note: this is an estimate from simple rules. It cannot prove
  a site is safe or malicious. Verify important links yourself.
```

## Scoring logic

Each rule that fires adds points. The total is capped at 100.

| Rule | Points |
|---|---|
| Uses HTTP instead of HTTPS | +15 |
| Host name is an IP address | +35 |
| Suspicious keyword in host, path or query | +10 each, max +30 |
| URL longer than 75 characters | +10 |
| `@` symbol before the host name | +20 |
| Unusual port (not 80 or 443) | +10 |
| Another `http://` or `https://` address hidden in the path or query | +10 |
| 3 or more subdomains | +15 |
| 3 or more hyphens in the host name | +10 |
| Punycode (`xn--`) look-alike characters | +10 |
| Link shortener (bit.ly, tinyurl.com, t.co, goo.gl, is.gd, ow.ly) | +10 |

| Score | Label |
|---|---|
| 0 - 29 | Low |
| 30 - 59 | Medium |
| 60 - 100 | High |

All weights and limits are named constants at the top of `phishguard.py`, so they are easy to adjust. They were chosen by hand for teaching purposes, not trained on real data.

## Sample test cases

| URL | Score | Label | Why |
|---|---|---|---|
| `https://www.google.com` | 0 | Low | No rules fired |
| `https://github.com/login` | 10 | Low | Keyword `login` (a legitimate page: a small false positive) |
| `http://example.com` | 15 | Low | HTTP only |
| `https://bit.ly/3abcde` | 10 | Low | Link shortener |
| `https://xn--pple-43d.com/` | 10 | Low | Punycode domain |
| `https://paypal.com@evil-site.com/signin` | 30 | Medium | `@` trick +20, keyword +10 |
| `https://secure.login.account.verify.example.com/` | 45 | Medium | 4 keywords (capped +30), 4 subdomains +15 |
| `http://192.168.1.1/login` | 60 | High | HTTP +15, IP +35, keyword +10 |
| `http://secure-paypal-login.verify-account.example.com/update/password?next=http://evil.com` | 75 | High | HTTP, keywords, long URL, hidden address, many hyphens |
| `example.com` | - | Invalid | Must start with `http://` or `https://` |
| (empty input) | - | Invalid | Empty input is rejected politely |
| `http://exa mple.com` | - | Invalid | URLs cannot contain spaces |

## Running the tests

```powershell
python -m unittest -v
```

Expected ending:

```
Ran 43 tests in 0.0Xs

OK
```

## Limitations and false positives

PhishGuard only looks at the **text of the URL**. It does not open the page, check reputation lists, inspect certificates, or look at the page content. Because of this:

- **False positives (safe sites flagged):** real sites can use words like `login` or `account`, long tracking links, many subdomains, or hyphens. A legitimate page such as `https://github.com/login` still receives a small warning.
- **False negatives (dangerous sites missed):** many phishing sites use HTTPS and clean-looking domains. Look-alike domains without any warning sign (for example a name with one letter changed), hacked legitimate websites, and brand-new domains can all score Low.
- **A Low score does not mean safe**, and a High score does not prove a site is malicious.
- A single serious warning can still produce a Low score (for example a lone link shortener).
- Keyword matching is text-based, so a word like `account` inside `accounting` also matches.
- Subdomains are counted by assuming the main domain has two parts (`example.com`). Domains such as `example.co.uk` can therefore be miscounted.
- The point values are hand-picked, not learned from data.

Always verify important links yourself and use your browser's and email provider's built-in protections.

## Future improvements

- Use the Public Suffix List (for example via a library) to count subdomains correctly
- Detect look-alike brand names (for example `paypa1.com`) using string similarity
- Optional online checks: domain age, redirect following, or a phishing blocklist
- A simple graphical or web interface

## Development workflow

Work was done on the feature branch `feature/phishguard-detector`, with small commits for each step: validation, rules and scoring, tests, documentation. Nothing is merged into `main` without explicit approval.