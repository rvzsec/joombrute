#!/usr/bin/env python3
"""
Drive the Joomla installer (3.x + 4.x + 5.x) over HTTP so the lab is
testable. Joomla 4/5 ship a Vue SPA installer that talks to a small JSON
API; J3 uses a classic POST form. This script handles both.

Usage:
    python3 install.py j3
    python3 install.py j4
    python3 install.py j5
    python3 install.py all
"""
import sys
import time
import re
import json
import urllib.parse
import urllib.request

# host -> (port, db_host, db_pass, version)
TARGETS = {
    "j3": {"port": 8310, "db_host": "joombrute-j3-db", "db_pass": "joomlapass",    "branch": "j3"},
    "j4": {"port": 8420, "db_host": "joombrute-j4-db", "db_pass": "joomlapass_j4", "branch": "j4"},
    "j5": {"port": 8500, "db_host": "joombrute-j5-db", "db_pass": "joomlapass_j5", "branch": "j5"},
}

ADMIN_USER = "admin"
ADMIN_PASS = "admin1234"   # Joomla 4/5 require >= 12 chars
ADMIN_NAME = "Administrator"
ADMIN_EMAIL = "admin@joombrute.local"

class Session:
    """Tiny cookie-aware HTTP client. Keeps PHPSESSID across requests."""

    def __init__(self, base):
        self.base = base
        self.cookies = {}
        self.last_html = ""

    def _build(self, url):
        return url if url.startswith("http") else f"{self.base}{url}"

    def _cookie_header(self):
        if not self.cookies:
            return None
        return "; ".join(f"{k}={v}" for k, v in self.cookies.items())

    def _absorb_cookies(self, resp):
        for h, v in resp.getheaders():
            if h.lower() == "set-cookie":
                # naive: take first "k=v" segment.
                kv = v.split(";", 1)[0]
                if "=" in kv:
                    k, val = kv.split("=", 1)
                    self.cookies[k.strip()] = val.strip()

    def get(self, url):
        req = urllib.request.Request(self._build(url), method="GET")
        ch = self._cookie_header()
        if ch:
            req.add_header("Cookie", ch)
        with urllib.request.urlopen(req, timeout=30) as r:
            self._absorb_cookies(r)
            self.last_html = r.read().decode("utf-8", "replace")
            return r.status, self.last_html

    def post(self, url, data, json_body=False, extra_headers=None):
        if json_body:
            body = json.dumps(data).encode()
            ct = "application/json"
        else:
            body = urllib.parse.urlencode(data).encode()
            ct = "application/x-www-form-urlencoded"
        req = urllib.request.Request(self._build(url), data=body, method="POST")
        req.add_header("Content-Type", ct)
        ch = self._cookie_header()
        if ch:
            req.add_header("Cookie", ch)
        if extra_headers:
            for k, v in extra_headers.items():
                req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                self._absorb_cookies(r)
                self.last_html = r.read().decode("utf-8", "replace")
                return r.status, self.last_html
        except urllib.error.HTTPError as e:
            self.last_html = e.read().decode("utf-8", "replace") if e.fp else ""
            return e.code, self.last_html


def grab_token(html):
    """Pluck the 32-hex CSRF token name from a hidden input value=1."""
    m = re.search(r'name="([a-f0-9]{32})"\s+value="1"', html)
    return m.group(1) if m else None


def wait_for(url, attempts=30):
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                if r.status in (200, 302):
                    return True
        except Exception:
            time.sleep(2)
    return False


def install_j3(t):
    """Joomla 3.10 classic 3-step installer."""
    base = f"http://localhost:{t['port']}"
    s = Session(base)
    print(f"[j3] step 1: site config")
    status, html = s.get("/installation/index.php")
    token = grab_token(html)
    if not token:
        print(f"[j3] could not find token on step1, status={status}")
        return False

    data = {
        "site_name": "J3Lab",
        "site_metadesc": "lab",
        "site_offline": "0",
        "admin_email": ADMIN_EMAIL,
        "admin_user": ADMIN_NAME,
        "admin_password": ADMIN_PASS,
        "admin_password2": ADMIN_PASS,
        "admin_username": ADMIN_USER,
        "lang_code": "en-GB",
        "helpurl": "",
        token: "1",
        "task": "installation.setdefaultlanguage",  # absorbed below
    }
    # In J3 the controller is com_install with task=installation.dbconfig
    # but the multi-page flow expects ajax pings. Use the legacy POST:
    data["task"] = "installation.dbconfig"
    s.post("/installation/index.php?tmpl=index", data)

    print(f"[j3] step 2: db config")
    data2 = {
        "db_type": "mysqli",
        "db_host": t["db_host"],
        "db_user": "joomla",
        "db_pass": t["db_pass"],
        "db_name": "joomla",
        "db_prefix": "jos_",
        "db_old": "remove",
        token: "1",
        "task": "installation.dbconfig",
    }
    s.post("/installation/index.php?tmpl=index", data2)

    print(f"[j3] step 3: install")
    data3 = {
        "sample_file": "",
        token: "1",
        "task": "installation.install",
    }
    s.post("/installation/index.php?tmpl=index", data3)

    print(f"[j3] step 4: remove installation folder")
    s.post("/installation/index.php?tmpl=index", {token: "1", "task": "installation.removeFolder"})

    # Verify.
    _, html = s.get("/administrator/")
    ok = "form-login" in html or "mod-login-username" in html
    print(f"[j3] verify: {'OK' if ok else 'FAILED'}")
    return ok


def install_j4or5(t, branch):
    """Joomla 4/5 JSON-API installer at /installation/index.php?option=com_setup."""
    base = f"http://localhost:{t['port']}"
    s = Session(base)
    print(f"[{branch}] step 1: bootstrap installer")
    status, html = s.get("/installation/index.php")
    # The Vue installer fetches a token at /installation/index.php?option=com_setup&task=setup.gettoken
    status, html = s.get("/installation/index.php?option=com_ajax&task=setup.gettoken&format=json")
    try:
        token_resp = json.loads(html)
        token = token_resp.get("token") or token_resp.get("data")
    except Exception:
        token = grab_token(html)
    if not token:
        # fallback: scrape from initial HTML
        token = grab_token(s.last_html)
    if not token:
        print(f"[{branch}] could not find CSRF token (last_html len={len(html)})")
        return False
    print(f"[{branch}] token len={len(token)}")

    # Step: setlanguage (J4/J5 expects this)
    s.post(
        f"/installation/index.php?option=com_ajax&task=setup.setlanguage&format=json",
        {"language": "en-GB", token: "1"},
    )

    # Step: setconfig (site name, admin, db all in one in J4)
    cfg = {
        "language": "en-GB",
        "site_name": f"{branch}Lab",
        "admin_email": ADMIN_EMAIL,
        "admin_user": ADMIN_NAME,
        "admin_username": ADMIN_USER,
        "admin_password": ADMIN_PASS,
        "admin_password2": ADMIN_PASS,
        "db_type": "mysqli",
        "db_host": t["db_host"],
        "db_user": "joomla",
        "db_pass": t["db_pass"],
        "db_name": "joomla",
        "db_prefix": "jos_",
        "db_old": "remove",
        "db_encryption": "0",
        "site_offline": "0",
        "sample_file": "",
        "helpurl": "",
        token: "1",
    }
    status, html = s.post(
        "/installation/index.php?option=com_ajax&task=setup.setconfig&format=json",
        cfg,
    )
    print(f"[{branch}] setconfig: status={status} body[:200]={html[:200]!r}")

    # Step: installation.create (DB tables)
    status, html = s.post(
        "/installation/index.php?option=com_ajax&task=installation.create&format=json",
        {token: "1"},
    )
    print(f"[{branch}] installation.create: status={status} body[:200]={html[:200]!r}")

    # Step: installation.populateDatabase
    status, html = s.post(
        "/installation/index.php?option=com_ajax&task=installation.populateDatabase&format=json",
        {token: "1"},
    )
    print(f"[{branch}] populateDatabase: status={status} body[:200]={html[:200]!r}")

    # Step: installation.customInstall (skip languages, finish)
    status, html = s.post(
        "/installation/index.php?option=com_ajax&task=installation.customInstall&format=json",
        {token: "1"},
    )
    print(f"[{branch}] customInstall: status={status} body[:200]={html[:200]!r}")

    # Step: installation.removeFolder
    status, html = s.post(
        "/installation/index.php?option=com_ajax&task=installation.removeFolder&format=json",
        {token: "1"},
    )
    print(f"[{branch}] removeFolder: status={status} body[:200]={html[:200]!r}")

    # Verify.
    s2 = Session(base)
    _, html = s2.get("/administrator/")
    ok = "form-login" in html or "mod-login-username" in html
    print(f"[{branch}] verify: {'OK' if ok else 'FAILED (len=%d)' % len(html)}")
    return ok


def main():
    sel = sys.argv[1] if len(sys.argv) > 1 else "all"
    todo = list(TARGETS.keys()) if sel == "all" else [sel]
    ok = True
    for k in todo:
        t = TARGETS[k]
        url = f"http://localhost:{t['port']}/installation/index.php"
        print(f"[{k}] waiting for installer at {url}...")
        if not wait_for(url):
            print(f"[{k}] installer never came up")
            ok = False
            continue
        if k == "j3":
            ok = install_j3(t) and ok
        else:
            ok = install_j4or5(t, k) and ok
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
