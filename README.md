<div align="center">
  <img src="https://www.zyenra.com/assets/img/joombrute.png" width="100" alt="joombrute"><br>
  <h3>JoomBrute</h3>
  <p>Modern Joomla auth-attack toolkit<br>J3 / J4 / J5 - CVE-2023-23752 · CVE-2023-23755 · CVE-2025-25227</p>
</div>

### Description

Joomla credential-attack toolkit covering CMS versions 3, 4, and 5. Six subcommands handle the full attack chain end-to-end:

- **`detect`** - version fingerprint (manifest XML → generator meta → admin markup)
- **`enum`** - CVE-2023-23752 unauthenticated API harvest: usernames, DB host/user/password, SMTP credentials, application secret
- **`brute`** - concurrent admin login bruteforce with per-worker session isolation and four-outcome classification (success / mfa-required / invalid / blocked)
- **`mfa-brute`** - CVE-2023-23755 exhaustive 6-digit TOTP attack against the captive MFA screen
- **`mfa-bypass`** - CVE-2025-25227 MFA bypass via `view=methods` (and four other candidate views/tasks) on the half-authenticated session
- **`chain`** - full autopilot: detect → enum → brute → automatic MFA-bypass pivot when the brute lands on a captive screen

Single static binary, no runtime dependencies. Native goroutine concurrency with per-worker cookie jars. JSONL output for SIEM ingest. HTTP/HTTPS/SOCKS5 proxy support. Verified end-to-end against Joomla 3.10, 4.2.7, and 5.4.6 docker labs.

### Install

```bash
# Option A - Go install (requires Go 1.22+)
go install github.com/rvzsec/joombrute/cmd/joombrute@latest

# Option B - Pre-built binary from releases
curl -L -o joombrute https://github.com/rvzsec/joombrute/releases/latest/download/joombrute-linux-amd64
chmod +x joombrute

# Option C - Build from source
git clone https://github.com/rvzsec/joombrute
cd joombrute
make
```

### Usage

```bash
joombrute detect      -u <target>
joombrute enum        -u <target>
joombrute brute       -u <target> --user admin -w rockyou.txt -c 20
joombrute mfa-brute   -u <target> --user admin --password <pw> -c 50
joombrute mfa-bypass  -u <target> --user admin --password <pw>
joombrute chain       -u <target> -w rockyou.txt -c 20

# JSONL output for piping / SIEM ingest
joombrute --json brute -u <target> --user admin -w rockyou.txt > hits.jsonl
```

### CVE Coverage

| CVE              | Affected versions             | Mode          | Patched in              | Lab-verified |
|------------------|-------------------------------|---------------|-------------------------|--------------|
| CVE-2023-23752   | 4.0.0 - 4.2.7                 | `enum`        | 4.2.8 (2023-02)         | ✅ J4.2.7    |
| CVE-2023-23755   | 4.2.0 - 4.3.1                 | `mfa-brute`   | 4.3.2 (2023-05)         | ✅ J4.2.7    |
| CVE-2025-25227   | 4.0.0 - 4.4.12, 5.0.0 - 5.2.5 | `mfa-bypass`  | 4.4.13 / 5.2.6 (2025-04)| ✅ J4.2.7    |

CVE-2025-25227 exploits `MultiFactorAuthenticationHandler::needsMultiFactorAuthenticationRedirection()` which calls `isMultiFactorAuthenticationPage()` without the `$onlyCaptive` flag - the bypass-exempt list silently includes MFA *management* views (`view=methods`, `view=method`, `view=callback`, `task=method.add` …) which a half-authed session can navigate to without solving the captive challenge.

### Subcommands

- **`detect`** - fingerprint via `joomla.xml` manifest → `<meta name="generator">` → admin markup
- **`enum`** - CVE-2023-23752 unauth API harvest (users, DB host/user/pass, SMTP, app secret)
- **`brute`** - admin form bruteforce, per-worker session isolation, four-outcome classification (`success` / `mfa-required` / `invalid` / `blocked`)
- **`mfa-brute`** - CVE-2023-23755 6-digit TOTP brute on captive screen
- **`mfa-bypass`** - CVE-2025-25227 state-check bypass probe (non-destructive)
- **`chain`** - full auto: detect → enum → brute → MFA-bypass probe

### Lab

```
make lab           # docker compose up + seed J3.10 / J4.2.7 / J5.x with admin user
make smoke         # end-to-end against all three (no MFA)
make lab-mfa       # seed a known TOTP secret on J4 admin (for mfa-* tests)
make smoke-mfa     # brute -> mfa-required, mfa-bypass VULN, chain auto-pivot
make lab-mfa-off   # remove the MFA record (back to plain admin)
make lab-down      # tear it all down
```

The lab installer bypasses Joomla's web installer entirely - loads the install SQL straight into MySQL, inserts an admin user (`admin` / `admin1234`), writes a minimal `configuration.php`. `seed_mfa.php` uses Joomla's own AES-128-CBC + secret-key encryption so the captive endpoint decrypts it correctly. Lab-only - both scripts assume the standard `joombrute-*` container names from `lab/docker-compose.yml`.

### Build Matrix

```
make all
# produces dist/joombrute-{linux,darwin,windows}-{amd64,arm64} statically linked
```

### Legal

Authorized security testing only. Run against systems you have explicit written permission to test. Generates traffic that any IDS will catch. Maintainers disclaim all liability for misuse.

### Credits

Ravindu Wickramasinghe | rvz ([@rvzsec](https://github.com/rvzsec)) · [www.zyenra.com](https://www.zyenra.com)

Original Joomla 3 brute concept: [@ajnik](https://github.com/ajnik/joomla-bruteforce)
CVE-2023-23752 chain research: [VulnCheck](https://vulncheck.com/)
