# Watson

Watson is a small open-source check for a school's **public** website. A technician runs one command. Watson reads the site the way a browser would, then writes a report about broken links, old news and dates, and a short passive security review.

It is written for school technicians, starting with Queensland state schools, and it works on any public school site.

```bash
watson https://example-school.eq.edu.au/
```

Replace that address with the public site **your** school is responsible for. The name above is only a placeholder. Watson does not ship with any real school's pages, and you should not commit a report from a real school to a public place.

## Passive checks only

**Watson does not test like an attacker.** School websites are often run by a department or another hosting provider. Intrusive testing is off limits.

Watson will only:

- send ordinary **GET** and **HEAD** requests (the same kind a browser sends when it opens a page or checks a file)
- open **one TLS handshake** to the host you named, so it can read the certificate
- if you turn it on, send a **library name and version** to the public [OSV](https://osv.dev) API

Watson will **not** log in, submit a form, guess hidden folders, fuzz parameters, scan ports, or try to bypass a password. It does not send telemetry. The report stays on your computer.

If `robots.txt` disallows a path, Watson does not request it. The default speed is about **one request per second**.

## What it checks

1. **Broken links.** Every link and embedded file it can see (pages, PDFs, images, documents), on your site and on other sites. HEAD first, then GET if HEAD is not a reliable answer.
   - **Broken:** 404, 410, a name that does not resolve, connection refused, or a timeout.
   - **Couldn't verify:** 401, 403, 429, 5xx, or a bot wall. Open the link in a browser before you treat it as broken.
   - **Redirects:** including soft 404s, where the link sends people to the home page or a generic "page not found" page.
   - **Insecure:** a link that was written as `http://` and should be `https://`.
   Each row names the page it was found on and the link text.
2. **Updates and stale content.** Last-updated dates where a page shows one. The newest newsletter, news item, and event it can date. It flags:
   - term dates or calendars from a past year
   - an event that is still in an "upcoming" section after its date
   - a newest newsletter older than a set number of weeks (default 8)
   - a copyright year older than this year
   Turn on the Australian ruleset for day/month/year dates, student-free days, and optional term windows you type in yourself. Watson does **not** ship a department calendar.
3. **Passive security review.** Each finding has a severity (High, Medium, Low, or Info), evidence, a likely owner, and a suggested fix.
   - **Platform/hosting provider** — site-wide HTTPS, the certificate, HSTS, security headers, cookie flags, server banners, `security.txt`, `robots.txt` and the sitemap.
   - **School content editor** — links, page content, embeds, forms in the page, and documents.
   The checks are: HTTPS and the HTTP-to-HTTPS redirect, certificate validity, days to expiry and TLS version, HSTS, Content-Security-Policy, X-Frame-Options or `frame-ancestors`, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, cookie Secure / HttpOnly / SameSite, mixed content, forms that post over http, third-party scripts and embeds with a version when the address contains one, outdated libraries from a bundled list (old jQuery and others), server version banners, `security.txt`, what `robots.txt` and the sitemap expose, external link names that no longer resolve (someone could register the name and take over the link), a **count** of email addresses (never the addresses), and a note when a PDF or Word file has author metadata (never the value).

## Install

You need Python 3.10 or newer for the `pip` install. The Windows and macOS downloads from [Releases](https://github.com/JeffStone69/Watson/releases) do not need a separate Python once a release has been published.

### pip or pipx

```bash
pip install git+https://github.com/JeffStone69/Watson.git
watson --help
```

`pipx` keeps the tool in its own folder, which is a good fit when you do not want to change other Python programs:

```bash
pipx install git+https://github.com/JeffStone69/Watson.git
```

From a clone of this repository (this is also how you run the tests):

```bash
pip install .
watson --help
```

### Windows laptop that is locked down

Many school laptops do not let you install "for all users".

1. Install Python from [python.org](https://www.python.org/downloads/windows/) for your own user. Tick **Add python.exe to PATH**. You do not need the admin install.
2. Open **Command Prompt** (not necessarily as administrator) and run `py -m pip install --user git+https://github.com/JeffStone69/Watson.git`.
3. If `watson` is not found, run `py -m watson` instead.
4. If the store or the image blocks installers, the [embeddable package](https://www.python.org/downloads/windows/) ("Windows embeddable package") plus `get-pip.py` is the usual portable option. Unzip it to a folder you can write to, for example `C:\Users\YourName\Tools\python`, enable `import site` in `python*._pth`, install pip, then `python -m pip install --user` the Watson address above.
5. When a release is attached to a version tag, you can instead download `watson-windows-x64.exe` from Releases and run it from a folder you can write to. The file is not code-signed. SmartScreen or the school's allow-list may warn or block it. If it is blocked, use the portable Python steps and do not try to bypass the control yourself — ask your local IT contact.

The macOS release file is `watson-macos-arm64` (Apple silicon). Intel Macs should use `pip` or `pipx`.

## Try it on the example site

The example site is inside Watson. It is fictional. Nothing is sent to a school.

```bash
watson --demo --output-dir watson-demo-report
```

Open `watson-demo-report/report.html` in a browser, and `report.xlsx` in Excel. You should see:

- broken links (a missing page, a removed page, and names such as `old-sponsor.invalid` that do not resolve)
- rows Watson could not verify (forbidden, server error, too many requests, and a draft path skipped because of `robots.txt`)
- redirects, including soft 404s, and one link that was written as `http://`
- stale content: a 2019 copyright, a June 2024 newsletter, 2024 term dates, and a promoted event from August 2024. A 2020 event in the "Past events" section is not flagged
- security rows for missing HTTPS, missing headers, a cookie without Secure / HttpOnly / SameSite, an old jQuery, a form that posts to `http://`, documents that have author metadata, and a count of email addresses

The example is served over plain HTTP on your computer, so the TLS rows say HTTPS is not in use. A real `https://` school site is where the certificate and HSTS checks show a real result.

The exit code is **1** because the example has broken links and High findings. That is the point of the demo.

## Check your school's public site

Only run Watson against a site your school is allowed to read. One request per second is the right default.

```bash
watson https://your-school.example.edu/ --output-dir watson-report --max-pages 100 --rate 1
```

Useful flags:

| Flag | Meaning |
| --- | --- |
| `--max-pages` | Stop after this many HTML pages (default 100). |
| `--max-depth` | How many clicks from the start page (default 3). |
| `--rate` | Requests **per second**. `1` is one per second. `2` is faster. |
| `--timeout` | Seconds to wait for each request (default 15). |
| `--output-dir` | Where to write the three report files. |
| `--no-external` | Do not request other host names. Dangling-name checks are skipped too. |
| `--checks` | `links`, `freshness`, `security`, or `all`. |
| `--australian-terms` | Day/month/year dates and Australian term language. |
| `--osv-lookup` | Opt in to OSV. Off unless you set this. |
| `--fail-on` | `high` (default), `medium`, `low`, `info`, or `none`. |
| `--config` | A TOML file. Start from `watson.example.toml`. |
| `--demo` | Example site only. Do not pass a school address with this. |

Copy `watson.example.toml`, change `start_url`, and pass `--config watson.toml`. A crawl-delay in `robots.txt` is used when it is slower than your `--rate`.

Scheduled runs can look at the exit code:

| Code | Meaning |
| --- | --- |
| 0 | Finished. No broken links, and nothing at or above `--fail-on` (default High). |
| 1 | Finished, but there is a broken link or a finding at or above `--fail-on`. |
| 2 | The command or the config file is not usable. |
| 3 | The start page could not be read. |

Medium and Low findings do not fail the command unless you set `--fail-on medium` or lower. Broken links still fail it unless you set `--fail-on none`.

## How to read the report

Three files, same information:

- `report.xlsx` — sheets **Summary**, **Broken links**, **Couldn't verify**, **Redirects & http**, **Updates & stale content**, and **Security**. Headers stay visible when you scroll, filters are on, and it is set to print on A4 landscape fitted to one page wide. URLs are plain text so a dangling name is not a live link.
- `report.html` — one file you can open offline. It does not load fonts or scripts from the internet.
- `report.json` — for a script or a scheduled task. It does not contain page HTML.

Times are your computer's local time.

**High** on the security sheet, especially HTTPS, the certificate, or a form posting over http, is something to raise. **Broken** links and stale newsletters are usually a content edit. **Couldn't verify** means "look at it in a browser" — a government site often answers 403 to tools and 200 to people.

Watson records link text so you can find the link on the page. It removes email addresses from that text. It does not try to detect every person's name. If a link or a URL contains a name, the report will contain that URL. Keep the report inside the school.

## What you can fix, and what to raise

**Fix in the content editor** when you can change the page yourself:

- a link that 404s, a soft 404, or an `http://` link that has an `https://` version
- a newsletter, news item, event, term-date page, or footer year that is out of date
- a document that still has author metadata (in Word: File → Info → Check for Issues → Inspect Document, then save a new PDF)
- an email address the school no longer wants on a public page
- an embed or old script that was pasted into a page

**Raise with your department web team or the hosting provider** when the finding says **Platform/hosting provider**:

- the site is not on HTTPS, or HTTP does not redirect to HTTPS
- the certificate is untrusted, expired, or about to expire
- HSTS and the security headers (Content-Security-Policy, framing protection, nosniff, Referrer-Policy, Permissions-Policy)
- cookie flags and server version banners
- a library that is part of the shared template rather than one page
- `security.txt`, or a sitemap that advertises a staff or admin path

Say which URL Watson checked, the severity, and the suggested fix. You do not need to attach addresses or document properties; Watson has already left those out. If you are unsure who owns the template, send the security sheet to the web team and keep the broken-link sheet for the people who edit pages.

## Privacy

- Reports store counts and locations, not email addresses, metadata values, or a list of people.
- Cookie values are not stored. You may see a cookie **name** such as `session`.
- There is no telemetry.
- The only network calls are to the site you named, DNS lookups for link targets, and — only with `--osv-lookup` — `https://api.osv.dev` with a library name and version.

## Limits

- JavaScript menus are not executed. A link that only appears after a script runs can be missed.
- Pages behind a login are not opened.
- Watson stays on the host name you gave it. `www` and the name without `www` are different hosts; links to the other one are checked, not crawled.
- Soft 404 detection is a heuristic (home page, a not-found address, or a title that says the page is missing).
- Library versions come from the script address or a short banner, not from a vulnerability scan. The OSV lookup is optional and off.
- Older `.doc` files (the binary Word format) are not inspected. PDF and DOCX are.
- This is not a departmental security assessment and it is not a penetration test.
- Large sites are slow on purpose. 100 pages at one request per second is a few minutes, plus the files those pages link to.

## Develop

```bash
pip install -e ".[dev]"
pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Tests use the local fixture only. [CHANGELOG.md](CHANGELOG.md) lists releases. The licence is [MIT](LICENSE).

Tagged releases (`v*`) build `watson-windows-x64.exe` and `watson-macos-arm64` with PyInstaller. See `.github/workflows/release.yml`.
