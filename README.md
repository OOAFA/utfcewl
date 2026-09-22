# utfcewl

**Unicode-aware website wordlist generator** (CeWL-style).

Crawls websites, extracts words with full Unicode support for any UTF-8
script, and produces frequency-sorted wordlists useful for:

- OSINT on Russian / Ukrainian / Belarusian / Bulgarian / Chinese / Japanese / Korean sites
- Directory & path brute-forcing (ffuf, gobuster, dirsearch, etc.)
- Username / password candidate generation
- Custom dictionaries for non-Latin-language targets

Unlike classic CeWL, `utfcewl` treats Cyrillic, CJK, and other non-Latin
scripts as first-class word characters, preserves UTF-8 correctly, and
can optionally emit Latin transliterations of Cyrillic words.

---

## Features

- Full Unicode word extraction across any UTF-8 script (Latin, Cyrillic,
  Greek, Arabic, Hebrew, Devanagari, etc.)
- Chinese (Simplified/Traditional) word segmentation via `jieba`, with
  per-character fallback for other unspaced scripts (Japanese, Korean, Thai)
- Optional GOST-style transliteration (`пароль` → `parol`)
- Depth-limited same-domain crawling
- Concurrent requests (thread pool)
- Configurable min/max word length and frequency filter
- Email extraction
- URL path-segment extraction (handy for directory wordlists)
- Meta / Open Graph / title / alt / placeholder text harvesting
- Custom headers, proxy, User-Agent, SSL verify toggle
- Clean UTF-8 output

---

## Install

```bash
cd utfcewl
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

Or install dependencies system-wide:

```bash
pip3 install -r requirements.txt
```

Make the script executable (optional):

```bash
chmod +x utfcewl.py
```

---

## Quick start

```bash
# Basic crawl of a Russian site, depth 2, min word length 4
python3 utfcewl.py https://example.ru -d 2 -m 4 -o words.txt

# With transliteration + emails + path segments
python3 utfcewl.py https://company.ru --translit --emails --paths -o russian.txt

# Deeper crawl, more threads, keep only words seen ≥ 2 times, with counts
python3 utfcewl.py https://target.ru -d 3 -t 12 --min-freq 2 --with-counts -o out.txt

# Polite crawl (delay + custom UA)
python3 utfcewl.py https://site.ru --delay 0.4 --ua "Mozilla/5.0 ..." -o safe.txt

# Behind a proxy / ignore SSL errors
python3 utfcewl.py https://internal.ru --proxy http://127.0.0.1:8080 --no-ssl-verify -o words.txt
```

---

## CLI options

| Flag | Description | Default |
|------|-------------|---------|
| `url` | Starting URL | required |
| `-d, --depth` | Max crawl depth | 2 |
| `-m, --min-word-length` | Minimum word length | 3 |
| `-x, --max-word-length` | Maximum word length | 40 |
| `-o, --output` | Output wordlist file | `utfcewl_wordlist.txt` |
| `-t, --threads` | Concurrent workers | 8 |
| `--timeout` | Request timeout (seconds) | 10 |
| `--delay` | Delay between requests (seconds) | 0 |
| `--min-freq` | Keep only words with ≥ N occurrences | 1 |
| `--with-counts` | Output `word,count` instead of plain words | off |
| `--sort-alpha` | Sort alphabetically (default is by frequency) | off |
| `--translit` | Also emit Latin transliterations of Cyrillic words | off |
| `--no-lowercase` | Keep original casing | off (lowercase) |
| `--emails` | Extract emails → `<output>.emails` | off |
| `--paths` | Extract URL path segments → `<output>.paths` | off |
| `--no-meta` | Skip meta / Open Graph content | off |
| `--ua` | Custom User-Agent | utfcewl default |
| `--header` | Extra header (`Name: Value`), repeatable | – |
| `--proxy` | HTTP/HTTPS proxy | – |
| `--no-ssl-verify` | Disable TLS certificate verification | off |
| `-v, --verbose` | Debug logging | off |

---

## Output files

- `utfcewl_wordlist.txt` (or whatever you pass to `-o`) – main wordlist, one word per line, UTF-8
- `<output>.emails` – unique email addresses (when `--emails` is used)
- `<output>.paths` – unique URL path segments (when `--paths` is used)

When `--with-counts` is enabled the main file contains lines of the form:

```
слово,42
пароль,17
admin,9
```

---

## Using the wordlist with other tools

```bash
# ffuf
ffuf -u https://target.ru/FUZZ -w russian.txt -mc 200,301,302,403

# gobuster
gobuster dir -u https://target.ru -w russian.txt -x php,html,txt

# dirsearch
python3 dirsearch.py -u https://target.ru -w russian.txt -e php,html

# hashcat / john (password candidates)
hashcat -a 0 -m 0 hashes.txt russian.txt
```

Tip: combine the path list (`*.paths`) with a general directory wordlist for better coverage on Russian sites.

---

## Transliteration notes

The built-in map follows a simplified GOST 7.79-2000 style:

| Cyrillic | Latin |
|----------|-------|
| а / А    | a / A |
| ж / Ж    | zh / Zh |
| х / Х    | kh / Kh |
| ц / Ц    | ts / Ts |
| ч / Ч    | ch / Ch |
| ш / Ш    | sh / Sh |
| щ / Щ    | shch / Shch |
| ю / Ю    | yu / Yu |
| я / Я    | ya / Ya |
| ї / Ї    | yi / Yi |
| є / Є    | ye / Ye |

You can extend `TRANSLIT_MAP` inside `utfcewl.py` if you need a different scheme (e.g. ISO 9 or passport-style).

---

## Limitations & ethics

- Same-domain only (does not follow external links).
- Does not execute JavaScript – content rendered purely client-side will be missed.
- Respect robots.txt and rate limits. Use `--delay` on production sites.
- Only crawl targets you are authorised to test.

---

## License

MIT – use freely for legitimate security research and OSINT.
