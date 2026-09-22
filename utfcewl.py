#!/usr/bin/env python3
"""
utfcewl – Unicode-aware website wordlist generator (CeWL-style)

Crawls websites, extracts words from any UTF-8 script (Cyrillic, Latin,
CJK, and more), and builds frequency-sorted wordlists useful for OSINT,
directory brute-forcing, and password/username guessing.

Supports:
  - Full Unicode text extraction (Cyrillic, Latin, Greek, Arabic, etc.)
  - Chinese word segmentation via jieba; per-character fallback for
    other unspaced scripts (Japanese, Korean, Thai)
  - Optional transliteration (Cyrillic → Latin)
  - Depth-limited crawling with same-domain restriction
  - Configurable min/max word length and frequency filtering
  - Email, metadata, and path extraction
"""

from __future__ import annotations

import argparse
import collections
import email.utils
import html
import logging
import os
import re
import sys
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, List, Optional, Set, Tuple

import regex
import requests
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning

try:
    import jieba  # Chinese word segmentation
    jieba.setLogLevel(logging.WARNING)  # silence "Building prefix dict..." noise
    HAS_JIEBA = True
except ImportError:
    HAS_JIEBA = False

# Suppress only the single InsecureRequestWarning from urllib3
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# ---------------------------------------------------------------------------
# Constants & patterns
# ---------------------------------------------------------------------------

VERSION = "1.1.0"

# Script-aware tokenizer: Han (Chinese/Kanji) is segmented via jieba since it has
# no whitespace between words; Hiragana/Katakana/Hangul/Thai (also unspaced, but
# with no segmenter available) fall back to per-character tokens; everything else
# (Latin, Cyrillic, Greek, Arabic, Hebrew, Devanagari, ...) uses generic Unicode
# letter/digit matching, same shape as the old Latin+Cyrillic-only pattern.
SCRIPT_SEGMENT_RE = regex.compile(
    r"(?P<han>\p{Script=Han}+)"
    r"|(?P<unsegmented>[\p{Script=Hiragana}\p{Script=Katakana}\p{Script=Hangul}\p{Script=Thai}]+)"
    r"|(?P<general>[\p{L}\p{N}][\p{L}\p{N}'’\-]*[\p{L}\p{N}]|[\p{L}\p{N}])",
    regex.UNICODE,
)

EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
    re.UNICODE,
)

# Basic Cyrillic → Latin transliteration map (GOST 7.79-2000 / simplified)
# Covers Russian + common additional letters
TRANSLIT_MAP = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "yo",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "kh", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "shch",
    "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
    "А": "A", "Б": "B", "В": "V", "Г": "G", "Д": "D", "Е": "E", "Ё": "Yo",
    "Ж": "Zh", "З": "Z", "И": "I", "Й": "Y", "К": "K", "Л": "L", "М": "M",
    "Н": "N", "О": "O", "П": "P", "Р": "R", "С": "S", "Т": "T", "У": "U",
    "Ф": "F", "Х": "Kh", "Ц": "Ts", "Ч": "Ch", "Ш": "Sh", "Щ": "Shch",
    "Ъ": "", "Ы": "Y", "Ь": "", "Э": "E", "Ю": "Yu", "Я": "Ya",
    # Ukrainian / Belarusian extras
    "і": "i", "І": "I", "ї": "yi", "Ї": "Yi", "є": "ye", "Є": "Ye",
    "ґ": "g", "Ґ": "G", "ў": "u", "Ў": "U",
}

DEFAULT_UA = (
    "Mozilla/5.0 (compatible; utfcewl/{}; +https://github.com/local/utfcewl)"
).format(VERSION)

# Tags / attributes that often contain useful text or links
TEXT_TAGS = {
    "title", "h1", "h2", "h3", "h4", "h5", "h6", "p", "li", "td", "th",
    "span", "div", "a", "label", "button", "option", "legend", "caption",
    "dt", "dd", "figcaption", "blockquote", "cite", "em", "strong", "b", "i",
}

META_NAME_KEYS = {
    "description", "keywords", "author", "og:title", "og:description",
    "twitter:title", "twitter:description",
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def transliterate(text: str) -> str:
    """Convert Cyrillic characters to Latin using a simple map."""
    return "".join(TRANSLIT_MAP.get(ch, ch) for ch in text)


def normalize_word(word: str, lowercase: bool = True) -> str:
    w = word.strip()
    if lowercase:
        w = w.lower()
    return w


def is_valid_word(word: str, min_len: int, max_len: int) -> bool:
    if not word:
        return False
    length = len(word)
    if length < min_len or length > max_len:
        return False
    # Reject pure numbers if desired? Keep them – useful for years, IDs, etc.
    return True


def extract_words_from_text(
    text: str,
    min_len: int,
    max_len: int,
    lowercase: bool = True,
) -> List[str]:
    """Extract words from a plain-text string, supporting any UTF-8 script."""
    if not text:
        return []
    # Unescape HTML entities that may remain
    text = html.unescape(text)
    words: List[str] = []
    for match in SCRIPT_SEGMENT_RE.finditer(text):
        han = match.group("han")
        unsegmented = match.group("unsegmented")
        if han is not None:
            tokens = jieba.cut(han) if HAS_JIEBA else list(han)
        elif unsegmented is not None:
            tokens = list(unsegmented)
        else:
            tokens = [match.group("general")]
        for tok in tokens:
            w = normalize_word(tok, lowercase=lowercase)
            if is_valid_word(w, min_len, max_len):
                words.append(w)
    return words


def extract_emails(text: str) -> Set[str]:
    return set(EMAIL_RE.findall(text or ""))


def get_base_domain(url: str) -> str:
    """Return scheme + netloc (lowercase) for same-origin checks."""
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc.lower()}"


def normalize_url(url: str, base: str) -> Optional[str]:
    """Resolve relative URLs and strip fragments."""
    try:
        joined = urllib.parse.urljoin(base, url)
        parsed = urllib.parse.urlparse(joined)
        if parsed.scheme not in ("http", "https"):
            return None
        # Drop fragment
        cleaned = parsed._replace(fragment="").geturl()
        return cleaned
    except Exception:
        return None


def should_follow(url: str, base_domain: str, allowed_ext: Optional[Set[str]]) -> bool:
    """Decide whether a link is worth following."""
    if not url.startswith(base_domain):
        return False
    path = urllib.parse.urlparse(url).path.lower()
    if not path or path.endswith("/"):
        return True
    # Skip obvious binary / media extensions
    skip_ext = {
        ".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico",
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
        ".mp3", ".mp4", ".avi", ".mov", ".wmv", ".flv", ".mkv",
        ".css", ".js", ".woff", ".woff2", ".ttf", ".eot",
        ".exe", ".dll", ".bin", ".iso", ".dmg",
    }
    for ext in skip_ext:
        if path.endswith(ext):
            return False
    if allowed_ext:
        # If user restricted extensions, enforce them
        for ext in allowed_ext:
            if path.endswith(ext):
                return True
        return False
    return True


# ---------------------------------------------------------------------------
# Core crawler
# ---------------------------------------------------------------------------

class UtfCewl:
    def __init__(
        self,
        start_url: str,
        depth: int = 2,
        min_word_length: int = 3,
        max_word_length: int = 40,
        lowercase: bool = True,
        translit: bool = False,
        threads: int = 8,
        timeout: int = 10,
        delay: float = 0.0,
        user_agent: str = DEFAULT_UA,
        verify_ssl: bool = True,
        headers: Optional[Dict[str, str]] = None,
        proxies: Optional[Dict[str, str]] = None,
        include_emails: bool = False,
        include_meta: bool = True,
        include_paths: bool = False,
        verbose: bool = False,
    ):
        self.start_url = start_url.rstrip("/")
        self.base_domain = get_base_domain(self.start_url)
        self.depth = max(0, depth)
        self.min_word_length = min_word_length
        self.max_word_length = max_word_length
        self.lowercase = lowercase
        self.translit = translit
        self.threads = max(1, threads)
        self.timeout = timeout
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.include_emails = include_emails
        self.include_meta = include_meta
        self.include_paths = include_paths
        self.verbose = verbose

        self.session = requests.Session()
        self.session.headers.update({"User-Agent": user_agent})
        if headers:
            self.session.headers.update(headers)
        if proxies:
            self.session.proxies.update(proxies)

        self.visited: Set[str] = set()
        self.word_counts: collections.Counter = collections.Counter()
        self.emails: Set[str] = set()
        self.paths: Set[str] = set()
        self.errors: List[str] = []

        self.logger = logging.getLogger("utfcewl")
        if verbose:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)

    def _fetch(self, url: str) -> Optional[Tuple[str, str]]:
        """Return (final_url, html_text) or None on failure."""
        try:
            if self.delay > 0:
                time.sleep(self.delay)
            resp = self.session.get(
                url,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=True,
            )
            resp.raise_for_status()
            # Force UTF-8 when possible; fall back to apparent encoding
            if resp.encoding is None or resp.encoding.lower() in ("iso-8859-1", "ascii"):
                resp.encoding = resp.apparent_encoding or "utf-8"
            # Prefer UTF-8 for Cyrillic sites
            try:
                text = resp.content.decode("utf-8")
            except UnicodeDecodeError:
                text = resp.text
            return resp.url, text
        except Exception as exc:
            msg = f"Failed {url}: {exc}"
            self.errors.append(msg)
            self.logger.debug(msg)
            return None

    def _parse_page(self, url: str, html_text: str) -> Tuple[List[str], Set[str]]:
        """Extract words and discover new links from a page."""
        words: List[str] = []
        links: Set[str] = set()

        try:
            soup = BeautifulSoup(html_text, "html.parser")
        except Exception as exc:
            self.logger.debug("BeautifulSoup failed on %s: %s", url, exc)
            # Fallback: raw regex on the whole document
            words.extend(
                extract_words_from_text(
                    html_text, self.min_word_length, self.max_word_length, self.lowercase
                )
            )
            return words, links

        # --- Text content ---
        # Remove script/style noise
        for tag in soup(["script", "style", "noscript", "template"]):
            tag.decompose()

        # Visible text
        body_text = soup.get_text(separator=" ", strip=True)
        words.extend(
            extract_words_from_text(
                body_text, self.min_word_length, self.max_word_length, self.lowercase
            )
        )

        # Title
        if soup.title and soup.title.string:
            words.extend(
                extract_words_from_text(
                    soup.title.string,
                    self.min_word_length,
                    self.max_word_length,
                    self.lowercase,
                )
            )

        # Meta tags
        if self.include_meta:
            for meta in soup.find_all("meta"):
                content = meta.get("content") or ""
                name = (meta.get("name") or meta.get("property") or "").lower()
                if content and (not name or name in META_NAME_KEYS or "description" in name or "keyword" in name):
                    words.extend(
                        extract_words_from_text(
                            content,
                            self.min_word_length,
                            self.max_word_length,
                            self.lowercase,
                        )
                    )

        # Alt attributes, placeholders, titles, aria-labels
        for tag in soup.find_all(True):
            for attr in ("alt", "title", "placeholder", "aria-label", "value"):
                val = tag.get(attr)
                if val and isinstance(val, str):
                    words.extend(
                        extract_words_from_text(
                            val,
                            self.min_word_length,
                            self.max_word_length,
                            self.lowercase,
                        )
                    )

        # Emails
        if self.include_emails:
            self.emails.update(extract_emails(html_text))
            self.emails.update(extract_emails(body_text))

        # Paths (useful for directory wordlists)
        if self.include_paths:
            parsed = urllib.parse.urlparse(url)
            path = parsed.path.strip("/")
            if path:
                for part in path.split("/"):
                    part = normalize_word(part, self.lowercase)
                    if is_valid_word(part, self.min_word_length, self.max_word_length):
                        self.paths.add(part)

        # --- Link discovery ---
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
                continue
            full = normalize_url(href, url)
            if full and should_follow(full, self.base_domain, None):
                links.add(full)

        # Also consider <link>, <area>, etc.
        for tag in soup.find_all(["link", "area"], href=True):
            href = tag["href"].strip()
            full = normalize_url(href, url)
            if full and should_follow(full, self.base_domain, None):
                links.add(full)

        return words, links

    def _process_url(self, url: str, current_depth: int) -> Set[str]:
        """Fetch + parse one URL; return newly discovered links."""
        if url in self.visited:
            return set()
        self.visited.add(url)
        self.logger.debug("Crawling [d=%d]: %s", current_depth, url)

        result = self._fetch(url)
        if not result:
            return set()
        final_url, html_text = result
        # In case of redirect to another domain
        if not final_url.startswith(self.base_domain):
            return set()

        words, links = self._parse_page(final_url, html_text)
        for w in words:
            self.word_counts[w] += 1
            if self.translit:
                t = transliterate(w)
                if t != w and is_valid_word(t, self.min_word_length, self.max_word_length):
                    self.word_counts[t] += 1

        if current_depth >= self.depth:
            return set()
        return links

    def crawl(self) -> None:
        """Breadth-first crawl up to the configured depth."""
        frontier: Dict[str, int] = {self.start_url: 0}  # url → depth
        self.logger.info("Starting crawl of %s (max depth %d)", self.start_url, self.depth)

        while frontier:
            # Process current frontier level with a thread pool
            batch = list(frontier.items())
            frontier.clear()
            new_links: Dict[str, int] = {}

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                future_to_url = {
                    executor.submit(self._process_url, url, depth): (url, depth)
                    for url, depth in batch
                }
                for future in as_completed(future_to_url):
                    url, depth = future_to_url[future]
                    try:
                        discovered = future.result()
                        for link in discovered:
                            if link not in self.visited and link not in new_links:
                                new_links[link] = depth + 1
                    except Exception as exc:
                        self.logger.debug("Worker error on %s: %s", url, exc)

            frontier.update(new_links)
            self.logger.info(
                "Visited %d pages, discovered %d new links, unique words so far: %d",
                len(self.visited),
                len(new_links),
                len(self.word_counts),
            )

        self.logger.info(
            "Crawl finished. Pages: %d | Words: %d | Emails: %d | Errors: %d",
            len(self.visited),
            len(self.word_counts),
            len(self.emails),
            len(self.errors),
        )

    def get_wordlist(
        self,
        min_freq: int = 1,
        with_counts: bool = False,
        sort_by: str = "freq",  # "freq" | "alpha"
    ) -> List[str]:
        """Return the final wordlist."""
        items = [
            (w, c) for w, c in self.word_counts.items() if c >= min_freq
        ]
        if sort_by == "alpha":
            items.sort(key=lambda x: x[0])
        else:
            items.sort(key=lambda x: (-x[1], x[0]))

        if with_counts:
            return [f"{w},{c}" for w, c in items]
        return [w for w, _ in items]

    def write_output(
        self,
        path: str,
        min_freq: int = 1,
        with_counts: bool = False,
        sort_by: str = "freq",
    ) -> None:
        words = self.get_wordlist(min_freq=min_freq, with_counts=with_counts, sort_by=sort_by)
        with open(path, "w", encoding="utf-8") as f:
            for line in words:
                f.write(line + "\n")
        self.logger.info("Wrote %d words to %s", len(words), path)

        if self.include_emails and self.emails:
            email_path = path + ".emails"
            with open(email_path, "w", encoding="utf-8") as f:
                for e in sorted(self.emails):
                    f.write(e + "\n")
            self.logger.info("Wrote %d emails to %s", len(self.emails), email_path)

        if self.include_paths and self.paths:
            path_file = path + ".paths"
            with open(path_file, "w", encoding="utf-8") as f:
                for p in sorted(self.paths):
                    f.write(p + "\n")
            self.logger.info("Wrote %d path segments to %s", len(self.paths), path_file)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="utfcewl",
        description="Unicode-aware website wordlist generator (CeWL-style). "
                    "Crawls a site and extracts words from any UTF-8 script, "
                    "including Cyrillic and CJK (Chinese/Japanese/Korean).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  utfcewl https://example.ru -d 2 -m 4 -o words.txt
  utfcewl https://company.ru --translit --emails -o russian_words.txt
  utfcewl https://target.ru -d 3 -t 12 --min-freq 2 --with-counts -o out.txt
  utfcewl https://site.ru --no-ssl-verify --delay 0.5 -o safe.txt
        """,
    )
    p.add_argument("url", help="Starting URL to crawl")
    p.add_argument("-d", "--depth", type=int, default=2,
                   help="Maximum crawl depth (default: 2)")
    p.add_argument("-m", "--min-word-length", type=int, default=3,
                   help="Minimum word length (default: 3)")
    p.add_argument("-x", "--max-word-length", type=int, default=40,
                   help="Maximum word length (default: 40)")
    p.add_argument("-o", "--output", default="utfcewl_wordlist.txt",
                   help="Output file for the wordlist (default: utfcewl_wordlist.txt)")
    p.add_argument("-t", "--threads", type=int, default=8,
                   help="Number of concurrent threads (default: 8)")
    p.add_argument("--timeout", type=int, default=10,
                   help="HTTP request timeout in seconds (default: 10)")
    p.add_argument("--delay", type=float, default=0.0,
                   help="Delay between requests in seconds (default: 0)")
    p.add_argument("--min-freq", type=int, default=1,
                   help="Minimum occurrence count to keep a word (default: 1)")
    p.add_argument("--with-counts", action="store_true",
                   help="Include occurrence counts in the output (word,count)")
    p.add_argument("--sort-alpha", action="store_true",
                   help="Sort alphabetically instead of by frequency")
    p.add_argument("--translit", action="store_true",
                   help="Also emit Latin transliterations of Cyrillic words")
    p.add_argument("--no-lowercase", action="store_true",
                   help="Keep original casing (default is to lowercase)")
    p.add_argument("--emails", action="store_true",
                   help="Also extract and save email addresses")
    p.add_argument("--paths", action="store_true",
                   help="Also extract URL path segments")
    p.add_argument("--no-meta", action="store_true",
                   help="Skip meta tags / Open Graph content")
    p.add_argument("--ua", default=DEFAULT_UA,
                   help="Custom User-Agent string")
    p.add_argument("--header", action="append", default=[],
                   help="Extra header (Header: Value). Can be repeated.")
    p.add_argument("--proxy", default=None,
                   help="HTTP/HTTPS proxy (e.g. http://127.0.0.1:8080)")
    p.add_argument("--no-ssl-verify", action="store_true",
                   help="Disable SSL certificate verification")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Verbose / debug logging")
    p.add_argument("--version", action="version", version=f"utfcewl {VERSION}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Logging setup
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    # Headers
    extra_headers: Dict[str, str] = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    proxies = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    crawler = UtfCewl(
        start_url=args.url,
        depth=args.depth,
        min_word_length=args.min_word_length,
        max_word_length=args.max_word_length,
        lowercase=not args.no_lowercase,
        translit=args.translit,
        threads=args.threads,
        timeout=args.timeout,
        delay=args.delay,
        user_agent=args.ua,
        verify_ssl=not args.no_ssl_verify,
        headers=extra_headers or None,
        proxies=proxies,
        include_emails=args.emails,
        include_meta=not args.no_meta,
        include_paths=args.paths,
        verbose=args.verbose,
    )

    try:
        crawler.crawl()
    except KeyboardInterrupt:
        logging.warning("Interrupted by user – writing partial results")
    except Exception as exc:
        logging.error("Crawl failed: %s", exc)
        return 1

    sort_by = "alpha" if args.sort_alpha else "freq"
    crawler.write_output(
        path=args.output,
        min_freq=args.min_freq,
        with_counts=args.with_counts,
        sort_by=sort_by,
    )

    # Also print a short summary to stdout
    top = crawler.get_wordlist(min_freq=args.min_freq, with_counts=True, sort_by="freq")[:15]
    if top:
        print("\nTop words:")
        for line in top:
            print(f"  {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
