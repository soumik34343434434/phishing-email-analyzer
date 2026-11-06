"""Extract links from email bodies without fetching or rendering anything."""

from __future__ import annotations

import re
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlsplit

_URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
_DOMAIN_IN_TEXT_RE = re.compile(r"(?:https?://)?((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[/:?#]|\b)", re.IGNORECASE)


@dataclass(frozen=True)
class Link:
    url: str
    source: str  # text | href | form
    anchor_text: str = ""

    @property
    def host(self) -> str:
        return host_of(self.url)


def host_of(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def userinfo_of(url: str) -> str:
    """The 'user@' part of http://user@host/ - a classic link-obfuscation trick."""
    try:
        netloc = urlsplit(url).netloc
    except ValueError:
        return ""
    return netloc.rpartition("@")[0] if "@" in netloc else ""


def domain_in_text(text: str) -> str:
    """If visible link text looks like a URL or domain, return its host."""
    match = _DOMAIN_IN_TEXT_RE.search(text.strip())
    return match.group(1).lower() if match else ""


def defang(url: str) -> str:
    """hxxps://evil[.]example/path - safe to paste into tickets and chats."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return url.replace(".", "[.]")
    scheme = parts.scheme.replace("http", "hxxp") if parts.scheme else ""
    netloc = parts.netloc.replace(".", "[.]")
    rest = url[len(f"{parts.scheme}://{parts.netloc}"):] if parts.scheme else url
    return f"{scheme}://{netloc}{rest}" if scheme else rest.replace(".", "[.]")


class _HTMLLinkParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.text_chunks: list[str] = []
        self.has_form = False
        self.has_password_input = False
        self._href: str | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): (value or "") for name, value in attrs}
        if tag == "a" and attributes.get("href"):
            self._href = attributes["href"].strip()
            self._anchor_text = []
        elif tag == "form":
            self.has_form = True
            action = attributes.get("action", "").strip()
            if action.lower().startswith(("http://", "https://")):
                self.links.append(Link(url=action, source="form"))
        elif tag == "input" and attributes.get("type", "").lower() == "password":
            self.has_password_input = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href is not None:
            if self._href.lower().startswith(("http://", "https://")):
                self.links.append(Link(url=self._href, source="href", anchor_text="".join(self._anchor_text).strip()))
            self._href = None

    def handle_data(self, data: str) -> None:
        self.text_chunks.append(data)
        if self._href is not None:
            self._anchor_text.append(data)


@dataclass
class ExtractedLinks:
    links: list[Link]
    html_text: str
    has_form: bool
    has_password_input: bool


def extract_links(text_body: str, html_body: str) -> ExtractedLinks:
    parser = _HTMLLinkParser()
    if html_body:
        parser.feed(html_body)
        parser.close()

    links: list[Link] = list(parser.links)
    seen = {link.url for link in links}
    for url in _URL_RE.findall(text_body):
        url = url.rstrip(".,;:!")
        if url not in seen:
            links.append(Link(url=url, source="text"))
            seen.add(url)

    return ExtractedLinks(
        links=links,
        html_text=" ".join(chunk.strip() for chunk in parser.text_chunks if chunk.strip()),
        has_form=parser.has_form,
        has_password_input=parser.has_password_input,
    )
