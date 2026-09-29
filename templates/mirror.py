from typing import List, Optional, Tuple

import httpx
from bs4 import BeautifulSoup


def _fetch(url: str) -> str:
    with httpx.Client(timeout=5.0, headers={"User-Agent": "Mozilla/5.0"}) as client:
        r = client.get(url)
        r.raise_for_status()
        return r.text

def _fetch_css_links(soup: BeautifulSoup, base_url: str) -> list[str]:
    links = []
    for link in soup.find_all("link", rel="stylesheet"):
        href = link.get("href")
        if href:
            if href.startswith("http"):
                links.append(href)
            else:
                if base_url.endswith("/") and href.startswith("/"):
                    links.append(base_url[:-1] + href)
                elif not base_url.endswith("/") and not href.startswith("/"):
                    links.append(base_url + "/" + href)
                else:
                    links.append(base_url + href)
    return links

def mirror(url: str, form_action: str | None = None) -> tuple[str, str]:
    html = _fetch(url)
    soup = BeautifulSoup(html, "html.parser")
    if form_action:
        try:
            for form in soup.find_all("form"):
                form["action"] = form_action
        except Exception:
            pass
    css_links = _fetch_css_links(soup, url)
    css_bundle = []
    with httpx.Client(timeout=5.0, headers={"User-Agent": "Mozilla/5.0"}) as client:
        for c in css_links:
            try:
                rc = client.get(c)
                if rc.status_code == 200:
                    css_bundle.append(rc.text)
            except Exception:
                pass
    css_content = "\n".join(css_bundle)
    body = soup.body
    dom = str(body) if body else html
    html_content = f"""<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>{css_content}</style></head>{dom}</html>"""
    return html_content, css_content
