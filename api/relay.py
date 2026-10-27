"""
DART Open API relay for Vercel (Seoul region / icn1).

Vercel Serverless Function (Python, stdlib only).
Deploy: push to GitHub (api/relay.py + vercel.json) -> Import in Vercel
        -> set env vars DART_API_KEY, DART_RELAY_TOKEN -> Deploy.

Security policy:
  - Bearer token (Authorization header) OR ?token= required for all
    /api/* paths. Fails closed if DART_RELAY_TOKEN is unset.
  - Only whitelisted DART API paths are proxied (anything else -> 404).
  - /api/resolve?stock_code=XXXXXX is a local endpoint (same auth):
    it fetches corpCode.xml server-side and returns only the single
    matching entry, so the ~10MB list never crosses Vercel's
    response-size limit (cache-miss fallback for the client).
  - DART API key lives only in server env vars, injected server-side.
    Never in URLs, never in logs (query strings are stripped from logs).
  - Upstream redirects are NOT followed.
"""

import hashlib
import hmac
import io
import json
import os
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler

API_KEY = os.environ.get("DART_API_KEY", "")
TOKEN = os.environ.get("DART_RELAY_TOKEN", "")

# DART Open API endpoints this relay is allowed to proxy.
ALLOWED_PATHS = {
    "/api/company.json",       # 기업개황
    "/api/list.json",          # 공시검색
    "/api/document.xml",       # 공시원문
    "/api/fnlttSinglAcnt.json",  # 단일회사 주요계정
    "/api/fnlttMultiAcnt.json",  # 다중회사 주요계정
    "/api/fnlttSinglIndx.json",  # 단일회사 주요지표
    "/api/fnlttXbrl.xml",        # XBRL 원문
    "/api/corpCode.xml",         # 고유번호 목록
}

UPSTREAM = "https://opendart.fss.or.kr"

_CACHE = {}
_CACHE_TTL = 600          # 10 min (corpCode: 24h, set per-path below)
_RATE = []
_RATE_MAX = 120           # 120 requests ...
_RATE_WIN = 60            # ... per 60 seconds (best-effort, per instance)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _corp_code_xml():
    """Fetch corpCode.xml from DART (server-side), cached 24h in memory.

    The ~10MB list is downloaded by the relay itself; callers never see
    it, so Vercel's response-size limit is never hit. Returns bytes or
    None on upstream failure.
    """
    now = time.time()
    hit = _CACHE.get("corpCode.xml")
    if hit and hit[0] > now:
        return hit[1]
    url = UPSTREAM + "/api/corpCode.xml?crtfc_key=" + API_KEY
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    opener = urllib.request.build_opener(_NoRedirect())
    try:
        resp = opener.open(req, timeout=25)
        body = resp.read()
    except Exception:
        return None
    _CACHE["corpCode.xml"] = (now + 86400, body, "application/xml")
    return body


def _find_in_corp_xml(body, stock):
    """Find one entry by stock_code in a corpCode.xml document.

    Streaming parse (iterparse + elem.clear) keeps memory low and stops
    as soon as the match is found. Returns the entry dict or None.
    """
    ctx = ET.iterparse(io.BytesIO(body), events=("end",))
    for _, elem in ctx:
        if elem.tag == "list":
            s = (elem.findtext("stock_code") or "").strip()
            if s == stock:
                code = (elem.findtext("corp_code") or "").strip()
                name = (elem.findtext("corp_name") or "").strip()
                return {"stock_code": s, "corp_code": code,
                        "corp_name": name}
            elem.clear()
    return None


class handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _handle_resolve(self, qd):
        """GET /api/resolve?stock_code=XXXXXX -> single corp_code entry.

        Local endpoint (not a DART path): fetches corpCode.xml
        server-side, returns only the matching entry as tiny JSON.
        Auth + rate limiting already applied by do_GET.
        """
        stock = (qd.get("stock_code") or "").strip()
        if not stock:
            self._send(400, '{"error":"stock_code required"}')
            return
        body = _corp_code_xml()
        if body is None:
            self._send(502, '{"error":"upstream failed"}')
            return
        try:
            entry = _find_in_corp_xml(body, stock)
        except Exception:
            self._send(502, '{"error":"upstream failed"}')
            return
        if entry is None:
            self._send(404, '{"error":"not found"}')
            return
        self._send(200, json.dumps(entry, ensure_ascii=False))

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        qd = dict(qs)

        # DART path comes from the vercel.json rewrite (?dart_path=...).
        # Direct calls without the rewrite can also pass ?dart_path=.
        dart_path = qd.get("dart_path") or parsed.path
        # /api/resolve is a local endpoint (see _handle_resolve), not a
        # DART path: it bypasses the allowlist but keeps auth + rate limit.
        is_resolve = (dart_path == "/api/resolve")
        if not is_resolve and dart_path not in ALLOWED_PATHS:
            self._send(404, '{"error":"not found"}')
            return

        # --- auth (fail closed) ---
        ok = False
        if TOKEN:
            auth = self.headers.get("Authorization", "")
            if auth.startswith("Bearer "):
                ok = hmac.compare_digest(auth[7:], TOKEN)
            if not ok:
                ok = any(hmac.compare_digest(v, TOKEN)
                         for k, v in qs if k == "token")
        if not ok:
            self._send(401, '{"error":"unauthorized"}')
            return

        # --- rate limit (best-effort per instance) ---
        now = time.time()
        while _RATE and _RATE[0] <= now - _RATE_WIN:
            _RATE.pop(0)
        if len(_RATE) >= _RATE_MAX:
            self._send(429, '{"error":"rate limited"}')
            return
        _RATE.append(now)

        if is_resolve:
            self._handle_resolve(qd)
            return

        # --- build upstream request ---
        fwd = [(k, v) for k, v in qs
               if k not in ("crtfc_key", "token", "dart_path")]
        fwd.append(("crtfc_key", API_KEY))
        query = urllib.parse.urlencode(fwd)

        # --- cache ---
        ckey = hashlib.sha256((dart_path + "?" + query).encode()).hexdigest()
        hit = _CACHE.get(ckey)
        if hit and hit[0] > now:
            self._send(200, hit[1], hit[2])
            return

        url = UPSTREAM + dart_path + "?" + query
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        opener = urllib.request.build_opener(_NoRedirect())
        try:
            resp = opener.open(req, timeout=25)
            body = resp.read()
            ctype = resp.headers.get("Content-Type",
                                     "application/json").split(";")[0]
        except Exception:
            self._send(502, '{"error":"upstream failed"}')
            return

        ttl = 86400 if dart_path == "/api/corpCode.xml" else _CACHE_TTL
        _CACHE[ckey] = (now + ttl, body, ctype)
        self._send(200, body, ctype)

    def log_message(self, *a):
        pass
