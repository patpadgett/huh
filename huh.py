#!/usr/bin/env python3
"""huh - what is this string?

Offline, read-only, zero dependencies. Give it a number, a token, a date, a
cron line, a mode, a hash, a colour, an address - anything you would
otherwise open a browser tab to decode - and it prints the plausible
readings, ranked, each with the conversions you came for and the plain Unix
one-liner (the "receipt") that would have told you the same thing.

    huh 1696500000              huh '0 */4 * * 1-5'         huh -rwxr-xr-x
    huh eyJhbGciOiJIUzI1Ni...   huh 137                     huh 10.0.0.0/22
    pbpaste | huh               huh                         (bare: reads the clipboard)

It never writes anything, never touches the network, and never runs the
receipts - it only prints them.
"""
from __future__ import annotations

import argparse
import ast
import base64
import binascii
import calendar
import colorsys
import datetime as dt
import email.utils
import errno as errno_mod
import html
import http
import ipaddress
import json
import math
import mimetypes
import operator
import os
import re
import shlex
import shutil
import signal as signal_mod
import stat
import struct
import subprocess
import sys
import time
import unicodedata
import urllib.parse
import uuid as uuid_mod
from dataclasses import dataclass, field
from typing import Callable, Iterable
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

__version__ = "0.1.0"

MAX_INPUT = 64 * 1024   # bytes accepted from argv, stdin or the clipboard
MAX_DEPTH = 3           # base64 -> JSON -> epoch is depth 3
MAX_DECODES = 48        # total decode() calls per run, nested ones included
SHOW_DEFAULT = 5        # readings printed without --all
CLIP_TIMEOUT = 2.0      # seconds allowed per clipboard command
GIT_TIMEOUT = 2.0       # seconds allowed per git command
UTC = dt.timezone.utc


# ---------------------------------------------------------------------------
# core types
# ---------------------------------------------------------------------------

@dataclass
class Reading:
    """One possible interpretation of the input."""
    kind: str
    confidence: float           # 0..1, a ranking heuristic - not a probability
    summary: str                # one line, already safe to print
    lines: list[str] = field(default_factory=list)      # details, one per line
    receipt: str | None = None  # the shell command that reproduces the answer; never executed
    children: list["Reading"] = field(default_factory=list)  # readings of decoded content
    data: dict = field(default_factory=dict)            # machine-readable extras for --json
    via: str = ""               # for children: where inside the parent this was found (a JSON path, a query key)

    def tier(self) -> str:
        if self.confidence >= 0.75:
            return "likely"
        return "maybe" if self.confidence >= 0.4 else "unlikely"

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "confidence": round(self.confidence, 2),
            "summary": self.summary,
            "details": list(self.lines),
            "receipt": self.receipt,
            "data": self.data,
            "via": self.via or None,
            "children": [c.to_dict() for c in self.children],
        }


@dataclass
class Context:
    now: dt.datetime                 # timezone-aware "current" instant
    zones: list[dt.tzinfo]           # display zones; the first one is primary
    depth: int = 0
    budget: list[int] = field(default_factory=lambda: [MAX_DECODES])

    @property
    def zone(self) -> dt.tzinfo:
        return self.zones[0]

    def child(self) -> "Context":
        return Context(self.now, self.zones, self.depth + 1, self.budget)


Detector = Callable[[str, Context], "Iterable[Reading] | None"]
DETECTORS: list[Detector] = []


def detector(fn: Detector) -> Detector:
    DETECTORS.append(fn)
    return fn


def decode(text: str, ctx: Context) -> list[Reading]:
    """Every reading of *text*, best first. Detector bugs are contained, never fatal."""
    if len(text.encode("utf-8", "surrogatepass")) > MAX_INPUT:
        raise ValueError(f"input is larger than {MAX_INPUT // 1024} KiB")
    if ctx.budget[0] <= 0:
        return []
    ctx.budget[0] -= 1
    s = text.strip(" \t\r\n")  # not str.strip(): that would also eat \x1f, the first byte of gzip's magic
    if not s:
        return []
    out: list[Reading] = []
    for det in DETECTORS:
        try:
            out.extend(det(s, ctx) or ())
        except Exception:  # noqa: BLE001 - one detector must not hide the others
            if os.environ.get("HUH_DEBUG"):
                raise
    out.sort(key=lambda r: -r.confidence)
    return out


def nested(text: str, ctx: Context, minimum: float = 0.6, limit: int = 3) -> list[Reading]:
    """Readings of decoded content, for recursion (base64 -> JSON -> epoch)."""
    if ctx.depth + 1 >= MAX_DEPTH or ctx.budget[0] <= 0 or len(text) > 8192:
        return []
    return [r for r in decode(text, ctx.child()) if r.confidence >= minimum][:limit]


# ---------------------------------------------------------------------------
# text helpers
# ---------------------------------------------------------------------------

_UNSAFE = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}


def clean(s: str) -> str:
    """Untrusted text made safe for a terminal: controls, bidi/zero-width format characters
    and surrogates become escapes. Nothing that could be an ANSI sequence gets through."""
    out = []
    for ch in s:
        if ch == " " or unicodedata.category(ch) not in _UNSAFE:
            out.append(ch)
        else:
            cp = ord(ch)
            out.append(f"\\x{cp:02x}" if cp < 0x100 else f"\\u{cp:04x}" if cp < 0x10000 else f"\\U{cp:08x}")
    return "".join(out)


def preview(s: str, n: int = 72) -> str:
    s = clean(s.replace("\r\n", "\n").replace("\n", "\\n").replace("\t", "\\t"))
    return s if len(s) <= n else s[: n - 3] + "..."


def q(s: str) -> str:
    """Shell-safe literal for receipts."""
    return shlex.quote(s)


def printf_literal(s: str) -> str:
    """A printf command reproducing *s* byte for byte, even when it holds invisible characters
    (so a receipt stays copy-pasteable instead of carrying the invisible bytes)."""
    if s and all(32 <= ord(c) < 127 for c in s):
        return "printf %s " + q(s)
    parts = []
    for ch in s:
        cp = ord(ch)
        if 32 <= cp < 127 and ch not in "\\'%":
            parts.append(ch)
        elif ch == "%":
            parts.append("%%")
        elif ch == "\\":
            parts.append("\\\\")
        elif ch == "'":
            parts.append("'\\''")
        elif cp < 0x10000:
            parts.append(f"\\u{cp:04x}")
        else:
            parts.append(f"\\U{cp:08x}")
    return "printf '" + "".join(parts) + "'"


def commas(n: int) -> str:
    return f"{n:,}"


def plural(n: int, word: str) -> str:
    return f"{commas(n)} {word}" + ("" if n == 1 else "s")


def hexdump(data: bytes, n: int = 16) -> str:
    return " ".join(f"{b:02x}" for b in data[:n]) + (" ..." if len(data) > n else "")


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def text_or_none(data: bytes) -> str | None:
    """The bytes as text, if they are well-formed UTF-8 without stray control characters."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text or any(unicodedata.category(c) == "Cc" and c not in "\n\r\t" for c in text):
        return None
    return text


MAGIC = (
    (0, b"\x1f\x8b", "gzip data"), (0, b"PK\x03\x04", "zip archive (also docx/xlsx/jar/apk)"),
    (0, b"\x89PNG", "PNG image"), (0, b"\xff\xd8\xff", "JPEG image"), (0, b"GIF8", "GIF image"),
    (0, b"%PDF", "PDF document"), (0, b"\x7fELF", "ELF executable"), (0, b"BZh", "bzip2 data"),
    (0, b"\xfd7zXZ\x00", "xz data"), (0, b"\x28\xb5\x2f\xfd", "zstd data"), (0, b"OggS", "Ogg media"),
    (0, b"RIFF", "RIFF container (WAV/AVI/WebP)"), (4, b"ftyp", "MP4/MOV media"),
    (0, b"\xca\xfe\xba\xbe", "Java class or Mach-O fat binary"), (0, b"MZ", "Windows PE executable"),
    (0, b"SQLite format 3", "SQLite database"), (0, b"\x30\x82", "ASN.1 DER (certificate or key)"),
    (0, b"x\x9c", "zlib data"), (0, b"x\x01", "zlib data"), (0, b"x\xda", "zlib data"),
    (0, b"\xef\xbb\xbf", "UTF-8 text with BOM"), (0, b"\xff\xfe", "UTF-16 LE text"),
    (0, b"\xfe\xff", "UTF-16 BE text"), (257, b"ustar", "tar archive"), (0, b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (0, b"Rar!", "RAR archive"), (0, b"\x00asm", "WebAssembly module"), (0, b"#!", "script with a shebang"),
)


def magic(data: bytes) -> str | None:
    for offset, sig, name in MAGIC:
        if data[offset:offset + len(sig)] == sig:
            return name
    return None


# ---------------------------------------------------------------------------
# time helpers
# ---------------------------------------------------------------------------

def zone_key(z: dt.tzinfo) -> str:
    key = getattr(z, "key", None) or str(z)
    return "UTC" if key in ("Etc/UTC", "Etc/GMT", "Etc/Zulu", "Etc/Universal", "Etc/UCT", "Zulu", "Universal", "UCT", "GMT", "GMT0", "Etc/Greenwich", "Greenwich") else key


def offset_str(off: dt.timedelta | None) -> str:
    if off is None:
        return "?"
    total = int(off.total_seconds())
    sign = "+" if total >= 0 else "-"
    h, m = divmod(abs(total) // 60, 60)
    return f"UTC{sign}{h:02d}:{m:02d}"


def zone_label(d: dt.datetime) -> str:
    """'UTC', 'EDT', or 'UTC+05:30' when the zone has no usable abbreviation."""
    name = d.tzname() or ""
    off = d.utcoffset()
    if off == dt.timedelta(0) and name in ("", "UTC", "GMT", "Z", "Etc/UTC", "Zulu", "UCT"):
        return "UTC"
    if name and not re.fullmatch(r"[+-]\d{2}:?\d{2}|UTC[+-].*", name):
        return name
    return offset_str(off)


def fmt(d: dt.datetime, zone: dt.tzinfo | None = None, seconds: bool = True, nanos: int | None = None) -> str:
    """'Thu 2023-10-05 10:00:00 UTC' (with the fraction when there is one)."""
    if zone is not None:
        d = d.astimezone(zone)
    text = d.strftime("%a %Y-%m-%d %H:%M:%S" if seconds else "%a %Y-%m-%d %H:%M")
    if seconds:
        if nanos is not None and nanos:
            text += ("." + f"{nanos:09d}").rstrip("0")
        elif d.microsecond:
            text += ("." + f"{d.microsecond:06d}").rstrip("0")
    return f"{text} {zone_label(d)}"


def iso(d: dt.datetime) -> str:
    d = d.astimezone(UTC)
    text = d.strftime("%Y-%m-%dT%H:%M:%S")
    if d.microsecond:
        text += ("." + f"{d.microsecond:06d}").rstrip("0")
    return text + "Z"


def relative(then: dt.datetime, now: dt.datetime) -> str:
    secs = (then - now).total_seconds()
    a = abs(secs)
    if a < 1:
        return "now"
    if a < 60:
        text = plural(int(a), "second")
    elif a < 3600:
        text = plural(int(a // 60), "minute")
    elif a < 86400:
        h, m = divmod(int(a // 60), 60)
        text = f"{h}h {m:02d}m"
    elif a < 86400 * 30:
        text = plural(int(a // 86400), "day")
    elif a < 86400 * 365.25:
        text = plural(max(1, int(a // (86400 * 30.44))), "month")
    else:
        y = int(a // (86400 * 365.25))
        mo = int((a - y * 86400 * 365.25) // (86400 * 30.44))
        text = plural(y, "year") + (f" {plural(mo, 'month')}" if mo and y < 10 else "")
    return f"{text} ago" if secs < 0 else f"in {text}"


def human_duration(seconds: float) -> str:
    """'17d 18h 40m', '1h 30m', '2m 17s', '1.5s', '250ms'."""
    if seconds < 0:
        return "-" + human_duration(-seconds)
    if seconds == 0:
        return "0s"
    if seconds < 1:
        if seconds >= 1e-3:
            return f"{seconds * 1e3:g}ms"
        if seconds >= 1e-6:
            return f"{seconds * 1e6:g}us"
        return f"{seconds * 1e9:g}ns"
    if seconds < 60:
        return f"{seconds:g}s"
    whole = int(seconds)
    frac = seconds - whole
    parts = []
    for unit, size in (("y", 31557600), ("d", 86400), ("h", 3600), ("m", 60)):
        if whole >= size:
            parts.append(f"{whole // size}{unit}")
            whole %= size
    if whole or (frac and seconds < 3600):
        parts.append(f"{whole + frac:.3g}s" if frac and seconds < 3600 else f"{whole}s")
    return " ".join(parts[:4])


def zone_lines(d: dt.datetime, ctx: Context, skip_offset: dt.timedelta | None = None,
               nanos: int | None = None) -> list[str]:
    """The instant in each display zone, except zones that would repeat a line already shown."""
    lines = []
    shown = {skip_offset} if skip_offset is not None else set()
    for z in ctx.zones:
        local = d.astimezone(z)
        if local.utcoffset() in shown:
            continue
        shown.add(local.utcoffset())
        lines.append(f"{fmt(local, nanos=nanos)}  ({zone_key(z)})")
    return lines


def local_zone() -> dt.tzinfo:
    """The system zone as an IANA zone when it can be identified, else a fixed offset."""
    candidates = []
    tz = os.environ.get("TZ", "").lstrip(":")
    if tz:
        candidates.append(tz)
    try:
        link = os.path.realpath("/etc/localtime")
        if "zoneinfo/" in link:
            candidates.append(link.split("zoneinfo/", 1)[1])
    except OSError:
        pass
    try:
        with open("/etc/timezone", encoding="utf-8") as fh:
            candidates.append(fh.read().strip())
    except OSError:
        pass
    for name in candidates:
        try:
            return ZoneInfo(name)
        except (ZoneInfoNotFoundError, ValueError, OSError):
            continue
    return dt.datetime.now().astimezone().tzinfo or UTC


# abbreviation -> (IANA zone for conversions, fixed offset in minutes or None, meaning, ambiguity)
TZ_ABBR: dict[str, tuple[str, int | None, str, str | None]] = {
    "UTC": ("UTC", 0, "Coordinated Universal Time", None),
    "GMT": ("Etc/GMT", 0, "Greenwich Mean Time", None),
    "Z": ("UTC", 0, "Zulu time = UTC", None),
    "EST": ("America/New_York", -300, "Eastern Standard Time (North America)", None),
    "EDT": ("America/New_York", -240, "Eastern Daylight Time (North America)", None),
    "ET": ("America/New_York", None, "Eastern Time (EST or EDT, whichever is in effect)", None),
    "CST": ("America/Chicago", -360, "Central Standard Time (North America)",
            "also China Standard Time (UTC+08:00) and Cuba Standard Time (UTC-05:00)"),
    "CDT": ("America/Chicago", -300, "Central Daylight Time (North America)", "also Cuba Daylight Time (UTC-04:00)"),
    "CT": ("America/Chicago", None, "Central Time (North America)", None),
    "MST": ("America/Denver", -420, "Mountain Standard Time", "Arizona (America/Phoenix) stays on MST all year"),
    "MDT": ("America/Denver", -360, "Mountain Daylight Time", None),
    "MT": ("America/Denver", None, "Mountain Time", None),
    "PST": ("America/Los_Angeles", -480, "Pacific Standard Time (North America)", "also Philippine Standard Time (UTC+08:00)"),
    "PDT": ("America/Los_Angeles", -420, "Pacific Daylight Time", None),
    "PT": ("America/Los_Angeles", None, "Pacific Time", None),
    "AKST": ("America/Anchorage", -540, "Alaska Standard Time", None),
    "AKDT": ("America/Anchorage", -480, "Alaska Daylight Time", None),
    "HST": ("Pacific/Honolulu", -600, "Hawaii Standard Time", None),
    "AST": ("America/Halifax", -240, "Atlantic Standard Time", "also Arabia Standard Time (UTC+03:00)"),
    "ADT": ("America/Halifax", -180, "Atlantic Daylight Time", None),
    "NST": ("America/St_Johns", -210, "Newfoundland Standard Time", None),
    "NDT": ("America/St_Johns", -150, "Newfoundland Daylight Time", None),
    "BST": ("Europe/London", 60, "British Summer Time", "also Bangladesh Standard Time (UTC+06:00)"),
    "IST": ("Asia/Kolkata", 330, "India Standard Time", "also Irish Standard Time (UTC+01:00) and Israel Standard Time (UTC+02:00)"),
    "WET": ("Europe/Lisbon", 0, "Western European Time", None),
    "WEST": ("Europe/Lisbon", 60, "Western European Summer Time", None),
    "CET": ("Europe/Paris", 60, "Central European Time", None),
    "CEST": ("Europe/Paris", 120, "Central European Summer Time", None),
    "EET": ("Europe/Athens", 120, "Eastern European Time", None),
    "EEST": ("Europe/Athens", 180, "Eastern European Summer Time", None),
    "MSK": ("Europe/Moscow", 180, "Moscow Time", None),
    "TRT": ("Europe/Istanbul", 180, "Turkey Time", None),
    "GST": ("Asia/Dubai", 240, "Gulf Standard Time", None),
    "PKT": ("Asia/Karachi", 300, "Pakistan Standard Time", None),
    "ICT": ("Asia/Bangkok", 420, "Indochina Time", None),
    "WIB": ("Asia/Jakarta", 420, "Western Indonesia Time", None),
    "WITA": ("Asia/Makassar", 480, "Central Indonesia Time", None),
    "WIT": ("Asia/Jayapura", 540, "Eastern Indonesia Time", None),
    "SGT": ("Asia/Singapore", 480, "Singapore Time", None),
    "HKT": ("Asia/Hong_Kong", 480, "Hong Kong Time", None),
    "PHT": ("Asia/Manila", 480, "Philippine Time", None),
    "AWST": ("Australia/Perth", 480, "Australian Western Standard Time", None),
    "JST": ("Asia/Tokyo", 540, "Japan Standard Time", None),
    "KST": ("Asia/Seoul", 540, "Korea Standard Time", None),
    "ACST": ("Australia/Adelaide", 570, "Australian Central Standard Time", None),
    "ACDT": ("Australia/Adelaide", 630, "Australian Central Daylight Time", None),
    "AEST": ("Australia/Sydney", 600, "Australian Eastern Standard Time", None),
    "AEDT": ("Australia/Sydney", 660, "Australian Eastern Daylight Time", None),
    "AET": ("Australia/Sydney", None, "Australian Eastern Time", None),
    "NZST": ("Pacific/Auckland", 720, "New Zealand Standard Time", None),
    "NZDT": ("Pacific/Auckland", 780, "New Zealand Daylight Time", None),
    "SAST": ("Africa/Johannesburg", 120, "South Africa Standard Time", None),
    "EAT": ("Africa/Nairobi", 180, "East Africa Time", None),
    "WAT": ("Africa/Lagos", 60, "West Africa Time", None),
    "CAT": ("Africa/Maputo", 120, "Central Africa Time", None),
    "BRT": ("America/Sao_Paulo", -180, "Brasilia Time", None),
    "ART": ("America/Argentina/Buenos_Aires", -180, "Argentina Time", None),
    "CLT": ("America/Santiago", -240, "Chile Standard Time", None),
    "COT": ("America/Bogota", -300, "Colombia Time", None),
    "PET": ("America/Lima", -300, "Peru Time", None),
}

OFFSET_RE = re.compile(r"(?:UTC|GMT)?\s*([+-])(\d{1,2})(?::?(\d{2}))?", re.I)


def resolve_zone(token: str) -> tuple[dt.tzinfo, str, list[str]] | None:
    """tzinfo for an IANA name, an abbreviation, or an offset: (tz, label, notes)."""
    t = token.strip()
    if not t:
        return None
    if "/" in t or t in ("UTC", "GMT", "Zulu", "Z", "UCT", "Universal"):
        name = {"Z": "UTC", "Zulu": "UTC"}.get(t, t)
        try:
            return ZoneInfo(name), name, []
        except (ZoneInfoNotFoundError, ValueError, OSError):
            return None
    m = OFFSET_RE.fullmatch(t)
    if m:
        sign, hh, mm = m.groups()
        if int(hh) > 14 or int(mm or 0) > 59:
            return None
        off = dt.timedelta(minutes=(int(hh) * 60 + int(mm or 0)) * (1 if sign == "+" else -1))
        return dt.timezone(off), offset_str(off), []
    info = TZ_ABBR.get(t.upper())
    if info:
        zone_name, fixed, meaning, note = info
        notes = [f"{t.upper()} = {meaning}"] + ([f"ambiguous: {note}"] if note else [])
        if fixed is None:
            return ZoneInfo(zone_name), t.upper(), notes
        return dt.timezone(dt.timedelta(minutes=fixed), t.upper()), t.upper(), notes
    return None


_CANONICAL_ZONES: list[str] | None = None


def canonical_zones() -> list[str]:
    """IANA zones worth listing: Area/Location names, no legacy aliases."""
    global _CANONICAL_ZONES
    if _CANONICAL_ZONES is None:
        skip = ("Etc/", "SystemV/", "US/", "Canada/", "Mexico/", "Chile/", "Brazil/", "posix/", "right/")
        _CANONICAL_ZONES = sorted(z for z in available_timezones()
                                  if "/" in z and not z.startswith(skip) and z not in ("GMT0", "UTC"))
    return _CANONICAL_ZONES


# == DETECTORS: time ==

EPOCH_UNITS = (
    ("epoch seconds", 1, "s"), ("epoch millis", 10**3, "ms"),
    ("epoch micros", 10**6, "us"), ("epoch nanos", 10**9, "ns"),
)


def epoch_receipt(value: str, divisor: int, zone: dt.tzinfo) -> str:
    if divisor == 1:
        secs = value
    else:
        secs = f"{int(value) // divisor}.{int(value) % divisor:0{len(str(divisor)) - 1}d}".rstrip("0").rstrip(".")
    base = f"date -u -d @{secs}" if divisor == 1 else f"date -u -d @{secs} '+%F %T.%N %Z'"
    key = zone_key(zone)
    if key not in ("UTC", "Etc/UTC") and "/" in key:
        return f"{base}   # local: TZ={q(key)} date -d @{secs}"
    return base


@detector
def detect_epoch(s: str, ctx: Context):
    m = re.fullmatch(r"[+-]?(\d{1,20})(?:\.(\d{1,9}))?", s)
    if not m:
        return None
    whole_digits, frac_digits = m.group(1), m.group(2)
    negative = s.startswith("-")
    whole = int(whole_digits)
    if whole == 0 and not frac_digits:
        return None
    out = []
    unlikely = []
    for kind, divisor, unit in EPOCH_UNITS:
        if frac_digits and divisor != 1:
            continue  # a decimal point means seconds
        nanos_total = whole * (10**9 // divisor) + (int(frac_digits.ljust(9, "0")) if frac_digits else 0)
        if negative:
            nanos_total = -nanos_total
        secs, nanos = divmod(nanos_total, 10**9)
        try:
            d = dt.datetime(1970, 1, 1, tzinfo=UTC) + dt.timedelta(seconds=secs, microseconds=nanos // 1000)
        except (OverflowError, ValueError):
            continue
        year = d.year
        distance = abs((d - ctx.now).total_seconds())
        # Plausibility: how close to "now" the reading lands, and whether the digit count fits the unit.
        if distance < 86400 * 365.25 * 30:
            conf = 0.95
        elif 1980 <= year <= ctx.now.year + 30:
            conf = 0.55
        elif 1970 <= year < 1980:
            conf = 0.25
        else:
            conf = 0.1
        expected_digits = {1: (9, 11), 10**3: (12, 14), 10**6: (15, 17), 10**9: (18, 20)}[divisor]
        if not expected_digits[0] <= len(whole_digits) <= expected_digits[1]:
            conf = min(conf, 0.25)
        if len(whole_digits) < 6:
            conf = min(conf, 0.12)  # "137" is not a date
        digits_note = f"{plural(len(whole_digits), 'digit')}, read as {unit} since 1970-01-01 UTC"
        local = d.astimezone(ctx.zone)
        show_nanos = nanos if divisor >= 10**6 else None
        receipt = epoch_receipt(whole_digits if not negative else "-" + whole_digits, divisor, ctx.zone)
        if conf < 0.4:
            unlikely.append((conf, kind, unit, d, local, show_nanos, receipt, digits_note))
            continue
        lines = zone_lines(d, ctx, skip_offset=local.utcoffset(), nanos=show_nanos)
        lines.append(f"ISO {iso(d)}  -  {digits_note}")
        out.append(Reading(kind, conf, f"{fmt(local, nanos=show_nanos)}, {relative(d, ctx.now)}", lines, receipt,
                           data={"iso": iso(d), "unit": unit, "seconds": secs}))
    if unlikely and not out:
        # Nothing plausible: one compact reading instead of four lines of 1970.
        unlikely.sort(key=lambda u: -u[0])
        conf, kind, unit, d, local, show_nanos, receipt, digits_note = unlikely[0]
        others = ", ".join(f"{fmt(u[4], seconds=False)} as {u[2]}" for u in unlikely[1:3])
        lines = [digits_note + f"; {len(unlikely)} unit readings all land in {'1970' if all(u[3].year == 1970 for u in unlikely) else 'implausible years'}"]
        if others:
            lines.append(f"other units: {others}")
        out.append(Reading(kind, conf, f"{fmt(local, nanos=show_nanos)} if {unit} - unlikely", lines, receipt,
                           data={"iso": iso(d), "unit": unit}))
    # Windows FILETIME: 100 ns ticks since 1601-01-01, 18 digits around now.
    if len(whole_digits) == 18 and not frac_digits and not negative:
        secs = whole / 10**7 - 11644473600
        try:
            d = dt.datetime.fromtimestamp(secs, UTC)
            if 1990 <= d.year <= 2100:
                out.append(Reading("epoch seconds", 0.5, f"Windows FILETIME: {fmt(d, ctx.zone)}, {relative(d, ctx.now)}",
                                   [*zone_lines(d, ctx), "100-nanosecond ticks since 1601-01-01 (NTFS, Active Directory, .NET)"],
                                   f"date -u -d @$(( ({whole_digits} - 116444736000000000) / 10000000 ))",
                                   data={"iso": iso(d), "unit": "filetime"}))
        except (OverflowError, ValueError, OSError):
            pass
    return out


DATE_FORMATS = (
    ("%Y-%m-%d %H:%M:%S", False), ("%Y-%m-%d %H:%M", False), ("%Y/%m/%d %H:%M:%S", False), ("%Y/%m/%d", False),
    ("%Y%m%dT%H%M%SZ", True), ("%Y%m%dT%H%M%S", False), ("%Y%m%d%H%M%S", False), ("%Y%m%d", False),
    ("%d %b %Y", False), ("%d %B %Y", False), ("%b %d %Y", False), ("%B %d %Y", False), ("%b %d, %Y", False),
    ("%B %d, %Y", False), ("%d %b %Y %H:%M:%S", False), ("%b %d %Y %H:%M:%S", False), ("%b %d, %Y %H:%M:%S", False),
    ("%a %b %d %H:%M:%S %Y", False), ("%a %b %d %H:%M:%S %Z %Y", True), ("%a %b %d %H:%M:%S %z %Y", True),
    ("%a, %d %b %Y %H:%M:%S %Z", True), ("%d/%b/%Y:%H:%M:%S %z", True), ("%d/%b/%Y:%H:%M:%S", False),
    ("%Y-%m-%dT%H:%M:%S%z", True), ("%Y-%m-%d %H:%M:%S%z", True), ("%Y-%m-%d %H:%M:%S %z", True),
    ("%Y-%m-%d %H:%M:%S.%f", False), ("%Y-%m-%d %H:%M:%S,%f", False), ("%m/%d/%Y", False), ("%m/%d/%Y %H:%M", False),
    ("%m/%d/%Y %H:%M:%S", False), ("%m/%d/%y", False), ("%d.%m.%Y", False), ("%d.%m.%Y %H:%M", False),
    ("%d-%m-%Y", False), ("%Y-%j", False), ("%Y-W%W-%w", False), ("%Y-%m", False), ("%b %Y", False), ("%B %Y", False),
    ("%d %b %Y %H:%M", False), ("%Y-%m-%dT%H:%M", False), ("%Y-%m-%d %H:%M:%S %Z", True),
)

_DATE_HINT = re.compile(r"\d{4}|\d{1,2}[/.-]\d{1,2}|(?i:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)")


def parse_date(s: str) -> tuple[dt.datetime, str, bool] | None:
    """(datetime, how-it-was-read, had-explicit-zone). Naive results are returned naive."""
    text = s.strip()
    if not _DATE_HINT.search(text) or len(text) > 64:
        return None
    # Trailing zone words we understand: "2024-01-01 09:00 EST", "... Asia/Tokyo"
    zone_note = None
    tz: dt.tzinfo | None = None
    m = re.fullmatch(r"(.*\d)\s+([A-Za-z]{1,5}|[A-Za-z]+/[A-Za-z_]+(?:/[A-Za-z_]+)?)", text)
    if m and m.group(2).upper() not in ("AM", "PM", "T"):
        resolved = resolve_zone(m.group(2))
        if resolved:
            tz, zone_note, _ = resolved
            text = m.group(1)
    iso_text = text.replace(" ", "T", 1) if re.fullmatch(r"\d{4}-\d{2}-\d{2} \d.*", text) else text
    if iso_text.endswith(("Z", "z")):
        iso_text = iso_text[:-1] + "+00:00"
    parsed = None
    how = ""
    try:
        parsed = dt.datetime.fromisoformat(iso_text)
        how = "ISO 8601"
    except ValueError:
        pass
    if parsed is None:
        try:
            parsed = email.utils.parsedate_to_datetime(text)
            how = "RFC 2822 (email/HTTP date)"
        except (TypeError, ValueError, IndexError, OverflowError):
            parsed = None
    if parsed is None:
        for pattern, _ in DATE_FORMATS:
            try:
                parsed = dt.datetime.strptime(text, pattern)
                how = "strptime " + pattern
                break
            except ValueError:
                continue
    if parsed is None:
        return None
    if tz is not None and parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=tz)
        how += f", zone {zone_note}"
    return parsed, how, parsed.tzinfo is not None


def date_receipt(s: str, zone: dt.tzinfo, aware: bool) -> str:
    key = zone_key(zone)
    core = q(s)
    if aware or key in ("UTC", "Etc/UTC"):
        return f"date -u -d {core}; date -d {core} +%s"
    return f"TZ={q(key)} date -d {core}; TZ={q(key)} date -d {core} +%s"


@detector
def detect_date(s: str, ctx: Context):
    if re.fullmatch(r"[+-]?\d+(?:\.\d+)?", s) and not re.fullmatch(r"(19|20)\d{6}", s):
        return None  # plain numbers belong to the epoch detector; 20231005 is also a date
    parsed = parse_date(s)
    if not parsed:
        return None
    d, how, aware = parsed
    lines = [f"read as {how}"]
    conf = 0.9 if aware else 0.8
    if "strptime" in how and re.fullmatch(r"\d{8}", s):
        conf = 0.6
    if not aware:
        # A naive timestamp: show it both as the primary zone's wall time and as UTC.
        primary = d.replace(tzinfo=ctx.zone)
        try:
            as_utc = primary.astimezone(UTC)
        except (OverflowError, ValueError):
            return None
        back = as_utc.astimezone(ctx.zone).replace(tzinfo=None)
        if back != d:
            lines.append(f"{d:%Y-%m-%d %H:%M} does not exist in {zone_key(ctx.zone)}: clocks jumped forward over it (DST gap); "
                         f"the next real instant is {fmt(as_utc.astimezone(ctx.zone))}")
        elif d.replace(tzinfo=ctx.zone, fold=1).utcoffset() != primary.utcoffset():
            second = d.replace(tzinfo=ctx.zone, fold=1)
            lines.append(f"ambiguous in {zone_key(ctx.zone)}: this wall time happens twice (clocks fall back) - "
                         f"{fmt(primary)} = {iso(primary)} and {fmt(second)} = {iso(second)}")
        else:
            lines.append(f"no zone given; if {zone_key(ctx.zone)}: {fmt(primary)} = {iso(as_utc)}")
        if ctx.zone.utcoffset(d) != dt.timedelta(0):
            as_if_utc = d.replace(tzinfo=UTC)
            lines.append(f"if UTC: {fmt(as_if_utc.astimezone(ctx.zone))}")
        instant = primary
    else:
        instant = d
        lines.extend(zone_lines(d, ctx, skip_offset=None))
        lines.append(f"ISO {iso(d)}")
    epoch = int(instant.timestamp())
    lines.append(f"epoch {epoch}, {relative(instant, ctx.now)}")
    doy = instant.timetuple().tm_yday
    week = instant.isocalendar()[1]
    lines.append(f"{instant.strftime('%A')}, day {doy} of {instant.year}, ISO week {week}")
    summary = f"{fmt(instant, ctx.zone) if aware else fmt(instant)}, {relative(instant, ctx.now)}"
    if not aware:
        summary = f"{fmt(d.replace(tzinfo=ctx.zone))} (zone assumed), {relative(instant, ctx.now)}"
    return [Reading("date", conf, summary, lines, date_receipt(s, ctx.zone, aware),
                    data={"iso": iso(instant), "epoch": epoch, "zone_given": aware})]


@detector
def detect_time_of_day(s: str, ctx: Context):
    """'14:00 UTC', '9:30pm EST', '15:00 Asia/Tokyo', 'noon PST' -> that wall time today, everywhere."""
    text = s
    words = {"noon": "12:00", "midnight": "00:00", "midday": "12:00"}
    m_word = re.fullmatch(r"(noon|midnight|midday)(?:\s+(\S+))?", text, re.I)
    if m_word:
        text = words[m_word.group(1).lower()] + (" " + m_word.group(2) if m_word.group(2) else "")
    m = re.fullmatch(r"(\d{1,2})(?::(\d{2}))?(?::(\d{2}))?\s*([ap]\.?m\.?)?(?:\s+(\S+))?", text, re.I)
    if not m or (not m.group(2) and not m.group(4)):
        return None
    if m.group(3) and not m.group(5) and not m.group(4) and ctx.depth == 0 and int(m.group(1)) < 24:
        pass  # "01:30:00" reads as both a duration and a time; let both speak
    hour, minute, second = int(m.group(1)), int(m.group(2) or 0), int(m.group(3) or 0)
    ampm, zone_token = m.group(4), m.group(5)
    if ampm:
        if not 1 <= hour <= 12:
            return None
        hour = hour % 12 + (12 if ampm.lower().startswith("p") else 0)
    if hour > 23 or minute > 59 or second > 59:
        return None
    label = None
    if zone_token:
        resolved = resolve_zone(zone_token)
        if not resolved:
            return None
        source_zone, label, notes = resolved
    else:
        source_zone, notes = ctx.zone, []
    today = ctx.now.astimezone(source_zone).date()
    wall = dt.datetime(today.year, today.month, today.day, hour, minute, second, tzinfo=source_zone)
    lines = list(notes)
    lines.append(f"{wall.strftime('%H:%M')} {label or zone_key(source_zone)} today is:")
    lines.extend("  " + line for line in zone_lines(wall, ctx, skip_offset=wall.utcoffset()))
    if not any(wall.astimezone(z).utcoffset() == dt.timedelta(0) for z in ctx.zones) and wall.utcoffset() != dt.timedelta(0):
        lines.append(f"  {fmt(wall, UTC)}")
    conf = 0.85 if zone_token else 0.5
    if m_word:
        conf = 0.8 if zone_token else 0.6
    receipt = f"date -d 'TZ=\"{zone_key(source_zone)}\" {hour:02d}:{minute:02d}'" if "/" in zone_key(source_zone) \
        else f"date -d {q(f'{hour:02d}:{minute:02d} {label or zone_key(source_zone)}')}"
    return [Reading("time", conf, f"{wall.strftime('%H:%M')} {label or zone_key(source_zone)} = "
                    + ", ".join(f"{wall.astimezone(z).strftime('%H:%M')} {zone_label(wall.astimezone(z))}" for z in ctx.zones
                                if wall.astimezone(z).utcoffset() != wall.utcoffset()) or "the same everywhere you asked",
                    lines, receipt)]


DURATION_UNITS = {
    "ns": 1e-9, "nanosecond": 1e-9, "us": 1e-6, "µs": 1e-6, "μs": 1e-6, "microsecond": 1e-6,
    "ms": 1e-3, "millisecond": 1e-3, "s": 1, "sec": 1, "second": 1, "m": 60, "min": 60, "minute": 60,
    "h": 3600, "hr": 3600, "hour": 3600, "d": 86400, "day": 86400, "w": 604800, "wk": 604800, "week": 604800,
    "y": 31557600, "yr": 31557600, "year": 31557600,
}


def parse_duration(s: str) -> tuple[float, str] | None:
    """Seconds for '1h 30m', '90min', '1.5h', 'PT1H30M', '01:30:00', '2d4h'; plus how it was read."""
    m = re.fullmatch(r"(?i)P(?:(\d+(?:\.\d+)?)Y)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)W)?(?:(\d+(?:\.\d+)?)D)?"
                     r"(?:T(?:(\d+(?:\.\d+)?)H)?(?:(\d+(?:\.\d+)?)M)?(?:(\d+(?:\.\d+)?)S)?)?", s)
    if m and any(m.groups()) and s.upper() != "P":
        y, mo, w, d, h, mi, sec = (float(v) if v else 0.0 for v in m.groups())
        total = y * 31557600 + mo * 2629800 + w * 604800 + d * 86400 + h * 3600 + mi * 60 + sec
        note = "ISO 8601 duration" + (" (months taken as 30.44 days, years as 365.25)" if y or mo else "")
        return total, note
    m = re.fullmatch(r"(\d{1,3}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?", s)
    if m:
        h, mi, sec, frac = m.groups()
        total = int(h) * 3600 + int(mi) * 60 + int(sec) + (float("0." + frac) if frac else 0)
        return total, "H:MM:SS"
    tokens = re.findall(r"(\d+(?:\.\d+)?)\s*([a-zA-Zµμ]+)", s)
    if tokens and re.fullmatch(r"(?:\s*\d+(?:\.\d+)?\s*[a-zA-Zµμ]+\s*,?(?:\s+and\s+)?)+", s):
        total = 0.0
        for number, unit in tokens:
            u = unit.lower().rstrip("s") if unit.lower() not in ("s", "ms", "us", "ns") else unit.lower()
            if u not in DURATION_UNITS:
                return None
            total += float(number) * DURATION_UNITS[u]
        return total, "units"
    return None


@detector
def detect_duration(s: str, ctx: Context):
    parsed = parse_duration(s)
    if not parsed:
        return None
    seconds, how = parsed
    if not math.isfinite(seconds) or seconds > 1e15:
        return None
    lines = [f"{seconds:,.9g} seconds" + (f" = {seconds * 1000:,.9g} ms" if seconds < 3600 else "")]
    if seconds >= 60:
        lines.append(f"{seconds / 60:,.6g} minutes" + (f" = {seconds / 3600:,.6g} hours" if seconds >= 3600 else "")
                     + (f" = {seconds / 86400:,.6g} days" if seconds >= 86400 else ""))
    then = ctx.now + dt.timedelta(seconds=min(seconds, 86400 * 365.25 * 1000))
    ago = ctx.now - dt.timedelta(seconds=min(seconds, 86400 * 365.25 * 1000))
    if seconds >= 60:
        lines.append(f"from now: {fmt(then, ctx.zone)}; that long ago: {fmt(ago, ctx.zone)}")
    if how == "units":
        lines.append("read as fixed units (m = minutes; 1y = 365.25 days)")
    elif how != "H:MM:SS":
        lines.append(how)
    conf = 0.85 if how != "H:MM:SS" else 0.6
    if how == "units" and re.fullmatch(r"\d+(?:\.\d+)?\s*m", s):
        lines.append("ambiguous: m could be metres or months elsewhere; here it means minutes")
        conf = 0.6
    receipt = f"systemd-analyze timespan {q(s)}" if how in ("units",) else None
    if how == "H:MM:SS":
        receipt = f"echo $(( {s.split('.')[0].split(':')[0]}*3600 + {int(s.split(':')[1])}*60 + {int(s.split(':')[2].split('.')[0])} ))"
    return [Reading("duration", conf, f"{human_duration(seconds)} = {seconds:,.9g} seconds", lines, receipt,
                    data={"seconds": seconds})]


# -- cron -------------------------------------------------------------------

CRON_ALIASES = {
    "@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *", "@weekly": "0 0 * * 0",
    "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *",
}
MONTH_NAMES = {name.upper(): i for i, name in enumerate(calendar.month_abbr) if name}
DAY_NAMES = {"SUN": 0, "MON": 1, "TUE": 2, "WED": 3, "THU": 4, "FRI": 5, "SAT": 6}
DAY_FULL = ("Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday")


@dataclass
class CronField:
    values: set[int]
    star: bool               # field was * or */n
    text: str
    step: int | None
    start: int | None       # for N/step or N-M/step
    end: int | None
    lo: int
    hi: int


def cron_field(text: str, lo: int, hi: int, names: dict[str, int] | None = None, sunday7: bool = False) -> CronField:
    names = names or {}
    values: set[int] = set()
    first_step = None
    first_start = first_end = None
    star = text.startswith("*") and "," not in text

    def number(tok: str) -> int:
        if tok.upper() in names:
            return names[tok.upper()]
        if not tok.isdigit():
            raise ValueError(f"bad cron value {tok!r}")
        return int(tok)

    for part in text.split(","):
        base, _, step_text = part.partition("/")
        step = int(step_text) if step_text else 1
        if step_text and (not step_text.isdigit() or step < 1):
            raise ValueError("bad step")
        if base == "*":
            a, b = lo, hi
        elif "-" in base:
            left, right = base.split("-", 1)
            a, b = number(left), number(right)
        else:
            a = number(base)
            b = hi if step_text else a
        if not (lo <= a <= b <= hi) and not (sunday7 and b == 7 and a <= 7):
            raise ValueError("cron value out of range")
        if first_step is None:
            first_step, first_start, first_end = (step if step_text else None), a, b
        values.update(range(a, b + 1, step))
    if sunday7 and 7 in values:
        values.discard(7)
        values.add(0)
    return CronField(values, star, text, first_step, first_start, first_end, lo, hi)


def hour12(h: int, m: int = 0) -> str:
    suffix = "am" if h < 12 else "pm"
    hh = h % 12 or 12
    return f"{hh}:{m:02d}{suffix}" if m else f"{hh}{suffix}"


def list_english(items: list[str]) -> str:
    if len(items) <= 1:
        return "".join(items)
    if len(items) == 2:
        return f"{items[0]} and {items[1]}"
    return ", ".join(items[:-1]) + f" and {items[-1]}"


def ordinal(n: int) -> str:
    suffix = "th" if 11 <= n % 100 <= 13 else {1: "st", 2: "nd", 3: "rd"}.get(n % 10, "th")
    return f"{n}{suffix}"


def cron_english(mins: CronField, hours: CronField, dom: CronField, mon: CronField, dow: CronField) -> str:
    """A sentence, in the style of crontab.guru."""
    # time part
    if mins.star and mins.step in (None, 1) and hours.star and hours.step in (None, 1):
        when = "every minute"
    elif mins.star and mins.step and hours.star and hours.step in (None, 1):
        when = f"every {mins.step} minutes"
    elif mins.star and mins.step in (None, 1) and not hours.star:
        when = "every minute past " + list_english([hour12(h) for h in sorted(hours.values)]) if len(hours.values) <= 4 \
            else "every minute during hours " + hours.text
    elif mins.star and mins.step and not hours.star:
        when = f"every {mins.step} minutes past " + ("hours " + hours.text if hours.step else
                                                     list_english([hour12(h) for h in sorted(hours.values)]) if len(hours.values) <= 4 else f"hours {hours.text}")
    elif not mins.star and hours.star and hours.step in (None, 1):
        mv = sorted(mins.values)
        when = ("at minute " + list_english([str(v) for v in mv]) + " of every hour") if len(mv) <= 4 \
            else f"at minutes {mins.text} of every hour"
    elif not mins.star and hours.star and hours.step:
        mv = sorted(mins.values)
        when = f"at minute {list_english([str(v) for v in mv])} every {hours.step} hours" + \
            (f" starting {hour12(hours.start)}" if hours.start else "")
    else:
        combos = [hour12(h, m) for h in sorted(hours.values) for m in sorted(mins.values)]
        when = "at " + list_english(combos) if len(combos) <= 6 else f"at {len(combos)} times a day ({mins.text} {hours.text})"
    # date part
    parts = []
    if not dom.star:
        dv = sorted(dom.values)
        parts.append("on the " + list_english([ordinal(v) for v in dv]) if len(dv) <= 5 else f"on days {dom.text}")
    if not dow.star:
        wv = sorted(dow.values)
        if wv == [1, 2, 3, 4, 5]:
            day_text = "Monday through Friday"
        elif wv == [0, 6]:
            day_text = "weekends"
        elif len(wv) == 7:
            day_text = "every day"
        else:
            day_text = list_english([DAY_FULL[v] for v in wv])
        parts.append(("and " if parts else "") + "on " + day_text)
    if not mon.star:
        mv = sorted(mon.values)
        parts.append("in " + list_english([calendar.month_name[v] for v in mv]) if len(mv) <= 6 else f"in months {mon.text}")
    if not parts:
        return when
    if dom.star and dow.star:
        return when
    return f"{when} {' '.join(parts)}"


def cron_next(fields: tuple[CronField, ...], zone: dt.tzinfo, now: dt.datetime, count: int = 3,
              horizon_days: int = 366 * 5) -> tuple[list[dt.datetime], list[str]]:
    """Next *count* fire times after *now*, honest about DST: a wall time that does not exist
    (spring forward) is skipped; one that happens twice (fall back) is listed once, the first time."""
    mins, hours, dom, mon, dow = fields
    found: list[dt.datetime] = []
    notes: list[str] = []
    start_local = now.astimezone(zone)
    day = start_local.date()
    hour_list, min_list = sorted(hours.values), sorted(mins.values)
    for offset in range(horizon_days):
        date = day + dt.timedelta(days=offset)
        if date.month not in mon.values:
            continue
        in_dom, in_dow = date.day in dom.values, (date.weekday() + 1) % 7 in dow.values
        ok = (in_dom and in_dow) if (dom.star or dow.star) else (in_dom or in_dow)
        if not ok:
            continue
        for h in hour_list:
            for m in min_list:
                naive = dt.datetime(date.year, date.month, date.day, h, m)
                aware = naive.replace(tzinfo=zone, fold=0)
                # Verify the wall time exists: round-trip through UTC.
                back = aware.astimezone(UTC).astimezone(zone)
                if back.replace(tzinfo=None) != naive:
                    if aware > now and len(notes) < 2:
                        notes.append(f"{naive:%Y-%m-%d %H:%M} does not exist in {zone_key(zone)} (clocks jump forward); skipped")
                    continue
                if aware <= now:
                    continue
                found.append(aware)
                if aware.replace(fold=1).utcoffset() != aware.utcoffset() and len(notes) < 2:
                    notes.append(f"{naive:%Y-%m-%d %H:%M} happens twice in {zone_key(zone)} (clocks fall back); "
                                 "most cron daemons run it once, some twice")
                if len(found) >= count:
                    return found, notes
    return found, notes


def cron_to_systemd(mins: CronField, hours: CronField, dom: CronField, mon: CronField, dow: CronField) -> str | None:
    """OnCalendar= form for the same schedule, when the schedule is expressible."""
    def part(f: CronField, names: dict | None = None) -> str | None:
        if f.star and f.step in (None, 1):
            return "*"
        if f.star and f.step:
            return f"{f.lo:02d}/{f.step}" if f.lo else f"00/{f.step}"
        if f.step and f.start is not None and "," not in f.text:
            return f"{f.start:02d}..{f.end:02d}/{f.step}" if f.end != f.hi else f"{f.start:02d}/{f.step}"
        if f.step:
            return None
        values = sorted(f.values)
        if len(values) > 1 and values == list(range(values[0], values[-1] + 1)):
            return f"{values[0]:02d}..{values[-1]:02d}"
        return ",".join(f"{v:02d}" for v in values)

    m_text, h_text, d_text, mo_text = part(mins), part(hours), part(dom), part(mon)
    if None in (m_text, h_text, d_text, mo_text):
        return None
    if not (dom.star or dow.star):
        return None  # cron's OR between day fields has no systemd equivalent
    names = ("Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat")
    weekdays = ""
    if not dow.star:
        values = sorted(dow.values)
        if values == list(range(values[0], values[-1] + 1)) and len(values) > 2:
            weekdays = f"{names[values[0]]}..{names[values[-1]]} "
        else:
            weekdays = ",".join(names[v] for v in values) + " "
    return f"{weekdays}*-{mo_text}-{d_text} {h_text}:{m_text}:00"


@detector
def detect_cron(s: str, ctx: Context):
    text = s
    alias = None
    if text.lower() in CRON_ALIASES:
        alias, text = text.lower(), CRON_ALIASES[text.lower()]
    elif text.lower() == "@reboot":
        return [Reading("cron", 0.95, "@reboot: runs once, when the cron daemon starts (usually at boot)",
                        ["cron alias; no schedule, no next run", "equivalent systemd unit: WantedBy=multi-user.target with a oneshot service"],
                        None)]
    parts = text.split()
    command = None
    if len(parts) > 6 or (len(parts) == 6 and not re.fullmatch(r"[\d*,/-]+", parts[0])):
        # A crontab line: five fields followed by the command (or, in /etc/crontab, a user then the command).
        if len(text) > 400 or not all(re.fullmatch(r"[\w*,/-]+", p) for p in parts[:5]) or all(p == "*" for p in parts[5:]):
            return None
        command, parts = " ".join(parts[5:]), parts[:5]
    if len(parts) not in (5, 6) or len(text) > 400:
        return None
    seconds_field = None
    if len(parts) == 6:
        seconds_field, parts = parts[0], parts[1:]   # Quartz/Spring style with a seconds column
        if not re.fullmatch(r"[\d*,/-]+", seconds_field):
            return None
    try:
        mins = cron_field(parts[0], 0, 59)
        hours = cron_field(parts[1], 0, 23)
        dom = cron_field(parts[2], 1, 31)
        mon = cron_field(parts[3], 1, 12, MONTH_NAMES)
        dow = cron_field(parts[4], 0, 7, DAY_NAMES, sunday7=True)
    except ValueError:
        return None
    fields = (mins, hours, dom, mon, dow)
    english = cron_english(*fields)
    upcoming, notes = cron_next(fields, ctx.zone, ctx.now)
    lines = []
    if alias:
        lines.append(f"{alias} expands to {text}")
    lines.append("fields: minute hour day-of-month month day-of-week  =  " + "  ".join(parts))
    if command:
        user_then_command = re.match(r"([a-z_][a-z0-9_-]{0,31})\s+(/.*|[a-z].*)", command)
        if user_then_command and user_then_command.group(1) in ("root", "www-data", "nobody", "postgres", "backup", "ubuntu", "ec2-user") or \
                (user_then_command and "/" in user_then_command.group(2)[:1]):
            lines.append(f"runs as {user_then_command.group(1)}: {preview(user_then_command.group(2), 80)}  (system crontab format)")
        else:
            lines.append(f"runs: {preview(command, 90)}")
        if ">" not in command and "|" not in command and "MAILTO" not in text:
            lines.append("output is mailed to the crontab owner unless redirected (>> /var/log/x.log 2>&1)")
    if seconds_field:
        lines.append(f"6 fields: leading seconds field {seconds_field!r} (Quartz/Spring style, not Unix cron)")
    if not (dom.star or dow.star):
        lines.append("day-of-month AND weekday both restricted: Unix cron fires when EITHER matches")
    if upcoming:
        for d in upcoming:
            lines.append(f"next: {fmt(d, seconds=False)}  ({relative(d, ctx.now)})")
    else:
        lines.append("no run found in the next 5 years (impossible date like Feb 30?)")
    lines.extend(notes)
    if len(ctx.zones) > 1 and upcoming:
        other = ctx.zones[1]
        lines.append(f"first run in {zone_key(other)}: {fmt(upcoming[0], other, seconds=False)}")
    lines.append(f"evaluated in {zone_key(ctx.zone)}; cron uses the daemon's local zone (TZ= or CRON_TZ= can override)")
    systemd = cron_to_systemd(*fields)
    if systemd:
        lines.append(f"systemd OnCalendar={systemd}")
        receipt = f"systemd-analyze calendar {q(systemd)}"
    else:
        receipt = None
    data = {"english": english, "next": [iso(d) for d in upcoming], "systemd": systemd}
    conf = 0.97 if alias or seconds_field is None and any(c in text for c in "*/,-") or len(set(parts)) > 2 else 0.6
    if len(set(parts)) == 1 and parts[0].isdigit():
        conf = 0.4   # "1 1 1 1 1" is probably not a schedule
    if command and conf < 0.97:
        conf = 0.85  # five schedule-ish fields followed by a command: that is a crontab line
    summary = english[0].upper() + english[1:]
    if upcoming:
        summary += f"; next {upcoming[0].strftime('%a %H:%M')}"
    if command:
        summary += f"  ->  {preview(command, 40)}"
    return [Reading("cron", conf, summary, lines, receipt, data=data)]


@detector
def detect_timezone(s: str, ctx: Context):
    """A zone name, abbreviation or offset -> the current time there and the offset now."""
    token = s
    if len(token) > 40:
        return None
    if token.lower() in {"utc", "gmt", "z", "zulu"} or token.upper() in TZ_ABBR or "/" in token or OFFSET_RE.fullmatch(token):
        resolved = resolve_zone(token)
    else:
        # Maybe a city: "tokyo", "new york", "los_angeles"
        wanted = token.lower().replace(" ", "_")
        if not re.fullmatch(r"[a-z_]+", wanted):
            return None
        matches = [z for z in canonical_zones() if z.split("/")[-1].lower() == wanted]
        if len(matches) != 1:
            return None
        resolved = (ZoneInfo(matches[0]), matches[0], [f"matched city {matches[0]}"])
    if not resolved:
        return None
    zone, label, notes = resolved
    now_there = ctx.now.astimezone(zone)
    off = now_there.utcoffset()
    conf = 0.9 if ("/" in label or token.upper() in TZ_ABBR) else 0.7
    if OFFSET_RE.fullmatch(token) and not token.upper().startswith(("UTC", "GMT")):
        conf = 0.6 if ":" in token or len(token) >= 5 else 0.2  # "+05:30" is an offset; "-1" could be anything
    lines = list(notes)
    lines.append(f"now there: {fmt(now_there)}  ({offset_str(off)})")
    for z in ctx.zones:
        if z is not zone:
            diff = (now_there.utcoffset() or dt.timedelta()) - (ctx.now.astimezone(z).utcoffset() or dt.timedelta())
            hours = diff.total_seconds() / 3600
            lines.append(f"{'ahead of' if hours > 0 else 'behind' if hours < 0 else 'same as'} {zone_key(z)}"
                         + (f" by {abs(hours):g} h" if hours else ""))
    if isinstance(zone, ZoneInfo):
        # Does this zone observe DST? Compare January and July offsets.
        jan = dt.datetime(ctx.now.year, 1, 1, tzinfo=zone).utcoffset()
        jul = dt.datetime(ctx.now.year, 7, 1, tzinfo=zone).utcoffset()
        if jan != jul:
            lines.append(f"observes DST: {offset_str(jan)} in January, {offset_str(jul)} in July")
        else:
            lines.append("no daylight saving time this year")
    if isinstance(zone, ZoneInfo):
        receipt = f"TZ={q(zone_key(zone))} date"
    else:
        # POSIX TZ strings put the sign the other way round: PST8 is UTC-8.
        minutes = -int((off or dt.timedelta()).total_seconds() // 60)
        sign = "-" if minutes < 0 else ""
        hh, mm = divmod(abs(minutes), 60)
        posix = f"{label if label.isalpha() and len(label) >= 3 else 'UTC'}{sign}{hh}" + (f":{mm:02d}" if mm else "")
        receipt = f"TZ={q(posix)} date   # POSIX TZ strings count hours west of UTC, hence the flipped sign"
    summary = f"{label}: {fmt(now_there, seconds=False)} now, {offset_str(off)}"
    return [Reading("timezone", conf, summary, lines, receipt, data={"zone": zone_key(zone), "offset": offset_str(off)})]


STRFTIME = {
    "%a": "weekday, abbreviated (Thu)", "%A": "weekday (Thursday)", "%b": "month, abbreviated (Oct)", "%B": "month (October)",
    "%c": "locale date and time", "%d": "day of month, 01-31", "%e": "day of month, space padded", "%f": "microseconds (Python)",
    "%F": "%Y-%m-%d", "%H": "hour 00-23", "%I": "hour 01-12", "%j": "day of year 001-366", "%m": "month 01-12",
    "%M": "minute 00-59", "%N": "nanoseconds (GNU date)", "%p": "AM/PM", "%s": "seconds since the epoch",
    "%S": "second 00-60", "%T": "%H:%M:%S", "%u": "weekday 1-7, Monday=1", "%U": "week of year, Sunday first",
    "%V": "ISO week 01-53", "%w": "weekday 0-6, Sunday=0", "%W": "week of year, Monday first", "%x": "locale date",
    "%X": "locale time", "%y": "year without century", "%Y": "year", "%z": "+hhmm offset", "%Z": "zone abbreviation",
    "%%": "literal %", "%G": "ISO week-based year", "%D": "%m/%d/%y", "%R": "%H:%M", "%r": "12-hour time", "%n": "newline",
    "%t": "tab", "%h": "same as %b", "%C": "century", "%g": "ISO year, two digits", "%k": "hour, space padded", "%l": "12-hour, space padded",
    "%P": "am/pm lowercase (GNU)", "%:z": "+hh:mm offset (GNU)",
}


@detector
def detect_strftime(s: str, ctx: Context):
    codes = re.findall(r"%:?[a-zA-Z%]", s)
    if not codes or len(s) > 80 or not all(c in STRFTIME for c in codes):
        return None
    if len(codes) < 2 and "%" + s.strip("%") == s:
        pass
    try:
        rendered = ctx.now.astimezone(ctx.zone).strftime(s.replace("%N", f"{(ctx.now.microsecond * 1000):09d}").replace("%:z", "%z"))
    except ValueError:
        return None
    lines = [f"now: {clean(rendered)}"]
    lines.extend(f"{c}  {STRFTIME[c]}" for c in dict.fromkeys(codes))
    receipt = f"date +{s}" if re.fullmatch(r"[\w%:+-]+", s) else f"date {q('+' + s)}"
    return [Reading("strftime", 0.85 if len(codes) > 1 or s.startswith("%") else 0.5,
                    f"date/strftime format -> {clean(rendered)}", lines, receipt)]


# == DETECTORS: encodings ==

def describe_bytes(data: bytes, ctx: Context, lines: list[str], children: list[Reading]) -> str:
    """Fill *lines*/*children* for decoded bytes; return a one-line summary of what they are."""
    text = text_or_none(data)
    kind = magic(data)
    if text is not None:
        shown = preview(text, 96)
        lines.append(f"-> {shown}" if len(text) <= 96 else f"-> {shown}  ({plural(len(text), 'char')})")
        children.extend(nested(text, ctx))
        return f"text: {preview(text, 60)}"
    if kind:
        lines.append(f"-> {plural(len(data), 'byte')} of {kind}: {hexdump(data)}")
        return f"{plural(len(data), 'byte')}, {kind}"
    lines.append(f"-> {plural(len(data), 'byte')} of binary: {hexdump(data)}")
    if len(data) in (16, 20, 28, 32, 48, 64):
        lines.append(f"{len(data) * 8} bits - the size of a {({16: 'MD5 digest / UUID / AES-128 key', 20: 'SHA-1 digest', 28: 'SHA-224 digest', 32: 'SHA-256 digest / Ed25519 key / AES-256 key', 48: 'SHA-384 digest', 64: 'SHA-512 digest / Ed25519 signature'})[len(data)]}")
    return f"{plural(len(data), 'byte')} of binary data"


@detector
def detect_base64(s: str, ctx: Context):
    if " " in s.strip() and "\n" not in s:
        return None  # words with spaces are not base64; line-wrapped base64 has newlines
    compact = re.sub(r"\s+", "", s)
    if len(compact) < 4 or len(compact) > MAX_INPUT:
        return None
    url_safe = "-" in compact or "_" in compact
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}" if not url_safe else r"[A-Za-z0-9_-]+={0,2}", compact):
        return None
    if len(compact.rstrip("=")) % 4 == 1:
        return None
    padded = compact.rstrip("=")
    padded += "=" * (-len(padded) % 4)
    try:
        data = base64.b64decode(padded, altchars=b"-_" if url_safe else None, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not data:
        return None
    lines: list[str] = []
    children: list[Reading] = []
    what = describe_bytes(data, ctx, lines, children)
    text = text_or_none(data)
    # Confidence: real base64 has padding or mixed case and digits and decodes to something sensible.
    conf = 0.35
    if "=" in compact:
        conf += 0.25
    if text is not None:
        conf += 0.3 if any(c.isalpha() for c in text) and text.isprintable() else 0.1
    elif magic(data):
        conf += 0.35
    else:
        conf -= 0.15  # binary with no recognisable header: almost always a coincidence
    letters = compact.replace("-", "").replace("_", "").rstrip("=")
    if compact.isdigit() or letters.isalpha() and (letters.islower() or letters.isupper()):
        conf -= 0.25  # real base64 mixes cases and digits
    if len(compact) < 8:
        conf -= 0.1
    if re.fullmatch(r"[0-9a-fA-F]+", compact) and len(compact) % 2 == 0:
        conf -= 0.15  # looks more like hex
    conf = max(0.05, min(0.97, conf))
    flags = " -d" if url_safe is False else " -d"
    decode_cmd = f"base64{flags}" if not url_safe else "tr '_-' '/+' | base64 -d"
    pad_note = "" if compact.endswith("=") or len(compact) % 4 == 0 else "   # (coreutils base64 wants padding; add = until the length is a multiple of 4)"
    receipt = f"{printf_literal(compact)} | {decode_cmd}" + (" | xxd" if text is None else "") + pad_note
    label = "base64url" if url_safe else "base64"
    return [Reading("base64", conf, f"{label} -> {what}", lines, receipt, children, data={"bytes": len(data)})]


@detector
def detect_hex(s: str, ctx: Context):
    compact = re.sub(r"[\s:]+", "", s)
    if compact.lower().startswith("0x"):
        compact = compact[2:]
    if compact.startswith("\\x") or " \\x" in s:
        compact = re.sub(r"\\x", "", compact)
    if len(compact) < 2 or len(compact) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", compact):
        return None
    data = bytes.fromhex(compact)
    lines: list[str] = []
    children: list[Reading] = []
    text = text_or_none(data)
    if compact.isdigit() and (len(compact) > 4 or text is None or not text.isalpha()):
        return None  # all-digit strings are numbers, not hex bytes
    if re.fullmatch(r"(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", s):
        return None  # that is a MAC address's job
    what = describe_bytes(data, ctx, lines, children)
    conf = 0.3
    if text is not None and text.isprintable() and any(c.isalpha() for c in text):
        conf = 0.75
    elif magic(data):
        conf = 0.7
    if any(c.isalpha() for c in compact) and any(c.isdigit() for c in compact):
        conf += 0.1
    if len(compact) >= 16 and text is None and not magic(data):
        conf = 0.25
    if compact.isdigit():
        conf = min(conf, 0.2)
    if len(compact) in (8, 16) and text is None and any(c.isalpha() for c in compact):
        n = int(compact, 16)
        lines.append(f"as a {len(compact) * 4}-bit integer: {commas(n)} (big-endian)" + (f"; as float32 {struct.unpack('>f', data)[0]:.7g}" if len(compact) == 8 and math.isfinite(struct.unpack('>f', data)[0]) else ""))
        conf = max(conf, 0.45)
    receipt = f"{printf_literal(compact)} | xxd -r -p" + ("" if text is not None else " | xxd")
    return [Reading("hex", min(conf, 0.9), f"hex bytes -> {what}", lines, receipt, children, data={"bytes": len(data)})]


@detector
def detect_url_encoded(s: str, ctx: Context):
    if not re.search(r"%[0-9A-Fa-f]{2}", s):
        return None
    decoded_bytes = urllib.parse.unquote_to_bytes(s)
    text = text_or_none(decoded_bytes)
    if text is None or text == s:
        return None
    plus_text = urllib.parse.unquote_plus(s) if "+" in s else None
    lines = [f"-> {preview(text, 96)}"]
    if plus_text and plus_text != text:
        lines.append(f"-> {preview(plus_text, 96)}  (if + means space, as in form data)")
    children = nested(text, ctx)
    receipt = f"python3 -c 'import sys,urllib.parse; print(urllib.parse.unquote(sys.argv[1]))' {q(s)}"
    return [Reading("url-encoded", 0.9, f"percent-encoded -> {preview(text, 60)}", lines, receipt, children)]


@detector
def detect_url(s: str, ctx: Context):
    m = re.fullmatch(r"([\w.-]+)@([\w.-]+):([\w./~-]+?)(?:\.git)?/?", s)
    if m and "://" not in s:
        user, host, path = m.groups()
        return [Reading("url", 0.85, f"scp-style git remote: {clean(host)} {clean(path)}",
                        [f"user {clean(user)} on host {clean(host)}, repository path {clean(path)}", f"same thing as ssh://{clean(user)}@{clean(host)}/{clean(path)}",
                         f"clone: git clone {clean(s)}"], f"git ls-remote {q(s)}   # lists refs without cloning (needs network)")]
    if len(s) > 4096 or " " in s.strip() or not re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*://\S+|mailto:|^[\w.-]+\.[a-z]{2,}(?:[/?#]\S*)$", s):
        return None
    u = urllib.parse.urlsplit(s if "://" in s or s.startswith("mailto:") else "//" + s)
    if not (u.netloc or u.scheme == "mailto"):
        return None
    lines = []
    if u.scheme:
        lines.append(f"scheme   {u.scheme}")
    if u.username or u.password:
        lines.append(f"userinfo {u.username or ''}{':<password>' if u.password else ''}   (credentials in a URL leak in logs and history)")
    if u.hostname:
        host = u.hostname
        try:
            host_ascii = host.encode("idna").decode()
        except UnicodeError:
            host_ascii = host
        lines.append(f"host     {clean(host)}" + (f"  (punycode {host_ascii})" if host_ascii != host else "")
                     + (f"  port {u.port}" if u.port else ""))
        if host.startswith("xn--") or any(part.startswith("xn--") for part in host.split(".")):
            try:
                lines.append(f"         decodes to {clean(host.encode().decode('idna'))}")
            except UnicodeError:
                pass
        try:
            addr = ipaddress.ip_address(host)
            lines.append(f"         host is a literal IP ({'private' if addr.is_private else 'public'})")
        except ValueError:
            pass
    if u.path and u.path != "/":
        lines.append(f"path     {clean(urllib.parse.unquote(u.path))}")
    children: list[Reading] = []
    if u.query:
        params = urllib.parse.parse_qsl(u.query, keep_blank_values=True)
        lines.append(f"query    {plural(len(params), 'parameter')}")
        for k, v in params[:12]:
            lines.append(f"  {clean(k)} = {preview(v, 60)}")
            if ctx.budget[0] > 8 and len(v) >= 6:
                for r in nested(v, ctx, 0.7, 1):
                    if r.kind not in ("number", "hex", "chmod", "port", "http status", "exit code", "base64"):
                        r.via = k
                        children.append(r)
    if u.fragment:
        lines.append(f"fragment {preview(u.fragment, 60)}")
    receipt = f"python3 -c 'import sys,urllib.parse; print(urllib.parse.urlsplit(sys.argv[1]))' {q(s)}"
    if have("trurl"):
        receipt = f"trurl --json {q(s)}"
    conf = 0.9 if u.scheme else 0.5
    return [Reading("url", conf, f"URL: {clean(u.hostname or '')}{' ' + clean(urllib.parse.unquote(u.path)) if u.path not in ('', '/') else ''}",
                    lines, receipt, children)]


def _json_walk(value, path: str, ctx: Context, found: list[tuple[str, Reading]], budget: list[int]):
    if budget[0] <= 0:
        return
    if isinstance(value, dict):
        for k, v in list(value.items())[:40]:
            _json_walk(v, f"{path}.{k}" if path else str(k), ctx, found, budget)
    elif isinstance(value, list):
        for i, v in enumerate(value[:40]):
            _json_walk(v, f"{path}[{i}]", ctx, found, budget)
    elif isinstance(value, (str, int, float)) and not isinstance(value, bool):
        text = str(value)
        if isinstance(value, float) and not math.isfinite(value):
            return
        if len(text) < 6 or len(text) > 4096:
            return
        budget[0] -= 1
        for r in nested(text, ctx, 0.7, 1):
            if r.kind in ("epoch seconds", "epoch millis", "epoch micros", "epoch nanos", "date", "jwt", "base64", "uuid",
                          "ulid", "ip", "cidr", "mac", "url", "duration", "byte size", "hash", "secret", "color", "cron"):
                found.append((path, r))


@detector
def detect_json(s: str, ctx: Context):
    if s[0] not in "{[" or s[-1] not in "}]":
        return None
    try:
        value = json.loads(s, parse_constant=lambda name: float("nan"))
    except (ValueError, RecursionError):
        return None
    if isinstance(value, dict):
        what = f"JSON object with {plural(len(value), 'key')}"
    else:
        what = f"JSON array with {plural(len(value), 'item')}"
    lines = []
    if isinstance(value, dict):
        for k, v in list(value.items())[:8]:
            lines.append(f"{preview(str(k), 32)}: {preview(json.dumps(v, ensure_ascii=False), 70)}")
        if len(value) > 8:
            lines.append(f"... {len(value) - 8} more")
    found: list[tuple[str, Reading]] = []
    _json_walk(value, "", ctx, found, [12])
    children = []
    for path, r in found[:6]:
        r.via = path
        children.append(r)
    receipt = f"{printf_literal(s) if len(s) < 500 else 'cat FILE'} | jq ." if have("jq") else f"python3 -m json.tool <<< {q(s)}"
    return [Reading("json", 0.98, what, lines, receipt, children, data={"keys": list(value)[:40] if isinstance(value, dict) else None})]


def b64url_json(segment: str):
    data = base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    return json.loads(data)


@detector
def detect_jwt(s: str, ctx: Context):
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*", s) or len(s) > 16384:
        return None
    parts = s.split(".")
    try:
        header, payload = b64url_json(parts[0]), b64url_json(parts[1])
    except (ValueError, binascii.Error, UnicodeDecodeError):
        return None
    if not isinstance(header, dict) or not isinstance(payload, dict):
        return None
    alg = header.get("alg", "?")
    lines = [f"header   alg={alg}" + (f" typ={header['typ']}" if "typ" in header else "") + (f" kid={preview(str(header['kid']), 40)}" if "kid" in header else "")]
    if alg in ("none", "None", "NONE"):
        lines.append("         alg=none: UNSIGNED - any server accepting this is broken")
    for claim in ("iss", "sub", "aud", "azp", "scope", "scp", "email", "name", "preferred_username", "roles", "jti"):
        if claim in payload:
            lines.append(f"{claim:<8} {preview(json.dumps(payload[claim], ensure_ascii=False) if not isinstance(payload[claim], str) else payload[claim], 80)}")
    for claim, label in (("iat", "issued"), ("nbf", "not before"), ("exp", "expires"), ("auth_time", "auth time")):
        v = payload.get(claim)
        if isinstance(v, (int, float)) and not isinstance(v, bool) and math.isfinite(v):
            d = dt.datetime.fromtimestamp(v, UTC)
            lines.append(f"{label:<8} {fmt(d, ctx.zone)}  ({relative(d, ctx.now)})")
    if "exp" in payload and isinstance(payload["exp"], (int, float)):
        d = dt.datetime.fromtimestamp(payload["exp"], UTC)
        status = "EXPIRED " + relative(d, ctx.now) if d < ctx.now else "valid for " + relative(d, ctx.now)[3:]
    else:
        status = "no exp claim (never expires)"
    extras = [k for k in payload if k not in ("iss", "sub", "aud", "azp", "scope", "scp", "email", "name", "preferred_username",
                                               "roles", "jti", "iat", "nbf", "exp", "auth_time")]
    if extras:
        lines.append(f"other claims: {', '.join(clean(k) for k in extras[:12])}" + (" ..." if len(extras) > 12 else ""))
    lines.append(f"signature {'present (' + str(len(parts[2])) + ' chars) - NOT verified; the claims above are whatever the issuer, or an attacker, put there' if parts[2] else 'MISSING'}")
    receipt = f"{printf_literal(parts[1])} | tr '_-' '/+' | base64 -d 2>/dev/null | jq ." if have("jq") \
        else f"{printf_literal(parts[1])} | tr '_-' '/+' | base64 -d 2>/dev/null; echo"
    who = payload.get("sub") or payload.get("email") or payload.get("client_id")
    summary = f"JWT ({alg}), {status}" + (f", sub={preview(str(who), 32)}" if who else "")
    return [Reading("jwt", 0.98, summary, lines, receipt, data={"header": header, "payload": payload, "verified": False})]


HTML_ENTITY_RE = re.compile(r"&(?:#\d{1,7}|#x[0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{1,31});")


@detector
def detect_html_entities(s: str, ctx: Context):
    if not HTML_ENTITY_RE.search(s):
        return None
    decoded = html.unescape(s)
    if decoded == s:
        return None
    lines = [f"-> {preview(decoded, 96)}"]
    for ent in dict.fromkeys(HTML_ENTITY_RE.findall(s)):
        ch = html.unescape(ent)
        if ch != ent and len(ch) <= 2:
            names = [unicodedata.name(c, "?") for c in ch]
            lines.append(f"{ent} = {clean(ch)}  U+{ord(ch[0]):04X} {' '.join(names)}")
    receipt = f"python3 -c 'import sys,html; print(html.unescape(sys.argv[1]))' {q(s)}"
    return [Reading("html entities", 0.9, f"HTML entities -> {preview(decoded, 60)}", lines[:10], receipt, nested(decoded, ctx))]


@detector
def detect_escapes(s: str, ctx: Context):
    """Backslash escapes as they appear in logs/JSON strings: \\u00e9, \\x41, \\n, \\303\\251."""
    if "\\" not in s or len(s) > 4096:
        return None
    if not re.search(r"\\(?:u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|x[0-9a-fA-F]{2}|[0-7]{3}|[nrt])", s):
        return None
    body = s
    if len(body) >= 2 and body[0] == body[-1] and body[0] in "\"'":
        body = body[1:-1]
    try:
        decoded = body.encode("latin-1", "backslashreplace").decode("unicode_escape")
    except (UnicodeDecodeError, UnicodeEncodeError):
        return None
    # unicode_escape treats bytes as latin-1; re-interpret \ooo / \xNN runs that form UTF-8.
    try:
        utf8_fixed = decoded.encode("latin-1").decode("utf-8")
        if utf8_fixed != decoded:
            decoded = utf8_fixed
    except (UnicodeDecodeError, UnicodeEncodeError):
        pass
    if decoded == body:
        return None
    lines = [f"-> {preview(decoded, 96)}"]
    receipt = f"printf '%b\\n' {q(body)}" if "\\u" not in body and "\\U" not in body else \
        f"python3 -c 'import sys; print(sys.argv[1].encode().decode(\"unicode_escape\"))' {q(body)}"
    return [Reading("escapes", 0.85, f"escape sequences -> {preview(decoded, 60)}", lines, receipt, nested(decoded, ctx))]


ANSI_RE = re.compile(r"\x1b\[([0-9;?]*)([A-Za-z])|\\(?:e|033|x1b|u001b)\[([0-9;?]*)([A-Za-z])")
SGR = {0: "reset", 1: "bold", 2: "dim", 3: "italic", 4: "underline", 5: "blink", 7: "reverse", 8: "hidden", 9: "strike",
       22: "normal intensity", 23: "no italic", 24: "no underline", 27: "no reverse", 29: "no strike", 39: "default fg", 49: "default bg"}
COLORS = ("black", "red", "green", "yellow", "blue", "magenta", "cyan", "white")


def sgr_words(params: str) -> str:
    if params == "":
        return "reset"
    codes = [int(p) if p else 0 for p in params.split(";")]
    words, i = [], 0
    while i < len(codes):
        c = codes[i]
        if c in SGR:
            words.append(SGR[c])
        elif 30 <= c <= 37:
            words.append(f"fg {COLORS[c - 30]}")
        elif 40 <= c <= 47:
            words.append(f"bg {COLORS[c - 40]}")
        elif 90 <= c <= 97:
            words.append(f"fg bright {COLORS[c - 90]}")
        elif 100 <= c <= 107:
            words.append(f"bg bright {COLORS[c - 100]}")
        elif c in (38, 48) and i + 2 < len(codes) and codes[i + 1] == 5:
            words.append(f"{'fg' if c == 38 else 'bg'} 256-color #{codes[i + 2]}")
            i += 2
        elif c in (38, 48) and i + 4 < len(codes) and codes[i + 1] == 2:
            words.append(f"{'fg' if c == 38 else 'bg'} rgb({codes[i + 2]},{codes[i + 3]},{codes[i + 4]})")
            i += 4
        else:
            words.append(f"SGR {c}")
        i += 1
    return ", ".join(words)


@detector
def detect_ansi(s: str, ctx: Context):
    matches = list(ANSI_RE.finditer(s))
    if not matches:
        return None
    lines = []
    stripped = ANSI_RE.sub("", s)
    if stripped.strip():
        lines.append(f"text without escapes: {preview(stripped, 80)}")
    for m in matches[:10]:
        params, final = (m.group(1), m.group(2)) if m.group(2) else (m.group(3), m.group(4))
        if final == "m":
            lines.append(f"ESC[{params}m  {sgr_words(params)}")
        else:
            meaning = {"A": "cursor up", "B": "cursor down", "C": "cursor forward", "D": "cursor back", "H": "cursor home/position",
                       "J": "erase in display", "K": "erase in line", "s": "save cursor", "u": "restore cursor",
                       "h": "set mode", "l": "reset mode", "G": "cursor to column", "n": "device status report"}.get(final, "control sequence")
            lines.append(f"ESC[{params}{final}  {meaning}")
    receipt = f"{printf_literal(s)} | sed 's/\\x1b\\[[0-9;?]*[A-Za-z]//g'"
    return [Reading("ansi", 0.95, f"{plural(len(matches), 'ANSI escape sequence')}: " + sgr_words(
        (matches[0].group(1) if matches[0].group(2) else matches[0].group(3)) or "") if (matches[0].group(2) or matches[0].group(4)) == "m"
        else f"{plural(len(matches), 'ANSI escape sequence')}", lines, receipt)]


CONFUSABLE_NOTE = {
    "Cf": "format character - invisible", "Cc": "control character", "Zs": "space, but not U+0020",
    "Mn": "combining mark - modifies the previous character", "Co": "private use - renders as a box or custom glyph",
}


def char_line(ch: str) -> str:
    cp = ord(ch)
    name = unicodedata.name(ch, "<unnamed>" if unicodedata.category(ch) != "Cc" else {
        0x00: "NULL", 0x07: "BELL", 0x08: "BACKSPACE", 0x09: "TAB", 0x0a: "LINE FEED", 0x0d: "CARRIAGE RETURN",
        0x1b: "ESCAPE", 0x7f: "DELETE"}.get(cp, "<control>"))
    cat = unicodedata.category(ch)
    utf8 = " ".join(f"{b:02x}" for b in ch.encode("utf-8", "surrogatepass"))
    note = CONFUSABLE_NOTE.get(cat, "")
    shown = clean(ch) if cat not in ("Mn", "Me") else "\u25cc" + ch
    return f"U+{cp:04X}  {name}  [{cat}]  utf-8 {utf8}  {shown}" + (f"  <- {note}" if note else "")


@detector
def detect_character(s: str, ctx: Context):
    """A single character, or a U+XXXX / &#x; / \\u reference to one."""
    text = s
    m = re.fullmatch(r"(?i)(?:U\+|\\u|\\U|0x|&#x)([0-9a-f]{2,8});?", text)
    if m and len(m.group(1)) >= 4 or (m and text.lower().startswith(("u+", "&#x"))):
        cp = int(m.group(1), 16)
        if cp > 0x10FFFF:
            return None
        text = chr(cp)
        via = f"code point reference {s}"
    else:
        via = None
        if len(text) != 1 and not (len(text) == 2 and unicodedata.category(text[1]) in ("Mn", "Me", "Mc")) \
                and not (len(text) <= 8 and all(unicodedata.category(c) in ("So", "Sk", "Mn", "Me", "Cf") or 0x1F000 <= ord(c) <= 0x1FFFF for c in text)):
            return None
    if len(text) == 1 and text.isascii() and text.isalnum() and via is None:
        conf = 0.3
    else:
        conf = 0.92 if via or not text.isascii() else 0.6
    lines = [char_line(c) for c in text[:8]]
    ch = text[0]
    cp = ord(ch)
    if len(text) == 1:
        lines.append(f"decimal {cp}, octal {cp:o}, HTML &#{cp}; / &#x{cp:x};" + (f", also {'&' + html.entities.codepoint2name[cp] + ';'}" if cp in html.entities.codepoint2name else ""))
        if unicodedata.decimal(ch, None) is not None or unicodedata.numeric(ch, None) is not None:
            lines.append(f"numeric value {unicodedata.numeric(ch)}")
        decomposed = unicodedata.normalize("NFKD", ch)
        if decomposed != ch and all(c.isascii() for c in decomposed):
            lines.append(f"looks like ASCII {clean(decomposed)!r} (NFKD) - a homoglyph risk in identifiers and URLs")
        try:
            block = unicodedata.name(ch).split()[0].title()
            lines.append(f"script/block hint: {block}")
        except ValueError:
            pass
    receipt = f"python3 -c 'import unicodedata,sys; c=sys.argv[1]; print(hex(ord(c)), unicodedata.name(c, \"?\"), unicodedata.category(c))' {q(text[0])}" \
        if text[0].isprintable() and text[0] != "'" else f"python3 -c 'import unicodedata; c=chr({cp}); print(unicodedata.name(c, \"?\"), unicodedata.category(c))'"
    if via is None and have("uconv"):
        receipt = f"{printf_literal(text)} | uconv -x 'any-name'"
    summary = f"U+{cp:04X} {unicodedata.name(ch, 'control character' if unicodedata.category(ch) == 'Cc' else 'unnamed')}" + \
        (f" + {len(text) - 1} more" if len(text) > 1 else "")
    return [Reading("character", conf, summary, lines, receipt)]


@detector
def detect_mojibake(s: str, ctx: Context):
    """UTF-8 bytes shown through a Latin-1/cp1252 lens: 'cafÃ©', 'â€™', 'ï¿½'."""
    if len(s) > 4096 or not re.search(r"[\u00c2\u00c3\u00e2\u00ef\u00c5\u00ce\u00d0\u00d1\u00d8\u00e0\u00e1][\u0080-\u00ff\u2013-\u203a\u00a0-\u00bf\u20ac\u2122\u0152\u0153\u0160\u0161\u0178\u017d\u017e\u0192\u02c6\u02dc\u2022\u2026\u2030\u2039\u203a]", s):
        return None
    for codec in ("cp1252", "latin-1"):
        try:
            fixed = s.encode(codec).decode("utf-8")
        except (UnicodeEncodeError, UnicodeDecodeError):
            continue
        if fixed != s:
            lines = [f"-> {preview(fixed, 96)}",
                     f"UTF-8 text that was decoded as {codec} (mojibake); each non-ASCII character became 2-4 characters"]
            if "\ufffd" in fixed:
                lines.append("contains U+FFFD REPLACEMENT CHARACTER: some bytes were already lost before this round trip")
            receipt = f"{printf_literal(s)} | iconv -f UTF-8 -t {'CP1252' if codec == 'cp1252' else 'LATIN1'}"
            return [Reading("unicode", 0.88, f"mojibake -> {preview(fixed, 60)}", lines, receipt, nested(fixed, ctx))]
    return None


@detector
def detect_unicode(s: str, ctx: Context):
    """Suspicious characters hiding in otherwise ordinary text: zero-width, bidi, lookalikes."""
    if len(s) < 2 or len(s) > 8192:
        return None
    suspicious = []
    for i, ch in enumerate(s):
        cat = unicodedata.category(ch)
        if cat in ("Cf", "Co", "Cn") or (cat == "Cc" and ch not in "\n\t\r") or (cat == "Zs" and ch != " ") \
                or ch in "\u00ad" or 0xFE00 <= ord(ch) <= 0xFE0F:
            suspicious.append((i, ch))
    non_ascii = [ch for ch in s if ord(ch) > 127]
    homoglyphs = []
    if non_ascii and sum(1 for ch in s if ch.isascii() and ch.isalpha()) >= 1:
        for i, ch in enumerate(s):
            if ord(ch) > 127 and ch.isalpha():
                folded = unicodedata.normalize("NFKD", ch)
                try:
                    name = unicodedata.name(ch)
                except ValueError:
                    continue
                if (("CYRILLIC" in name or "GREEK" in name or "ARMENIAN" in name) and ch.isalpha()) and len(folded) == 1:
                    homoglyphs.append((i, ch, name))
    if not suspicious and not homoglyphs:
        if non_ascii and len(non_ascii) <= 8 and len(s) <= 64 and not detect_mojibake(s, ctx):
            # modest info reading: what are the non-ASCII characters here
            lines = [f"offset {i}: {char_line(ch)}" for i, ch in enumerate(s) if ord(ch) > 127][:8]
            lines.append(f"{plural(len(s), 'character')}, {plural(len(s.encode('utf-8')), 'byte')} UTF-8, NFC {'yes' if unicodedata.is_normalized('NFC', s) else 'NO'}")
            return [Reading("unicode", 0.3, f"{plural(len(non_ascii), 'non-ASCII character')} in {plural(len(s), 'char')}", lines,
                            f"{printf_literal(s)} | iconv -f UTF-8 -t UTF-32LE | od -An -tx4 -w4 -v")]
        return None
    if suspicious and all(ch == "\x1b" for _, ch in suspicious) and ANSI_RE.search(s):
        return None  # terminal escape sequences: the ansi detector explains those
    if ctx.depth == 0 and (magic(raw_bytes(s)) or "") not in ("", "UTF-8 text with BOM", "UTF-16 LE text", "UTF-16 BE text", "script with a shebang"):
        return None  # file contents: the binary detector explains those
    lines = []
    for i, ch in suspicious[:12]:
        lines.append(f"offset {i}: {char_line(ch)}")
    for i, ch, name in homoglyphs[:8]:
        lines.append(f"offset {i}: U+{ord(ch):04X} {name} - looks like Latin {clean(unicodedata.normalize('NFKD', ch))!s}")
    visible = "".join(ch for i, ch in enumerate(s) if (i, ch) not in suspicious)
    if suspicious:
        lines.append(f"without the invisible characters: {preview(visible, 72)}")
    lines.append(f"{plural(len(s), 'character')}, {plural(len(s.encode('utf-8')), 'byte')} UTF-8")
    receipt = f"{printf_literal(s)} | iconv -f UTF-8 -t UTF-32LE | od -An -tx4 -w4 -v" if not have("uconv") \
        else f"{printf_literal(s)} | uconv -x 'any-name'"
    summary_bits = []
    if suspicious:
        kinds = dict.fromkeys(unicodedata.name(ch, "control") for _, ch in suspicious)
        summary_bits.append(f"{plural(len(suspicious), 'hidden character')} ({', '.join(list(kinds)[:2])}{', ...' if len(kinds) > 2 else ''})")
    if homoglyphs:
        summary_bits.append(f"{plural(len(homoglyphs), 'non-Latin lookalike letter')}")
    return [Reading("unicode", 0.96, " and ".join(summary_bits), lines, receipt)]


# == DETECTORS: numbers and system codes ==

def int_facts(n: int) -> list[str]:
    lines = []
    if n >= 0:
        lines.append(f"hex 0x{n:x}   octal 0o{n:o}   binary 0b{n:b}" if n.bit_length() <= 64 else f"hex 0x{n:x}")
    else:
        lines.append(f"hex -0x{-n:x}   two's complement 32-bit 0x{n & 0xFFFFFFFF:08x}, 64-bit 0x{n & 0xFFFFFFFFFFFFFFFF:016x}")
    if n > 0 and n.bit_length() <= 64:
        lines.append(f"{n.bit_length()} bits" + (f"; fits in {'u8' if n < 2**8 else 'u16' if n < 2**16 else 'u32' if n < 2**32 else 'u64'}")
                     + (f"; = 2^{n.bit_length() - 1}" if n & (n - 1) == 0 else "")
                     + (f"; = 2^{(n + 1).bit_length() - 1} - 1" if (n + 1) & n == 0 and n > 1 else ""))
    if n > 1 and n.bit_length() <= 64:
        if n in (255, 65535, 4294967295, 18446744073709551615, 127, 32767, 2147483647, 9223372036854775807):
            which = {255: "max u8", 65535: "max u16", 4294967295: "max u32", 18446744073709551615: "max u64", 127: "max i8",
                     32767: "max i16", 2147483647: "max i32 (INT_MAX)", 9223372036854775807: "max i64"}[n]
            lines.append(f"= {which}")
        elif n in (2147483648, 4294967296, 1073741824, 1048576, 1024, 65536, 16777216, 4096):
            lines.append(f"= {dict([(2147483648, '2^31'), (4294967296, '2^32'), (1073741824, '2^30 = 1 GiB'), (1048576, '2^20 = 1 MiB'), (1024, '2^10 = 1 KiB'), (65536, '2^16'), (16777216, '2^24 = 16 MiB / 24-bit colour count'), (4096, '2^12 = a common page size')])[n]}")
    return lines


def num_words(n: int) -> str:
    """Rough magnitude: 1.7 billion."""
    for value, word in ((10**12, "trillion"), (10**9, "billion"), (10**6, "million"), (10**3, "thousand")):
        if abs(n) >= value:
            return f"{n / value:.3g} {word}"
    return str(n)


@detector
def detect_number(s: str, ctx: Context):
    raw = s.replace("_", "")
    sign = -1 if raw.startswith("-") else 1
    body = raw.lstrip("+-")
    base, how = None, None
    if re.fullmatch(r"0[xX][0-9a-fA-F]{1,32}", body):
        base, how = 16, "hexadecimal literal"
    elif re.fullmatch(r"0[bB][01]{1,128}", body):
        base, how = 2, "binary literal"
    elif re.fullmatch(r"0[oO][0-7]{1,43}", body):
        base, how = 8, "octal literal"
    elif re.fullmatch(r"[01]{8,64}", body) and len(body) % 8 == 0:
        base, how = 2, "binary digits (a multiple of 8 bits)"
    elif re.fullmatch(r"\d{1,3}(?:,\d{3})+", body):
        base, how = 10, "decimal with thousands separators"
        body = body.replace(",", "")
    elif re.fullmatch(r"\d{1,40}", body):
        base, how = 10, "decimal"
    if base is None:
        return None
    n = sign * int(body, base)
    lines = []
    if base != 10:
        lines.append(f"decimal {commas(n)}" + (f"  ({num_words(n)})" if abs(n) >= 10000 else ""))
    elif abs(n) >= 10000:
        lines.append(f"{commas(n)}  ({num_words(n)})")
    lines.extend(int_facts(n))
    if base == 2 and len(body) % 8 == 0 and len(body) <= 64:
        chars = bytes(int(body[i:i + 8], 2) for i in range(0, len(body), 8))
        text = text_or_none(chars)
        if text and text.isprintable():
            lines.append(f"as 8-bit characters: {clean(text)!r}")
    if base == 10 and 1024 <= abs(n) < 2**60:
        lines.append(f"as bytes: {size_text(abs(n))}")
    if base == 10 and 60 <= abs(n) < 86400 * 365.25 * 10:
        lines.append(f"as seconds: {human_duration(abs(n))}" + (f"; as milliseconds: {human_duration(abs(n) / 1000)}" if abs(n) >= 1000 else ""))
    if base == 10 and len(body) <= 5 and s.isdigit():
        conf = 0.2  # small decimals are mostly exit codes/ports/http - let those speak
    elif base == 10:
        conf = 0.3
    else:
        conf = 0.8
    if base == 16 and 1 < len(body) - 2 <= 8:
        # Maybe a 32-bit float or a packed colour
        if len(body) - 2 == 8:
            f32 = struct.unpack(">f", (n & 0xFFFFFFFF).to_bytes(4, "big"))[0]
            if math.isfinite(f32) and abs(f32) > 1e-30:
                lines.append(f"as IEEE-754 float32 (big-endian): {f32:.7g}")
            lines.append(f"as 0xAARRGGBB colour: alpha {n >> 24 & 255}, rgb({n >> 16 & 255}, {n >> 8 & 255}, {n & 255})")
        if len(body) - 2 == 6:
            lines.append(f"as RGB colour: #{n:06x} = rgb({n >> 16 & 255}, {n >> 8 & 255}, {n & 255})")
    if base == 16 and len(body) - 2 == 16:
        f64 = struct.unpack(">d", (n & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "big"))[0]
        if math.isfinite(f64):
            lines.append(f"as IEEE-754 float64 (big-endian): {f64:.15g}")
    receipt = f"printf '%d 0x%x 0o%o\\n' {q(raw if base != 2 else str(n))} {q(raw if base != 2 else str(n))} {q(raw if base != 2 else str(n))}" if base != 2 \
        else f"echo $(( 2#{body} ))"
    if base == 10 and "," in s:
        receipt = f"printf '0x%x 0o%o\\n' {n} {n}"
    label = {16: "hex", 2: "binary", 8: "octal", 10: "integer"}[base]
    summary = f"{label} {commas(n)}" if base != 10 else f"integer {commas(n)}" + (f", {num_words(n)}" if abs(n) >= 10**4 else "")
    if base == 10 and abs(n) < 10**4:
        summary = f"integer {n} = 0x{abs(n):x} = 0b{abs(n):b}"
    return [Reading("number", conf, summary, lines, receipt, data={"value": n if abs(n) < 2**63 else str(n), "how": how})]


_SAFE_OPS = {
    ast.Add: operator.add, ast.Sub: operator.sub, ast.Mult: operator.mul, ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv, ast.Mod: operator.mod, ast.Pow: operator.pow, ast.LShift: operator.lshift,
    ast.RShift: operator.rshift, ast.BitAnd: operator.and_, ast.BitOr: operator.or_, ast.BitXor: operator.xor,
}


def safe_eval(expr: str):
    """Arithmetic only: literals, + - * / // % ** << >> & | ^ ~, parentheses. Bounded sizes."""
    if len(expr) > 200:
        raise ValueError("too long")
    tree = ast.parse(expr, mode="eval")
    if sum(1 for _ in ast.walk(tree)) > 60:
        raise ValueError("too complex")

    def ev(node):
        if isinstance(node, ast.Expression):
            return ev(node.body)
        if isinstance(node, ast.Constant) and type(node.value) in (int, float):
            return node.value
        if isinstance(node, ast.UnaryOp) and isinstance(node.op, (ast.USub, ast.UAdd, ast.Invert)):
            v = ev(node.operand)
            return -v if isinstance(node.op, ast.USub) else +v if isinstance(node.op, ast.UAdd) else ~v
        if isinstance(node, ast.BinOp) and type(node.op) in _SAFE_OPS:
            a, b = ev(node.left), ev(node.right)
            if isinstance(node.op, ast.Pow) and (abs(b) > 4096 or (isinstance(a, int) and abs(a) > 1 and abs(b) * math.log2(abs(a)) > 4096)):
                raise ValueError("exponent too large")
            if isinstance(node.op, (ast.LShift,)) and (b > 4096 or b < 0):
                raise ValueError("shift too large")
            if isinstance(node.op, ast.RShift) and b < 0:
                raise ValueError("negative shift")
            r = _SAFE_OPS[type(node.op)](a, b)
            if isinstance(r, int) and r.bit_length() > 4096:
                raise ValueError("result too large")
            if isinstance(r, float) and not math.isfinite(r):
                raise ValueError("not finite")
            return r
        raise ValueError("unsupported")
    return ev(tree)


@detector
def detect_arithmetic(s: str, ctx: Context):
    expr = s
    if not re.search(r"[+\-*/%&|^~<>()]", expr) or re.fullmatch(r"[+-]?\d+(?:\.\d+)?", expr) or len(expr) > 200:
        return None
    if not re.fullmatch(r"[\d\s+\-*/%&|^~<>().xXoObBa-fA-F_]+", expr):
        return None
    # Letters are only allowed as 0x/0b/0o prefixes and hex digits.
    if re.search(r"[a-zA-Z_]", re.sub(r"0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+", "0", expr)):
        return None
    if re.fullmatch(r"\d{1,3}(?:[.-]\d{1,3}){2,3}", expr) or re.fullmatch(r"[\d.:a-fA-F]*[.:][\d.:a-fA-F]*/\d+", expr):
        return None  # IPs, CIDRs, versions and dates are not sums
    if re.search(r"\d[-/]\d", expr) and re.fullmatch(r"\d{1,4}[-/]\d{1,2}[-/]\d{1,4}", expr):
        return None
    plain_minus = re.fullmatch(r"\d+\s*-\s*\d+", expr) is not None  # "2024-123" is as likely a date or a range
    caret_as_power = "^" in expr and "**" not in expr and not re.search(r"[&|]", expr)
    try:
        value = safe_eval(expr.replace("^", "**") if caret_as_power else expr)
    except (ValueError, SyntaxError, TypeError, ZeroDivisionError, OverflowError, RecursionError, MemoryError):
        return None
    lines = []
    if isinstance(value, int):
        lines.append(f"= {commas(value)}" + (f"  ({num_words(value)})" if abs(value) >= 10**4 else ""))
        lines.extend(int_facts(value)[:1])
    else:
        lines.append(f"= {value:.12g}")
        if value == int(value) and abs(value) < 2**53:
            lines.append(f"= {int(value)} exactly")
    if caret_as_power:
        try:
            xor = safe_eval(expr)
            lines.append(f"^ read as power; as XOR (C, Python, shells) it would be {xor}")
        except (ValueError, SyntaxError, TypeError, ZeroDivisionError, OverflowError):
            lines.append("^ read as power (in C, Python and shells ^ means XOR)")
    shell_safe = isinstance(value, int) and not caret_as_power and "**" not in expr and "/" not in expr and "0b" not in expr.lower() and "0o" not in expr.lower()
    receipt = f"echo $(( {expr} ))" if shell_safe else f"python3 -c 'print({expr.replace('^', '**') if caret_as_power else expr})'"
    shown = f"{commas(value)}" if isinstance(value, int) else f"{value:.12g}"
    conf = 0.9 if re.search(r"[\da-fA-F]\s*[+\-*/%&|^<>]+\s*[\d(]", expr) or "(" in expr else 0.6
    if plain_minus:
        conf = 0.5
    return [Reading("arithmetic", conf, f"{expr} = {shown}", lines, receipt,
                    data={"value": value if not isinstance(value, int) or abs(value) < 2**63 else str(value)})]


SIZE_RE = re.compile(r"(\d+(?:[.,]\d+)?)\s*([kKmMgGtTpPeE]?)(i?)([bB]?)(?:ytes?|its?)?")


def size_text(n: float) -> str:
    parts = []
    for unit, size in (("TiB", 2**40), ("GiB", 2**30), ("MiB", 2**20), ("KiB", 2**10)):
        if n >= size:
            parts.append(f"{n / size:.4g} {unit}")
            break
    for unit, size in (("TB", 10**12), ("GB", 10**9), ("MB", 10**6), ("kB", 10**3)):
        if n >= size:
            parts.append(f"{n / size:.4g} {unit}")
            break
    return " / ".join(parts) if parts else f"{n:g} bytes"


@detector
def detect_byte_size(s: str, ctx: Context):
    m = SIZE_RE.fullmatch(s)
    if not m:
        return None
    number, prefix, binary, unit = m.groups()
    explicit_unit = bool(unit) or s.lower().endswith(("bytes", "byte", "bits", "bit"))
    if not prefix and not explicit_unit:
        return None
    bits = s.lower().endswith(("bits", "bit")) or (unit == "b" and prefix and not s.lower().endswith("bytes"))
    value = float(number.replace(",", "."))
    exp = "kmgtpe".index(prefix.lower()) + 1 if prefix else 0
    decimal_n = value * 1000**exp
    binary_n = value * 1024**exp
    if bits:
        decimal_n, binary_n = decimal_n / 8, binary_n / 8
    lines = []
    if prefix:
        if binary:
            lines.append(f"{commas(round(binary_n))} bytes  (binary prefix {prefix.upper()}i = 1024^{exp})")
            lines.append(f"= {decimal_n and binary_n / 1000**exp:.4g} {prefix.upper()}B in decimal units")
            n = binary_n
        else:
            lines.append(f"if {prefix.upper()} = 1000^{exp} (SI, disks, networks): {commas(round(decimal_n))} bytes")
            lines.append(f"if {prefix.upper()} = 1024^{exp} (RAM, ls -h, Windows): {commas(round(binary_n))} bytes = {binary_n / 1000**exp:.4g} {prefix.upper()}B decimal")
            n = binary_n if prefix.lower() in "kmg" else decimal_n
    else:
        n = decimal_n
        lines.append(f"{commas(round(n))} bytes = {size_text(n)}")
    if bits:
        lines.append("read as bits (lowercase b / 'bits'); divide by 8 for bytes - done above")
    if n >= 1024:
        lines.append(f"{commas(round(n))} bytes = {commas(round(n / 1024))} KiB = {n / 2**20:.4g} MiB" + (f" = {n / 2**30:.4g} GiB" if n >= 2**30 else ""))
    if n >= 1_000_000:
        lines.append(f"{n / 10**6:.4g} MB decimal; {n * 8 / 10**6:.4g} Mbit; ~{n / (12.5 * 10**6):.3g} s at 100 Mbit/s, {n / (125 * 10**6):.3g} s at 1 Gbit/s")
    conf = 0.9 if explicit_unit or binary else 0.6
    if not explicit_unit and not binary and prefix.islower():
        conf = 0.45  # "5m" is more often minutes than megabytes
    numfmt_unit = "iec-i" if binary else "iec" if prefix and prefix.lower() in "kmg" else "si"
    receipt = f"numfmt --from={numfmt_unit} {q(number + prefix.upper() + ('i' if binary else ''))}" + \
        ("   # or --from=si for powers of 1000" if not binary and prefix else "")
    summary = f"{commas(round(n))} bytes" + (f" ({size_text(n)})" if n >= 1000 else "")
    if prefix and not binary:
        summary = f"{commas(round(binary_n))} B (binary) or {commas(round(decimal_n))} B (SI)"
    return [Reading("byte size", conf, summary, lines, receipt, data={"bytes": n})]


@detector
def detect_data_rate(s: str, ctx: Context):
    m = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([kKmMgG]?)(i?)([bB])(?:it|yte)?s?/?(?:ps|/s|per\s+s(?:ec(?:ond)?)?)", s)
    if not m:
        return None
    value, prefix, binary, unit = m.groups()
    exp = "kmg".index(prefix.lower()) + 1 if prefix else 0
    mult = 1024**exp if binary else 1000**exp
    per_s = float(value) * mult
    bits_per_s = per_s * (8 if unit == "B" or "yte" in s else 1)
    bytes_per_s = bits_per_s / 8
    lines = [f"{bits_per_s / 10**6:,.4g} Mbit/s = {bytes_per_s / 10**6:,.4g} MB/s = {bytes_per_s / 2**20:,.4g} MiB/s",
             f"1 GB takes {human_duration(10**9 / bytes_per_s)}; 1 GiB takes {human_duration(2**30 / bytes_per_s)}; {bytes_per_s * 3600 / 10**9:,.4g} GB per hour",
             "lowercase b = bits, uppercase B = bytes; ISPs quote bits, downloads show bytes"]
    return [Reading("data rate", 0.85, f"{bits_per_s / 10**6:,.4g} Mbit/s = {bytes_per_s / 2**20:,.4g} MiB/s", lines,
                    f"echo $(( {int(bits_per_s)} / 8 ))   # bytes per second")]


def mode_words(mode: int) -> str:
    who = {"owner": (mode >> 6) & 7, "group": (mode >> 3) & 7, "others": mode & 7}
    words = []
    for label, bits in who.items():
        perms = [name for bit, name in ((4, "read"), (2, "write"), (1, "execute")) if bits & bit]
        words.append(f"{label}: {', '.join(perms) if perms else 'nothing'}")
    return "; ".join(words)


@detector
def detect_chmod(s: str, ctx: Context):
    mode = None
    how = None
    if re.fullmatch(r"[0-7]{3,4}", s):
        mode = int(s, 8)
        how = "octal"
    elif re.fullmatch(r"[-dlcbsp][r-][w-][xsS-][r-][w-][xsS-][r-][w-][xtT-][.+@]?", s):
        how = "ls -l"
        mode = 0
        for i, ch in enumerate(s[1:10]):
            if ch not in "-ST":
                mode |= 1 << (8 - i)
        if s[3] in "sS":
            mode |= stat.S_ISUID
        if s[6] in "sS":
            mode |= stat.S_ISGID
        if s[9] in "tT":
            mode |= stat.S_ISVTX
    elif re.fullmatch(r"[r-][w-][x-][r-][w-][x-][r-][w-][x-]", s):
        how = "rwx triplets"
        mode = int("".join("0" if c == "-" else "1" for c in s), 2)
    if mode is None:
        if re.fullmatch(r"(?:[ugoa]*[+=-][rwxXstugo]+)(?:,[ugoa]*[+=-][rwxXstugo]+)*", s) and s not in ("-", "+", "="):
            clauses = []
            for clause in s.split(","):
                m = re.fullmatch(r"([ugoa]*)([+=-])([rwxXstugo]+)", clause)
                who, op, perms = m.groups()
                who_words = list_english([{"u": "owner", "g": "group", "o": "others", "a": "everyone"}[c] for c in dict.fromkeys(who)]) or "everyone (minus umask)"
                perm_words = list_english([{"r": "read", "w": "write", "x": "execute", "X": "execute (dirs, or already-executable files)",
                                            "s": "setuid/setgid", "t": "sticky", "u": "owner's bits", "g": "group's bits", "o": "others' bits"}[c] for c in dict.fromkeys(perms)])
                clauses.append(f"{ {'+': 'add', '-': 'remove', '=': 'set exactly'}[op]} {perm_words} for {who_words}")
            return [Reading("chmod", 0.8, f"chmod symbolic: {'; '.join(clauses)}", clauses + ["the result depends on the file's current mode"],
                            f"chmod -c {q(s)} FILE   # -c reports the change", data={"symbolic": s})]
        return None
    sym = stat.filemode(mode | (stat.S_IFDIR if s.startswith("d") else stat.S_IFREG))[1:]
    lines = [f"{mode & 0o777:03o} = {sym}  ({mode_words(mode)})"]
    special = []
    if mode & stat.S_ISUID:
        special.append("setuid (runs as the file's owner)")
    if mode & stat.S_ISGID:
        special.append("setgid (runs as the group / new files inherit the directory's group)")
    if mode & stat.S_ISVTX:
        special.append("sticky (in a directory, only owners can delete their files)")
    if special:
        lines.append("special bits: " + "; ".join(special))
    if how == "ls -l":
        kinds = {"-": "regular file", "d": "directory", "l": "symbolic link", "c": "character device", "b": "block device",
                 "s": "socket", "p": "named pipe"}
        lines.append(f"type: {kinds[s[0]]}" + ("; trailing . = SELinux context, + = ACL present, @ = extended attributes" if s[-1] in ".+@" else ""))
    lines.append(f"umask to create files like this by default: {(~mode) & 0o777:03o}" if how == "octal" and len(s) == 3 else
                 f"octal {mode & 0o7777:04o}")
    common = {0o755: "the usual mode for directories and executables", 0o644: "the usual mode for files", 0o600: "private file (ssh keys, secrets)",
              0o700: "private directory (~/.ssh)", 0o777: "everyone can do everything - rarely a good idea", 0o666: "everyone can read and write",
              0o400: "read-only for the owner (ssh private keys on some systems)", 0o4755: "setuid root binary mode (sudo, passwd)",
              0o1777: "sticky world-writable directory (/tmp)", 0o750: "group can enter, others cannot", 0o640: "group can read, others cannot"}
    if mode in common:
        lines.append(common[mode])
    if (mode & 0o002) and not s.startswith("d") and how != "octal":
        lines.append("world-writable file")
    conf = 0.9 if how != "octal" else (0.85 if s in ("755", "644", "600", "700", "777", "664", "775", "440", "640", "750", "666", "444", "400", "0755", "0644", "0600", "0700", "0777") else 0.45)
    if how == "octal" and len(s) == 4 and s[0] != "0" and mode not in common:
        conf = 0.3  # 1234 is more likely a number than sticky+234
    receipt = f"stat -c '%a %A %n' FILE   # mode of a file; chmod {s if how == 'octal' else format(mode & 0o7777, 'o')} FILE sets this one"
    summary = f"chmod {mode & 0o7777:o} = {('d' if s.startswith('d') else '-') + sym}" if how == "octal" else f"{s[:10]} = chmod {mode & 0o7777:o}"
    return [Reading("chmod", conf, summary, lines, receipt, data={"octal": format(mode & 0o7777, "o"), "symbolic": sym})]


EXIT_CODES = {
    0: "success", 1: "general error (catch-all)", 2: "misuse of a shell builtin, or bad usage / missing file in many tools",
    64: "EX_USAGE: command line usage error (sysexits.h)", 65: "EX_DATAERR: bad input data", 66: "EX_NOINPUT: input file missing or unreadable",
    67: "EX_NOUSER: user unknown", 68: "EX_NOHOST: host unknown", 69: "EX_UNAVAILABLE: service unavailable", 70: "EX_SOFTWARE: internal software error",
    71: "EX_OSERR: system error", 72: "EX_OSFILE: critical OS file missing", 73: "EX_CANTCREAT: cannot create output", 74: "EX_IOERR: I/O error",
    75: "EX_TEMPFAIL: temporary failure, retry", 76: "EX_PROTOCOL: remote protocol error", 77: "EX_NOPERM: permission denied", 78: "EX_CONFIG: configuration error",
    100: "pip/apt/make: generic failure (tool-specific)", 124: "timeout(1): the command timed out", 125: "docker: the daemon itself failed; also xargs/timeout internal error",
    126: "command found but not executable (permissions, or a directory)", 127: "command not found (typo, or not on PATH)", 128: "invalid exit argument",
    130: "terminated by Ctrl-C (128 + SIGINT 2)", 137: "killed with SIGKILL (128 + 9) - often the OOM killer or docker/kubernetes memory limits", 139: "segmentation fault (128 + SIGSEGV 11)",
    143: "terminated with SIGTERM (128 + 15) - a polite kill, docker stop, kubectl delete", 255: "exit status out of range, or ssh connection failure",
}


@detector
def detect_exit_code(s: str, ctx: Context):
    if not re.fullmatch(r"\d{1,3}", s):
        return None
    n = int(s)
    if n > 255:
        return None
    lines = []
    conf = 0.2
    meaning = EXIT_CODES.get(n)
    if meaning:
        lines.append(meaning)
        conf = 0.75 if n in (1, 2, 126, 127, 130, 137, 139, 143) else 0.55
        if n == 137:
            conf = 0.9
    if 128 < n <= 128 + 64:
        signum = n - 128
        try:
            name = signal_mod.Signals(signum).name
            desc = signal_mod.strsignal(signum) if hasattr(signal_mod, "strsignal") else name
            lines.append(f"128 + {signum} = killed by {name} ({desc})")
            if not meaning:
                conf = 0.6
            if n == 137:
                lines.append("check: dmesg -T | grep -i 'killed process'   (OOM), or docker inspect --format '{{.State.OOMKilled}}' CONTAINER")
        except ValueError:
            pass
    if n == 0:
        conf = 0.3
    if not lines:
        lines.append("no conventional meaning; application-defined (anything 3-125 is the program's own)")
    lines.append("inspect the last status in a shell with: echo $?")
    receipt = f"kill -l {n - 128}" if 128 < n <= 192 else "echo $?   # right after the command"
    summary = f"exit code {n}: {meaning.split(' - ')[0] if meaning else lines[0]}"
    return [Reading("exit code", conf, summary, lines, receipt, data={"code": n})]


@detector
def detect_signal(s: str, ctx: Context):
    name = s.upper()
    if re.fullmatch(r"-?\d{1,2}", s):
        try:
            sig = signal_mod.Signals(abs(int(s)))
        except ValueError:
            return None
        conf = 0.45 if s.startswith("-") else 0.25
    else:
        if not name.startswith("SIG"):
            name = "SIG" + name
        if name not in signal_mod.Signals.__members__ or len(name) > 10:
            return None
        sig = signal_mod.Signals[name]
        conf = 0.9
    desc = signal_mod.strsignal(sig) if hasattr(signal_mod, "strsignal") else sig.name
    default = {"SIGKILL": "cannot be caught or ignored; the process dies immediately", "SIGTERM": "polite request to exit; the default for kill(1)",
               "SIGINT": "Ctrl-C", "SIGQUIT": "Ctrl-\\, dumps core", "SIGHUP": "terminal hung up; daemons reread config", "SIGSTOP": "pause, cannot be caught",
               "SIGTSTP": "Ctrl-Z", "SIGCONT": "resume a stopped process", "SIGSEGV": "invalid memory access", "SIGABRT": "abort(), assertion failure",
               "SIGPIPE": "wrote to a pipe nobody reads (head/less closed early)", "SIGCHLD": "a child process exited", "SIGUSR1": "user-defined; nginx reopen logs, dd print progress",
               "SIGUSR2": "user-defined", "SIGALRM": "alarm() timer expired", "SIGBUS": "bad memory alignment or truncated mmap", "SIGFPE": "arithmetic error (divide by zero)",
               "SIGWINCH": "terminal resized", "SIGXCPU": "CPU time limit exceeded", "SIGTRAP": "debugger breakpoint"}.get(sig.name, "")
    lines = [f"{sig.name} = {int(sig)}: {desc}" + (f"  ({default})" if default else ""),
             f"a process killed by it exits with status {128 + int(sig)}",
             f"send it: kill -{sig.name[3:]} PID"]
    return [Reading("signal", conf, f"{sig.name} ({int(sig)}): {desc}", lines, f"kill -l {int(sig)}", data={"number": int(sig)})]


ERRNO_HINTS = {
    "ENOENT": "a path component does not exist (typo, wrong cwd, missing dependency)", "EACCES": "permission denied by file mode or ownership",
    "EPERM": "operation not permitted: needs root or a capability, or the file is immutable", "EEXIST": "the target already exists",
    "ECONNREFUSED": "nothing is listening on that host:port", "ECONNRESET": "the peer closed the connection abruptly",
    "ETIMEDOUT": "no answer in time - firewall, wrong host, or the service is down", "EADDRINUSE": "port already bound: another process is listening",
    "EMFILE": "too many open files for this process (ulimit -n)", "ENOSPC": "disk (or inode table) full", "EPIPE": "wrote to a closed pipe/socket",
    "EAGAIN": "try again: non-blocking I/O had nothing ready, or a resource limit hit (fork)", "EINTR": "a signal interrupted the call; retry",
    "EINVAL": "invalid argument to a system call", "ENOTDIR": "a path component is not a directory", "EISDIR": "expected a file, got a directory",
    "EBUSY": "device or resource busy (unmounting a mounted fs?)", "EROFS": "read-only filesystem", "ENOMEM": "out of memory",
    "ENXIO": "no such device or address", "EIO": "low-level I/O error - check dmesg", "ENOTEMPTY": "directory not empty",
    "ELOOP": "too many symbolic links (a symlink loop)", "ENAMETOOLONG": "path or component too long", "EXDEV": "cross-device link (rename across filesystems)",
    "EHOSTUNREACH": "no route to host", "ENETUNREACH": "network unreachable", "EPROTO": "protocol error", "ENOTSUP": "operation not supported",
}


@detector
def detect_errno(s: str, ctx: Context):
    name = None
    text = s
    m = re.fullmatch(r"(?i)errno\s*[=:]?\s*(\d{1,3}|E[A-Z0-9]{2,15})", s)
    if m:
        text = m.group(1).upper() if not m.group(1).isdigit() else m.group(1)
    if re.fullmatch(r"E[A-Z0-9]{2,15}", text) and hasattr(errno_mod, text):
        name = text
        num = getattr(errno_mod, text)
        conf = 0.95
    elif re.fullmatch(r"\d{1,3}", text) and int(text) in errno_mod.errorcode:
        num = int(text)
        name = errno_mod.errorcode[num]
        conf = 0.9 if m else 0.35 if num <= 34 else 0.25
    else:
        return None
    lines = [f"{name} = {num}: {os.strerror(num)}"]
    if name in ERRNO_HINTS:
        lines.append(ERRNO_HINTS[name])
    aliases = [n for n in dir(errno_mod) if n.startswith("E") and getattr(errno_mod, n) == num and n != name]
    if aliases:
        lines.append(f"same number as {', '.join(aliases)} on this platform")
    lines.append(f"numbers are platform-specific; this table is {sys.platform}'s")
    receipt = f"errno {name}" if have("errno") else f"python3 -c 'import os,errno; print(errno.{name}, os.strerror(errno.{name}))'"
    return [Reading("errno", conf, f"{name} ({num}): {os.strerror(num)}", lines, receipt, data={"name": name, "number": num})]


HTTP_HINTS = {
    301: "permanent redirect; browsers cache it aggressively", 302: "temporary redirect", 304: "not modified: use your cached copy",
    307: "temporary redirect keeping the method/body", 308: "permanent redirect keeping the method/body",
    400: "the server could not parse the request", 401: "not authenticated: missing or invalid credentials (despite the name)",
    403: "authenticated but not allowed", 404: "no such resource", 405: "wrong HTTP method for this URL", 408: "the client took too long to send the request",
    409: "conflict with the current state (duplicate, version mismatch)", 410: "gone for good", 413: "request body too large", 415: "unsupported Content-Type",
    418: "I'm a teapot (RFC 2324, April 1st)", 422: "well-formed but semantically invalid", 429: "rate limited: slow down, check Retry-After",
    500: "unhandled error on the server", 501: "not implemented", 502: "a proxy/load balancer got a bad response from the backend",
    503: "overloaded or in maintenance; check Retry-After", 504: "the upstream did not answer the proxy in time",
    200: "success", 201: "created", 202: "accepted for later processing", 204: "success with no body", 206: "partial content (range request)",
}


@detector
def detect_http_status(s: str, ctx: Context):
    if not re.fullmatch(r"[1-5]\d{2}", s):
        return None
    n = int(s)
    try:
        status = http.HTTPStatus(n)
        phrase, desc = status.phrase, status.description
    except ValueError:
        if n in (419, 420, 430, 440, 444, 449, 450, 499, 509, 520, 521, 522, 523, 524, 525, 526, 527, 530, 599):
            phrase = {444: "No Response (nginx)", 499: "Client Closed Request (nginx)", 509: "Bandwidth Limit Exceeded",
                      520: "Web Server Returned an Unknown Error (Cloudflare)", 521: "Web Server Is Down (Cloudflare)", 522: "Connection Timed Out (Cloudflare)",
                      523: "Origin Is Unreachable (Cloudflare)", 524: "A Timeout Occurred (Cloudflare)", 525: "SSL Handshake Failed (Cloudflare)",
                      526: "Invalid SSL Certificate (Cloudflare)", 527: "Railgun Error (Cloudflare)", 530: "Cloudflare error", 599: "Network Connect Timeout (non-standard)",
                      419: "Page Expired (Laravel CSRF)", 420: "Enhance Your Calm (Twitter, old)", 430: "Request Header Fields Too Large (Shopify)",
                      440: "Login Time-out (IIS)", 449: "Retry With (IIS)", 450: "Blocked by Parental Controls (Microsoft)"}[n]
            desc = "non-standard"
        else:
            return None
    cls = {1: "informational", 2: "success", 3: "redirection", 4: "client error", 5: "server error"}[n // 100]
    lines = [f"{n} {phrase} - {cls}" + (f"; {desc}" if desc and desc != "non-standard" else "")]
    if n in HTTP_HINTS:
        lines.append(HTTP_HINTS[n])
    conf = 0.85 if n in HTTP_HINTS or n in (100, 101, 203, 205, 300, 303, 305, 402, 406, 407, 411, 412, 414, 416, 417, 423, 424, 426, 428, 431, 451, 505, 506, 507, 508, 510, 511) else 0.5
    receipt = f"curl -sS -o /dev/null -w '%{{http_code}}\\n' URL   # what a URL actually returns"
    return [Reading("http status", conf, f"HTTP {n} {phrase}: {HTTP_HINTS.get(n, cls)}", lines, receipt, data={"code": n, "phrase": phrase})]


WELL_KNOWN_PORTS = {
    20: "FTP data", 21: "FTP control", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP server", 68: "DHCP client", 69: "TFTP", 80: "HTTP",
    88: "Kerberos", 110: "POP3", 111: "rpcbind/portmapper", 119: "NNTP", 123: "NTP", 135: "MS RPC", 137: "NetBIOS name service", 138: "NetBIOS datagram",
    139: "NetBIOS session / SMB over NetBIOS", 143: "IMAP", 161: "SNMP", 162: "SNMP trap", 179: "BGP", 194: "IRC", 389: "LDAP", 443: "HTTPS",
    445: "SMB (Windows file sharing)", 465: "SMTPS (submission over TLS)", 500: "IKE (IPsec)", 514: "syslog", 515: "LPD printing", 520: "RIP",
    546: "DHCPv6 client", 547: "DHCPv6 server", 587: "SMTP submission (STARTTLS)", 631: "IPP / CUPS printing", 636: "LDAPS", 853: "DNS over TLS",
    873: "rsync", 989: "FTPS data", 990: "FTPS control", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS proxy", 1194: "OpenVPN", 1433: "Microsoft SQL Server",
    1521: "Oracle DB", 1723: "PPTP", 1883: "MQTT", 2049: "NFS", 2375: "Docker daemon (plain)", 2376: "Docker daemon (TLS)", 2379: "etcd client",
    2380: "etcd peer", 3000: "dev servers (Rails, Grafana, Node apps)", 3128: "Squid proxy", 3268: "AD global catalog", 3306: "MySQL / MariaDB",
    3389: "RDP (Windows remote desktop)", 4443: "HTTPS alternate", 4444: "Metasploit default / Selenium Grid", 5000: "Flask dev server / Docker registry / macOS AirPlay",
    5001: "iperf", 5060: "SIP", 5061: "SIP over TLS", 5173: "Vite dev server", 5222: "XMPP", 5353: "mDNS (Bonjour/Avahi)", 5432: "PostgreSQL", 5601: "Kibana",
    5671: "AMQP over TLS", 5672: "AMQP (RabbitMQ)", 5900: "VNC", 5984: "CouchDB", 6000: "X11", 6379: "Redis", 6443: "Kubernetes API server", 6514: "syslog over TLS",
    6667: "IRC", 7001: "WebLogic", 8000: "dev servers (Django, python -m http.server)", 8008: "HTTP alternate", 8080: "HTTP alternate / proxies / Tomcat",
    8081: "HTTP alternate / Nexus", 8086: "InfluxDB", 8088: "Hadoop YARN", 8123: "Home Assistant / ClickHouse HTTP", 8200: "HashiCorp Vault", 8443: "HTTPS alternate",
    8500: "Consul", 8888: "Jupyter", 9000: "PHP-FPM / SonarQube / MinIO (older)", 9090: "Prometheus", 9092: "Kafka", 9093: "Alertmanager", 9100: "node_exporter / JetDirect printing",
    9200: "Elasticsearch HTTP", 9300: "Elasticsearch transport", 9418: "git protocol", 10250: "kubelet", 11211: "memcached", 15672: "RabbitMQ management",
    25565: "Minecraft", 27017: "MongoDB", 27018: "MongoDB shard", 32400: "Plex", 51820: "WireGuard",
}


@detector
def detect_port(s: str, ctx: Context):
    m = re.fullmatch(r":?(\d{1,5})(?:/(tcp|udp))?", s)
    if not m:
        return None
    n = int(m.group(1))
    if n > 65535 or n == 0:
        return None
    proto = m.group(2)
    known = WELL_KNOWN_PORTS.get(n)
    etc = None
    try:
        import socket
        etc = socket.getservbyport(n, proto or "tcp")
    except (OSError, OverflowError):
        try:
            import socket
            etc = socket.getservbyport(n, "udp")
        except (OSError, OverflowError):
            etc = None
    if not known and not etc and not s.startswith(":") and not proto:
        return None
    lines = []
    if known:
        lines.append(f"commonly {known}")
    if etc and (not known or etc.lower() not in known.lower()):
        lines.append(f"/etc/services: {etc}")
    rng = "well-known (0-1023, needs root to bind)" if n < 1024 else "registered (1024-49151)" if n < 49152 else "dynamic/ephemeral (49152-65535)"
    lines.append(rng)
    lines.append(f"who is listening: ss -ltnp 'sport = :{n}'   (or lsof -i :{n})")
    conf = 0.7 if known and (n < 1024 or n in (3306, 5432, 6379, 8080, 27017, 3389, 5900, 8443, 9200, 3000, 8000, 5000)) else 0.45 if known or etc else 0.3
    if n < 20 and n not in (7, 9, 13):
        conf = min(conf, 0.25)
    elif n in (7, 9, 13):
        conf = 0.25  # echo/discard/daytime: historic, nobody runs them
    if s.startswith(":") or proto:
        conf = max(conf, 0.85)
    summary = f"port {n}: {known or etc or 'no well-known service'}"
    return [Reading("port", conf, summary, lines, f"getent services {n}" + (f"/{proto}" if proto else ""), data={"port": n, "service": known or etc})]


CSS_COLORS = {
    "black": (0, 0, 0), "white": (255, 255, 255), "red": (255, 0, 0), "lime": (0, 255, 0), "blue": (0, 0, 255), "yellow": (255, 255, 0),
    "cyan": (0, 255, 255), "aqua": (0, 255, 255), "magenta": (255, 0, 255), "fuchsia": (255, 0, 255), "silver": (192, 192, 192), "gray": (128, 128, 128),
    "grey": (128, 128, 128), "maroon": (128, 0, 0), "olive": (128, 128, 0), "green": (0, 128, 0), "purple": (128, 0, 128), "teal": (0, 128, 128),
    "navy": (0, 0, 128), "orange": (255, 165, 0), "gold": (255, 215, 0), "pink": (255, 192, 203), "hotpink": (255, 105, 180), "deeppink": (255, 20, 147),
    "crimson": (220, 20, 60), "tomato": (255, 99, 71), "coral": (255, 127, 80), "salmon": (250, 128, 114), "orangered": (255, 69, 0), "darkorange": (255, 140, 0),
    "khaki": (240, 230, 140), "beige": (245, 245, 220), "ivory": (255, 255, 240), "tan": (210, 180, 140), "brown": (165, 42, 42), "chocolate": (210, 105, 30),
    "sienna": (160, 82, 45), "peru": (205, 133, 63), "wheat": (245, 222, 179), "linen": (250, 240, 230), "lavender": (230, 230, 250), "plum": (221, 160, 221),
    "violet": (238, 130, 238), "orchid": (218, 112, 214), "indigo": (75, 0, 130), "slateblue": (106, 90, 205), "royalblue": (65, 105, 225), "dodgerblue": (30, 144, 255),
    "deepskyblue": (0, 191, 255), "skyblue": (135, 206, 235), "lightblue": (173, 216, 230), "steelblue": (70, 130, 180), "cornflowerblue": (100, 149, 237),
    "midnightblue": (25, 25, 112), "darkblue": (0, 0, 139), "turquoise": (64, 224, 208), "aquamarine": (127, 255, 212), "seagreen": (46, 139, 87),
    "forestgreen": (34, 139, 34), "limegreen": (50, 205, 50), "springgreen": (0, 255, 127), "chartreuse": (127, 255, 0), "olivedrab": (107, 142, 35),
    "darkgreen": (0, 100, 0), "lightgreen": (144, 238, 144), "palegreen": (152, 251, 152), "mintcream": (245, 255, 250), "honeydew": (240, 255, 240),
    "slategray": (112, 128, 144), "slategrey": (112, 128, 144), "lightgray": (211, 211, 211), "lightgrey": (211, 211, 211), "darkgray": (169, 169, 169),
    "darkgrey": (169, 169, 169), "dimgray": (105, 105, 105), "dimgrey": (105, 105, 105), "gainsboro": (220, 220, 220), "whitesmoke": (245, 245, 245),
    "snow": (255, 250, 250), "firebrick": (178, 34, 34), "darkred": (139, 0, 0), "rebeccapurple": (102, 51, 153), "darkviolet": (148, 0, 211),
    "mediumpurple": (147, 112, 219), "goldenrod": (218, 165, 32), "lemonchiffon": (255, 250, 205), "lightyellow": (255, 255, 224), "papayawhip": (255, 239, 213),
    "peachpuff": (255, 218, 185), "mistyrose": (255, 228, 225), "aliceblue": (240, 248, 255), "azure": (240, 255, 255), "lightcyan": (224, 255, 255),
    "cadetblue": (95, 158, 160), "darkcyan": (0, 139, 139), "lightseagreen": (32, 178, 170), "mediumseagreen": (60, 179, 113), "darkslategray": (47, 79, 79),
    "darkslategrey": (47, 79, 79), "darkslateblue": (72, 61, 139), "mediumslateblue": (123, 104, 238), "lightsteelblue": (176, 196, 222), "powderblue": (176, 224, 230),
    "thistle": (216, 191, 216), "rosybrown": (188, 143, 143), "burlywood": (222, 184, 135), "sandybrown": (244, 164, 96), "navajowhite": (255, 222, 173),
    "moccasin": (255, 228, 181), "bisque": (255, 228, 196), "blanchedalmond": (255, 235, 205), "antiquewhite": (250, 235, 215), "oldlace": (253, 245, 230),
    "floralwhite": (255, 250, 240), "seashell": (255, 245, 238), "cornsilk": (255, 248, 220), "lightpink": (255, 182, 193), "palevioletred": (219, 112, 147),
    "mediumvioletred": (199, 21, 133), "darkmagenta": (139, 0, 139), "mediumorchid": (186, 85, 211), "blueviolet": (138, 43, 226), "darkorchid": (153, 50, 204),
    "mediumblue": (0, 0, 205), "lightskyblue": (135, 206, 250), "lightslategray": (119, 136, 153), "lightslategrey": (119, 136, 153), "mediumturquoise": (72, 209, 204),
    "paleturquoise": (175, 238, 238), "darkturquoise": (0, 206, 209), "mediumaquamarine": (102, 205, 170), "darkseagreen": (143, 188, 143), "mediumspringgreen": (0, 250, 154),
    "lawngreen": (124, 252, 0), "greenyellow": (173, 255, 47), "yellowgreen": (154, 205, 50), "darkolivegreen": (85, 107, 47), "darkkhaki": (189, 183, 107),
    "palegoldenrod": (238, 232, 170), "darkgoldenrod": (184, 134, 11), "lightsalmon": (255, 160, 122), "darksalmon": (233, 150, 122), "lightcoral": (240, 128, 128),
    "indianred": (205, 92, 92), "saddlebrown": (139, 69, 19), "lavenderblush": (255, 240, 245), "ghostwhite": (248, 248, 255),
}


def nearest_css(rgb: tuple[int, int, int]) -> tuple[str, float]:
    best, dist = "", float("inf")
    for name, (r, g, b) in CSS_COLORS.items():
        d = (r - rgb[0]) ** 2 + (g - rgb[1]) ** 2 + (b - rgb[2]) ** 2
        if d < dist:
            best, dist = name, d
    return best, math.sqrt(dist)


def luminance(rgb: tuple[int, int, int]) -> float:
    def chan(c: int) -> float:
        v = c / 255
        return v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = (chan(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


@detector
def detect_color(s: str, ctx: Context):
    rgb = None
    alpha = None
    how = None
    text = s.lower().strip()
    m = re.fullmatch(r"#?([0-9a-f]{3}|[0-9a-f]{4}|[0-9a-f]{6}|[0-9a-f]{8})", text)
    if m and (text.startswith("#") or len(m.group(1)) in (6, 8) and any(c.isalpha() for c in text)):
        h = m.group(1)
        if len(h) in (3, 4):
            h = "".join(c * 2 for c in h)
        rgb = (int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16))
        if len(h) == 8:
            alpha = int(h[6:8], 16) / 255
        how = "hex"
    m = re.fullmatch(r"rgba?\(\s*(\d{1,3})\s*[, ]\s*(\d{1,3})\s*[, ]\s*(\d{1,3})\s*(?:[,/]\s*([\d.]+%?)\s*)?\)", text)
    if m:
        rgb = tuple(min(255, int(v)) for v in m.groups()[:3])
        if m.group(4):
            alpha = float(m.group(4).rstrip("%")) / (100 if m.group(4).endswith("%") else 1)
        how = "rgb()"
    m = re.fullmatch(r"hsla?\(\s*([\d.]+)(?:deg)?\s*[, ]\s*([\d.]+)%\s*[, ]\s*([\d.]+)%\s*(?:[,/]\s*([\d.]+%?)\s*)?\)", text)
    if m:
        hh, ss_, ll = float(m.group(1)) % 360 / 360, float(m.group(2)) / 100, float(m.group(3)) / 100
        r, g, b = colorsys.hls_to_rgb(hh, ll, ss_)
        rgb = (round(r * 255), round(g * 255), round(b * 255))
        how = "hsl()"
    if rgb is None and text in CSS_COLORS:
        rgb = CSS_COLORS[text]
        how = "CSS name"
    if rgb is None:
        return None
    r, g, b = rgb
    hh, ll, ss_ = colorsys.rgb_to_hls(r / 255, g / 255, b / 255)
    name, dist = nearest_css(rgb)
    lum = luminance(rgb)
    contrast_white = (1.05) / (lum + 0.05)
    contrast_black = (lum + 0.05) / 0.05
    lines = [f"#{r:02x}{g:02x}{b:02x} = rgb({r}, {g}, {b}) = hsl({hh * 360:.0f}, {ss_ * 100:.0f}%, {ll * 100:.0f}%)"]
    if alpha is not None:
        lines.append(f"alpha {alpha:.2f} ({alpha * 100:.0f}% opaque)")
    lines.append(f"nearest CSS name: {name}" + ("" if dist == 0 else f" (distance {dist:.0f})"))
    lines.append(f"{'light' if lum > 0.5 else 'dark'} colour; contrast vs white {contrast_white:.1f}:1, vs black {contrast_black:.1f}:1 "
                 f"({'black' if contrast_black > contrast_white else 'white'} text reads better; 4.5:1 is the WCAG AA minimum)")
    lines.append(f"ANSI truecolor: \\e[38;2;{r};{g};{b}m   nearest 256-colour index {16 + 36 * round(r / 51) + 6 * round(g / 51) + round(b / 51)}")
    lines.append(f"as a packed int: {r << 16 | g << 8 | b} (0x{r << 16 | g << 8 | b:06x}); little-endian BGR 0x{b << 16 | g << 8 | r:06x}")
    conf = 0.92 if how in ("rgb()", "hsl()") or text.startswith("#") else 0.75 if how == "CSS name" else 0.45
    if how == "hex" and not text.startswith("#") and len(text) == 8:
        conf = 0.3  # 8 bare hex digits: more often a short hash/id than an RRGGBBAA colour
    receipt = f"printf '\\e[48;2;{r};{g};{b}m    \\e[0m #{r:02x}{g:02x}{b:02x}\\n'   # paints a swatch in a truecolor terminal"
    summary = f"#{r:02x}{g:02x}{b:02x} rgb({r},{g},{b}) hsl({hh * 360:.0f},{ss_ * 100:.0f}%,{ll * 100:.0f}%) ~ {name}"
    return [Reading("color", conf, summary, lines, receipt, data={"hex": f"#{r:02x}{g:02x}{b:02x}", "rgb": [r, g, b], "nearest": name})]


# == DETECTORS: identifiers, networks, files ==

@detector
def detect_uuid(s: str, ctx: Context):
    text = s.strip("{}").lower()
    if text.startswith("urn:uuid:"):
        text = text[9:]
    if not re.fullmatch(r"[0-9a-f]{8}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{4}-?[0-9a-f]{12}", text):
        return None
    try:
        u = uuid_mod.UUID(text.replace("-", ""))
    except ValueError:
        return None
    hyphenated = "-" in text
    if u.int == 0:
        return [Reading("uuid", 0.95, "the nil UUID (all zeros)", ["often a placeholder or 'no value'"], f"uuidparse {text}" if have("uuidparse") else None)]
    if u.int == (1 << 128) - 1:
        return [Reading("uuid", 0.95, "the max UUID (all ones)", ["RFC 9562 sentinel value"], None)]
    variant = u.variant
    version = u.version if variant == uuid_mod.RFC_4122 else None
    lines = []
    conf = 0.95 if hyphenated else 0.5
    data = {"uuid": str(u), "version": version}
    kind_text = f"UUID v{version}" if version else "UUID (non-RFC variant)"
    when = None
    if version == 1:
        ts = (u.time - 0x01B21DD213814000) / 1e7
        try:
            when = dt.datetime.fromtimestamp(ts, UTC)
            lines.append(f"v1 time-based: {fmt(when, ctx.zone)}  ({relative(when, ctx.now)}), clock seq {u.clock_seq}")
            node = f"{u.node:012x}"
            mac = ":".join(node[i:i + 2] for i in range(0, 12, 2))
            lines.append(f"node {mac}" + (" (random, multicast bit set)" if u.node >> 40 & 1 else " - looks like a real MAC address of the generating host"))
        except (OverflowError, OSError, ValueError):
            pass
    elif version == 6:
        t = ((u.time_low << 28) | (u.time_mid << 12) | (u.time_hi_version & 0x0FFF))
        ts = (t - 0x01B21DD213814000) / 1e7
        try:
            when = dt.datetime.fromtimestamp(ts, UTC)
            lines.append(f"v6 reordered time: {fmt(when, ctx.zone)}  ({relative(when, ctx.now)})")
        except (OverflowError, OSError, ValueError):
            pass
    elif version == 7:
        ms = u.int >> 80
        when = dt.datetime.fromtimestamp(ms / 1000, UTC)
        lines.append(f"v7 Unix-time ordered: created {fmt(when, ctx.zone)}  ({relative(when, ctx.now)})")
        lines.append("sorts by creation time; the remaining 74 bits are random")
    elif version == 4:
        lines.append("v4 random: 122 random bits, no embedded time or host; collision odds are negligible")
    elif version == 3 or version == 5:
        lines.append(f"v{version} name-based: {'MD5' if version == 3 else 'SHA-1'} of a namespace + name; the same input always gives this UUID")
    elif version == 8:
        lines.append("v8 custom/vendor-defined layout")
    elif version == 2:
        lines.append("v2 DCE security UUID (rare)")
    if variant != uuid_mod.RFC_4122:
        lines.append(f"variant: {variant} - not an RFC 4122/9562 UUID; may be a GUID from another system, or random bytes")
        conf -= 0.2
    lines.append(f"hex {u.hex}  int {u.int}  urn:uuid:{u}")
    if hyphenated and text != str(u):
        lines.append(f"canonical form: {u}")
    if have("uuidparse"):
        receipt = f"uuidparse {text}"
    else:
        receipt = f"python3 -c 'import uuid,sys; u=uuid.UUID(sys.argv[1]); print(u.version, u.variant)' {text}"
    summary = kind_text + (f", created {fmt(when, ctx.zone, seconds=False)} ({relative(when, ctx.now)})" if when else
                           (", random" if version == 4 else ""))
    return [Reading("uuid", conf, summary, lines, receipt, data=data)]


CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


@detector
def detect_ulid(s: str, ctx: Context):
    text = s.upper()
    if len(text) != 26 or not all(c in CROCKFORD for c in text) or text[0] > "7":
        return None
    value = 0
    for c in text:
        value = value * 32 + CROCKFORD.index(c)
    ms = value >> 80
    try:
        when = dt.datetime.fromtimestamp(ms / 1000, UTC)
    except (OverflowError, OSError, ValueError):
        return None
    plausible = 2000 <= when.year <= 2100
    lines = [f"timestamp {fmt(when, ctx.zone)}  ({relative(when, ctx.now)})", f"as UUID: {uuid_mod.UUID(int=value)}",
             "ULID: 48-bit ms timestamp + 80 random bits, Crockford base32, lexically sortable"]
    conf = 0.85 if plausible and not s.isdigit() else 0.3
    return [Reading("ulid", conf, f"ULID created {fmt(when, ctx.zone, seconds=False)} ({relative(when, ctx.now)})", lines,
                    f"python3 -c 'import sys,datetime; s=sys.argv[1]; a=\"{CROCKFORD}\"; v=0\nfor c in s: v=v*32+a.index(c)\nprint(datetime.datetime.fromtimestamp((v>>80)/1000, datetime.timezone.utc))' {text}",
                    data={"iso": iso(when)})]


SNOWFLAKE_EPOCHS = (
    ("Twitter/X", 1288834974657), ("Discord", 1420070400000), ("Instagram", 1314220021721), ("Mastodon", 0),
)


@detector
def detect_snowflake(s: str, ctx: Context):
    if not re.fullmatch(r"\d{17,20}", s):
        return None
    n = int(s)
    out = []
    seen_minutes = set()
    for name, epoch in SNOWFLAKE_EPOCHS:
        if name == "Mastodon":
            ms = n >> 16
        else:
            ms = (n >> 22) + epoch
        try:
            when = dt.datetime.fromtimestamp(ms / 1000, UTC)
        except (OverflowError, OSError, ValueError):
            continue
        if 2009 <= when.year <= ctx.now.year + 1 and when <= ctx.now + dt.timedelta(days=1):
            key = int(when.timestamp()) // 60
            if key in seen_minutes:
                continue  # two services whose epochs happen to agree: one line is enough
            seen_minutes.add(key)
            worker = (n >> 12) & 0x3FF if name != "Mastodon" else None
            seq = n & 0xFFF if name != "Mastodon" else n & 0xFFFF
            lines = [f"{name} snowflake: created {fmt(when, ctx.zone)}  ({relative(when, ctx.now)})"]
            if worker is not None:
                lines.append(f"worker/process id {worker}, sequence {seq}")
            lines.append("a 64-bit id with a millisecond timestamp in the high bits; the epoch differs per service")
            conf = 0.55 if name in ("Twitter/X", "Discord") else 0.35
            if len(s) == 19 and s[0] in "12" and name == "Twitter/X":
                conf = 0.5  # 19-digit ids starting 1x are also plausible nanosecond epochs
            if name == "Discord" and when > ctx.now - dt.timedelta(days=3650) and len(s) == 19 and s[0] == "1":
                conf = 0.45  # Discord ids in this range would be recent; Twitter is the older, likelier source
            out.append(Reading("snowflake", conf, f"{name} snowflake id from {fmt(when, ctx.zone, seconds=False)}", lines,
                               f"date -u -d @$(( ({s} >> 22) + {epoch} ))" if name != "Mastodon" else f"date -u -d @$(( ({s} >> 16) / 1000 ))",
                               data={"service": name, "iso": iso(when)}))
    return out


SPECIAL_V4 = (
    ("10.0.0.0/8", "private (RFC 1918)"), ("172.16.0.0/12", "private (RFC 1918)"), ("192.168.0.0/16", "private (RFC 1918)"),
    ("127.0.0.0/8", "loopback"), ("169.254.0.0/16", "link-local / APIPA (no DHCP answer)"), ("100.64.0.0/10", "carrier-grade NAT (RFC 6598); also Tailscale"),
    ("0.0.0.0/8", "'this' network; 0.0.0.0 = all interfaces when binding"), ("224.0.0.0/4", "multicast"), ("240.0.0.0/4", "reserved (class E)"),
    ("255.255.255.255/32", "limited broadcast"), ("192.0.2.0/24", "TEST-NET-1 documentation"), ("198.51.100.0/24", "TEST-NET-2 documentation"),
    ("203.0.113.0/24", "TEST-NET-3 documentation"), ("198.18.0.0/15", "benchmarking"), ("192.88.99.0/24", "6to4 relay (deprecated)"),
    ("1.1.1.0/24", "Cloudflare DNS"), ("8.8.8.0/24", "Google DNS"), ("8.8.4.0/24", "Google DNS"), ("9.9.9.0/24", "Quad9 DNS"),
)
SPECIAL_V6 = (
    ("::1/128", "loopback"), ("::/128", "unspecified"), ("fe80::/10", "link-local"), ("fc00::/7", "unique local (private)"),
    ("ff00::/8", "multicast"), ("2001:db8::/32", "documentation"), ("2001::/32", "Teredo"), ("2002::/16", "6to4"), ("64:ff9b::/96", "NAT64"),
    ("::ffff:0:0/96", "IPv4-mapped"), ("2001:4860:4860::/48", "Google DNS"), ("2606:4700:4700::/48", "Cloudflare DNS"),
)


def special_range(addr) -> str | None:
    table = SPECIAL_V4 if addr.version == 4 else SPECIAL_V6
    for net, label in table:
        if addr in ipaddress.ip_network(net):
            return label
    return None


@detector
def detect_ip(s: str, ctx: Context):
    text = s
    port = None
    m = re.fullmatch(r"\[([0-9a-fA-F:.]+)\]:(\d{1,5})", text) or re.fullmatch(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})", text)
    if m:
        text, port = m.group(1), int(m.group(2))
    if "/" in text:
        return None
    try:
        addr = ipaddress.ip_address(text)
    except ValueError:
        return None
    lines = []
    label = special_range(addr)
    if label:
        lines.append(f"{label} address")
    elif addr.is_global:
        lines.append("public (globally routable) address - owner lookup needs the network: whois " + str(addr))
    if addr.is_global and label and "DNS" in label:
        lines.append("public (globally routable)")
    if addr.version == 4:
        n = int(addr)
        lines.append(f"integer {n}, hex 0x{n:08x}, octets {' '.join(f'{b:08b}' for b in addr.packed)}")
        lines.append(f"IPv4-mapped IPv6 ::ffff:{addr}; reverse DNS name {addr.reverse_pointer}")
        if addr.is_private and not addr.is_loopback:
            lines.append("not reachable from the internet without NAT/port forwarding")
    else:
        lines.append(f"exploded {addr.exploded}")
        if addr.ipv4_mapped:
            lines.append(f"IPv4-mapped: {addr.ipv4_mapped}")
        if addr.teredo:
            lines.append(f"Teredo: server {addr.teredo[0]}, client {addr.teredo[1]}")
        if addr.sixtofour:
            lines.append(f"6to4 embedded IPv4: {addr.sixtofour}")
        if addr.is_link_local:
            lines.append("needs a scope id on the wire: fe80::...%eth0")
        if str(addr).startswith(("2", "3")) and addr.is_global:
            lines.append("global unicast; the first 64 bits are the network prefix, the last 64 the interface id")
    if port:
        svc = WELL_KNOWN_PORTS.get(port)
        lines.append(f"port {port}" + (f": {svc}" if svc else ""))
    conf = 0.95 if addr.version == 4 and text.count(".") == 3 or addr.version == 6 and ":" in text else 0.6
    receipt = f"python3 -c 'import ipaddress,sys; a=ipaddress.ip_address(sys.argv[1]); print(a.exploded, a.is_private, a.is_global, a.reverse_pointer)' {q(text)}"
    if have("ipcalc") and addr.version == 4:
        receipt = f"ipcalc {text}"
    summary = f"IPv{addr.version} {addr}" + (f":{port}" if port else "") + (f" - {label}" if label else " - public")
    if label and addr.is_global:
        summary += " (public)"
    return [Reading("ip", conf, summary, lines, receipt, data={"version": addr.version, "special": label})]


@detector
def detect_cidr(s: str, ctx: Context):
    if "/" not in s or s.count("/") != 1:
        return None
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None
    given = ipaddress.ip_interface(s)
    lines = []
    total = net.num_addresses
    if net.version == 4:
        usable = max(total - 2, 1) if net.prefixlen < 31 else total
        lines.append(f"netmask {net.netmask} (wildcard {net.hostmask}), {commas(total)} addresses, {commas(usable)} usable hosts")
        if net.prefixlen < 31:
            lines.append(f"network {net.network_address}, first host {net.network_address + 1}, last host {net.broadcast_address - 1}, broadcast {net.broadcast_address}")
        elif net.prefixlen == 31:
            lines.append(f"point-to-point link (RFC 3021): both {net.network_address} and {net.broadcast_address} are hosts")
        else:
            lines.append("a single host")
        if str(given.ip) != str(net.network_address) and net.prefixlen < 32:
            lines.append(f"{given.ip} is a host inside {net} (the network address is {net.network_address})")
        if net.prefixlen >= 8 and net.prefixlen <= 30:
            lines.append(f"splits into 2 x /{net.prefixlen + 1} ({commas(total // 2)} each); 4 x /{net.prefixlen + 2}" if net.prefixlen <= 28 else f"splits into 2 x /{net.prefixlen + 1}")
    else:
        lines.append(f"{total:.3g} addresses (2^{128 - net.prefixlen}); prefix {net.network_address}")
        if net.prefixlen == 64:
            lines.append("a standard LAN segment: SLAAC needs exactly /64")
        elif net.prefixlen in (48, 56):
            lines.append(f"a typical {'site' if net.prefixlen == 48 else 'residential'} allocation: {2 ** (64 - net.prefixlen)} /64 subnets")
        lines.append(f"range {net[0]} - {net[-1]}")
    label = special_range(net.network_address)
    if label:
        lines.append(f"{label} range")
    lines.append(f"other notation: {net.network_address}/{net.netmask}" if net.version == 4 else f"compressed {net.compressed}")
    conf = 0.96
    receipt = f"ipcalc {q(s)}" if have("ipcalc") else f"python3 -c 'import ipaddress,sys; n=ipaddress.ip_network(sys.argv[1], strict=False); print(n, n.netmask, n.num_addresses, n[0], n[-1])' {q(s)}"
    summary = f"{net}: {commas(total) if net.version == 4 else f'2^{128 - net.prefixlen}'} addresses" + (f", {net[1] if net.prefixlen < 31 else net[0]}-{net[-2] if net.prefixlen < 31 else net[-1]}" if net.version == 4 and net.prefixlen < 32 else "") + (f", {label}" if label else "")
    return [Reading("cidr", conf, summary, lines, receipt, data={"network": str(net), "addresses": total})]


OUI_FILES = ("/usr/share/ieee-data/oui.txt", "/usr/share/misc/oui.txt", "/usr/share/hwdata/oui.txt", "/var/lib/ieee-data/oui.txt",
             "/usr/share/wireshark/manuf", "/usr/share/nmap/nmap-mac-prefixes")


def oui_lookup(prefix: str) -> str | None:
    """Vendor for a 6-hex-digit OUI from whatever local database exists (never the network)."""
    hexp = prefix.upper()
    dashed = "-".join(hexp[i:i + 2] for i in range(0, 6, 2))
    colon = ":".join(hexp[i:i + 2] for i in range(0, 6, 2))
    for path in OUI_FILES:
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    if line.startswith((hexp, dashed, colon)) or line.startswith(colon.lower()):
                        rest = line.split(None, 1)[1] if len(line.split(None, 1)) > 1 else ""
                        rest = rest.replace("(hex)", "").replace("(base 16)", "").strip()
                        rest = re.sub(r"^\s*#?\s*", "", rest)
                        if rest:
                            return rest.split("\t")[0].strip()[:60]
        except OSError:
            continue
    return None


@detector
def detect_mac(s: str, ctx: Context):
    text = s.strip()
    m = re.fullmatch(r"([0-9A-Fa-f]{2})([:-])([0-9A-Fa-f]{2})\2([0-9A-Fa-f]{2})\2([0-9A-Fa-f]{2})\2([0-9A-Fa-f]{2})\2([0-9A-Fa-f]{2})", text) \
        or re.fullmatch(r"([0-9A-Fa-f]{4})\.([0-9A-Fa-f]{4})\.([0-9A-Fa-f]{4})", text)
    if not m:
        return None
    digits = re.sub(r"[^0-9A-Fa-f]", "", text).lower()
    if len(digits) != 12:
        return None
    octets = [int(digits[i:i + 2], 16) for i in range(0, 12, 2)]
    canonical = ":".join(f"{b:02x}" for b in octets)
    first = octets[0]
    lines = [f"canonical {canonical}; Cisco {digits[0:4]}.{digits[4:8]}.{digits[8:12]}; Windows {'-'.join(digits[i:i + 2] for i in range(0, 12, 2)).upper()}"]
    if canonical == "ff:ff:ff:ff:ff:ff":
        lines.append("broadcast address")
    elif first & 1:
        lines.append("multicast (group) address" + (" - IPv4 multicast 01:00:5e" if canonical.startswith("01:00:5e") else " - IPv6 multicast 33:33" if canonical.startswith("33:33") else ""))
    else:
        lines.append("unicast")
    if first & 2:
        lines.append("locally administered (bit 2 of the first octet set): randomized or virtual - VM, container, docker bridge, phone privacy MAC; no vendor")
    else:
        vendor = oui_lookup(digits[:6])
        lines.append(f"OUI {digits[:6]}: {vendor}" if vendor else f"OUI {digits[:6]} (universally administered; no local vendor database found to name it)")
    eui64 = f"{first ^ 2:02x}{octets[1]:02x}:{octets[2]:02x}ff:fe{octets[3]:02x}:{octets[4]:02x}{octets[5]:02x}"
    lines.append(f"IPv6 link-local via EUI-64: fe80::{eui64}")
    lines.append(f"Wake-on-LAN magic packet payload: ff*6 + this address x16")
    conf = 0.9 if m.re.pattern.count("\\2") else 0.75
    receipt = f"grep -i {q(digits[:6])} /usr/share/ieee-data/oui.txt" if os.path.exists("/usr/share/ieee-data/oui.txt") else "ip link   # your own interfaces' MACs"
    summary = f"MAC {canonical}: " + ("broadcast" if canonical == "ff:ff:ff:ff:ff:ff" else "locally administered (virtual/randomized)" if first & 2 else
                                       (oui_lookup(digits[:6]) or "universally administered"))
    return [Reading("mac", conf, summary, lines, receipt, data={"mac": canonical})]


HASH_LENGTHS = {
    32: ("MD5 (or 128-bit: NTLM, LM, half a SHA-256, a UUID without hyphens)", "md5sum"),
    40: ("SHA-1 (or a git object id, RIPEMD-160)", "sha1sum"), 56: ("SHA-224 / SHA3-224", "sha224sum"),
    64: ("SHA-256 (or SHA3-256, BLAKE2s, a 32-byte key)", "sha256sum"), 96: ("SHA-384 / SHA3-384", "sha384sum"),
    128: ("SHA-512 (or SHA3-512, BLAKE2b, Whirlpool)", "sha512sum"), 8: ("CRC-32 (or 32-bit value)", "crc32"),
    16: ("64-bit: xxHash64, CRC-64, FNV-1a, SipHash, or a short git id", None),
}


@detector
def detect_hash(s: str, ctx: Context):
    text = s.lower()
    if not re.fullmatch(r"[0-9a-f]+", text) or len(text) not in HASH_LENGTHS:
        return None
    if text.isdigit():
        return None
    name, tool = HASH_LENGTHS[len(text)]
    bits = len(text) * 4
    lines = [f"{len(text)} hex digits = {bits} bits = {bits // 8} bytes: {name}"]
    if len(text) in (7, 8, 12, 40, 64) or 7 <= len(text) <= 40:
        pass
    if len(text) == 40:
        lines.append("if from git: a full commit/tree/blob id - try git cat-file -t ID in the repository")
    if len(text) == 32:
        lines.append("MD5 is broken for collision resistance; fine as a checksum, not as a signature")
    if len(text) == 64:
        lines.append("also the shape of a hex-encoded 256-bit key, an Ethereum tx hash prefix-less, a docker image digest (sha256:...), or a Bitcoin txid")
    lines.append("a hash is one-way: the only way to 'decode' it is to hash candidate inputs and compare")
    conf = 0.65 if len(text) in (32, 40, 64, 128) else 0.3
    if len(text) in (32, 40, 64) and (text.count("0") > len(text) * 0.5):
        conf = 0.3
    receipt = f"printf %s 'candidate' | {tool}   # compare" if tool and tool != "crc32" else "git cat-file -t " + text if len(text) == 40 else None
    if have("hashid"):
        receipt = f"hashid {text}"
    return [Reading("hash", conf, f"{bits}-bit hex digest: {name.split(' (')[0]}", lines, receipt, data={"bits": bits})]


@detector
def detect_password_hash(s: str, ctx: Context):
    m = re.fullmatch(r"\$([0-9a-zA-Z-]+)\$(.+)", s)
    if not m or " " in s:
        return None
    tag = m.group(1)
    rest = m.group(2).split("$")
    names = {"1": "MD5-crypt (md5crypt, legacy Linux/BSD)", "2": "bcrypt (old)", "2a": "bcrypt", "2b": "bcrypt", "2y": "bcrypt (PHP)", "5": "SHA-256-crypt",
             "6": "SHA-512-crypt (Linux /etc/shadow default for years)", "7": "scrypt (BSD)", "y": "yescrypt (current Debian/Fedora default)",
             "gy": "gost-yescrypt", "argon2i": "Argon2i", "argon2d": "Argon2d", "argon2id": "Argon2id (current best practice)", "sha1": "SHA-1-crypt",
             "md5": "Sun MD5", "pbkdf2-sha256": "PBKDF2-SHA256 (passlib)", "pbkdf2-sha512": "PBKDF2-SHA512", "apr1": "Apache MD5 (htpasswd)",
             "scrypt": "scrypt", "P": "phpass (WordPress/phpBB)", "H": "phpass"}
    if tag not in names:
        return None
    lines = [f"modular crypt format: ${tag}$ = {names[tag]}"]
    if tag.startswith("2"):
        cost = rest[0] if rest and rest[0].isdigit() else rest[0][:2] if rest else ""
        if cost.isdigit():
            lines.append(f"cost {cost}: 2^{cost} = {commas(2 ** int(cost))} rounds; 10-12 is typical today")
        lines.append("bcrypt truncates passwords at 72 bytes")
    elif tag in ("5", "6") and rest and rest[0].startswith("rounds="):
        lines.append(f"{rest[0]} (default 5000)")
    elif tag.startswith("argon2"):
        params = [p for p in rest if "=" in p]
        if params:
            lines.append("parameters " + ", ".join(params) + "  (v=version, m=memory KiB, t=iterations, p=parallelism)")
    elif tag == "y" and rest:
        lines.append(f"yescrypt parameters {rest[0]}")
    lines.append("one-way: verify with the same algorithm; to crack you need hashcat/john and a wordlist")
    return [Reading("password hash", 0.95, f"password hash: {names[tag]}", [ln for ln in lines if ln],
                    f"python3 -c 'import crypt,sys; print(crypt.crypt(\"password\", sys.argv[1]))' {q(s)}   # compares (Python < 3.13)" if tag in ("1", "5", "6", "y") else None)]


@detector
def detect_sri(s: str, ctx: Context):
    m = re.fullmatch(r"(sha256|sha384|sha512|md5|sha1)[-:]([A-Za-z0-9+/=]+|[0-9a-f]+)", s)
    if not m:
        return None
    algo, value = m.groups()
    lines = []
    if re.fullmatch(r"[0-9a-f]+", value):
        lines.append(f"{algo} digest in hex (docker image digests look like this: sha256:...)")
        receipt = f"docker image inspect --format '{{{{.Id}}}}' IMAGE" if algo == "sha256" and len(value) == 64 else None
        what = "digest reference"
    else:
        raw = base64.b64decode(value + "=" * (-len(value) % 4)) if len(value) % 4 != 1 else b""
        lines.append(f"Subresource Integrity hash: {algo}, {len(raw) * 8} bits, hex {raw.hex()}")
        lines.append("browsers refuse the <script>/<link> if the fetched bytes do not hash to this")
        receipt = f"curl -sL URL | openssl dgst -{algo} -binary | openssl base64 -A"
        what = "SRI integrity value"
    return [Reading("sri", 0.9, f"{algo} {what}", lines, receipt)]


def git_lookup(oid: str) -> tuple[str, str] | None:
    """(type, one-line description) for an object in the current repository, read-only."""
    if not have("git") or not re.fullmatch(r"[0-9a-f]{4,64}", oid):
        return None
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1", LC_ALL="C")

    def run(*args):
        return subprocess.run(["git", "--no-pager", "-c", "core.hooksPath=/dev/null", *args], capture_output=True, text=True,
                              timeout=GIT_TIMEOUT, env=env, stdin=subprocess.DEVNULL)
    try:
        if run("rev-parse", "--is-inside-work-tree").stdout.strip() != "true" and run("rev-parse", "--is-bare-repository").stdout.strip() != "true":
            return None
        p = run("cat-file", "-t", oid)
        if p.returncode != 0:
            return None
        kind = p.stdout.strip()
        if kind == "commit":
            p = run("log", "-1", "--format=%h %ad %an: %s", "--date=short", oid)
            return kind, p.stdout.strip()
        if kind == "tag":
            p = run("tag", "-l", "--format=%(refname:short) -> %(*objectname:short)", "--points-at", oid)
            return kind, p.stdout.strip().splitlines()[0] if p.stdout.strip() else "annotated tag"
        p = run("cat-file", "-s", oid)
        return kind, f"{p.stdout.strip()} bytes"
    except (OSError, subprocess.SubprocessError):
        return None


@detector
def detect_git(s: str, ctx: Context):
    if ctx.depth > 0 or not re.fullmatch(r"[0-9a-f]{7,64}", s.lower()) or s.isdigit():
        return None
    found = git_lookup(s.lower())
    if not found:
        return None
    kind, desc = found
    lines = [f"git {kind} in the current repository: {clean(desc)}"]
    if kind == "commit":
        lines.append(f"show it: git show --stat {s}")
    return [Reading("git", 0.97, f"git {kind}: {clean(desc)}", lines, f"git cat-file -t {q(s)} && git show --stat --oneline {q(s)}")]


@detector
def detect_ssh_key(s: str, ctx: Context):
    m = re.match(r"(ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp(?:256|384|521)|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)\s+([A-Za-z0-9+/]+=*)(?:\s+(.*))?$", s, re.S)
    if m:
        algo, blob, comment = m.groups()
        try:
            raw = base64.b64decode(blob)
        except (binascii.Error, ValueError):
            return None
        import hashlib
        fp = base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        md5 = ":".join(f"{b:02x}" for b in hashlib.md5(raw).digest())
        bits = ""
        if algo == "ssh-rsa" and len(raw) > 20:
            # string "ssh-rsa", mpint e, mpint n
            off = 4 + struct.unpack(">I", raw[:4])[0]
            e_len = struct.unpack(">I", raw[off:off + 4])[0]
            off += 4 + e_len
            n_len = struct.unpack(">I", raw[off:off + 4])[0]
            n_bits = (n_len - (1 if raw[off + 4] == 0 else 0)) * 8
            bits = f"{n_bits}-bit "
        elif algo == "ssh-ed25519":
            bits = "256-bit "
        lines = [f"OpenSSH public key, {bits}{algo}" + (f", comment {preview(comment.strip(), 40)}" if comment else ""),
                 f"SHA256:{fp}", f"MD5:{md5}", "safe to share; the matching private key is the secret"]
        if algo == "ssh-rsa" and bits and int(bits.split('-')[0]) < 2048:
            lines.append("weak: RSA under 2048 bits is rejected by modern OpenSSH")
        if algo == "ssh-dss":
            lines.append("DSA keys are disabled by default since OpenSSH 7.0")
        return [Reading("ssh key", 0.98, f"SSH public key {algo} SHA256:{fp[:16]}...", lines, "ssh-keygen -lf KEYFILE.pub   # same fingerprint")]
    m = re.fullmatch(r"SHA256:([A-Za-z0-9+/]{43})=?", s)
    if m:
        return [Reading("ssh key", 0.9, "SSH key fingerprint (SHA-256, base64)", ["compare with: ssh-keygen -lf ~/.ssh/id_ed25519.pub",
                        "for a host: ssh-keyscan HOST 2>/dev/null | ssh-keygen -lf -", f"hex: {base64.b64decode(m.group(1) + '=').hex()}"],
                        "ssh-keygen -lf ~/.ssh/id_*.pub")]
    if re.fullmatch(r"(?:[0-9a-f]{2}:){15}[0-9a-f]{2}", s.lower()):
        return [Reading("ssh key", 0.6, "legacy MD5 key fingerprint (16 colon-separated bytes)", ["ssh-keygen -lE md5 -f KEY.pub shows this form",
                        "could also be any 128-bit value written as colon-hex"], "ssh-keygen -E md5 -lf KEYFILE.pub")]
    return None


@detector
def detect_pem(s: str, ctx: Context):
    m = re.search(r"-----BEGIN ([A-Z0-9 ]+)-----(.*?)-----END \1-----", s, re.S)
    if not m:
        return None
    label, body = m.group(1), re.sub(r"\s+", "", m.group(2))
    body = re.sub(r"^(?:Proc-Type|DEK-Info):.*$", "", body, flags=re.M)
    try:
        raw = base64.b64decode(body, validate=False)
    except (binascii.Error, ValueError):
        raw = b""
    private = "PRIVATE" in label
    lines = [f"PEM block: {label}, {plural(len(raw), 'byte')} of DER inside"]
    if private:
        lines.append("THIS IS A PRIVATE KEY - do not paste it anywhere, including here; rotate it if it has been shared")
        if "ENCRYPTED" in label or "Proc-Type" in s:
            lines.append("encrypted with a passphrase")
    if label == "CERTIFICATE":
        lines.append("X.509 certificate; details: openssl x509 -noout -text -in FILE")
        receipt = "openssl x509 -noout -subject -issuer -dates -in FILE"
    elif label == "CERTIFICATE REQUEST":
        receipt = "openssl req -noout -text -in FILE"
    elif "PUBLIC KEY" in label:
        receipt = "openssl pkey -pubin -noout -text -in FILE"
    elif "PRIVATE KEY" in label:
        receipt = "ssh-keygen -lf FILE   # fingerprint, without printing the key"
    elif label == "OPENSSH PRIVATE KEY":
        receipt = "ssh-keygen -lf FILE"
    else:
        receipt = "openssl asn1parse -in FILE"
    if raw[:2] == b"\x30\x82" and len(raw) > 4:
        lines.append(f"DER SEQUENCE of {struct.unpack('>H', raw[2:4])[0]} bytes")
    return [Reading("pem", 0.99, f"PEM {label.lower()}" + (" - PRIVATE, keep it secret" if private else ""), lines, receipt)]


SECRET_PATTERNS = (
    (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token (classic)"), (r"github_pat_[A-Za-z0-9_]{60,}", "GitHub fine-grained personal access token"),
    (r"gho_[A-Za-z0-9]{36}", "GitHub OAuth token"), (r"ghs_[A-Za-z0-9]{36}", "GitHub app installation token"), (r"ghr_[A-Za-z0-9]{36}", "GitHub refresh token"),
    (r"glpat-[A-Za-z0-9_-]{20,}", "GitLab personal access token"), (r"AKIA[0-9A-Z]{16}", "AWS access key id (the secret key is a separate 40-char string)"),
    (r"ASIA[0-9A-Z]{16}", "AWS temporary (STS) access key id"), (r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}", "OpenAI API key (legacy format)"),
    (r"sk-proj-[A-Za-z0-9_-]{40,}", "OpenAI project API key"), (r"sk-ant-[A-Za-z0-9_-]{40,}", "Anthropic API key"),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}", "Slack token"), (r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+", "Slack incoming webhook URL"),
    (r"sk_live_[A-Za-z0-9]{24,}", "Stripe live secret key"), (r"sk_test_[A-Za-z0-9]{24,}", "Stripe test secret key"), (r"pk_live_[A-Za-z0-9]{24,}", "Stripe publishable key (not secret)"),
    (r"rk_live_[A-Za-z0-9]{24,}", "Stripe restricted key"), (r"AIza[0-9A-Za-z_-]{35}", "Google API key"), (r"ya29\.[0-9A-Za-z_-]+", "Google OAuth access token"),
    (r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com", "Google OAuth client id"), (r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}", "SendGrid API key"),
    (r"key-[0-9a-zA-Z]{32}", "Mailgun API key"), (r"SK[0-9a-fA-F]{32}", "Twilio API key"), (r"AC[0-9a-fA-F]{32}", "Twilio account SID"),
    (r"npm_[A-Za-z0-9]{36}", "npm access token"), (r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]+", "PyPI API token"), (r"dop_v1_[a-f0-9]{64}", "DigitalOcean personal access token"),
    (r"hf_[A-Za-z0-9]{34,}", "Hugging Face token"), (r"r8_[A-Za-z0-9]{37,}", "Replicate API token"), (r"dckr_pat_[A-Za-z0-9_-]{27,}", "Docker Hub personal access token"),
    (r"shpat_[a-fA-F0-9]{32}", "Shopify private app token"), (r"sq0atp-[0-9A-Za-z_-]{22}", "Square access token"), (r"[0-9]{8,10}:[A-Za-z0-9_-]{35}", "Telegram bot token"),
    (r"lin_api_[A-Za-z0-9]{40}", "Linear API key"), (r"figd_[A-Za-z0-9_-]{40,}", "Figma personal access token"), (r"pul-[a-f0-9]{40}", "Pulumi access token"),
    (r"tfr\.[A-Za-z0-9_-]+", "Terraform Cloud token"), (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", None),  # JWT: handled elsewhere
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", None),
    (r"(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^:/\s]+:[^@/\s]+@[^\s]+", "database URL with an embedded password"),
    (r"(?i)(?:api[_-]?key|secret|token|password|passwd|pwd)\s*[=:]\s*['\"]?[A-Za-z0-9_\-/+=]{8,}", "a key=value assignment that looks like a credential"),
)


@detector
def detect_secret(s: str, ctx: Context):
    if len(s) > 4096:
        return None
    for pattern, label in SECRET_PATTERNS:
        if label is None:
            continue
        m = re.search(pattern, s)
        if m:
            token = m.group(0)
            lines = [f"matches the shape of: {label}",
                     "this tool did not send it anywhere and does not log it. If it is real and was pasted somewhere shared, rotate it.",
                     f"{len(token)} characters" + (f", prefix {token.split('_')[0] + '_' if '_' in token[:12] else token[:4]}" if not label.startswith(("database", "a key")) else "")]
            if "AWS" in label:
                lines.append("an access key id alone cannot authenticate; it pairs with a 40-char secret. Check: aws sts get-caller-identity")
            if "GitHub" in label:
                lines.append("check what it can do: curl -sS -H 'Authorization: Bearer TOKEN' https://api.github.com/user  (GitHub auto-revokes tokens it finds in public repos)")
            if label.startswith("database"):
                try:
                    u = urllib.parse.urlsplit(token)
                    lines.append(f"{u.scheme} at {u.hostname}:{u.port or 'default'} as {u.username}, database {u.path.lstrip('/') or '?'}")
                except ValueError:
                    pass
            conf = 0.9 if not label.startswith(("a key", "Twilio account", "Stripe publishable", "Google OAuth client")) else 0.55
            summary = f"looks like a {label}" if not label.startswith("a key") else "looks like a credential assignment"
            return [Reading("secret", conf, summary, lines, None, data={"label": label})]
    return None


PATH_HINTS = {
    "/etc": "system configuration", "/etc/passwd": "user accounts (not passwords)", "/etc/shadow": "password hashes (root only)", "/etc/hosts": "static hostname mapping",
    "/etc/fstab": "filesystems mounted at boot", "/etc/resolv.conf": "DNS resolver config", "/etc/ssh/sshd_config": "SSH server config", "/etc/sudoers": "sudo rules (edit with visudo)",
    "/etc/crontab": "system crontab", "/etc/cron.d": "drop-in cron jobs", "/var/log": "logs", "/var/log/syslog": "system log (Debian/Ubuntu)", "/var/log/messages": "system log (RHEL)",
    "/var/log/auth.log": "logins and sudo", "/var/lib": "state for services (databases, docker, apt)", "/var/lib/docker": "docker images, layers, volumes", "/var/run": "runtime state (now /run)",
    "/run": "runtime state, tmpfs", "/tmp": "temporary files, often wiped at boot", "/var/tmp": "temporary files that survive reboots", "/proc": "kernel/process info as files",
    "/proc/cpuinfo": "CPU details", "/proc/meminfo": "memory details", "/sys": "kernel/device tree as files", "/dev": "devices", "/dev/null": "discards writes, reads EOF",
    "/dev/zero": "infinite zeros", "/dev/urandom": "random bytes", "/dev/sda": "first SCSI/SATA disk", "/dev/nvme0n1": "first NVMe disk", "/dev/shm": "shared memory tmpfs",
    "/usr/bin": "user commands", "/usr/local/bin": "locally installed commands (ahead of /usr/bin on PATH)", "/usr/lib": "libraries", "/usr/share": "architecture-independent data",
    "/opt": "optional third-party software", "/boot": "kernel and bootloader", "/home": "user home directories", "/root": "root's home", "/srv": "data served by this host",
    "/mnt": "temporary mounts", "/media": "removable media", "/lib/systemd/system": "vendor systemd units", "/etc/systemd/system": "local systemd units and overrides",
    "~/.ssh": "SSH keys and known_hosts (mode 700)", "~/.ssh/authorized_keys": "public keys allowed to log in as you", "~/.ssh/config": "per-host SSH settings",
    "~/.bashrc": "interactive bash startup", "~/.profile": "login shell environment", "~/.zshrc": "zsh startup", "~/.config": "XDG user config", "~/.local/share": "XDG user data",
    "~/.cache": "XDG cache (safe to delete)", "~/.local/bin": "user-installed commands", "~/.gitconfig": "git identity and aliases", "~/.docker/config.json": "docker registry logins",
    "~/.aws/credentials": "AWS keys", "~/.kube/config": "Kubernetes clusters and tokens", "~/.npmrc": "npm registry and tokens", "~/.netrc": "plaintext logins for curl/ftp",
    "/etc/nginx": "nginx config", "/etc/apache2": "Apache config (Debian)", "/etc/httpd": "Apache config (RHEL)", "/var/www": "web roots", "/etc/ld.so.conf": "library search paths",
    "/etc/os-release": "distro name and version", "/etc/environment": "system-wide environment (PAM)", "/etc/profile": "login shell setup for everyone", "/etc/skel": "template for new home dirs",
    "/etc/apt": "APT sources and preferences", "/etc/yum.repos.d": "yum/dnf repositories", "/etc/docker/daemon.json": "docker daemon config", "/var/spool/cron": "per-user crontabs",
    "/var/mail": "local mailboxes", "/etc/logrotate.d": "log rotation rules", "/etc/security/limits.conf": "ulimit defaults", "/etc/sysctl.conf": "kernel parameters",
    "/etc/modprobe.d": "kernel module options", "/etc/udev/rules.d": "device rules", "/usr/share/zoneinfo": "the IANA timezone database", "/etc/localtime": "the system timezone (symlink into zoneinfo)",
}


@detector
def detect_path(s: str, ctx: Context):
    if len(s) > 1024 or " " in s and not s.startswith(("/", "~")) or "\n" in s:
        return None
    if not (s.startswith(("/", "~/", "./", "../")) or s == "~" or re.fullmatch(r"[A-Za-z]:\\.*", s)):
        return None
    if re.fullmatch(r"/\d+", s) or (s.count("/") == 1 and re.fullmatch(r"[\d.:a-fA-F]+/\d+", s)):
        return None
    lines = []
    expanded = os.path.expanduser(s) if s.startswith("~") else s
    hint_key = s.rstrip("/")
    best = None
    for key in sorted(PATH_HINTS, key=len, reverse=True):
        if hint_key == key or hint_key.startswith(key + "/"):
            best = key
            break
    if best:
        lines.append(f"{best}: {PATH_HINTS[best]}" + (" (a path under it)" if best != hint_key else ""))
    if s.startswith("/proc/") and re.fullmatch(r"/proc/\d+(/.*)?", s):
        lines.append("per-process directory: /proc/PID/{cmdline,environ,fd,maps,status,cwd,exe}")
    if "\\" in s and re.fullmatch(r"[A-Za-z]:\\.*", s):
        lines.append("Windows path; in WSL: /mnt/" + s[0].lower() + s[2:].replace("\\", "/"))
    if not re.fullmatch(r"[A-Za-z]:\\.*", s):
        try:
            st = os.lstat(expanded)
            kind = "directory" if stat.S_ISDIR(st.st_mode) else "symlink -> " + os.readlink(expanded) if stat.S_ISLNK(st.st_mode) else "file"
            lines.append(f"exists here: {kind}, mode {stat.S_IMODE(st.st_mode):o} ({stat.filemode(st.st_mode)})" +
                         (f", {size_text(st.st_size)}" if stat.S_ISREG(st.st_mode) else "") +
                         f", modified {fmt(dt.datetime.fromtimestamp(st.st_mtime, UTC), ctx.zone, seconds=False)}")
            if stat.S_ISREG(st.st_mode) and st.st_size:
                guess, _ = mimetypes.guess_type(expanded)
                if guess:
                    lines.append(f"type by extension: {guess}")
        except OSError:
            lines.append("does not exist on this machine (or not readable)")
    name = os.path.basename(s.rstrip("/\\"))
    ext = os.path.splitext(name)[1]
    if ext and ext.lower() in EXTENSIONS:
        lines.append(f"{ext}: {EXTENSIONS[ext.lower()]}")
    if not lines:
        return None
    conf = 0.85 if best or s.startswith(("/", "~")) and len(s) > 3 else 0.4
    if re.fullmatch(r"[A-Za-z]:\\.*", s):
        receipt = None
    else:
        shown_path = ("~/" + q(s[2:])) if s.startswith("~/") else ("~" if s == "~" else q(s))  # keep ~ unquoted so the shell expands it
        receipt = f"ls -ld {shown_path}; file {shown_path}"
    summary = f"path: {PATH_HINTS[best]}" if best and best == hint_key else f"path under {best} ({PATH_HINTS[best]})" if best else f"filesystem path {preview(s, 50)}"
    return [Reading("path", conf, summary, lines, receipt)]


EXTENSIONS = {
    ".tar.gz": "gzip-compressed tar archive", ".tgz": "gzip-compressed tar archive", ".tar.xz": "xz-compressed tar", ".tar.zst": "zstd-compressed tar", ".tar.bz2": "bzip2-compressed tar",
    ".gz": "gzip (single file)", ".xz": "xz compressed", ".zst": "zstandard compressed", ".bz2": "bzip2 compressed", ".7z": "7-Zip archive", ".zip": "zip archive", ".rar": "RAR archive",
    ".deb": "Debian package (ar archive)", ".rpm": "RPM package", ".apk": "Android package (zip) or Alpine package (tar.gz)", ".whl": "Python wheel (zip)", ".egg": "legacy Python egg (zip)",
    ".jar": "Java archive (zip)", ".war": "Java web app (zip)", ".ear": "Java enterprise archive", ".class": "Java bytecode", ".pyc": "Python bytecode", ".pyo": "old Python optimized bytecode",
    ".so": "shared library (Linux)", ".dylib": "shared library (macOS)", ".dll": "shared library (Windows)", ".a": "static library", ".o": "object file", ".ko": "kernel module",
    ".img": "disk image", ".iso": "optical disc image", ".qcow2": "QEMU disk image", ".vmdk": "VMware disk image", ".vhd": "Hyper-V disk image", ".vhdx": "Hyper-V disk image v2", ".ova": "VM appliance (tar)",
    ".pem": "PEM-encoded certificate or key", ".crt": "certificate", ".cer": "certificate", ".key": "private key", ".pub": "public key", ".csr": "certificate signing request",
    ".p12": "PKCS#12 bundle (key + cert, password protected)", ".pfx": "PKCS#12 bundle", ".der": "DER-encoded certificate/key", ".jks": "Java keystore", ".gpg": "GnuPG encrypted/signed", ".asc": "ASCII-armored GPG",
    ".sig": "detached signature", ".sha256": "checksum file", ".md5": "checksum file", ".lock": "lock file (dependency lock or mutex)", ".pid": "process id file", ".sock": "Unix socket", ".socket": "systemd socket unit",
    ".service": "systemd service unit", ".timer": "systemd timer unit", ".mount": "systemd mount unit", ".desktop": "desktop launcher entry", ".conf": "configuration", ".cfg": "configuration", ".ini": "INI configuration",
    ".toml": "TOML configuration", ".yaml": "YAML", ".yml": "YAML", ".json": "JSON", ".jsonl": "JSON lines (one object per line)", ".ndjson": "newline-delimited JSON", ".xml": "XML", ".csv": "comma-separated values",
    ".tsv": "tab-separated values", ".parquet": "Apache Parquet columnar data", ".avro": "Avro data", ".orc": "ORC columnar data", ".arrow": "Arrow IPC", ".feather": "Arrow Feather", ".h5": "HDF5", ".hdf5": "HDF5",
    ".npy": "NumPy array", ".npz": "zipped NumPy arrays", ".pkl": "Python pickle (unsafe to load from strangers)", ".pickle": "Python pickle", ".pt": "PyTorch checkpoint (pickle-based)", ".pth": "PyTorch checkpoint",
    ".safetensors": "safetensors model weights", ".gguf": "GGUF model (llama.cpp)", ".ggml": "legacy GGML model", ".onnx": "ONNX model", ".pb": "protobuf / TensorFlow graph", ".tflite": "TensorFlow Lite model",
    ".ckpt": "checkpoint (TensorFlow or Stable Diffusion pickle)", ".bin": "binary blob (often model weights)", ".db": "database (often SQLite)", ".sqlite": "SQLite database", ".sqlite3": "SQLite database", ".sql": "SQL script",
    ".dump": "database dump", ".bak": "backup copy", ".orig": "original before a patch", ".rej": "rejected patch hunks", ".patch": "unified diff", ".diff": "unified diff", ".swp": "vim swap file", ".swo": "vim swap file",
    ".tmp": "temporary", ".log": "log", ".out": "program output / a.out executable", ".err": "error output", ".core": "core dump", ".dmp": "memory dump", ".pcap": "packet capture", ".pcapng": "packet capture (next gen)",
    ".har": "HTTP archive (browser network log, JSON)", ".env": "environment variables (often secrets; keep out of git)", ".envrc": "direnv config", ".editorconfig": "editor settings", ".gitignore": "git ignore rules",
    ".dockerignore": "docker build ignore rules", ".tf": "Terraform", ".tfstate": "Terraform state (contains secrets)", ".tfvars": "Terraform variables", ".hcl": "HashiCorp config language", ".nix": "Nix expression",
    ".sh": "shell script", ".bash": "bash script", ".zsh": "zsh script", ".fish": "fish script", ".ps1": "PowerShell", ".bat": "Windows batch", ".cmd": "Windows batch", ".py": "Python", ".pyi": "Python type stub",
    ".ipynb": "Jupyter notebook (JSON)", ".rb": "Ruby", ".pl": "Perl", ".php": "PHP", ".js": "JavaScript", ".mjs": "ES module JavaScript", ".cjs": "CommonJS JavaScript", ".ts": "TypeScript (or MPEG transport stream)",
    ".tsx": "TypeScript React", ".jsx": "JavaScript React", ".vue": "Vue component", ".svelte": "Svelte component", ".go": "Go", ".rs": "Rust", ".c": "C", ".h": "C/C++ header", ".cpp": "C++", ".cc": "C++", ".hpp": "C++ header",
    ".java": "Java", ".kt": "Kotlin", ".scala": "Scala", ".swift": "Swift", ".m": "Objective-C (or MATLAB)", ".cs": "C#", ".fs": "F#", ".ex": "Elixir", ".exs": "Elixir script", ".erl": "Erlang", ".hs": "Haskell", ".ml": "OCaml",
    ".clj": "Clojure", ".lua": "Lua", ".r": "R", ".jl": "Julia", ".zig": "Zig", ".nim": "Nim", ".dart": "Dart", ".wasm": "WebAssembly binary", ".wat": "WebAssembly text", ".proto": "Protocol Buffers schema", ".graphql": "GraphQL schema",
    ".md": "Markdown", ".rst": "reStructuredText", ".adoc": "AsciiDoc", ".tex": "LaTeX", ".txt": "plain text", ".org": "Org mode", ".1": "man page section 1 (roff)", ".man": "man page source",
    ".html": "HTML", ".htm": "HTML", ".css": "CSS", ".scss": "Sass (SCSS)", ".less": "Less CSS", ".svg": "SVG vector image (XML)", ".png": "PNG image", ".jpg": "JPEG image", ".jpeg": "JPEG image", ".gif": "GIF image",
    ".webp": "WebP image", ".avif": "AVIF image", ".heic": "HEIC image (Apple)", ".ico": "Windows icon", ".bmp": "bitmap image", ".tiff": "TIFF image", ".psd": "Photoshop document", ".xcf": "GIMP image",
    ".mp3": "MP3 audio", ".flac": "FLAC audio", ".wav": "WAV audio", ".ogg": "Ogg audio", ".opus": "Opus audio", ".m4a": "AAC audio (MP4 container)", ".aac": "AAC audio", ".mid": "MIDI",
    ".mp4": "MP4 video", ".mkv": "Matroska video", ".webm": "WebM video", ".mov": "QuickTime video", ".avi": "AVI video", ".m3u8": "HLS playlist", ".srt": "subtitles", ".vtt": "WebVTT subtitles",
    ".pdf": "PDF", ".epub": "EPUB ebook (zip)", ".mobi": "Kindle ebook", ".docx": "Word document (zip of XML)", ".xlsx": "Excel workbook (zip of XML)", ".pptx": "PowerPoint (zip of XML)", ".odt": "OpenDocument text",
    ".ods": "OpenDocument spreadsheet", ".doc": "legacy Word", ".xls": "legacy Excel", ".rtf": "Rich Text Format", ".ttf": "TrueType font", ".otf": "OpenType font", ".woff": "web font", ".woff2": "web font 2",
    ".ovpn": "OpenVPN profile", ".pcf": "Cisco VPN profile", ".mobileconfig": "Apple configuration profile", ".plist": "Apple property list", ".app": "macOS application bundle", ".dmg": "macOS disk image", ".pkg": "macOS installer",
    ".exe": "Windows executable", ".msi": "Windows installer", ".sys": "Windows driver", ".reg": "Windows registry export", ".lnk": "Windows shortcut", ".AppImage": "portable Linux app", ".flatpakref": "Flatpak reference", ".snap": "snap package",
    ".torrent": "BitTorrent metadata", ".magnet": "magnet link", ".ics": "iCalendar", ".vcf": "vCard contact", ".eml": "email message", ".mbox": "mailbox", ".pst": "Outlook data file",
    ".crdownload": "Chrome partial download", ".part": "partial download", ".DS_Store": "macOS Finder metadata (gitignore it)", ".Thumbs.db": "Windows thumbnail cache",
}


@detector
def detect_extension(s: str, ctx: Context):
    text = s.strip()
    m = re.fullmatch(r"\*?(\.[A-Za-z0-9]{1,12}(?:\.[A-Za-z0-9]{1,8})?)", text)
    if not m:
        return None
    ext = m.group(1)
    key = ext.lower()
    if key not in EXTENSIONS and key.split(".")[-1] and ("." + key.split(".")[-1]) in EXTENSIONS:
        key = "." + key.split(".")[-1]
    if key not in EXTENSIONS and ext not in EXTENSIONS:
        guess, encoding = mimetypes.guess_type("x" + ext)
        if not guess:
            return None
        return [Reading("extension", 0.5, f"{ext}: {guess}", [f"MIME type {guess}" + (f", encoding {encoding}" if encoding else "")], f"file --mime-type FILE{ext}")]
    desc = EXTENSIONS.get(key) or EXTENSIONS.get(ext)
    lines = [f"{ext}: {desc}"]
    guess, _ = mimetypes.guess_type("x" + key)
    if guess:
        lines.append(f"MIME {guess}")
    lines.append("extensions are a convention; the bytes decide: file FILE")
    return [Reading("extension", 0.8, f"{ext} file: {desc}", lines, f"file FILE{ext}")]


@detector
def detect_mime_type(s: str, ctx: Context):
    if not re.fullmatch(r"(application|text|image|audio|video|font|multipart|message|model)/[A-Za-z0-9.+_-]+(?:;\s*[A-Za-z]+=[^;]+)*", s):
        return None
    base = s.split(";")[0].strip()
    exts = mimetypes.guess_all_extensions(base)
    lines = [f"MIME type {base}" + (f", usual extensions {', '.join(exts[:6])}" if exts else ", no registered extension on this system")]
    known = {"application/octet-stream": "arbitrary binary; browsers download it", "application/x-www-form-urlencoded": "HTML form body: key=value&key2=value2, percent-encoded",
             "multipart/form-data": "HTML form body with files; parts separated by the boundary parameter", "application/json": "JSON body", "text/event-stream": "server-sent events",
             "application/x-ndjson": "newline-delimited JSON", "application/problem+json": "RFC 9457 error details", "application/ld+json": "JSON-LD linked data",
             "application/wasm": "WebAssembly module", "text/html": "HTML page", "image/svg+xml": "SVG (XML, can contain scripts)", "application/pdf": "PDF document",
             "application/zip": "zip archive", "application/gzip": "gzip", "application/x-tar": "tar archive", "application/vnd.api+json": "JSON:API", "application/xml": "XML",
             "text/plain": "plain text", "application/javascript": "JavaScript (text/javascript is the modern name)", "text/javascript": "JavaScript", "text/css": "CSS",
             "application/graphql": "GraphQL query", "application/x-yaml": "YAML (unofficial)", "application/yaml": "YAML (RFC 9512)", "application/toml": "TOML",
             "image/webp": "WebP image", "image/avif": "AVIF image", "video/mp4": "MP4 video", "audio/mpeg": "MP3 audio", "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "Word .docx",
             "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "Excel .xlsx", "application/msword": "legacy Word .doc", "application/vnd.ms-excel": "legacy Excel .xls",
             "application/x-httpd-php": "PHP source", "application/vnd.docker.distribution.manifest.v2+json": "Docker image manifest", "application/vnd.oci.image.manifest.v1+json": "OCI image manifest"}
    if base.lower() in known:
        lines.append(known[base.lower()])
    if ";" in s:
        for param in s.split(";")[1:]:
            lines.append(f"parameter {param.strip()}")
    if "+" in base:
        lines.append(f"structured syntax suffix: +{base.split('+')[-1]} means it is {base.split('+')[-1].upper()} underneath")
    return [Reading("mime type", 0.9, f"MIME type {base}" + (f": {known[base.lower()]}" if base.lower() in known else ""), lines, f"grep -i {q(base)} /etc/mime.types")]


@detector
def detect_passwd_line(s: str, ctx: Context):
    parts = s.split(":")
    if len(parts) == 7 and parts[2].isdigit() and parts[3].isdigit() and parts[5].startswith(("/", "")):
        user, pw, uid, gid, gecos, home, shell = parts
        lines = [f"user {clean(user)}, uid {uid}, gid {gid}, home {clean(home)}, shell {clean(shell) or '(none)'}"]
        lines.append({"x": "password is in /etc/shadow", "*": "no password login", "!": "locked", "": "EMPTY password field - no password needed"}.get(pw, "password hash inline (very old style)"))
        if gecos:
            lines.append(f"GECOS/comment: {clean(gecos)}")
        if shell.endswith(("nologin", "false")):
            lines.append("a service account: cannot log in interactively")
        if uid == "0":
            lines.append("uid 0 = superuser")
        elif int(uid) < 1000:
            lines.append("system account range (uid < 1000)")
        return [Reading("passwd", 0.95, f"/etc/passwd entry: {clean(user)} (uid {uid}, shell {clean(shell)})", lines, f"getent passwd {q(user)}")]
    if len(parts) == 4 and parts[2].isdigit() and re.fullmatch(r"[a-z_][a-z0-9_-]*\$?", parts[0]):
        group, pw, gid, members = parts
        lines = [f"group {clean(group)}, gid {gid}, members: {clean(members) or '(only users with this primary gid)'}"]
        return [Reading("group", 0.85, f"/etc/group entry: {clean(group)} (gid {gid})", lines, f"getent group {q(group)}")]
    if len(parts) == 9 and re.fullmatch(r"[a-z_][a-z0-9_-]*\$?", parts[0]) and (parts[1].startswith(("$", "!", "*")) or parts[1] == ""):
        user, hashed, last_change, *_ = parts
        lines = [f"/etc/shadow entry for {clean(user)}"]
        if hashed.startswith("!") or hashed.startswith("*"):
            lines.append("password locked / login disabled")
        elif hashed == "":
            lines.append("EMPTY password")
        else:
            sub = detect_password_hash(hashed, ctx)
            if sub:
                lines.extend(sub[0].lines[:1])
        if last_change.isdigit():
            d = dt.datetime(1970, 1, 1, tzinfo=UTC) + dt.timedelta(days=int(last_change))
            lines.append(f"password last changed {d:%Y-%m-%d} (day {last_change} since 1970)")
        lines.append("do not paste shadow lines anywhere; this is the password hash")
        return [Reading("shadow", 0.95, f"/etc/shadow entry: {clean(user)}", lines, None)]
    return None


@detector
def detect_fstab(s: str, ctx: Context):
    parts = s.split()
    if len(parts) not in (4, 5, 6) or not (parts[0].startswith(("/dev/", "UUID=", "LABEL=", "PARTUUID=", "tmpfs", "proc", "sysfs", "//", "none")) or ":" in parts[0]):
        return None
    if not parts[1].startswith("/") and parts[1] not in ("none", "swap"):
        return None
    dev, mnt, fstype, opts = parts[:4]
    dump = parts[4] if len(parts) > 4 else "0"
    pass_ = parts[5] if len(parts) > 5 else "0"
    lines = [f"mount {clean(dev)} at {clean(mnt)} as {fstype}, options {clean(opts)}"]
    opt_words = {"defaults": "rw,suid,dev,exec,auto,nouser,async", "noatime": "do not update access times (faster)", "relatime": "update atime only when older than mtime",
                 "nofail": "boot continues if the device is missing", "noauto": "not mounted at boot; mount it manually", "ro": "read-only", "rw": "read-write",
                 "nosuid": "ignore setuid bits", "nodev": "no device files", "noexec": "no executables", "user": "any user may mount it", "x-systemd.automount": "mount on first access",
                 "_netdev": "wait for the network", "discard": "TRIM on delete (SSDs)", "compress=zstd": "btrfs transparent compression", "subvol": "btrfs subvolume", "errors=remount-ro": "go read-only on errors",
                 "size": "tmpfs size cap", "uid": "owner uid for filesystems without Unix permissions (vfat/ntfs)", "umask": "mode mask for vfat/ntfs", "credentials": "file holding the SMB username/password"}
    for opt in opts.split(","):
        key = opt.split("=")[0]
        if key in opt_words:
            lines.append(f"{opt}: {opt_words[key]}")
        elif opt in opt_words:
            lines.append(f"{opt}: {opt_words[opt]}")
    lines.append(f"dump {dump} ({'back up with dump(8)' if dump != '0' else 'not dumped'}), fsck pass {pass_} ({'root fs, checked first' if pass_ == '1' else 'checked after root' if pass_ == '2' else 'never fsck-ed'})")
    if dev.startswith("UUID="):
        lines.append("find the device: blkid -U " + dev[5:])
    return [Reading("fstab", 0.9, f"fstab: {clean(dev)} on {clean(mnt)} ({fstype})", lines, f"findmnt {q(mnt)}")]


def luhn_ok(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


@detector
def detect_card_number(s: str, ctx: Context):
    digits = re.sub(r"[\s-]", "", s)
    if not re.fullmatch(r"\d{13,19}", digits) or not re.fullmatch(r"[\d\s-]+", s) or " " not in s and "-" not in s and len(digits) != 16:
        return None
    if not luhn_ok(digits):
        return None
    brand = "Visa" if digits[0] == "4" else "Mastercard" if 51 <= int(digits[:2]) <= 55 or 2221 <= int(digits[:4]) <= 2720 else \
        "American Express" if digits[:2] in ("34", "37") else "Discover" if digits[:4] == "6011" or digits[:2] == "65" else \
        "JCB" if 3528 <= int(digits[:4]) <= 3589 else "Diners Club" if digits[:2] in ("36", "38") or 300 <= int(digits[:3]) <= 305 else "unknown network"
    lines = [f"passes the Luhn check; issuer prefix suggests {brand}", f"masked: {digits[:6]}{'*' * (len(digits) - 10)}{digits[-4:]}",
             "if this is a real card number, do not paste it into tools or chat; it is cardholder data"]
    return [Reading("card number", 0.6 if brand != "unknown network" else 0.3, f"payment card number shape ({brand}, Luhn valid)", lines, None)]


@detector
def detect_coordinates(s: str, ctx: Context):
    m = re.fullmatch(r"([+-]?\d{1,2}(?:\.\d+)?)\s*°?\s*([NS])?\s*,?\s+([+-]?\d{1,3}(?:\.\d+)?)\s*°?\s*([EW])?", s)
    if not m:
        m = re.fullmatch(r"([+-]?\d{1,2}\.\d+),\s*([+-]?\d{1,3}\.\d+)", s)
        if not m:
            return None
        lat, lon = float(m.group(1)), float(m.group(2))
    else:
        lat, lon = float(m.group(1)), float(m.group(3))
        if m.group(2) == "S":
            lat = -abs(lat)
        if m.group(4) == "W":
            lon = -abs(lon)
    if not (-90 <= lat <= 90 and -180 <= lon <= 180) or (lat == int(lat) and lon == int(lon)):
        return None

    def dms(value: float, pos: str, neg: str) -> str:
        hemi = pos if value >= 0 else neg
        value = abs(value)
        d = int(value)
        mnt = int((value - d) * 60)
        sec = (value - d - mnt / 60) * 3600
        return f"{d}°{mnt:02d}'{sec:04.1f}\"{hemi}"
    lines = [f"latitude {lat:.6f}, longitude {lon:.6f}", f"DMS {dms(lat, 'N', 'S')} {dms(lon, 'E', 'W')}",
             f"hemisphere: {'northern' if lat >= 0 else 'southern'}, {'eastern' if lon >= 0 else 'western'}; rough UTC offset by longitude {lon / 15:+.1f} h",
             f"map: https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=12/{lat}/{lon}", "geo URI: geo:" + f"{lat},{lon}"]
    conf = 0.75 if (m.lastindex and m.lastindex >= 4 and (m.group(2) or m.group(4))) or "°" in s else 0.5 if "," in s else 0.4
    return [Reading("coordinates", conf, f"lat/lon {lat:.5f}, {lon:.5f} ({dms(lat, 'N', 'S')} {dms(lon, 'E', 'W')})", lines, None)]


def raw_bytes(s: str) -> bytes:
    """Best reconstruction of the bytes behind *s*: undecodable stdin bytes arrive as surrogates
    (surrogateescape); a string whose code points all fit in a byte is treated as a latin-1 view."""
    if any(0xDC80 <= ord(c) <= 0xDCFF for c in s):
        return s.encode("utf-8", "surrogateescape")
    if all(ord(c) < 256 for c in s):
        return s.encode("latin-1")
    return s.encode("utf-8")


@detector
def detect_binary_blob(s: str, ctx: Context):
    """Raw bytes that reached us (e.g. piped file contents): identify by magic number only."""
    if ctx.depth or len(s) < 4:
        return None
    data = raw_bytes(s)
    kind = magic(data)
    if not kind or kind.startswith(("UTF-", "script")):
        return None
    return [Reading("binary", 0.9, f"{kind}, {plural(len(data), 'byte')}", [f"first bytes: {hexdump(data)}", "this looks like a file's contents, not a string; try: file -"], "file -")]


# == CLI ==

def read_clipboard() -> str:
    """Clipboard text via whichever paste tool exists; bounded in time and size; never a shell."""
    commands = (["wl-paste", "--no-newline"], ["xclip", "-selection", "clipboard", "-o"], ["xsel", "--clipboard", "--output"],
                ["pbpaste"], ["powershell.exe", "-NoProfile", "-Command", "Get-Clipboard"], ["termux-clipboard-get"])
    tried = []
    for cmd in commands:
        if not have(cmd[0]):
            continue
        tried.append(cmd[0])
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=CLIP_TIMEOUT, stdin=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            continue
        if p.returncode != 0:
            continue
        data = p.stdout
        if len(data) > MAX_INPUT:
            raise ValueError(f"clipboard holds more than {MAX_INPUT // 1024} KiB; pipe the part you mean")
        text = data.decode("utf-8", "replace")
        if text.strip():
            return text
    if tried:
        raise ValueError(f"clipboard is empty ({', '.join(tried)})")
    raise ValueError("no clipboard tool found (wl-paste, xclip, xsel or pbpaste); pass the text as an argument or pipe it")


def read_stdin() -> str:
    data = sys.stdin.buffer.read(MAX_INPUT + 1)
    if len(data) > MAX_INPUT:
        raise ValueError(f"stdin is larger than {MAX_INPUT // 1024} KiB; huh reads short strings, not files")
    return data.decode("utf-8", "surrogateescape")


def dedupe(readings: list[Reading]) -> list[Reading]:
    """Drop readings that say the same thing as a stronger one (e.g. four epoch units all unlikely)."""
    out: list[Reading] = []
    seen_summaries = set()
    for r in readings:
        key = (r.kind, r.summary)
        if key in seen_summaries:
            continue
        seen_summaries.add(key)
        out.append(r)
    return out


def render(readings: list[Reading], total: int, verbose: bool, width: int) -> str:
    lines_out: list[str] = []
    if not readings:
        return "huh: no idea. Nothing matched - try --all, or check the input for stray quotes/spaces."
    for i, r in enumerate(readings):
        tag = f"{r.kind}" if r.confidence >= 0.75 else f"{r.kind}?" if r.confidence >= 0.4 else f"{r.kind}??"
        head = f"{tag:<16} {clean(r.summary)}"
        lines_out.append(head if len(head) <= width or width < 60 else head[: width - 3] + "...")
        for ln in r.lines:
            lines_out.append(f"{'':16} {clean(ln)}")
        for child in r.children:
            where = f"{clean(child.via)} = " if child.via else ""
            lines_out.append(f"{'':16}   -> {where}{child.kind}: {clean(child.summary)}")
            for ln in child.lines[:3]:
                lines_out.append(f"{'':16}      {clean(ln)}")
            for grandchild in child.children[:3]:
                where = f"{clean(grandchild.via)} = " if grandchild.via else ""
                lines_out.append(f"{'':16}      -> {where}{grandchild.kind}: {clean(grandchild.summary)}")
        if r.receipt:
            lines_out.append(f"{'':16} $ {clean(r.receipt)}")
        if i != len(readings) - 1:
            lines_out.append("")
    hidden = total - len(readings)
    if hidden > 0:
        lines_out.append("")
        lines_out.append(f"{'':16} ({plural(hidden, 'more reading')} hidden; --all shows them)")
    return "\n".join(lines_out)


def parse_zones(spec: str | None) -> list[dt.tzinfo]:
    zones: list[dt.tzinfo] = []
    if spec:
        for token in spec.split(","):
            token = token.strip()
            if not token:
                continue
            if token.lower() == "local":
                zones.append(local_zone())
                continue
            resolved = resolve_zone(token)
            if not resolved:
                wanted = token.lower().replace(" ", "_")
                matches = [z for z in canonical_zones() if z.split("/")[-1].lower() == wanted]
                if len(matches) == 1:
                    resolved = (ZoneInfo(matches[0]), matches[0], [])
            if not resolved:
                raise ValueError(f"unknown timezone {token!r} (use an IANA name like Europe/Berlin, an abbreviation like EST, or +05:30)")
            zones.append(resolved[0])
    if not zones:
        zones.append(local_zone())
    # Always include UTC as a secondary zone.
    if not any(z.utcoffset(dt.datetime(2000, 1, 1)) == dt.timedelta(0) and z.utcoffset(dt.datetime(2000, 7, 1)) == dt.timedelta(0) for z in zones):
        zones.append(UTC)
    # drop duplicates by key
    unique: list[dt.tzinfo] = []
    for z in zones:
        if zone_key(z) not in {zone_key(u) for u in unique}:
            unique.append(z)
    return unique


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="huh",
        description="What is this string? Ranked readings of timestamps, tokens, cron lines, modes, hashes, "
                    "colours, addresses and more - offline, read-only, with the Unix one-liner that reproduces each answer.",
        epilog="Examples:\n  huh 1696500000\n  huh '0 */4 * * 1-5' --tz America/New_York\n  huh -rwxr-xr-x\n"
               "  huh eyJhbGciOi...   (a JWT)\n  pbpaste | huh\n  huh                  (bare: reads the clipboard)\n\n"
               "Receipts (the $ lines) are printed, never run. Nothing leaves this machine.",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("text", nargs="*", help="the string to explain (quoting optional; several words are joined with spaces)")
    p.add_argument("-a", "--all", action="store_true", help="show every reading, not just the top five")
    p.add_argument("-j", "--json", action="store_true", help="machine-readable output")
    p.add_argument("-t", "--type", metavar="KIND", help="only readings of this kind (comma-separated; see --list)")
    p.add_argument("--tz", metavar="ZONE[,ZONE]", help="timezone(s) to show instants in; default is the system zone, plus UTC")
    p.add_argument("--now", metavar="WHEN", help=argparse.SUPPRESS)  # for tests: fixed reference instant
    p.add_argument("--list", action="store_true", help="list the kinds of reading huh knows about")
    p.add_argument("-n", "--max", type=int, default=SHOW_DEFAULT, metavar="N", help="how many readings to show (default 5)")
    p.add_argument("-V", "--version", action="version", version=f"huh {__version__}")
    return p


def all_kinds() -> list[str]:
    """Kinds, in detector order, discovered from the source so --list cannot go stale."""
    kinds: list[str] = []
    for fn in DETECTORS:
        name = fn.__name__.removeprefix("detect_").replace("_", " ")
        if name == "epoch":
            kinds.extend(k for k, _, _ in EPOCH_UNITS)
        elif name == "passwd line":
            kinds.extend(["passwd", "group", "shadow"])
        elif name == "binary blob":
            kinds.append("binary")
        elif name == "time of day":
            kinds.append("time")
        else:
            kinds.append(name)
    return kinds


def main(argv: list[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    # "huh -rwxr-xr-x" and "huh -1": things that start with '-' but are input, not options.
    fixed: list[str] = []
    for i, a in enumerate(raw_args):
        if a.startswith("-") and a not in ("-a", "--all", "-j", "--json", "-t", "--type", "--tz", "--now", "--list", "-n", "--max", "-V", "--version", "-h", "--help", "--") \
                and not a.startswith(("--tz=", "--type=", "--now=", "--max=")) and (i == 0 or raw_args[i - 1] not in ("-t", "--type", "--tz", "--now", "-n", "--max")) \
                and "--" not in fixed:
            fixed.append("--")
        fixed.append(a)
    parser = build_parser()
    args = parser.parse_args(fixed)
    if args.list:
        for k in all_kinds():
            print(k)
        return 0
    try:
        zones = parse_zones(args.tz)
    except ValueError as e:
        parser.error(str(e))
    now = dt.datetime.now(UTC)
    if args.now:
        try:
            parsed = dt.datetime.fromisoformat(args.now.replace("Z", "+00:00"))
            now = parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
        except ValueError:
            parser.error(f"--now wants an ISO instant, not {args.now!r}")
    try:
        if args.text:
            text = " ".join(args.text)
        elif not sys.stdin.isatty():
            text = read_stdin()
        else:
            text = read_clipboard()
    except ValueError as e:
        print(f"huh: {e}", file=sys.stderr)
        return 2
    if len(text.encode("utf-8", "surrogateescape")) > MAX_INPUT:
        print(f"huh: input is larger than {MAX_INPUT // 1024} KiB", file=sys.stderr)
        return 2
    text = text.strip("\n\r")
    if not text.strip():
        print("huh: nothing to explain (empty input)", file=sys.stderr)
        return 2
    ctx = Context(now=now, zones=zones)
    readings = dedupe(decode(text, ctx))
    if args.type:
        wanted = {k.strip().lower() for k in args.type.split(",")}
        readings = [r for r in readings if r.kind in wanted or r.kind.replace(" ", "-") in wanted or r.kind.split()[0] in wanted]
    total = len(readings)
    if args.all:
        shown = readings
    else:
        # With a confident answer on the table, drop the long-shot noise; without one, show the long shots.
        floor = 0.25 if readings and readings[0].confidence >= 0.75 else 0.1
        shown = [r for r in readings if r.confidence >= floor][: max(1, args.max)] or readings[:1]
    if args.json:
        print(json.dumps({"input": text, "readings": [r.to_dict() for r in shown], "hidden": total - len(shown)}, indent=2, ensure_ascii=False, default=str))
        return 0
    width = shutil.get_terminal_size((100, 24)).columns if sys.stdout.isatty() else 10_000
    print(render(shown, total, args.all, width))
    return 0 if readings else 1


if __name__ == "__main__":
    sys.exit(main())
