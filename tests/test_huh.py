"""Tests for huh. Run with:  python3 -m unittest discover -s tests -v

Everything uses a fixed reference instant (2026-10-06 14:00 UTC) so results are reproducible.
"""
import base64
import datetime as dt
import io
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import huh  # noqa: E402

UTC = dt.timezone.utc
NOW = dt.datetime(2026, 10, 6, 14, 0, tzinfo=UTC)


def ctx(tz="UTC", now=NOW):
    return huh.Context(now=now, zones=huh.parse_zones(tz))


def readings(text, tz="UTC", now=NOW):
    return huh.dedupe(huh.decode(text, ctx(tz, now)))


def kinds(text, **kw):
    return [r.kind for r in readings(text, **kw)]


def best(text, **kw):
    rs = readings(text, **kw)
    assert rs, f"no readings for {text!r}"
    return rs[0]


def find(text, kind, **kw):
    for r in readings(text, **kw):
        if r.kind == kind:
            return r
    raise AssertionError(f"no {kind!r} reading for {text!r}; got {kinds(text, **kw)}")


def joined(r):
    return "\n".join([r.summary, *r.lines])


class SchemaTests(unittest.TestCase):
    def test_every_reading_is_well_formed(self):
        for text in ["1696500000", "0 */4 * * 1-5", "-rwxr-xr-x", "137", "#1e90ff", "10.0.0.0/22", "SGVsbG8=", "ENOENT"]:
            for r in readings(text):
                self.assertTrue(0 <= r.confidence <= 1, r)
                self.assertTrue(r.kind and r.summary, r)
                self.assertIsInstance(r.lines, list)
                d = r.to_dict()
                json.dumps(d)  # serialisable
                self.assertEqual(set(d), {"kind", "confidence", "summary", "details", "receipt", "data", "via", "children"})

    def test_readings_sorted_by_confidence(self):
        rs = readings("137")
        self.assertEqual([r.confidence for r in rs], sorted((r.confidence for r in rs), reverse=True))

    def test_list_kinds_matches_detectors(self):
        names = huh.all_kinds()
        self.assertIn("epoch seconds", names)
        self.assertIn("cron", names)
        self.assertIn("shadow", names)
        self.assertEqual(len(names), len(set(names)))


class EpochTests(unittest.TestCase):
    def test_seconds(self):
        r = best("1696500000")
        self.assertEqual(r.kind, "epoch seconds")
        self.assertIn("2023-10-05 10:00:00 UTC", r.summary)
        self.assertIn("3 years ago", r.summary)
        self.assertEqual(r.receipt, "date -u -d @1696500000")

    def test_units_by_digit_count(self):
        self.assertEqual(best("1696500000000").kind, "epoch millis")
        self.assertEqual(best("1696500000123456").kind, "epoch micros")
        self.assertEqual(best("1696500000123456789").kind, "epoch nanos")
        self.assertIn("2023-10-05 10:00:00.123456789", best("1696500000123456789").summary)

    def test_fractional_seconds(self):
        r = best("1696500000.5")
        self.assertEqual(r.kind, "epoch seconds")
        self.assertIn("10:00:00.5", r.summary)

    def test_local_zone_and_receipt(self):
        r = best("1696500000", tz="America/New_York")
        self.assertIn("2023-10-05 06:00:00 EDT", r.summary)
        self.assertIn("10:00:00 UTC", joined(r))
        self.assertIn("TZ=America/New_York date -d @1696500000", r.receipt)

    def test_small_numbers_are_not_dates(self):
        r = find("137", "epoch seconds")
        self.assertLess(r.confidence, 0.2)
        self.assertNotEqual(best("137").kind, "epoch seconds")
        self.assertNotEqual(best("1536000").kind, "epoch seconds")

    def test_implausible_epochs_collapse_to_one_line(self):
        rs = [r for r in readings("1536000") if r.kind.startswith("epoch")]
        self.assertEqual(len(rs), 1)
        self.assertIn("unlikely", rs[0].summary)

    def test_filetime(self):
        ft = (1696500000 + 11644473600) * 10**7  # 2023-10-05 10:00:00 UTC as Windows FILETIME
        r = [r for r in readings(str(ft)) if "FILETIME" in r.summary]
        self.assertTrue(r)
        self.assertIn("2023-10-05 10:00:00 UTC", r[0].summary)

    def test_negative_and_zero(self):
        self.assertNotIn("epoch seconds", kinds("0"))
        self.assertTrue(readings("-1"))


class DateTests(unittest.TestCase):
    def test_iso_with_zone(self):
        r = find("2024-01-01T12:30:00Z", "date", tz="Asia/Tokyo")
        self.assertIn("2024-01-01 21:30:00 JST", r.summary)
        self.assertIn("epoch 1704112200", joined(r))

    def test_rfc2822(self):
        r = find("Mon, 01 Jan 2024 12:30:00 +0000", "date")
        self.assertIn("RFC 2822", joined(r))
        self.assertIn("2024-01-01 12:30:00 UTC", r.summary)

    def test_naive_date_assumes_zone(self):
        r = find("2024-01-01 09:00", "date", tz="America/New_York")
        self.assertIn("zone assumed", r.summary)
        self.assertIn("2024-01-01T14:00:00Z", joined(r))
        self.assertIn("if UTC", joined(r))

    def test_trailing_abbreviation(self):
        r = find("2024-01-01 09:00 EST", "date")
        self.assertIn("2024-01-01T14:00:00Z", joined(r))

    def test_dst_gap_and_fold_flagged(self):
        gap = find("2024-03-10 02:30", "date", tz="America/New_York")
        self.assertIn("does not exist", joined(gap))
        fold = find("2024-11-03 01:30", "date", tz="America/New_York")
        self.assertIn("happens twice", joined(fold))
        self.assertIn("2024-11-03T05:30:00Z", joined(fold))
        self.assertIn("2024-11-03T06:30:00Z", joined(fold))

    def test_many_formats(self):
        for text in ["20231005", "Jan 5 2024", "5 Jan 2024", "01/Oct/2023:10:00:00 +0000", "Thu Oct  5 10:00:00 UTC 2023",
                     "12/25/2024", "2024-W01-1", "20231005T100000Z", "2023-10-05T10:00:00.123456789Z"]:
            self.assertIn("date", kinds(text), text)

    def test_time_of_day_conversion(self):
        r = find("9:30pm EST", "time", tz="Europe/Berlin")
        self.assertIn("21:30 EST", r.summary)
        self.assertIn("04:30 CEST", r.summary)  # October: Berlin is still on summer time
        r2 = find("14:00 UTC", "time", tz="America/New_York")
        self.assertIn("10:00 EDT", r2.summary)
        self.assertIn("12:00 EST", find("noon EST", "time").summary)

    def test_strftime(self):
        r = find("%Y-%m-%dT%H:%M:%S%z", "strftime")
        self.assertIn("2026-10-06T14:00:00+0000", r.summary)
        self.assertEqual(r.receipt, "date +%Y-%m-%dT%H:%M:%S%z")
        self.assertEqual(find("%F %T", "strftime").receipt, "date '+%F %T'")


class DurationTests(unittest.TestCase):
    def test_units(self):
        r = find("1h 30m", "duration")
        self.assertEqual(r.data["seconds"], 5400)
        self.assertIn("1h 30m = 5,400 seconds", r.summary)
        self.assertEqual(find("PT1H30M", "duration").data["seconds"], 5400)
        self.assertEqual(find("01:30:00", "duration").data["seconds"], 5400)
        self.assertEqual(find("2d4h", "duration").data["seconds"], 2 * 86400 + 4 * 3600)
        self.assertAlmostEqual(find("250ms", "duration").data["seconds"], 0.25)

    def test_human_duration(self):
        self.assertEqual(huh.human_duration(1536000), "17d 18h 40m")
        self.assertEqual(huh.human_duration(90), "1m 30s")
        self.assertEqual(huh.human_duration(0.25), "250ms")
        self.assertEqual(huh.human_duration(129600), "1d 12h")

    def test_ambiguous_m(self):
        self.assertIn("minutes", joined(find("5m", "duration")))


class CronTests(unittest.TestCase):
    def test_english_and_next(self):
        r = find("0 */4 * * 1-5", "cron")
        self.assertIn("At minute 0 every 4 hours on Monday through Friday", r.summary)
        self.assertEqual(r.data["next"][:2], ["2026-10-06T16:00:00Z", "2026-10-06T20:00:00Z"])
        self.assertEqual(r.data["systemd"], "Mon..Fri *-*-* 00/4:00:00")
        self.assertIn("systemd-analyze calendar", r.receipt)

    def test_business_hours_in_zone(self):
        r = find("*/15 9-17 * * MON-FRI", "cron", tz="America/New_York")
        self.assertIn("Every 15 minutes past hours 9-17 on Monday through Friday", r.summary)
        self.assertTrue(r.data["next"][0].endswith("T14:15:00Z"))  # 10:15 EDT
        self.assertEqual(r.data["systemd"], "Mon..Fri *-*-* 09..17:00/15:00")

    def test_aliases_and_reboot(self):
        self.assertEqual(find("@daily", "cron").data["english"], "at 12am")
        self.assertIn("@reboot", find("@reboot", "cron").summary)

    def test_dom_dow_or_semantics(self):
        r = find("30 4 1,15 * 5", "cron")
        self.assertIn("EITHER", joined(r))
        self.assertEqual(r.data["next"][0], "2026-10-09T04:30:00Z")  # Friday the 9th comes before the 15th

    def test_impossible_date(self):
        r = find("0 0 30 2 *", "cron")
        self.assertEqual(r.data["next"], [])
        self.assertIn("no run found", joined(r))

    def test_leap_day(self):
        r = find("0 0 29 2 *", "cron")
        self.assertEqual(r.data["next"][0], "2028-02-29T00:00:00Z")

    def test_dst_gap_skipped_and_fold_noted(self):
        gap_now = dt.datetime(2024, 3, 9, 12, tzinfo=UTC)
        r = find("30 2 * * *", "cron", tz="America/New_York", now=gap_now)
        self.assertEqual(r.data["next"][0], "2024-03-11T06:30:00Z")  # the 10th has no 02:30
        self.assertIn("does not exist", joined(r))
        fold_now = dt.datetime(2024, 11, 2, 12, tzinfo=UTC)
        r = find("30 1 * * *", "cron", tz="America/New_York", now=fold_now)
        self.assertEqual(r.data["next"][0], "2024-11-03T05:30:00Z")  # the first 01:30 (EDT)
        self.assertIn("happens twice", joined(r))

    def test_invalid(self):
        self.assertNotIn("cron", kinds("60 * * * *"))
        self.assertNotIn("cron", kinds("* * * * * * *"))
        self.assertLess(find("1 1 1 1 1", "cron").confidence, 0.5)

    def test_six_field(self):
        r = find("0 0 * * * *", "cron")
        self.assertIn("seconds field", joined(r))

    def test_crontab_line_with_command(self):
        r = find("0 2 * * * /usr/local/bin/backup.sh >> /var/log/backup.log 2>&1", "cron")
        self.assertIn("backup.sh", joined(r))
        self.assertEqual(r.data["next"][0], "2026-10-07T02:00:00Z")
        r = find("17 *\t* * *\troot    cd / && run-parts --report /etc/cron.hourly", "cron")
        self.assertIn("runs as root", joined(r))
        self.assertIn("mailed", joined(r))


class TimezoneTests(unittest.TestCase):
    def test_iana(self):
        r = find("Asia/Kolkata", "timezone")
        self.assertIn("UTC+05:30", r.summary)
        self.assertIn("19:30", r.summary)
        self.assertEqual(r.receipt, "TZ=Asia/Kolkata date")

    def test_abbreviation_ambiguity(self):
        r = find("CST", "timezone")
        self.assertIn("ambiguous", joined(r))
        self.assertIn("China", joined(r))

    def test_city(self):
        self.assertEqual(find("tokyo", "timezone").data["zone"], "Asia/Tokyo")
        self.assertEqual(find("new york", "timezone").data["zone"], "America/New_York")

    def test_offset(self):
        self.assertEqual(find("+05:30", "timezone").data["offset"], "UTC+05:30")

    def test_parse_zones(self):
        zs = huh.parse_zones("America/New_York,Asia/Tokyo")
        self.assertEqual([huh.zone_key(z) for z in zs], ["America/New_York", "Asia/Tokyo", "UTC"])
        with self.assertRaises(ValueError):
            huh.parse_zones("Not/AZone")


class EncodingTests(unittest.TestCase):
    def test_base64_text(self):
        r = best("SGVsbG8sIHdvcmxkIQ==")
        self.assertEqual(r.kind, "base64")
        self.assertIn("Hello, world!", r.summary)
        self.assertEqual(r.receipt, "printf %s SGVsbG8sIHdvcmxkIQ== | base64 -d")

    def test_base64url_unpadded(self):
        r = find("aGVsbG8gd29ybGQ", "base64")
        self.assertIn("hello world", r.summary)
        self.assertIn("padding", r.receipt)
        r = find("eyJzdWIiOiIxMjM0NTY3ODkwIn0", "base64")
        self.assertIn('{"sub":"1234567890"}', r.summary)

    def test_base64_false_positives_rank_low(self):
        for text in ["hello", "1696500000", "deadbeef", "-rwxr-xr-x", "the quick brown fox"]:
            for r in readings(text):
                if r.kind == "base64":
                    self.assertLess(r.confidence, 0.3, text)

    def test_recursion_base64_json_epoch(self):
        r = best("eyJjcmVhdGVkIjoxNjk2NTAwMDAwfQ==")
        self.assertEqual(r.kind, "base64")
        self.assertEqual(r.children[0].kind, "json")
        grand = r.children[0].children[0]
        self.assertEqual(grand.kind, "epoch seconds")
        self.assertEqual(grand.via, "created")

    def test_recursion_is_bounded(self):
        text = "1696500000"
        for _ in range(8):
            text = base64.b64encode(text.encode()).decode()
        rs = readings(text)
        self.assertLess(len(json.dumps([r.to_dict() for r in rs])), 60000)

        def depth(r):
            return 1 + max((depth(c) for c in r.children), default=0)
        self.assertLessEqual(max(depth(r) for r in rs), huh.MAX_DEPTH)

    def test_hex(self):
        r = best("48656c6c6f")
        self.assertEqual(r.kind, "hex")
        self.assertIn("Hello", r.summary)
        self.assertIn("xxd -r -p", r.receipt)
        self.assertEqual(find("48 65 6c 6c 6f", "hex").summary, r.summary)
        self.assertNotIn("hex", kinds("1696500000"))

    def test_magic_numbers(self):
        png = base64.b64encode(b"\x89PNG\r\n\x1a\n" + b"\0" * 8).decode()
        self.assertIn("PNG image", best(png).summary)
        gz = bytes.fromhex("1f8b0800000000000003")
        self.assertIn("gzip", find(gz.hex(), "hex").summary)

    def test_url_encoding(self):
        r = best("hello%20world%21")
        self.assertEqual(r.kind, "url-encoded")
        self.assertIn("hello world!", r.summary)
        self.assertIn("if + means space", joined(find("a+b%20c", "url-encoded")))

    def test_url(self):
        r = best("https://user:pw@example.com:8443/path/to?x=1696500000&tok=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhIn0.sig#frag")
        self.assertEqual(r.kind, "url")
        text = joined(r)
        self.assertIn("<password>", text)
        self.assertNotIn("pw ", text)
        self.assertIn("port 8443", text)
        self.assertEqual({c.via: c.kind for c in r.children}, {"x": "epoch seconds", "tok": "jwt"})
        self.assertEqual(best("git@github.com:user/repo.git").kind, "url")

    def test_json(self):
        r = best('{"created":1696500000,"id":"018bcfe5-6800-7000-8000-000000000000","ip":"10.0.0.5"}')
        self.assertEqual(r.kind, "json")
        self.assertEqual({c.via: c.kind for c in r.children}, {"created": "epoch seconds", "id": "uuid", "ip": "ip"})
        self.assertEqual(best("[1,2,3]").kind, "json")
        self.assertNotIn("json", kinds("{not json"))

    def test_json_hostile(self):
        for text in ["[1e999]", "[NaN]", "[" * 3000 + "]" * 3000, '{"a":' * 500 + "1" + "}" * 500]:
            readings(text)  # must not raise or hang

    def test_jwt(self):
        tok = ("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE3OTEyNzM2MDB9"
               ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
        r = best(tok)
        self.assertEqual(r.kind, "jwt")
        self.assertIn("HS256", r.summary)
        self.assertIn("EXPIRED", r.summary)
        self.assertIn("NOT verified", joined(r))
        self.assertFalse(r.data["verified"])
        self.assertIn("tr '_-' '/+' | base64 -d", r.receipt)
        none_tok = base64.urlsafe_b64encode(b'{"alg":"none"}').decode().rstrip("=") + ".eyJzdWIiOiJhIn0."
        self.assertIn("alg=none", joined(best(none_tok)))

    def test_html_entities_and_escapes(self):
        self.assertIn("<div>café</div>", best("&lt;div&gt;caf&eacute;&lt;/div&gt;").summary)
        self.assertIn("café A", best(r"caf\u00e9 \x41").summary)
        self.assertIn("é", best(r"caf\303\251").summary)

    def test_ansi(self):
        r = best("\x1b[1;31mERROR\x1b[0m")
        self.assertEqual(r.kind, "ansi")
        self.assertIn("bold, fg red", r.summary)
        self.assertIn("ERROR", joined(r))
        self.assertEqual(best(r"\e[32mOK\e[0m").kind, "ansi")

    def test_mojibake(self):
        self.assertIn("café", best("cafÃ©").summary)
        self.assertIn("’", best("â€™").summary)


class UnicodeTests(unittest.TestCase):
    def test_zero_width_space(self):
        r = best("caf\u200b\u00e9")
        self.assertEqual(r.kind, "unicode")
        self.assertIn("ZERO WIDTH SPACE", r.summary)
        self.assertIn("offset 3", joined(r))
        self.assertIn("café", joined(r))

    def test_bidi_override(self):
        self.assertIn("RIGHT-TO-LEFT OVERRIDE", best("\u202eevil.txt").summary)

    def test_homoglyph(self):
        r = best("p\u0430ypal.com")
        self.assertEqual(r.kind, "unicode")
        self.assertIn("CYRILLIC SMALL LETTER A", joined(r))

    def test_single_character(self):
        r = best("é")
        self.assertEqual(r.kind, "character")
        self.assertIn("U+00E9", r.summary)
        self.assertIn("c3 a9", joined(r))
        self.assertIn("GRINNING FACE", best("U+1F600").summary)
        self.assertIn("ZERO WIDTH SPACE", best("\u200b").summary)
        self.assertIn("homoglyph", joined(best("Ａ")).lower())

    def test_plain_text_is_quiet(self):
        self.assertEqual(readings("hello"), [])
        self.assertEqual([r for r in readings("the quick brown fox") if r.confidence >= 0.1], [])


class NumberTests(unittest.TestCase):
    def test_bases(self):
        r = best("0x7fffffff")
        self.assertEqual(r.kind, "number")
        self.assertIn("2,147,483,647", r.summary)
        self.assertIn("max i32", joined(r))
        self.assertIn("255", best("0b11111111").summary)
        self.assertIn("493", best("0o755").summary)

    def test_big_decimal_facts(self):
        r = find("1536000", "number")
        self.assertIn("1.465 MiB", joined(r))
        self.assertIn("17d 18h 40m", joined(r))

    def test_arithmetic(self):
        self.assertIn("= 265", best("0xff + 0b1010").summary)
        self.assertIn("4,294,967,295", best("2**32-1").summary)
        self.assertIn("1,048,576", best("1<<20").summary)
        self.assertEqual(best("1<<20").receipt, "echo $(( 1<<20 ))")
        self.assertIn("1,024", best("2^10").summary)
        self.assertIn("XOR", joined(best("2^10")))
        self.assertIn("1.46484375", best("(1536000 / 1024) / 1024").summary)

    def test_arithmetic_is_safe(self):
        for text in ["__import__('os').system('id')", "9**9**9", "2**100000000", "1<<99999999", "[1]*99999999", "().__class__",
                     "1/0", "x+1", "open('/etc/passwd')", "9" * 300 + "+1", "(" * 100 + "1" + ")" * 100]:
            self.assertNotIn("arithmetic", kinds(text), text)
        self.assertNotIn("arithmetic", kinds("10.0.0.0/8"))
        self.assertNotIn("arithmetic", kinds("2024-01-01"))

    def test_byte_sizes(self):
        r = best("1.5 MiB")
        self.assertEqual(r.kind, "byte size")
        self.assertEqual(r.data["bytes"], 1572864)
        self.assertEqual(r.receipt, "numfmt --from=iec-i 1.5Mi")
        r = best("1.5MB")
        self.assertIn("1,572,864 B (binary) or 1,500,000 B (SI)", r.summary)
        self.assertIn("1,000,000", best("1000000 bytes").summary)

    def test_data_rate(self):
        r = best("100Mbps")
        self.assertEqual(r.kind, "data rate")
        self.assertIn("12.5 MB/s", joined(r))
        self.assertIn("1m 20s", joined(r))


class SystemCodeTests(unittest.TestCase):
    def test_chmod(self):
        r = best("755")
        self.assertEqual(r.kind, "chmod")
        self.assertIn("-rwxr-xr-x", r.summary)
        self.assertIn("umask", joined(r))
        self.assertEqual(best("-rwxr-xr-x").data["octal"], "755")
        self.assertEqual(best("-rw-r--r--").data["octal"], "644")
        self.assertEqual(best("drwxrwxrwt").data["octal"], "1777")
        self.assertIn("sticky", joined(best("drwxrwxrwt")))
        self.assertEqual(best("-rwsr-xr-x").data["octal"], "4755")
        self.assertIn("setuid", joined(best("-rwsr-xr-x")))
        self.assertIn("add execute for owner", best("u+x").summary)
        self.assertIn("remove", best("g-w,o-rwx").summary)
        self.assertLess(find("137", "chmod").confidence, 0.5)

    def test_exit_codes(self):
        r = best("137")
        self.assertEqual(r.kind, "exit code")
        self.assertIn("SIGKILL", r.summary)
        self.assertIn("OOM", joined(r))
        self.assertIn("often", joined(r))  # a hint, never a certainty
        self.assertIn("command not found", best("127").summary)
        self.assertIn("Ctrl-C", best("130").summary)
        self.assertIn("SIGSEGV", joined(best("139")))

    def test_signals(self):
        r = best("SIGTERM")
        self.assertEqual(r.kind, "signal")
        self.assertIn("15", r.summary)
        self.assertIn("143", joined(r))
        self.assertEqual(best("sigkill").kind, "signal")
        self.assertEqual(best("KILL").kind, "signal")
        self.assertEqual(best("-9").kind, "signal")

    def test_errno(self):
        r = best("ENOENT")
        self.assertEqual(r.kind, "errno")
        self.assertIn("No such file or directory", r.summary)
        self.assertEqual(best("errno 2").kind, "errno")
        self.assertIn("ECONNREFUSED", best("ECONNREFUSED").summary)

    def test_http(self):
        r = best("404")
        self.assertEqual(r.kind, "http status")
        self.assertIn("Not Found", r.summary)
        self.assertIn("rate limited", best("429").summary)
        self.assertIn("Cloudflare", joined(best("522")))
        self.assertNotIn("http status", kinds("999"))

    def test_ports(self):
        r = best("443")
        self.assertEqual(r.kind, "port")
        self.assertIn("HTTPS", r.summary)
        self.assertIn("PostgreSQL", best("5432").summary)
        self.assertEqual(best(":3000").kind, "port")
        self.assertIn("Plex", best("32400").summary)
        self.assertEqual(find("8080/tcp", "port").confidence, 0.85)

    def test_colors(self):
        r = best("#1e90ff")
        self.assertEqual(r.kind, "color")
        self.assertIn("rgb(30,144,255)", r.summary)
        self.assertIn("hsl(210,100%,56%)", r.summary)
        self.assertIn("dodgerblue", r.summary)
        self.assertEqual(best("rgb(255, 0, 0)").data["hex"], "#ff0000")
        self.assertEqual(best("hsl(120,100%,50%)").data["hex"], "#00ff00")
        self.assertEqual(best("rebeccapurple").data["hex"], "#663399")
        self.assertIn("WCAG", joined(r))


class IdentifierTests(unittest.TestCase):
    def test_uuid_versions(self):
        v1 = best("f81d4fae-7dec-11d0-a765-00a0c91e6bf6")
        self.assertEqual(v1.kind, "uuid")
        self.assertIn("1997-02-03 17:43", v1.summary)
        self.assertIn("00:a0:c9:1e:6b:f6", joined(v1))
        v7 = best("018bcfe5-6800-7000-8000-000000000000")
        self.assertIn("2023-11-14 22:13", v7.summary)
        v4 = best("550e8400-e29b-41d4-a716-446655440000")
        self.assertIn("random", v4.summary)
        self.assertIn("nil", best("00000000-0000-0000-0000-000000000000").summary)
        self.assertEqual(best("{550e8400-e29b-41d4-a716-446655440000}").kind, "uuid")

    def test_ulid(self):
        r = best("01HGW2N7EHJVJ4CJ999RRS2E97")
        self.assertEqual(r.kind, "ulid")
        self.assertEqual(r.data["iso"][:7], "2023-12")

    def test_snowflake(self):
        r = find("1341923634421944320", "snowflake")
        self.assertIn("Twitter/X", r.summary)
        self.assertIn("2020-12-24", r.data["iso"])

    def test_ip(self):
        r = best("192.168.1.10:8080")
        self.assertEqual(r.kind, "ip")
        self.assertIn("private (RFC 1918)", r.summary)
        self.assertIn("8080", r.summary)
        self.assertIn("loopback", best("::1").summary)
        self.assertIn("link-local", best("169.254.1.1").summary)
        self.assertIn("carrier-grade NAT", best("100.64.0.1").summary)
        self.assertIn("public", best("8.8.8.8").summary)
        self.assertIn("Cloudflare", best("1.1.1.1").summary)
        self.assertEqual(readings("256.1.1.1"), [])

    def test_cidr(self):
        r = best("10.0.0.0/22")
        self.assertEqual(r.kind, "cidr")
        self.assertEqual(r.data["addresses"], 1024)
        self.assertIn("10.0.0.1-10.0.3.254", r.summary)
        self.assertIn("1,022 usable hosts", joined(r))
        self.assertIn("point-to-point", joined(best("10.0.0.0/31")))
        self.assertIn("single host", joined(best("10.0.0.1/32")))
        self.assertIn("is a host inside", joined(best("192.168.1.77/24")))
        self.assertIn("2^64", best("2001:db8::/64").summary)
        self.assertIn("SLAAC", joined(best("2001:db8::/64")))

    def test_mac(self):
        r = best("02:42:ac:11:00:02")
        self.assertEqual(r.kind, "mac")
        self.assertIn("locally administered", r.summary)
        self.assertEqual(best("AA-BB-CC-DD-EE-FF").data["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(best("aabb.ccdd.eeff").data["mac"], "aa:bb:cc:dd:ee:ff")
        self.assertIn("broadcast", best("ff:ff:ff:ff:ff:ff").summary)
        self.assertIn("multicast", joined(best("01:00:5e:00:00:fb")))
        self.assertIn("fe80::", joined(r))

    def test_mac_vendor_lookup_offline(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("OUI/MA-L   Organization\n\n3C-22-FB   (hex)\t\tExample Corp\n3C22FB     (base 16)\t\tExample Corp\n")
            path = fh.name
        try:
            with mock.patch.object(huh, "OUI_FILES", (path,)):
                self.assertEqual(huh.oui_lookup("3c22fb"), "Example Corp")
                self.assertIn("Example Corp", best("3c:22:fb:12:34:56").summary)
        finally:
            os.unlink(path)

    def test_hashes(self):
        self.assertIn("MD5", best("d41d8cd98f00b204e9800998ecf8427e").summary)
        self.assertIn("SHA-1", best("da39a3ee5e6b4b0d3255bfef95601890afd80709").summary)
        self.assertIn("SHA-256", best("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").summary)
        self.assertEqual(best("sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855").kind, "sri")
        self.assertIn("Subresource Integrity", joined(best("sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC")))

    def test_password_hashes(self):
        bcrypt = "$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW"
        self.assertIn("bcrypt", best(bcrypt).summary)
        self.assertIn("4,096 rounds", joined(best(bcrypt)))
        self.assertIn("Argon2id", best("$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG").summary)
        self.assertIn("SHA-512", best("$6$rounds=5000$saltsalt$qFmFH.bQmmtXzyBY0s9v7Oicd2z4XSIecDzlB5KiA2/jctKu9YterLp8wwnSq.qc.eoxqOmSuNp2xS0ktL3nh/").summary)
        self.assertIn("yescrypt", best("$y$j9T$salt$hash").summary)

    def test_secrets_are_flagged_and_never_get_a_receipt(self):
        # Fixtures are assembled at runtime so no token-shaped literal sits in the source
        # (GitHub push protection, and every secret scanner since, would flag it).
        github_pat = "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz"
        aws_key = "AKIA" + "IOSFODNN7EXAMPLE"
        slack_token = "xox" + "b-" + "0" * 12 + "-" + "0" * 13 + "-" + "a" * 24
        r = best(github_pat)
        self.assertEqual(r.kind, "secret")
        self.assertIn("GitHub personal access token", r.summary)
        self.assertIsNone(r.receipt)
        self.assertIn("rotate", joined(r))
        self.assertIn("AWS access key", best(aws_key).summary)
        self.assertIn("Slack", best(slack_token).summary)
        db = find("postgres://user:" + "s3cret" + "@db.example.com:5432/app", "secret")
        self.assertIn("db.example.com:5432 as user", joined(db))
        self.assertIn("credential", best("API_KEY=abcdef1234567890").summary)

    def test_ssh_keys(self):
        pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM3yar08yz6Fd9+lYpgWBQUEDu7y5b6KIFvTu9kHePeT test@example"
        r = best(pub)
        self.assertEqual(r.kind, "ssh key")
        self.assertIn("SHA256:ipgPwFapiMxuTFCpW8s0yHHwlFEhKA578HBUf59EJRM", joined(r))  # matches ssh-keygen -lf
        self.assertIn("test@example", joined(r))
        self.assertEqual(best("SHA256:ipgPwFapiMxuTFCpW8s0yHHwlFEhKA578HBUf59EJRM").kind, "ssh key")

    def test_pem(self):
        r = best("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----")
        self.assertEqual(r.kind, "pem")
        self.assertIn("PRIVATE", r.summary)
        self.assertIn("do not paste", joined(r))
        self.assertIn("certificate", best("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----").summary)

    def test_git_lookup_is_read_only_and_bounded(self):
        calls = []

        def fake_run(args, **kwargs):
            calls.append((args, kwargs))
            out = {"--is-inside-work-tree": "true\n", "-t": "commit\n", "-1": "abc1234 2024-01-01 Someone: a message\n"}
            key = next((a for a in args if a in out), None)
            return subprocess.CompletedProcess(args, 0, out.get(key, ""), "")
        with mock.patch.object(huh.subprocess, "run", side_effect=fake_run), mock.patch.object(huh, "have", return_value=True):
            r = find("abc1234", "git")
        self.assertIn("a message", r.summary)
        self.assertTrue(calls)
        for args, kwargs in calls:
            self.assertEqual(args[0], "git")
            self.assertNotIn("shell", kwargs)
            self.assertEqual(kwargs["timeout"], huh.GIT_TIMEOUT)
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertIn("core.hooksPath=/dev/null", args)
            self.assertFalse(any(a in ("push", "fetch", "pull", "commit", "checkout", "reset") for a in args))

    def test_no_git_outside_repo(self):
        with mock.patch.object(huh, "git_lookup", return_value=None):
            self.assertNotIn("git", kinds("abc1234"))


class FileTests(unittest.TestCase):
    def test_paths(self):
        r = best("/etc/passwd")
        self.assertEqual(r.kind, "path")
        self.assertIn("user accounts", r.summary)
        self.assertIn("~/.ssh", joined(best("~/.ssh/authorized_keys")))
        self.assertEqual(best("~/.ssh/authorized_keys").receipt, "ls -ld ~/.ssh/authorized_keys; file ~/.ssh/authorized_keys")
        self.assertIn("per-process", joined(best("/proc/1234/status")))
        self.assertIn("/mnt/c/", joined(best("C:\\Windows\\System32")))
        self.assertNotIn("path", kinds("10.0.0.0/8"))

    def test_extensions_and_mime(self):
        self.assertIn("gzip-compressed tar", best(".tar.gz").summary)
        self.assertIn("GGUF", best(".gguf").summary)
        self.assertEqual(readings(".xyzzy"), [])
        r = best("text/html; charset=utf-8")
        self.assertEqual(r.kind, "mime type")
        self.assertIn("parameter charset=utf-8", joined(r))
        self.assertIn("form body", best("application/x-www-form-urlencoded").summary)

    def test_passwd_group_shadow_fstab(self):
        r = best("root:x:0:0:root:/root:/bin/bash")
        self.assertEqual(r.kind, "passwd")
        self.assertIn("superuser", joined(r))
        self.assertIn("nologin", joined(best("nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin")).lower())
        self.assertEqual(best("sudo:x:27:pat,alice").kind, "group")
        r = best("pat:$6$abc$def:19500:0:99999:7:::")
        self.assertEqual(r.kind, "shadow")
        self.assertIn("2023-05-23", joined(r))
        r = best("UUID=1234-5678 /boot/efi vfat umask=0077 0 1")
        self.assertEqual(r.kind, "fstab")
        self.assertIn("blkid -U 1234-5678", joined(r))

    def test_card_number(self):
        r = best("4111 1111 1111 1111")
        self.assertEqual(r.kind, "card number")
        self.assertIn("Visa", r.summary)
        self.assertIn("411111******1111", joined(r))
        self.assertNotIn("card number", kinds("1234 5678 9012 3456"))  # fails Luhn

    def test_coordinates(self):
        r = best("27.9506 N, 82.4572 W")
        self.assertEqual(r.kind, "coordinates")
        self.assertIn("27.95060, -82.45720", r.summary)
        self.assertIn("openstreetmap", joined(r))
        self.assertEqual(readings("0, 0"), [])

    def test_binary_blob(self):
        r = best("\x89PNG\r\n\x1a\n" + "\0" * 16)
        self.assertEqual(r.kind, "binary")
        self.assertIn("PNG", r.summary)
        self.assertIn("gzip", best("\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03").summary)


class SafetyTests(unittest.TestCase):
    def test_clean_strips_terminal_control(self):
        self.assertNotIn("\x1b", huh.clean("a\x1b[31mb"))
        self.assertNotIn("\u202e", huh.clean("a\u202eb"))
        self.assertNotIn("\u200b", huh.clean("a\u200bb"))
        self.assertEqual(huh.clean("plain text, café"), "plain text, café")

    def test_rendered_output_has_no_raw_escapes(self):
        for text in ["\x1b[31mred\x1b[0m", "a\u200bb", "\u202eevil", "\x07bell", "\x1b]0;title\x07"]:
            out = huh.render(readings(text), 1, False, 100)
            for ch in out:
                self.assertFalse(ord(ch) < 32 and ch not in "\n\t", f"control char {ord(ch):#x} in output for {text!r}")
            self.assertNotIn("\u200b", out)
            self.assertNotIn("\u202e", out)

    def test_printf_receipts_reproduce_input_exactly(self):
        for text in ["a'b;$(false)%20", "`id`%41", "$(rm -rf /)%20x", "caf\u200b\u00e9", "SGVsbG8="]:
            for r in readings(text):
                if r.receipt and r.receipt.startswith("printf"):
                    cmd = r.receipt.split(" | ")[0]
                    out = subprocess.run(["bash", "-c", cmd], capture_output=True, timeout=5).stdout.decode("utf-8")
                    self.assertEqual(out, text, cmd)

    def test_printf_literal_round_trips(self):
        shells = [sh for sh in ("bash", "dash", "sh", "zsh") if huh.have(sh)]
        for text in ["plain", "a'b", "50%", "back\\slash", "caf\u200b\u00e9", "\u202eevil", "tab\tx", "😀", "$(id)"]:
            cmd = huh.printf_literal(text)
            for sh in shells:
                out = subprocess.run([sh, "-c", cmd], capture_output=True, timeout=5).stdout
                self.assertEqual(out.decode("utf-8"), text, f"{sh}: {cmd}")

    def test_input_size_limit(self):
        with self.assertRaises(ValueError):
            huh.decode("x" * (huh.MAX_INPUT + 1), ctx())

    def test_detector_exception_is_contained(self):
        def boom(s, c):
            raise RuntimeError("bug")
        with mock.patch.object(huh, "DETECTORS", [boom, *huh.DETECTORS]):
            self.assertTrue(readings("1696500000"))

    def test_budget_bounds_total_work(self):
        c = ctx()
        inner = base64.b64encode(b'{"b":"' + base64.b64encode(b"1696500000") + b'"}').decode()
        huh.decode('{"a":"' + inner + '"}', c)
        self.assertGreaterEqual(c.budget[0], 0)

    def test_clipboard_bounded(self):
        with mock.patch.object(huh, "have", return_value=False):
            with self.assertRaises(ValueError):
                huh.read_clipboard()
        big = subprocess.CompletedProcess([], 0, b"x" * (huh.MAX_INPUT + 1), b"")
        with mock.patch.object(huh, "have", return_value=True), mock.patch.object(huh.subprocess, "run", return_value=big):
            with self.assertRaises(ValueError):
                huh.read_clipboard()
        ok = subprocess.CompletedProcess([], 0, b"1696500000", b"")
        with mock.patch.object(huh, "have", return_value=True), mock.patch.object(huh.subprocess, "run", return_value=ok) as run:
            self.assertEqual(huh.read_clipboard(), "1696500000")
            self.assertEqual(run.call_args.kwargs["timeout"], huh.CLIP_TIMEOUT)
            self.assertNotIn("shell", run.call_args.kwargs)


class CLITests(unittest.TestCase):
    def run_cli(self, *args, stdin=None):
        env = dict(os.environ, PYTHONIOENCODING="utf-8")
        env.pop("HUH_DEBUG", None)
        return subprocess.run([sys.executable, str(ROOT / "huh.py"), "--now", "2026-10-06T14:00:00Z", *args],
                              input=stdin, capture_output=True, text=True, timeout=30, env=env)

    def test_basic(self):
        p = self.run_cli("1696500000")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("epoch seconds", p.stdout)
        self.assertIn("$ date -u -d @1696500000", p.stdout)

    def test_leading_dash_input(self):
        p = self.run_cli("-rwxr-xr-x")
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("chmod 755", p.stdout)
        self.assertEqual(self.run_cli("-1").returncode, 0)
        self.assertEqual(self.run_cli("-9").returncode, 0)

    def test_multiword_without_quotes(self):
        p = self.run_cli("0", "*/4", "*", "*", "1-5")
        self.assertIn("cron", p.stdout)

    def test_stdin(self):
        p = self.run_cli(stdin="SGVsbG8=\n")
        self.assertIn("Hello", p.stdout)
        p = self.run_cli(stdin="   \n")
        self.assertEqual(p.returncode, 2)
        self.assertIn("empty", p.stderr)

    def test_json_flag(self):
        p = self.run_cli("--json", "137")
        data = json.loads(p.stdout)
        self.assertEqual(data["input"], "137")
        self.assertEqual(data["readings"][0]["kind"], "exit code")
        self.assertLessEqual(len(data["readings"]), 5)

    def test_all_and_max_and_type(self):
        few = json.loads(self.run_cli("--json", "137").stdout)["readings"]
        every = json.loads(self.run_cli("--json", "--all", "137").stdout)["readings"]
        self.assertGreater(len(every), len(few))
        one = json.loads(self.run_cli("--json", "-n", "1", "137").stdout)["readings"]
        self.assertEqual(len(one), 1)
        only = json.loads(self.run_cli("--json", "--type", "chmod", "137").stdout)["readings"]
        self.assertEqual([r["kind"] for r in only], ["chmod"])

    def test_tz(self):
        p = self.run_cli("--tz", "America/New_York,Asia/Tokyo", "1696500000")
        self.assertIn("06:00:00 EDT", p.stdout)
        self.assertIn("19:00:00 JST", p.stdout)
        self.assertIn("10:00:00 UTC", p.stdout)
        p = self.run_cli("--tz", "Nowhere/Land", "1")
        self.assertEqual(p.returncode, 2)

    def test_list_version_help(self):
        self.assertIn("cron", self.run_cli("--list").stdout)
        self.assertIn(huh.__version__, self.run_cli("--version").stdout)
        self.assertIn("usage:", self.run_cli("--help").stdout)

    def test_no_match_exit_code(self):
        p = self.run_cli("hello")
        self.assertEqual(p.returncode, 1)
        self.assertIn("no idea", p.stdout)

    def test_no_ansi_in_output(self):
        p = self.run_cli("\x1b[31mred\x1b[0m")
        self.assertNotIn("\x1b", p.stdout)

    def test_too_large(self):
        p = self.run_cli(stdin="x" * (huh.MAX_INPUT + 10))
        self.assertEqual(p.returncode, 2)

    def test_no_clipboard_when_piped(self):
        with mock.patch.object(huh, "read_clipboard", side_effect=AssertionError("clipboard must not be read")), \
                mock.patch.object(sys, "stdin", io.TextIOWrapper(io.BytesIO(b"755"))), \
                mock.patch("sys.stdout", new_callable=io.StringIO):
            self.assertEqual(huh.main(["--now", "2026-10-06T14:00:00Z"]), 0)


if __name__ == "__main__":
    unittest.main()
