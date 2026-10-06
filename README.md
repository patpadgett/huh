# huh

**What is this string?**

`huh` is the terminal answer to every browser tab you open to decode something.
Epoch timestamp, JWT, cron line, `chmod` mode, exit code, CIDR block, colour,
UUID, base64 blob, invisible Unicode character: paste it in, get the plausible
readings ranked, each with the conversions you came for and the plain Unix
one-liner (the *receipt*) that would have told you the same thing. So next time
you don't need `huh` at all.

```
$ huh 1696500000
epoch seconds    Thu 2023-10-05 06:00:00 EDT, 3 years ago
                 Thu 2023-10-05 10:00:00 UTC  (UTC)
                 ISO 2023-10-05T10:00:00Z  -  10 digits, read as s since 1970-01-01 UTC
                 $ date -u -d @1696500000   # local: TZ=America/New_York date -d @1696500000

number??         integer 1,696,500,000, 1.7 billion
                 hex 0x651e8920   octal 0o14507504440   binary 0b1100101000111101000100100100000
                 31 bits; fits in u32
                 as bytes: 1.58 GiB / 1.696 GB
                 $ printf '%d 0x%x 0o%o\n' 1696500000 1696500000 1696500000
```

One file, standard library only, Python 3.10+. Offline. Read-only. It never
runs the receipts; it only prints them.

## Install

```sh
pipx install whatsthis         # or: pip install whatsthis
huh --version
```

Or just grab the file - it has no dependencies:

```sh
curl -fsSLo ~/.local/bin/huh https://raw.githubusercontent.com/patpadgett/huh/main/huh.py
chmod +x ~/.local/bin/huh
```

The PyPI distribution name is `whatsthis` (the name `huh` was taken); the
command is `huh` either way.

## Use

```sh
huh 1696500000                  # a number
huh '0 */4 * * 1-5'             # a cron line (quote it, or the shell eats the *)
huh -rwxr-xr-x                  # ls -l mode; a leading dash is fine
huh 137                         # an exit code (and a port, and a chmod...)
huh eyJhbGciOi...               # a JWT
pbpaste | huh                   # from a pipe
huh                             # bare: reads the clipboard (wl-paste / xclip / xsel / pbpaste)

huh --tz Europe/Berlin,Asia/Tokyo '2024-01-01 09:00 EST'   # show instants in these zones too
huh --all 137                   # every reading, not just the top five
huh --type cron,date '...'      # only these kinds (huh --list shows them all)
huh --json 1696500000           # machine-readable
```

Readings are tagged by how sure `huh` is: `kind` means likely, `kind?` means
maybe, `kind??` means a long shot shown because nothing better matched. The
confidence is a ranking heuristic, not a probability. When the input is
genuinely ambiguous (`137`: exit code? port? mode?) you get all of them.

## What it reads

A tour, with real output. The timestamps below use `--tz America/New_York`
and a fixed clock, so they stay reproducible.

**Cron**, in English, with the next three runs in your zone, DST handled
honestly (a wall time that doesn't exist is skipped; one that happens twice is
flagged), plus the `systemd` `OnCalendar=` translation:

```
$ huh '0 */4 * * 1-5'
cron             At minute 0 every 4 hours on Monday through Friday; next Tue 12:00
                 fields: minute hour day-of-month month day-of-week  =  0  */4  *  *  1-5
                 next: Tue 2026-10-06 12:00 EDT  (in 2h 00m)
                 next: Tue 2026-10-06 16:00 EDT  (in 6h 00m)
                 next: Tue 2026-10-06 20:00 EDT  (in 10h 00m)
                 first run in UTC: Tue 2026-10-06 16:00 UTC
                 evaluated in America/New_York; cron uses the daemon's local zone (TZ= or CRON_TZ= can override)
                 systemd OnCalendar=Mon..Fri *-*-* 00/4:00:00
                 $ systemd-analyze calendar 'Mon..Fri *-*-* 00/4:00:00'
```

Whole crontab lines work too (`0 2 * * * /usr/local/bin/backup.sh >> ...`),
including the `/etc/crontab` form with a user column, and `@daily`-style aliases.

**JWTs**, decoded but never trusted:

```
$ huh eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE3OTEyNzM2MDB9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
jwt              JWT (HS256), EXPIRED 6h 00m ago, sub=1234567890
                 header   alg=HS256 typ=JWT
                 sub      1234567890
                 name     John Doe
                 issued   Wed 2018-01-17 20:30:22 EST  (8 years 8 months ago)
                 expires  Tue 2026-10-06 04:00:00 EDT  (6h 00m ago)
                 signature present (43 chars) - NOT verified; the claims above are whatever the issuer, or an attacker, put there
                 $ printf %s eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE3OTEyNzM2MDB9 | tr '_-' '/+' | base64 -d 2>/dev/null | jq .
```

**Exit codes**, with the ambiguity kept visible:

```
$ huh 137
exit code        exit code 137: killed with SIGKILL (128 + 9)
                 killed with SIGKILL (128 + 9) - often the OOM killer or docker/kubernetes memory limits
                 128 + 9 = killed by SIGKILL (Killed)
                 check: dmesg -T | grep -i 'killed process'   (OOM), or docker inspect --format '{{.State.OOMKilled}}' CONTAINER
                 inspect the last status in a shell with: echo $?
                 $ kill -l 9

port?            port 137: NetBIOS name service
                 commonly NetBIOS name service
                 /etc/services: netbios-ns
                 well-known (0-1023, needs root to bind)
                 who is listening: ss -ltnp 'sport = :137'   (or lsof -i :137)
                 $ getent services 137

chmod?           chmod 137 = ---x-wxrwx
                 137 = --x-wxrwx  (owner: execute; group: write, execute; others: read, write, execute)
                 umask to create files like this by default: 640
                 $ stat -c '%a %A %n' FILE   # mode of a file; chmod 137 FILE sets this one

                 (2 more readings hidden; --all shows them)
```

**Invisible characters** - the one that costs people an afternoon:

```
$ huh 'caf​é'
unicode          1 hidden character (ZERO WIDTH SPACE)
                 offset 3: U+200B  ZERO WIDTH SPACE  [Cf]  utf-8 e2 80 8b  \u200b  <- format character - invisible
                 without the invisible characters: café
                 5 characters, 8 bytes UTF-8
                 $ printf 'caf\342\200\213\303\251' | uconv -x 'any-name'
```

It also catches bidi overrides (`\u202e`), Cyrillic/Greek lookalike letters in
hostnames, and mojibake (`cafÃ©` -> `café`).

**Recursive decoding** - base64 that holds JSON that holds a timestamp:

```
$ huh eyJjcmVhdGVkIjoxNjk2NTAwMDAwLCJob3N0IjoiMTAuMC4wLjUifQ==
base64           base64 -> text: {"created":1696500000,"host":"10.0.0.5"}
                 -> {"created":1696500000,"host":"10.0.0.5"}
                   -> json: JSON object with 2 keys
                      created: 1696500000
                      host: "10.0.0.5"
                      -> created = epoch seconds: Thu 2023-10-05 06:00:00 EDT, 3 years ago
                      -> host = ip: IPv4 10.0.0.5 - private (RFC 1918)
                 $ printf %s eyJjcmVhdGVkIjoxNjk2NTAwMDAwLCJob3N0IjoiMTAuMC4wLjUifQ== | base64 -d
```

**Networks, modes, colours, sizes**:

```
$ huh 10.0.0.0/22
cidr             10.0.0.0/22: 1,024 addresses, 10.0.0.1-10.0.3.254, private (RFC 1918)
                 netmask 255.255.252.0 (wildcard 0.0.3.255), 1,024 addresses, 1,022 usable hosts
                 network 10.0.0.0, first host 10.0.0.1, last host 10.0.3.254, broadcast 10.0.3.255
                 splits into 2 x /23 (512 each); 4 x /24
                 ...

$ huh -rwxr-xr-x
chmod            -rwxr-xr-x = chmod 755
                 755 = rwxr-xr-x  (owner: read, write, execute; group: read, execute; others: read, execute)
                 type: regular file
                 the usual mode for directories and executables
                 $ stat -c '%a %A %n' FILE   # mode of a file; chmod 755 FILE sets this one

$ huh '#1e90ff'
color            #1e90ff rgb(30,144,255) hsl(210,100%,56%) ~ dodgerblue
                 dark colour; contrast vs white 3.2:1, vs black 6.5:1 (black text reads better; 4.5:1 is the WCAG AA minimum)
                 ANSI truecolor: \e[38;2;30;144;255m   nearest 256-colour index 75
                 $ printf '\e[48;2;30;144;255m    \e[0m #1e90ff\n'   # paints a swatch in a truecolor terminal

$ huh '1.5 MiB'
byte size        1,572,864 bytes (1.5 MiB / 1.573 MB)
                 1,572,864 bytes  (binary prefix Mi = 1024^2)
                 1.573 MB decimal; 12.58 Mbit; ~0.126 s at 100 Mbit/s, 0.0126 s at 1 Gbit/s
                 $ numfmt --from=iec-i 1.5Mi
```

**Dates**, including the trap:

```
$ huh '2024-03-10 02:30'
date             Sun 2024-03-10 02:30:00 EST (zone assumed), 2 years 6 months ago
                 2024-03-10 02:30 does not exist in America/New_York: clocks jumped forward over it (DST gap); the next real instant is Sun 2024-03-10 03:30:00 EDT
                 if UTC: Sat 2024-03-09 21:30:00 EST
                 epoch 1710055800, 2 years 6 months ago
                 $ TZ=America/New_York date -d '2024-03-10 02:30'; TZ=America/New_York date -d '2024-03-10 02:30' +%s
```

### The full list

| Family | Kinds (`--type`) | Notes |
|---|---|---|
| Time | `epoch seconds/millis/micros/nanos`, `date`, `time`, `duration`, `cron`, `timezone`, `strftime` | Unit picked by digit count and plausibility; Windows FILETIME; ISO 8601, RFC 2822, syslog, Apache log and many strptime shapes; `14:00 UTC` / `9am PST` converted to your zones; `1h 30m`, `PT1H30M`, `01:30:00`; cron aliases, 6-field (seconds) and full crontab lines; IANA names, abbreviations (with their ambiguity: CST is three things), `+05:30`, city names; `%Y-%m-%d` rendered with every code explained |
| Encodings | `base64`, `hex`, `url-encoded`, `url`, `json`, `jwt`, `html entities`, `escapes`, `ansi`, `unicode`, `character` | base64/base64url with or without padding, magic-number sniffing of the decoded bytes (gzip, PNG, zip, PDF, ELF...), recursion three levels deep; URL parts with credentials masked and query values decoded; JSON values inspected for timestamps/ids/addresses; JWT claims and expiry (unverified, and it says so); `\u00e9`/`\x41`/`\303\251`; ANSI SGR sequences in English; zero-width/bidi/lookalike characters; mojibake |
| Numbers | `number`, `arithmetic`, `byte size`, `data rate` | 0x/0b/0o and thousands separators, "fits in u32", powers of two, float32/64 bit patterns; `0xff + 0b1010`, `2**32-1`, `1<<20`, `2^10` via a restricted AST (no names, no calls, bounded exponents); SI vs binary sizes side by side; Mbit/s vs MiB/s |
| System | `chmod`, `exit code`, `signal`, `errno`, `http status`, `port`, `color` | octal and `ls -l` modes both ways, setuid/setgid/sticky, symbolic `u+x,g-w`, matching umask; 128+N signal deaths, sysexits.h, Docker/timeout codes; `SIGTERM`/`KILL`/`-9`; `ENOENT` or `errno 2` with a plain-English hint; HTTP including nginx/Cloudflare codes; well-known ports plus `/etc/services`; hex/rgb()/hsl()/CSS names with contrast ratios and the nearest named colour |
| Identifiers | `uuid`, `ulid`, `snowflake`, `hash`, `password hash`, `sri`, `git`, `ssh key`, `pem`, `secret` | UUID versions 1/6/7 give their embedded timestamp, v1 its MAC; ULIDs and Twitter/Discord snowflakes dated; digest lengths named (MD5/SHA-1/SHA-256...); `$2b$`, `$6$`, `$argon2id$`, `$y$` explained with cost parameters; git object ids looked up read-only in the current repo; OpenSSH public keys fingerprinted exactly like `ssh-keygen -lf`; PEM blocks (private ones get a warning); API-token shapes for GitHub, AWS, Slack, Stripe, OpenAI, Anthropic, Google, npm, PyPI and more, plus database URLs with passwords |
| Networks | `ip`, `cidr`, `mac` | special ranges (RFC 1918, CGNAT, link-local, documentation, public DNS), `host:port`, reverse pointer, IPv4-mapped; subnet maths incl. /31 and /32, IPv6 prefixes; MAC vendor from the local IEEE OUI file when present, locally-administered/multicast bits, EUI-64 link-local |
| Files | `path`, `extension`, `mime type`, `passwd`, `group`, `shadow`, `fstab`, `binary` | what lives at common paths, whether this one exists here; 300+ extensions; MIME types with their usual extensions; `/etc/passwd`, `/etc/group`, `/etc/shadow` and `/etc/fstab` lines; raw file contents identified by magic number |
| Other | `coordinates`, `card number` | lat/lon in decimal or DMS with an OpenStreetMap link; payment-card shapes (Luhn-checked, masked, with a warning) |

## Receipts

Every reading ends with a `$` line: the plain command that produces the same
answer. They are built with shell-safe quoting, use tools that exist on an
ordinary Linux/macOS box (`date`, `base64`, `xxd`, `numfmt`, `jq`,
`systemd-analyze`, `getent`, `ssh-keygen`, `stat`, `kill -l`), and are
*printed, never run*. When the input contains invisible characters the receipt
spells them as octal byte escapes (`\342\200\213`), the one form every
POSIX `printf` understands, so it stays copy-pasteable in bash, zsh and dash.

Secrets (API tokens, private keys, card numbers) get no receipt at all.

## Safety

* Nothing leaves the machine. There is no network code.
* Nothing is written. The only subprocesses are a paste tool (bare `huh` only),
  and read-only `git cat-file`/`git log` when a hex id matches an object in the
  current repository; both have 2-second timeouts and run without a shell.
* Input is capped at 64 KiB; recursion at 3 levels and 48 total decodes;
  arithmetic at 200 characters, 60 AST nodes and 4096-bit results. Hostile JSON
  depth, `9**9**9`, `__import__(...)` and friends are tested to do nothing.
* Output is sanitised: control characters, ANSI escapes and bidi/zero-width
  format characters in the *input* are shown as `\x1b`, `\u202e`, never
  emitted raw. `huh` itself prints no colour codes.
* Exit status: 0 when something was read, 1 when nothing matched, 2 on bad
  usage or input.

## Development

```sh
python3 -m unittest discover -s tests -v     # 110 tests, ~3 s, no third-party packages
HUH_DEBUG=1 huh ...                           # let detector exceptions surface instead of being swallowed
```

Adding a detector is one function:

```python
@detector
def detect_thing(s: str, ctx: Context):
    if not looks_like_a_thing(s):
        return None
    return [Reading("thing", 0.9, "one-line summary", ["detail", "detail"], "the-command-that-proves-it")]
```

`ctx` carries the reference instant (`--now`) and display zones (`--tz`);
`nested(text, ctx)` recurses into decoded content with the shared budget.
`--list` is generated from the registry, so it cannot go stale.

## Non-goals

`huh` ranks *plausible readings*; it does not identify things with certainty,
verify signatures, resolve hostnames, look up WHOIS, or crack hashes. It is a
decoder ring, not an oracle. When it's wrong, the receipt shows you exactly
what it assumed.

## License

MIT - see [LICENSE](LICENSE).
