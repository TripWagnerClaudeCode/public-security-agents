"""Package risk assessment: registry metadata + OSV + typosquat check, cached.

`assess` returns human-readable reasons (empty list = not risky). All network
access goes through an injected `Fetcher`, so tests never touch the network.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import Callable

from .commands import PkgRef
from .state import State

Fetcher = Callable[[str, "dict | None"], dict]

DATA_DIR = Path(__file__).parent / "data"
NEW_PACKAGE_DAYS = 90
NEW_VERSION_DAYS = 30
TYPO_DISTANCE = 2
TYPO_MIN_LEN = 4
MAX_REQUIREMENT_ENTRIES = 50
OSV_URL = "https://api.osv.dev/v1/query"
URL_REASON = "installed from a URL/git/path"
OFFLINE_REASON = "couldn't check (offline)"
INSTALL_SCRIPT_KEYS = ("preinstall", "install", "postinstall")
REGISTRY_LABEL = {"pypi": "PyPI", "npm": "npm", "crates": "crates.io", "go": "the Go module proxy"}
OSV_ECOSYSTEM = {"pypi": "PyPI", "npm": "npm", "crates": "crates.io", "go": "Go"}


class FetchError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def urllib_fetcher(timeout: float = 3.0) -> Fetcher:
    def fetch(url: str, json_body: dict | None = None) -> dict:
        data = None
        headers = {"User-Agent": "gatekeeper/0.1", "Accept": "application/json"}
        if json_body is not None:
            data = json.dumps(json_body).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method="GET" if json_body is None else "POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise FetchError(f"HTTP {e.code} for {url}", status=e.code) from e
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            raise FetchError(f"{type(e).__name__} for {url}") from e
    return fetch


# --------------------------------------------------------------------------
# Names and typosquats
# --------------------------------------------------------------------------

def normalize(name: str, eco: str) -> str:
    if eco == "pypi":
        return re.sub(r"[-_.]+", "-", name).lower()
    if eco == "npm":
        return name.lower()
    return name


@lru_cache(maxsize=None)
def _top(eco: str) -> tuple[tuple[str, ...], frozenset[str]]:
    f = DATA_DIR / f"top_{eco}.txt"
    if not f.exists():
        return (), frozenset()
    names = tuple(normalize(n.strip(), eco) for n in f.read_text(encoding="utf-8").splitlines() if n.strip())
    return names, frozenset(names)


def _typo_limit(name: str) -> int:
    return 1 if len(name) < 6 else TYPO_DISTANCE


def _dl_distance(a: str, b: str, limit: int) -> int:
    """Damerau-Levenshtein (optimal string alignment); returns limit+1 when above `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2: list[int] | None = None
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)
            if prev2 is not None and i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def typo_target(name: str, eco: str) -> str | None:
    """The top-5k package `name` closely resembles (and is not), else None."""
    if eco not in ("pypi", "npm"):
        return None
    norm = normalize(name, eco)
    names, as_set = _top(eco)
    if norm in as_set or len(norm) < TYPO_MIN_LEN:
        return None
    limit = _typo_limit(norm)
    best, best_d = None, limit + 1
    for cand in names:
        d = _dl_distance(norm, cand, limit)
        if d < best_d:
            best, best_d = cand, d
            if d == 1:
                break
    return best


# --------------------------------------------------------------------------
# Registry lookups (each returns a JSON-able summary)
# --------------------------------------------------------------------------

_EXACT_RE = re.compile(r"^v?\d+(?:[.!+_-]?[0-9A-Za-z]+)*$")
_SEMVER3_RE = re.compile(r"^v?\d+\.\d+\.\d+")
_WILD_RE = re.compile(r"(^|[.\-])[xX*](?=$|[.\-])")
_TAG_RE = re.compile(r"^[A-Za-z][\w.-]*$")


def _is_exact(v: str) -> bool:
    return bool(_EXACT_RE.match(v)) and not _WILD_RE.search(v)


def _selected_version(eco: str, version: str | None) -> str | None:
    """The version to look up, or None to use the latest (ranges, wildcards, unknown tags)."""
    if not version:
        return None
    version = version.strip()
    if _is_exact(version):
        if eco in ("npm", "crates") and not _SEMVER3_RE.match(version):
            return None  # "4" / "4.17" are ranges in npm and cargo
        return version
    if eco == "npm" and _TAG_RE.match(version) and not _WILD_RE.search(version):
        return version  # dist-tag such as latest / next
    return None


def _age_days(now: datetime, then: datetime) -> int:
    return max(0, (now - then).days)


def _dt(s: str | None) -> datetime | None:
    if not s:
        return None
    d = datetime.fromisoformat(s.replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def _earliest(stamps: list[str]) -> str | None:
    ds = [d for d in (_dt(s) for s in stamps) if d]
    return min(ds).isoformat() if ds else None


def _missing(**kw) -> dict:
    return {"found": False, **kw}


def _lookup_pypi(name: str, version: str | None, fetch: Fetcher) -> dict:
    data = fetch(f"https://pypi.org/pypi/{urllib.parse.quote(name)}/json", None)
    releases = data.get("releases") or {}
    ver = version or (data.get("info") or {}).get("version")
    if version and version not in releases:
        return _missing(reason=f"version {version} not found on PyPI")
    stamp = lambda files: [f.get("upload_time_iso_8601") or f.get("upload_time") for f in files or []]
    all_stamps = [s for files in releases.values() for s in stamp(files)] or stamp(data.get("urls"))
    ver_stamps = stamp(releases.get(ver)) or (stamp(data.get("urls")) if not version else [])
    return {"found": True, "version": ver, "created": _earliest(all_stamps),
            "version_at": _earliest(ver_stamps), "scripts": False}


def _lookup_npm(name: str, version: str | None, fetch: Fetcher) -> dict:
    data = fetch("https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@"), None)
    versions = data.get("versions") or {}
    tags = data.get("dist-tags") or {}
    ver = version or tags.get("latest")
    if version and version not in versions:
        ver = tags.get(version)
        if ver is None or ver not in versions:
            return _missing(reason=f"version {version} not found on npm")
    times = data.get("time") or {}
    scripts = (versions.get(ver) or {}).get("scripts") or {}
    return {"found": True, "version": ver, "created": _earliest([times.get("created")]),
            "version_at": _earliest([times.get(ver)]),
            "scripts": any(k in scripts for k in INSTALL_SCRIPT_KEYS)}


def _lookup_crates(name: str, version: str | None, fetch: Fetcher) -> dict:
    data = fetch(f"https://crates.io/api/v1/crates/{urllib.parse.quote(name)}", None)
    crate = data.get("crate") or {}
    ver = version or crate.get("max_version") or crate.get("newest_version")
    entry = next((v for v in data.get("versions") or [] if v.get("num") == ver), None)
    if version and entry is None:
        return _missing(reason=f"version {version} not found on crates.io")
    return {"found": True, "version": ver, "created": _earliest([crate.get("created_at")]),
            "version_at": _earliest([(entry or {}).get("created_at")]), "scripts": False}


def _go_escape(module: str) -> str:
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), module)


def _lookup_go(name: str, version: str | None, fetch: Fetcher) -> dict:
    tail = f"@v/{version}.info" if version else "@latest"
    data = fetch(f"https://proxy.golang.org/{_go_escape(name)}/{tail}", None)
    return {"found": True, "version": data.get("Version") or version, "created": None,
            "version_at": _earliest([data.get("Time")]), "scripts": False}


_LOOKUPS = {"pypi": _lookup_pypi, "npm": _lookup_npm, "crates": _lookup_crates, "go": _lookup_go}


def _osv_ids(eco: str, name: str, version: str | None, fetch: Fetcher) -> list[str]:
    if not version:
        return []
    v = version[1:] if eco == "go" and version.startswith("v") else version
    data = fetch(OSV_URL, {"package": {"name": name, "ecosystem": OSV_ECOSYSTEM[eco]}, "version": v})
    return [x["id"] for x in data.get("vulns") or [] if x.get("id")]


def _summary(eco: str, name: str, version: str | None, fetch: Fetcher) -> dict:
    try:
        info = _LOOKUPS[eco](name, version, fetch)
    except FetchError as e:
        if e.status in (404, 410):
            return _missing(reason=f"not found on {REGISTRY_LABEL[eco]}")
        raise
    if info["found"]:
        info["vulns"] = _osv_ids(eco, name, info["version"], fetch)
    return info


def _reasons(info: dict, now: datetime, selected: bool) -> list[str]:
    if not info["found"]:
        return [info["reason"]]
    out: list[str] = []
    created, ver_at = _dt(info.get("created")), _dt(info.get("version_at"))
    if created and _age_days(now, created) < NEW_PACKAGE_DAYS:
        out.append(f"first published {_age_days(now, created)} days ago")
    if ver_at and _age_days(now, ver_at) < NEW_VERSION_DAYS:
        what = f"version {info['version']}" if selected else f"latest version {info['version']}"
        out.append(f"{what} published {_age_days(now, ver_at)} days ago")
    for vid in info.get("vulns", [])[:3]:
        out.append(f"known vulnerability {vid}")
    if info.get("scripts"):
        out.append("runs install scripts")
    return out


# --------------------------------------------------------------------------
# requirements files
# --------------------------------------------------------------------------

_REQ_RE = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(?:(===?)\s*([^\s,;]+)|[<>!~=]\S*)?")
_KNOWN_OPTIONS = {
    "--hash",
    "--no-binary", "--only-binary", "--prefer-binary", "--pre", "--trusted-host", "--require-hashes",
    "--no-index", "--use-feature", "--no-deps", "--upgrade", "-U", "--config-settings", "-C",
}
_INDEX_OPTIONS = {"-i", "--index-url", "--extra-index-url", "-f", "--find-links", "--trusted-host"}
MAX_REQ_DEPTH = 3
NESTED_MARK = "\0nested"
UNREADABLE_MARK = "\0unreadable:"


def _option_parts(line: str) -> tuple[str, str]:
    parts = re.split(r"[\s=]+", line, maxsplit=1)
    return parts[0], parts[1].strip() if len(parts) > 1 else ""


def _safe_host(value: str) -> str:
    """Host[:port] of a URL (never userinfo, path or query); other values minus any userinfo."""
    if "://" in value:
        try:
            u = urllib.parse.urlparse(value)
            host = u.hostname or ""
            return f"{host}:{u.port}" if u.port else host
        except ValueError:
            return "(unparseable url)"
    return value.rsplit("@", 1)[-1].split("?", 1)[0]


def _read_requirement_lines(path: Path, depth: int = 0, seen: frozenset = frozenset(),
                            constraints: bool = False) -> list[str]:
    seen = seen | {path.resolve()}
    lines: list[str] = []
    for raw in path.read_text(encoding="utf-8-sig").splitlines():
        line = re.sub(r"(^|\s)#.*$", "", raw).strip().rstrip("\\").strip()
        if not line:
            continue
        m = re.match(r"^(-r|--requirement|-c|--constraint)[\s=]*(\S+)$", line)
        if not m:
            # a constraints file cannot add packages, but its index options still count
            if not constraints or _option_parts(line)[0] in _INDEX_OPTIONS:
                lines.append(line)
            continue
        sub = path.parent / m.group(2)
        sub_constraints = constraints or m.group(1) in ("-c", "--constraint")
        if depth >= MAX_REQ_DEPTH:
            lines.append(NESTED_MARK)
        elif sub.resolve() in seen:
            continue
        else:
            try:
                lines += _read_requirement_lines(sub, depth + 1, seen, sub_constraints)
            except (OSError, UnicodeDecodeError):
                lines.append(UNREADABLE_MARK + m.group(2))
    return lines


def _assess_requirements(file: str, fetch: Fetcher, state: State, now: datetime,
                         cwd: Path | None, cache_days: float) -> list[str]:
    path = Path(file)
    if not path.is_absolute():
        path = (cwd or Path.cwd()) / path
    try:
        lines = _read_requirement_lines(path)
    except (OSError, UnicodeDecodeError):
        return [f"couldn't read requirements file {file}"]
    out: list[str] = []
    entries = 0
    for line in lines:
        if line.startswith(UNREADABLE_MARK):
            out.append(f"couldn't read requirements file {line[len(UNREADABLE_MARK):]}")
            continue
        if line == NESTED_MARK:
            out.append("nested requirements not followed")
            continue
        opt, value = _option_parts(line) if line.startswith("-") else ("", "")
        if opt in _INDEX_OPTIONS:
            out.append(f"custom package index/source: {opt} {_safe_host(value)}")
            continue
        if opt in _KNOWN_OPTIONS:
            continue
        if line.startswith(("-e", "--editable")) or "://" in line or " @ " in line \
                or line.startswith((".", "/", "~")) or re.match(r"^[A-Za-z]:[\\/]", line):
            out.append(f"{line}: {URL_REASON}")
            continue
        m = None if line.startswith("-") else _REQ_RE.match(line.split(";")[0].strip())
        if not m:
            out.append(f"requirements line not understood: {line[:40]}")
            continue
        entries += 1
        if entries > MAX_REQUIREMENT_ENTRIES:
            out.append(f"requirements file has more than {MAX_REQUIREMENT_ENTRIES} packages; rest not checked")
            break
        ref = PkgRef("pypi", m.group(1), m.group(3) if m.group(2) else None, "registry")
        out += [f"{ref.name}: {r}" for r in assess(ref, fetch, state, now, cache_days=cache_days)]
    return out


# --------------------------------------------------------------------------
# Public entry point
# --------------------------------------------------------------------------

# scheme://authority or scheme-less //authority. The authority runs to the first / ? # or
# whitespace; userinfo is everything up to its LAST "@" (as URL parsers split it), so an
# unencoded "@" inside a password cannot leak the password's tail.
_URL_RE = re.compile(
    r"(?:(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*:)|(?<![\w:/]))//(?P<auth>[^\s/?#]*)(?P<path>[^\s?#]*)"
    r"(?P<tail>(?:\?[^\s#]*)?(?:#\S*)?)")
_SCP_RE = re.compile(r"(?<![\w.@/-])[\w.-]+@([\w.-]+):(?=[\w./~-])")
_TRAILING_PUNCT = re.compile(r"[,.;:!'\")\]>]*$")


def _url_sub(m: re.Match) -> str:
    auth = m["auth"]
    if not m["scheme"] and "@" not in auth:
        return m.group(0)  # scheme-less "//" without userinfo: not treated as a URL
    out = (m["scheme"] or "") + "//" + auth.rpartition("@")[2] + m["path"]
    tail = m["tail"]
    egg = re.match(r"#egg=[\w.-]+", tail)
    if egg:
        return out + egg.group(0)
    return out + _TRAILING_PUNCT.search(tail).group(0)  # keep sentence punctuation after the URL


def redact_urls(text: str) -> str:
    """Strip userinfo, query and fragment (except a bare #egg=name) from URL-like substrings."""
    return _SCP_RE.sub(r"\1:", _URL_RE.sub(_url_sub, text))


def assess(pkg: PkgRef, fetch: Fetcher, state: State, now: datetime, *,
           cwd: Path | None = None, cache_days: float = 7) -> list[str]:
    """Reasons this package is risky (empty = not risky). Every reason is URL-redacted."""
    return [redact_urls(r) for r in _assess(pkg, fetch, state, now, cwd=cwd, cache_days=cache_days)]


def _assess(pkg: PkgRef, fetch: Fetcher, state: State, now: datetime, *,
            cwd: Path | None = None, cache_days: float = 7) -> list[str]:
    if pkg.source in ("url", "git", "path"):
        return [URL_REASON]
    if pkg.source == "requirements":
        return _assess_requirements(pkg.name, fetch, state, now, cwd, cache_days)
    eco = pkg.ecosystem
    if eco not in _LOOKUPS:
        return []  # winget / choco / scoop: no registry checks
    name = normalize(pkg.name, eco)
    reasons: list[str] = []
    target = typo_target(name, eco)
    if target:
        reasons.append(f"name looks like '{target}' (possible typosquat)")

    wanted = _selected_version(eco, pkg.version)
    key_ver = wanted or ""
    info = state.cache_get(eco, name, key_ver, cache_days)
    if info is None:
        try:
            info = _summary(eco, name, wanted, fetch)
        except FetchError:
            return reasons + [OFFLINE_REASON]
        except (KeyError, TypeError, ValueError, AttributeError):
            return reasons + ["couldn't check (unexpected registry response)"]
        state.cache_put(eco, name, key_ver, info)
    return reasons + _reasons(info, now, selected=wanted is not None)
