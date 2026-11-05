"""Install-command parser. Pure: no I/O, no network.

`split_commands` tokenizes a shell command line into simple commands;
`parse_installs` recognises package-manager installs among them (recursing
into wrappers such as `bash -c`, `pwsh -EncodedCommand`, `sudo`, `$(...)`);
`too_deeply_nested` and `install_mentioned_unparsed` report commands that
could not be fully understood so callers can fail safe (ask).
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Iterator, Literal

Ecosystem = Literal["pypi", "npm", "crates", "go", "winget", "choco", "scoop"]
Source = Literal["registry", "url", "git", "path", "requirements"]
Shell = Literal["bash", "powershell"]

MAX_NEST_DEPTH = 3
MAX_INPUT_CHARS = 20_000
MAX_SUBSTITUTIONS = 50


@dataclass(frozen=True)
class PkgRef:
    ecosystem: Ecosystem
    name: str
    version: str | None
    source: Source


# --------------------------------------------------------------------------
# Tokenizer
# --------------------------------------------------------------------------

def _balanced(s: str, start: int, open_c: str, close_c: str) -> int:
    """Index of the bracket closing the one just before `start`, or len(s)."""
    depth, i, quote = 1, start, None
    while i < len(s):
        c = s[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 1
            elif c == quote:
                quote = None
        elif c in "'\"":
            quote = c
        elif c == open_c:
            depth += 1
        elif c == close_c:
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return len(s)


_Seg = tuple[list[str], bool]  # (tokens, fed by a pipe)


def _split(command: str, shell: Shell) -> list[_Seg]:
    ps = shell == "powershell"
    esc = "`" if ps else "\\"
    commands: list[_Seg] = []
    cur: list[str] = []
    buf: list[str] = []
    has_tok = False
    piped = False
    last_gt = -2  # index of the last unquoted, unescaped `>` operator char
    i, n = 0, len(command)

    def end_token() -> None:
        nonlocal has_tok
        if has_tok:
            cur.append("".join(buf))
        buf.clear()
        has_tok = False

    def end_command(pipe_after: bool = False) -> None:
        nonlocal cur, piped
        end_token()
        if ps and cur and cur[0] == "&":
            cur = cur[1:]
        if cur:
            commands.append((cur, piped))
        cur = []
        piped = pipe_after

    def swallow(close_at: int) -> None:
        nonlocal has_tok, i
        has_tok = True
        buf.append(command[i:close_at + 1])
        i = close_at + 1

    while i < n:
        c = command[i]
        nxt1 = command[i + 1:i + 2]
        if c == "#" and not has_tok:
            j = command.find("\n", i)
            i = n if j == -1 else j
        elif c == "'":
            has_tok = True
            j = command.find("'", i + 1)
            if j == -1:
                j = n
            buf.append(command[i + 1:j])
            i = j + 1
        elif c == '"':
            has_tok = True
            i += 1
            while i < n and command[i] != '"':
                ch = command[i]
                if ch == "$" and command[i + 1:i + 2] == "(":
                    end = _balanced(command, i + 2, "(", ")")
                    buf.append(command[i:end + 1])
                    i = end + 1
                    continue
                if ch == esc and i + 1 < n and (ps or command[i + 1] in '"\\$`'):
                    i += 1
                buf.append(command[i])
                i += 1
            i += 1
        elif c == "$" and nxt1 == "(":
            swallow(_balanced(command, i + 2, "(", ")"))
        elif c == "$" and nxt1 == "{":
            j = command.find("}", i + 2)
            swallow(n - 1 if j == -1 else j)
        elif not ps and c in "<>" and nxt1 == "(":
            swallow(_balanced(command, i + 2, "(", ")"))
        elif not ps and c == "`":
            j = command.find("`", i + 1)
            swallow(n - 1 if j == -1 else j)
        elif c == esc and i + 1 < n:
            nxt = command[i + 1]
            if nxt == "\n":
                i += 2  # line continuation
            elif nxt == "\r" and command[i + 2:i + 3] == "\n":
                i += 3
            else:
                has_tok = True
                if ps or nxt in " \t\"'\\$;|&<>()`":
                    buf.append(nxt)
                else:
                    buf.append(c + nxt)  # keep Windows-style paths like .\m.yaml
                i += 2
        elif c in " \t":
            end_token()
            i += 1
        elif c in "\r\n;":
            end_command()
            i += 1
        elif c == "|" and not ps and last_gt == i - 1 and has_tok:
            buf.append(c)  # bash noclobber redirect `>|`
            i += 1
        elif c == "|":
            double = nxt1 == "|"
            end_command(pipe_after=not double)
            i += 2 if double else 1
        elif (not ps and c in "()") or (ps and c in "{}"):
            end_command()  # subshell / script-block grouping
            i += 1
        elif c == "&":
            if nxt1 == "&":
                end_command()
                i += 2
            elif ps and not has_tok and not cur:
                cur.append("&")  # call operator; dropped by end_command()
                i += 1
            elif i > 0 and command[i - 1] in "<>":
                has_tok = True  # redirection like 2>&1
                buf.append(c)
                i += 1
            else:
                end_command()
                i += 1
        else:
            has_tok = True
            if c == ">":
                last_gt = i
            buf.append(c)
            i += 1
    end_command()
    return commands


def split_commands(command: str, shell: Shell) -> list[list[str]]:
    """Split on && || ; | & and newlines; return one token list per command.

    Handles quotes, escapes (backslash for bash, backtick for PowerShell),
    comments, `$(...)` spans (kept inside one token), bash `( )` and
    PowerShell `{ }` grouping (which end a command). PowerShell's leading `&`
    call operator is dropped. Never raises on unbalanced input.
    """
    return [tokens for tokens, _ in _split(command, shell)]


# --------------------------------------------------------------------------
# Argument scanning
# --------------------------------------------------------------------------

Event = tuple[str | None, str]  # (flag, value) for value flags; (None, arg) positional


def _events(args: list[str], value_flags: frozenset[str]) -> list[Event]:
    """Walk args; boolean flags are dropped, value flags consume a value."""
    out: list[Event] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            out.extend((None, x) for x in args[i + 1:])
            break
        if a.startswith("--") and "=" in a:
            flag, _, val = a.partition("=")
            if flag in value_flags:
                out.append((flag, val))
        elif a.startswith("-") and len(a) > 1:
            if a in value_flags:
                if i + 1 < len(args):
                    out.append((a, args[i + 1]))
                    i += 1
            elif not a.startswith("--") and len(a) > 2 and a[:2] in value_flags:
                out.append((a[:2], a[2:].lstrip("=")))
        else:
            out.append((None, a))
        i += 1
    return out


def _after_sub(events: list[Event], subs: set[str], skip: set[str] = frozenset()) -> list[Event] | None:
    """Events after the first positional, if that positional is in `subs`."""
    pos = [k for k, (f, _) in enumerate(events) if f is None]
    k = 0
    while k < len(pos) and events[pos[k]][1] in skip:
        k += 1
    if k >= len(pos) or events[pos[k]][1] not in subs:
        return None
    return events[pos[k] + 1:]


def _first_sub(events: list[Event], subs: set[str], skip: set[str] = frozenset()) -> str | None:
    pos = [v for f, v in events if f is None and v not in skip]
    return pos[0] if pos and pos[0] in subs else None


def _positionals(events: list[Event]) -> list[str]:
    return [v for f, v in events if f is None]


# --------------------------------------------------------------------------
# Spec classification
# --------------------------------------------------------------------------

_SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*://")
_DRIVE = re.compile(r"^[A-Za-z]:[\\/]")
_VCS_PREFIXES = ("git+", "hg+", "svn+", "bzr+")
_ARCHIVES = (".whl", ".tar.gz", ".tgz", ".zip", ".tar.bz2", ".tar")


def _looks_path(s: str) -> bool:
    return s.startswith((".", "/", "~", "\\")) or bool(_DRIVE.match(s)) or s.lower().startswith("file:")


def _url_source(s: str) -> Source | None:
    low = s.lower()
    if low.startswith(_VCS_PREFIXES) or low.startswith(("git://", "ssh://git@")):
        return "git"
    if low.startswith("file:"):
        return "path"
    if _SCHEME.match(s):
        return "url"
    return None


_PIP_NAME = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$")
_PIP_DIRECT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*@\s*(\S+)$")


def _pypi_spec(spec: str) -> PkgRef:
    spec = spec.strip()
    m = _PIP_DIRECT.match(spec)
    if m:
        src = _url_source(m.group(2)) or ("path" if _looks_path(m.group(2)) else "url")
        return PkgRef("pypi", m.group(1), None, src)
    src = _url_source(spec)
    if src:
        return PkgRef("pypi", spec, None, src)
    if _looks_path(spec) or "/" in spec or "\\" in spec or spec.lower().endswith(_ARCHIVES):
        return PkgRef("pypi", spec, None, "path")
    spec = spec.split(";", 1)[0].strip()
    m = _PIP_NAME.match(spec)
    if not m:
        return PkgRef("pypi", spec, None, "registry")
    name, rest = m.group(1), m.group(2).strip()
    version = None
    if rest.startswith("=="):
        version = rest.lstrip("=").split(",", 1)[0].strip() or None
    return PkgRef("pypi", name, version, "registry")


def _pypi_runner_spec(spec: str) -> PkgRef:
    """uvx / pipx run accept `name@version` as well as pip specs."""
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)@([^/:\s]+)$", spec)
    if m:
        return PkgRef("pypi", m.group(1), m.group(2), "registry")
    return _pypi_spec(spec)


def _at_version(spec: str) -> tuple[str, str | None]:
    idx = spec.find("@", 1) if spec.startswith("@") else spec.find("@")
    if idx <= 0:
        return spec, None
    return spec[:idx], spec[idx + 1:] or None


_GH_SHORTHAND = re.compile(r"^[\w.-]+/[\w.-]+(#.*)?$")


def _npm_nonregistry(s: str, archive: bool = True) -> Source | None:
    """Source class for an npm spec (or the version part of name@spec)."""
    if _looks_path(s):
        return "path"
    if s.lower().startswith(("github:", "gitlab:", "bitbucket:", "gist:")) or _url_source(s) == "git" \
            or _GH_SHORTHAND.match(s):
        return "git"
    src = _url_source(s)
    if src:
        return src
    if archive and s.lower().endswith((".tgz", ".tar.gz", ".tar")):
        return "path"
    return None


def _npm_spec(spec: str) -> PkgRef:
    src = _npm_nonregistry(spec, archive=False)
    if src:
        return PkgRef("npm", spec, None, src)
    name, version = _at_version(spec)
    if version:
        src = _npm_nonregistry(version)
        if src:
            return PkgRef("npm", spec, None, src)
    src = _npm_nonregistry(spec)
    if src:
        return PkgRef("npm", spec, None, src)
    return PkgRef("npm", name, version, "registry")


def _npm_create_spec(spec: str) -> PkgRef:
    """`npm create foo@1` runs package `create-foo@1`."""
    if _npm_nonregistry(spec):
        return _npm_spec(spec)
    name, version = _at_version(spec)
    if name.startswith("@"):
        scope, _, rest = name.partition("/")
        if not rest:
            name = f"{scope}/create"
        elif not rest.startswith("create-"):
            name = f"{scope}/create-{rest}"
    elif not name.startswith("create-"):
        name = f"create-{name}"
    return PkgRef("npm", name, version, "registry")


# --------------------------------------------------------------------------
# Per-manager parsers. Each takes the args after the executable name.
# --------------------------------------------------------------------------

_PIP_VALUE = frozenset({
    "-r", "--requirement", "-e", "--editable", "-c", "--constraint", "-i", "--index-url",
    "--extra-index-url", "-f", "--find-links", "-t", "--target", "--prefix", "--root",
    "--python", "--platform", "--python-version", "--implementation", "--abi", "--src",
    "--cache-dir", "--proxy", "--trusted-host", "--retries", "--timeout", "--log",
    "--index", "--default-index", "--group", "--optional", "--spec", "--pip-args",
    "--suffix", "-p", "--git", "--rev", "--tag", "--branch",
    "--upgrade-strategy", "--no-binary", "--only-binary", "--progress-bar", "--report",
    "--use-feature", "--exists-action", "--global-option", "--config-settings", "-C",
    "--cert", "--client-cert", "--keyring-provider", "--build", "-b", "--prefer-binary-dummy",
    "--use-deprecated", "--dest", "-d", "--isolated-dummy",
})
_UV_VALUE = _PIP_VALUE | {"--from", "--with", "--with-requirements", "--with-editable",
                          "--project", "--directory", "--env-file", "--index-strategy"}


def _pip_events(events: list[Event]) -> list[PkgRef]:
    refs: list[PkgRef] = []
    spec_flag = [v for f, v in events if f == "--spec"]
    pending: str | None = None  # `name@` followed by a separate URL token
    for f, v in events:
        if f in ("-r", "--requirement"):
            refs.append(PkgRef("pypi", v, None, "requirements"))
        elif f in ("-e", "--editable"):
            refs.append(_pypi_spec(v))
        elif f == "--git":
            refs.append(PkgRef("pypi", v, None, "git"))
        elif f is None and not spec_flag:
            if pending is not None:
                refs.append(_pypi_spec(f"{pending} @ {v}"))
                pending = None
            elif v.endswith("@") and len(v) > 1:
                pending = v[:-1]
            else:
                refs.append(_pypi_spec(v))
    if pending is not None:
        refs.append(PkgRef("pypi", pending, None, "registry"))
    refs.extend(_pypi_spec(v) for v in spec_flag)
    return refs


def _parse_pip(args: list[str]) -> list[PkgRef]:
    ev = _after_sub(_events(args, _PIP_VALUE), {"install"})
    return [] if ev is None else _pip_events(ev)


def _pypi_runner(ev: list[Event]) -> list[PkgRef]:
    specs = [v for f, v in ev if f == "--from"]
    withs = [x for f, v in ev if f == "--with" for x in v.split(",") if x]
    if not specs:
        specs = [v for f, v in ev if f == "--spec"]
    if not specs:
        pos = _positionals(ev)
        specs = pos[:1]
    refs = [_pypi_runner_spec(s) for s in specs + withs]
    refs += [PkgRef("pypi", v, None, "requirements") for f, v in ev if f == "--with-requirements"]
    return refs


def _parse_uv(args: list[str]) -> list[PkgRef]:
    events = _events(args, _UV_VALUE)
    ev = _after_sub(events, {"add"})
    if ev is not None:
        return _pip_events(ev)
    ev = _after_sub(events, {"pip"})
    if ev is not None:
        ev2 = _after_sub(ev, {"install"})
        return [] if ev2 is None else _pip_events(ev2)
    ev = _after_sub(events, {"tool"})
    if ev is not None:
        ev2 = _after_sub(ev, {"install"})
        if ev2 is not None:
            return _pip_events(ev2)
        ev2 = _after_sub(ev, {"run"})
        return [] if ev2 is None else _pypi_runner(ev2)
    ev = _after_sub(events, {"run"})
    if ev is not None:
        withs = [x for f, v in ev if f == "--with" for x in v.split(",") if x]
        refs = [_pypi_runner_spec(s) for s in withs]
        refs += [PkgRef("pypi", v, None, "requirements") for f, v in ev if f == "--with-requirements"]
        return refs
    return []


def _parse_uvx(args: list[str]) -> list[PkgRef]:
    return _pypi_runner(_events(args, _UV_VALUE))


def _parse_pipx(args: list[str]) -> list[PkgRef]:
    ev = _events(args, _PIP_VALUE)
    after = _after_sub(ev, {"install"})
    if after is not None:
        return _pip_events(after)
    after = _after_sub(ev, {"run"})
    return [] if after is None else _pypi_runner(after)


_NODE_VALUE = frozenset({
    "--prefix", "--registry", "-w", "--workspace", "--tag", "--cache", "--userconfig",
    "--omit", "--include", "--loglevel", "-C", "--filter", "-F", "--dir", "--cwd",
    "--config", "--store-dir", "--fetch-timeout", "--network-concurrency",
    "--save-prefix", "--otp", "--scope", "--before", "--install-strategy", "--logs-dir",
    "--cafile", "--ca", "--proxy", "--https-proxy", "--maxsockets", "--fetch-retries",
})
_NPX_VALUE = _NODE_VALUE | {"-p", "--package", "-c", "--call"}


def _node_specs(ev: list[Event]) -> list[PkgRef]:
    return [_npm_spec(v) for v in _positionals(ev)]


def _node_runner(ev: list[Event]) -> list[PkgRef]:
    pkgs = [v for f, v in ev if f in ("-p", "--package")]
    if pkgs:
        return [_npm_spec(p) for p in pkgs]
    pos = _positionals(ev)
    return [_npm_spec(pos[0])] if pos else []


def _node_create(ev: list[Event]) -> list[PkgRef]:
    pos = _positionals(ev)
    return [_npm_create_spec(pos[0])] if pos else []


def _parse_npm(args: list[str]) -> list[PkgRef]:
    ev = _events(args, _NPX_VALUE)
    after = _after_sub(ev, {"install", "i", "add", "in", "ins", "inst"})
    if after is not None:
        return _node_specs(after)
    after = _after_sub(ev, {"exec", "x"})
    if after is not None:
        return _node_runner(after)
    after = _after_sub(ev, {"create", "init", "innit"})
    return [] if after is None else _node_create(after)


def _parse_npx(args: list[str]) -> list[PkgRef]:
    return _node_runner(_events(args, _NPX_VALUE))


def _parse_node_pm(args: list[str], subs: set[str], runners: set[str], creators: set[str]) -> list[PkgRef]:
    ev = _events(args, _NPX_VALUE)
    after = _after_sub(ev, subs, skip={"global"})
    if after is not None:
        return _node_specs(after)
    after = _after_sub(ev, runners)
    if after is not None:
        return _node_runner(after)
    after = _after_sub(ev, creators)
    return [] if after is None else _node_create(after)


def _parse_go(args: list[str]) -> list[PkgRef]:
    ev = _events(args, frozenset({"-ldflags", "-tags", "-o", "-C", "-gcflags", "-mod"}))
    after = _after_sub(ev, {"install", "get"})
    run = False
    if after is None:
        after = _after_sub(ev, {"run"})
        run = True
    if after is None:
        return []
    refs = []
    for v in _positionals(after):
        if run and ("@" not in v or _looks_path(v)):
            continue
        if _looks_path(v):
            refs.append(PkgRef("go", v, None, "path"))
        else:
            name, version = _at_version(v)
            refs.append(PkgRef("go", name, version, "registry"))
    return refs


_CARGO_VALUE = frozenset({
    "--version", "--vers", "--git", "--branch", "--tag", "--rev", "--path", "--root",
    "--registry", "--index", "--features", "-F", "--bin", "--example", "--target",
    "--profile", "-j", "--jobs", "--target-dir", "--config", "--manifest-path", "-p", "--package",
})


def _parse_cargo(args: list[str]) -> list[PkgRef]:
    while args and args[0].startswith("+"):
        args = args[1:]  # rustup toolchain override, e.g. `cargo +nightly install`
    ev = _after_sub(_events(args, _CARGO_VALUE), {"install", "add", "binstall"})
    if ev is None:
        return []
    opts = {f: v for f, v in ev if f}
    pos = _positionals(ev)
    version = opts.get("--version") or opts.get("--vers")
    if "--git" in opts:
        return [PkgRef("crates", p, None, "git") for p in pos] or [PkgRef("crates", opts["--git"], None, "git")]
    if "--path" in opts:
        return [PkgRef("crates", p, None, "path") for p in pos] or [PkgRef("crates", opts["--path"], None, "path")]
    refs = []
    for p in pos:
        name, v = _at_version(p)
        refs.append(PkgRef("crates", name, v or version, "registry"))
    return refs


_WINGET_VALUE = frozenset({
    "--id", "--name", "--moniker", "-v", "--version", "-s", "--source", "--manifest", "-m",
    "-l", "--location", "--override", "-o", "--log", "--locale", "-a", "--architecture",
    "-q", "--query", "--installer-type", "--scope", "-r", "--rename",
})


def _parse_winget(args: list[str]) -> list[PkgRef]:
    ev = _after_sub(_events(args, _WINGET_VALUE), {"install", "add"})
    if ev is None:
        return []
    version = next((v for f, v in ev if f in ("-v", "--version")), None)
    refs = [PkgRef("winget", v, None, "path") for f, v in ev if f in ("--manifest", "-m")]
    ids = [v for f, v in ev if f == "--id"]
    names = ids or _positionals(ev) + [v for f, v in ev if f in ("--name", "--moniker", "-q", "--query")]
    refs += [PkgRef("winget", n, version, "registry") for n in names]
    return refs


_CHOCO_VALUE = frozenset({
    "--version", "-s", "--source", "--params", "--parameters", "--package-parameters",
    "--install-arguments", "--ia", "-u", "--user", "-p", "--password", "--cache-location",
    "--timeout", "--execution-timeout", "--install-directory",
})


def _parse_choco(args: list[str], implicit: bool = False) -> list[PkgRef]:
    ev = _events(args, _CHOCO_VALUE)
    if not implicit:
        ev = _after_sub(ev, {"install", "upgrade"})
    if ev is None:
        return []
    version = next((v for f, v in ev if f == "--version"), None)
    refs = []
    for p in _positionals(ev):
        if _looks_path(p) or p.lower().endswith((".nupkg", ".config")):
            refs.append(PkgRef("choco", p, None, "path"))
        else:
            refs.append(PkgRef("choco", p, version, "registry"))
    return refs


def _parse_scoop(args: list[str]) -> list[PkgRef]:
    ev = _after_sub(_events(args, frozenset({"-a", "--arch"})), {"install"})
    if ev is None:
        return []
    refs = []
    for p in _positionals(ev):
        src = _url_source(p)
        if src:
            refs.append(PkgRef("scoop", p, None, src))
        elif _looks_path(p) or p.lower().endswith(".json"):
            refs.append(PkgRef("scoop", p, None, "path"))
        else:
            name, version = _at_version(p)
            refs.append(PkgRef("scoop", name, version, "registry"))
    return refs


# --------------------------------------------------------------------------
# Command recognition: prefixes, python, wrappers
# --------------------------------------------------------------------------

_ENV_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_PIP_EXE = re.compile(r"^pip[\d.]*$")
_PY_EXE = re.compile(r"^(python|py)[\d.]*$")
_LEAD_KEYWORDS = {"!", "then", "do", "else", "elif", "elseif", "if", "while", "until", "{", "}"}
_REDIRECT = re.compile(r"^\d*[<>]+(&?\S*)$")


def _exe_name(tok: str) -> str:
    base = re.split(r"[\\/]", tok)[-1].lower()
    for ext in (".exe", ".cmd", ".bat", ".ps1"):
        if base.endswith(ext):
            return base[: -len(ext)]
    return base


def _strip_redirects(tokens: list[str]) -> list[str]:
    out, k = [], 0
    while k < len(tokens):
        m = _REDIRECT.match(tokens[k])
        if m:
            if not m.group(1):
                k += 1  # operator alone: the next token is its target
        else:
            out.append(tokens[k])
        k += 1
    return out


# prefix command -> (flags that take a value, positionals to skip after flags)
_PREFIX_CMDS: dict[str, tuple[frozenset[str], int]] = {
    "sudo": (frozenset({"-u", "-g", "-h", "-p", "-C", "-D", "-R", "-T", "-U", "-r", "-t", "--user",
                        "--group", "--host", "--prompt", "--chdir", "--role", "--type",
                        "--close-from", "--other-user", "--chroot"}), 0),
    "doas": (frozenset({"-u", "-C"}), 0),
    "timeout": (frozenset({"-s", "-k", "--signal", "--kill-after"}), 1),
    "nice": (frozenset({"-n", "--adjustment"}), 0),
    "ionice": (frozenset({"-c", "-n", "-p", "-P", "-u", "--class", "--classdata"}), 0),
    "nohup": (frozenset(), 0),
    "busybox": (frozenset(), 0),
    "toybox": (frozenset(), 0),
    "setsid": (frozenset(), 0),
    "time": (frozenset({"-f", "-o", "--format", "--output"}), 0),
    "command": (frozenset(), 0),
    "builtin": (frozenset(), 0),
    "exec": (frozenset({"-a"}), 0),
    "stdbuf": (frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}), 0),
    "xargs": (frozenset({"-n", "-I", "-P", "-L", "-d", "-E", "-s", "-a", "-l", "--max-args",
                         "--replace", "--max-procs", "--max-lines", "--delimiter", "--eof",
                         "--arg-file", "--max-chars"}), 0),
}
_WSL_VALUE_FLAGS = {"-d", "--distribution", "-u", "--user", "--cd", "--shell-type"}


def _skip_opts(args: list[str], vflags: frozenset[str], npos: int) -> list[str]:
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            i += 1
            break
        if a.startswith("-") and len(a) > 1:
            i += 2 if a in vflags else 1
        else:
            break
    return args[i + npos:]


@dataclass
class _Unwrapped:
    tokens: list[str]
    inner: tuple[str, Shell] | None = None  # payload string from su -c / env -S / wsl "..."
    xargs: bool = False


def _unwrap(tokens: list[str]) -> _Unwrapped:
    """Strip redirects, grouping keywords, VAR=x prefixes and command wrappers."""
    xargs = False
    while True:
        tokens = _strip_redirects(tokens)
        while tokens and (tokens[0].lower() in _LEAD_KEYWORDS or _ENV_ASSIGN.match(tokens[0])):
            tokens = tokens[1:]
        if not tokens:
            return _Unwrapped([], None, xargs)
        exe, args = _exe_name(tokens[0]), tokens[1:]
        if exe == "env":
            i = 0
            while i < len(args):
                a = args[i]
                if a in ("-S", "--split-string"):
                    return _Unwrapped([], (" ".join(args[i + 1:]), "bash"), xargs)
                if a.startswith("-S") and len(a) > 2:
                    return _Unwrapped([], (" ".join([a[2:]] + args[i + 1:]), "bash"), xargs)
                if a in ("-u", "-C", "--unset", "--chdir"):
                    i += 2
                elif (a.startswith("-") and a != "-") or _ENV_ASSIGN.match(a):
                    i += 1
                else:
                    break
            tokens = args[i:]
        elif exe == "su":
            for k, a in enumerate(args):
                if (a in ("-c", "--command") or re.fullmatch(r"-[A-Za-z]*c", a)) and k + 1 < len(args):
                    return _Unwrapped([], (args[k + 1], "bash"), xargs)
            return _Unwrapped([], None, xargs)
        elif exe == "wsl":
            k = 0
            rest: list[str] = []
            while k < len(args):
                a = args[k]
                if a in ("-e", "--exec", "--"):
                    rest = args[k + 1:]
                    break
                if a in _WSL_VALUE_FLAGS:
                    k += 2
                elif a.startswith("-"):
                    k += 1
                else:
                    rest = args[k:]
                    break
            if len(rest) == 1 and " " in rest[0]:
                return _Unwrapped([], (rest[0], "bash"), xargs)
            tokens = rest
        elif exe in _PREFIX_CMDS:
            vflags, npos = _PREFIX_CMDS[exe]
            xargs = xargs or exe == "xargs"
            tokens = _skip_opts(args, vflags, npos)
        else:
            return _Unwrapped(tokens, None, xargs)


# ---- payload-carrying shells -------------------------------------------------

_POSIX_SHELLS = {"bash", "sh", "zsh", "dash", "ash", "ksh"}
_PS_SHELLS = {"powershell", "pwsh", "powershell_ise"}
_POSIX_VALUE_FLAGS = {"-o", "-O", "+o", "+O", "--rcfile", "--init-file"}
_PS_VALUE_FULL = ("executionpolicy", "windowstyle", "inputformat", "outputformat",
                  "configurationname", "workingdirectory", "version", "psconsolefile",
                  "custompipename", "settingsfile")
_PS_VALUE_ALIASES = {"ep", "w", "wd", "if", "of", "v", "ver", "config", "cn"}


class _Unparseable(Exception):
    pass


def _decode_ps(b64: str) -> str | None:
    try:
        return base64.b64decode(b64, validate=True).decode("utf-16-le")
    except (ValueError, UnicodeDecodeError):
        return None


def _ps_payload(args: list[str]) -> str | None:
    n, k = len(args), 0
    while k < n:
        a = args[k]
        if a.startswith("-") and len(a) > 1:
            name, sep, val = a[1:].partition(":")
            low = name.lower()
            if "command".startswith(low) or low == "cwa" or (
                    len(low) >= 8 and "commandwithargs".startswith(low)):
                return val if sep else " ".join(args[k + 1:])
            if "encodedcommand".startswith(low) or low == "ec":
                b64 = val if sep else (args[k + 1] if k + 1 < n else "")
                dec = _decode_ps(b64)
                if dec is None:
                    raise _Unparseable
                return dec
            if "file".startswith(low):
                return None  # script file: contents unknown, args are not code
            takes_value = low in _PS_VALUE_ALIASES or (
                len(low) >= 2 and any(f.startswith(low) for f in _PS_VALUE_FULL))
            k += 2 if (takes_value and not sep) else 1
        else:
            return " ".join(args[k:])  # a bare argument is the command text
    return None


_SAPS_VALUE = ("verb", "windowstyle", "workingdirectory", "credential", "redirectstandardoutput",
               "redirectstandardinput", "redirectstandarderror", "environment")
_SAPS_SWITCH = ("wait", "nonewwindow", "passthru", "loaduserprofile", "usenewenvironment", "whatif",
                "confirm")
_CMD_START_VALUE = {"/d"}


def _ps_quote(a: str) -> str:
    return "'" + a.replace("'", "''") + "'" if (not a or re.search(r"[\s'\"|;&]", a)) else a


def _arg_list(value: str) -> list[str]:
    """-ArgumentList value: a comma list ('-c','irm x | iex') becomes quoted words; one string is raw."""
    parts = value.split(",")
    return [_ps_quote(p) for p in parts] if len(parts) > 1 else [value]


def _start_process(args: list[str]) -> tuple[str, Shell] | None:
    """`Start-Process|saps|start FILE [-ArgumentList A]` and cmd's `start [/flags] ["title"] FILE args`:
    the launched command line, so download-pipe and install rules see it."""
    fp: str | None = None
    rest: list[str] = []
    k = 0
    while k < len(args):
        a = args[k]
        if fp is None and a.startswith("/") and len(a) > 1:  # cmd start switches
            k += 2 if a.lower() in _CMD_START_VALUE else 1
            continue
        if a.startswith("-") and len(a) > 1:
            name, sep, val = a[1:].partition(":")
            low = name.lower()
            nxt = val if sep else (args[k + 1] if k + 1 < len(args) else "")
            step = 1 if sep else 2
            if low in ("path", "pspath") or (len(low) >= 2 and "filepath".startswith(low)):
                fp, k = nxt, k + step
                continue
            if low == "args" or (len(low) >= 2 and "argumentlist".startswith(low)):
                rest += _arg_list(nxt)
                k += step
                continue
            if len(low) >= 2 and any(v.startswith(low) for v in _SAPS_VALUE):
                k += step
                continue
            if len(low) >= 2 and any(v.startswith(low) for v in _SAPS_SWITCH):
                k += 1
                continue
            if fp is not None:  # unknown dash word after the program: its own arguments (cmd start)
                # a dash word with spaces is a raw argument string ('-c "irm x | iex"'): keep it raw
                rest += [x if re.search(r"\s", x) and x.startswith("-") else _ps_quote(x) for x in args[k:]]
                break
            k += 1
            continue
        if not a:
            pass
        elif fp is None:
            fp = a
        else:  # second positional = -ArgumentList
            rest += _arg_list(a)
        k += 1
    if not fp:
        return None
    return " ".join([_ps_quote(fp)] + rest), "powershell"


def _inner_from_wrapper(exe: str, args: list[str]) -> tuple[str, Shell] | None:
    if exe in _POSIX_SHELLS:
        k = 0
        while k < len(args):
            a = args[k]
            if a in _POSIX_VALUE_FLAGS:
                k += 2
            elif re.fullmatch(r"-[a-zA-Z]*c[a-zA-Z]*", a):
                return (args[k + 1], "bash") if k + 1 < len(args) else None
            elif a.startswith(("-", "+")):
                k += 1
            else:
                return None  # script file
        return None
    if exe in _PS_SHELLS:
        payload = _ps_payload(args)
        return None if payload is None else (payload, "powershell")
    if exe == "cmd":
        for k, a in enumerate(args):
            if a.lower() in ("/c", "/k", "/r"):
                return (" ".join(args[k + 1:]), "powershell")
        return None
    if exe in ("start-process", "saps", "start"):
        return _start_process(args)
    if exe in ("invoke-expression", "iex"):
        return (" ".join(args), "powershell") if args else None
    if exe == "eval":
        return (" ".join(args), "bash") if args else None
    return None


# ---- python -------------------------------------------------------------------

_INLINE_CODE_SUSPECT = re.compile(r"\b(pip|install|subprocess|system|popen|ensurepip)\b")


def _python_args(args: list[str]) -> tuple[str, list[str] | str] | None:
    """('pip', rest) for `-m pip ...`; ('inline', code) for `-c code`; else None."""
    k = 0
    while k < len(args):
        a = args[k]
        if a == "-m":
            if k + 1 < len(args) and _PIP_EXE.match(args[k + 1].lower()):
                return "pip", args[k + 2:]
            return None
        if a == "-c":
            return "inline", args[k + 1] if k + 1 < len(args) else ""
        if a.startswith("-c") and not a.startswith("--") and len(a) > 2:
            return "inline", a[2:]
        if a in ("-W", "-X"):
            k += 2
        elif a.startswith("-"):
            k += 1  # -O -B -u -E -I -s -S -Wvalue -Xvalue --flag ...
        else:
            return None  # script file
    return None


# --------------------------------------------------------------------------
# Dispatch
# --------------------------------------------------------------------------

def _parse_manager(exe: str, args: list[str]) -> list[PkgRef]:
    if _PIP_EXE.match(exe):
        return _parse_pip(args)
    if exe == "uv":
        return _parse_uv(args)
    if exe == "uvx":
        return _parse_uvx(args)
    if exe == "pipx":
        return _parse_pipx(args)
    if exe == "npm":
        return _parse_npm(args)
    if exe in ("npx", "bunx"):
        return _parse_npx(args)
    if exe == "pnpm":
        return _parse_node_pm(args, {"add", "install", "i"}, {"dlx", "exec"}, {"create"})
    if exe == "yarn":
        return _parse_node_pm(args, {"add"}, {"dlx"}, {"create"})
    if exe == "bun":
        return _parse_node_pm(args, {"add", "install", "i"}, {"x"}, {"create"})
    if exe == "cargo":
        return _parse_cargo(args)
    if exe == "go":
        return _parse_go(args)
    if exe == "winget":
        return _parse_winget(args)
    if exe in ("choco", "chocolatey"):
        return _parse_choco(args)
    if exe in ("cinst", "cup"):
        return _parse_choco(args, implicit=True)
    if exe == "scoop":
        return _parse_scoop(args)
    return []


# ---- fail-safe detection of installs we may have missed ----------------------

# installer -> (install-like subcommands, always-installs-first-positional)
_INSTALLERS: dict[str, tuple[frozenset[str], bool]] = {
    "pip": (frozenset({"install"}), False),
    "uv": (frozenset({"add", "install", "run"}), False),
    "uvx": (frozenset(), True),
    "pipx": (frozenset({"install", "run"}), False),
    "npm": (frozenset({"install", "i", "add", "exec", "x", "create", "init"}), False),
    "npx": (frozenset(), True),
    "pnpm": (frozenset({"install", "i", "add", "exec", "dlx", "create"}), False),
    "yarn": (frozenset({"add", "dlx", "create"}), False),
    "bun": (frozenset({"install", "i", "add", "x", "create"}), False),
    "bunx": (frozenset(), True),
    "cargo": (frozenset({"install", "add", "binstall"}), False),
    "go": (frozenset({"install", "get", "run"}), False),
    "winget": (frozenset({"install", "add"}), False),
    "choco": (frozenset({"install", "upgrade"}), False),
    "cinst": (frozenset(), True),
    "cup": (frozenset(), True),
    "scoop": (frozenset({"install"}), False),
}
_HARMLESS = {"echo", "printf", "write-output", "write-host", "write-error", "grep", "egrep",
             "fgrep", "rg", "man", "which", "where", "cat", "type", "select-string"}
_SHELL_LIKE = _POSIX_SHELLS | _PS_SHELLS | {"iex", "invoke-expression", "eval"}


def _installer_key(exe: str) -> str | None:
    if _PIP_EXE.match(exe):
        return "pip"
    return exe if exe in _INSTALLERS else None


def _mentions_install(tokens: list[str]) -> bool:
    for j, t in enumerate(tokens):
        key = _installer_key(_exe_name(t))
        if key is None:
            continue
        subs, always = _INSTALLERS[key]
        rest = tokens[j + 1:]
        if always:
            if any(not a.startswith("-") for a in rest):
                return True
            continue
        for k, a in enumerate(rest):
            if a in subs:
                after = [x for x in rest[k + 1:] if not x.startswith("-")]
                if key == "go" and a == "run":
                    after = [x for x in after if "@" in x]
                if key == "uv" and a == "run" and not (
                        "tool" in rest[:k] or any(x.startswith("--with") for x in rest)):
                    after = []
                if after:
                    return True
    return False


_DYNAMIC_NAME = re.compile(r"\$|`")


@dataclass
class _Ctx:
    refs: list[PkgRef] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    deep: bool = False
    nsubs: int = 0
    aborted: bool = False

    def reason(self, text: str) -> None:
        if text not in self.reasons:
            self.reasons.append(text)


def _substitutions(command: str, shell: Shell) -> list[str]:
    """Flattened inner strings of $(...), `...`, <(...), >(...) (nested ones included)."""
    ps = shell == "powershell"
    out: list[str] = []
    i, n = 0, len(command)
    while i < n:
        c = command[i]
        if c == "'":
            j = command.find("'", i + 1)
            i = n if j == -1 else j + 1
        elif c == "\\" and not ps:
            i += 2
        elif c == "`" and ps:
            i += 2
        elif (c == "$" or (not ps and c in "<>")) and command[i + 1:i + 2] == "(":
            end = _balanced(command, i + 2, "(", ")")
            out.append(command[i + 2:end])
            if len(out) > MAX_SUBSTITUTIONS:
                return out
            i += 2  # keep scanning inside to flatten nested substitutions
        elif c == "`":
            j = i + 1
            while j < n and command[j] != "`":
                j += 2 if command[j] == "\\" else 1
            out.append(command[i + 1:j])
            if len(out) > MAX_SUBSTITUTIONS:
                return out
            i = j + 1
        else:
            i += 1
    return out


def _analyze(ctx: _Ctx, command: str, shell: Shell, depth: int, scan_subs: bool = True) -> None:
    if depth > MAX_NEST_DEPTH:
        ctx.deep = True
        ctx.reason("commands nested too deeply to inspect")
        return
    if len(command) > MAX_INPUT_CHARS:
        ctx.aborted = True
        ctx.reason(f"command longer than {MAX_INPUT_CHARS} characters")
        return
    if ctx.aborted:
        return
    if scan_subs:
        subs = _substitutions(command, shell)
        ctx.nsubs += len(subs)
        if ctx.nsubs > MAX_SUBSTITUTIONS:
            ctx.aborted = True
            ctx.reason(f"more than {MAX_SUBSTITUTIONS} command substitutions")
            return
        for sub in subs:
            _analyze(ctx, sub, shell, depth + 1, scan_subs=False)
    for tokens, piped in _split(command, shell):
        if ctx.aborted:
            return
        _analyze_tokens(ctx, tokens, piped, shell, depth)


def _is_dynamic_command(exe_tok: str, args: list[str], shell: Shell) -> bool:
    if "$(" in exe_tok or "`" in exe_tok or exe_tok.startswith("("):
        return True
    if exe_tok.startswith("$"):
        if shell == "powershell" and ("=" in exe_tok or (args and args[0] in ("=", "+=", "-=", "*=", "/="))):
            return False  # PowerShell variable assignment
        return True
    return False


def _analyze_tokens(ctx: _Ctx, tokens: list[str], piped: bool, shell: Shell, depth: int) -> None:
    u = _unwrap(tokens)
    if u.inner is not None:
        _analyze(ctx, u.inner[0], u.inner[1], depth + 1)
        return
    tokens = u.tokens
    if not tokens:
        return
    exe, args = _exe_name(tokens[0]), tokens[1:]

    if _is_dynamic_command(tokens[0], args, shell):
        ctx.reason("command name is computed at runtime")
        return

    try:
        inner = _inner_from_wrapper(exe, args)
    except _Unparseable:
        ctx.deep = True
        ctx.reason("undecodable EncodedCommand")
        return
    if inner is not None:
        _analyze(ctx, inner[0], inner[1], depth + 1)
        return
    if piped and exe in _SHELL_LIKE:
        ctx.reason(f"input piped into {exe}")
        return

    if _PY_EXE.match(exe):
        res = _python_args(args)
        if res and res[0] == "pip":
            exe, args = "pip", res[1]  # type: ignore[assignment]
        elif res and res[0] == "inline":
            if _INLINE_CODE_SUSPECT.search(str(res[1])):
                ctx.reason("python -c code may install packages")
            return
        else:
            return
    if u.xargs:
        if _installer_key(exe) is not None:
            ctx.reason(f"xargs feeds {exe} its arguments")
        return

    raw = _parse_manager(exe, args)
    dropped = [r for r in raw if _DYNAMIC_NAME.search(r.name)]
    refs = [r for r in raw if r not in dropped]
    ctx.refs.extend(refs)
    if exe in _HARMLESS:
        return
    if (not refs or dropped) and _mentions_install(tokens):
        ctx.reason("package install not understood: " + " ".join(tokens[:4]))


def parse_installs(command: str, shell: Shell) -> list[PkgRef]:
    ctx = _Ctx()
    _analyze(ctx, command, shell, 0)
    return list(dict.fromkeys(ctx.refs))


def too_deeply_nested(command: str, shell: Shell) -> bool:
    """True if wrappers/substitutions nest deeper than MAX_NEST_DEPTH or an
    encoded command cannot be decoded (callers should treat as `ask`)."""
    ctx = _Ctx()
    _analyze(ctx, command, shell, 0)
    return ctx.deep


def install_mentioned_unparsed(command: str, shell: Shell) -> list[str]:
    """Reasons why an install may be present that parse_installs did not report.

    Empty means the command was fully understood. Non-empty reasons cover:
    an installer used with an install-like subcommand but no package found,
    dynamic payloads (`bash -c "$X"`, `... | bash`, `xargs pip install`),
    oversized input or too many substitutions, undecodable EncodedCommand,
    and nesting beyond MAX_NEST_DEPTH. Callers should treat these as `ask`.
    """
    ctx = _Ctx()
    _analyze(ctx, command, shell, 0)
    return list(ctx.reasons)


# --------------------------------------------------------------------------
# Public walker for other rule sets (gatekeeper.rules)
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Segment:
    """One simple command, after wrapper unwrapping.

    argv: tokens with redirects, VAR=x prefixes and sudo/env/timeout/xargs/wsl removed
    (empty for a bare `VAR=x` assignment or redirect-only statement).
    piped: its stdin comes from the previous command in a pipeline.
    shell: dialect the command was written in.
    raw: tokens as split (before unwrapping), so callers can see VAR=x prefixes.
    redirects: output-redirection targets (`> f`, `>> f`, `2> f`, `&> f`).
    """
    argv: list[str]
    piped: bool
    shell: Shell
    raw: list[str]
    redirects: list[str]


_OUT_REDIRECT = re.compile(r"^(?:\d*|&|\*)>>?\|?(.*)$")


def _redirect_targets(tokens: list[str]) -> list[str]:
    out: list[str] = []
    for k, tok in enumerate(tokens):
        m = _OUT_REDIRECT.match(tok)
        if not m:
            continue
        target = m.group(1)
        if not target and k + 1 < len(tokens):
            target = tokens[k + 1]
        if target and not target.startswith("&"):
            out.append(target)
    return out


def iter_command_segments(command: str, shell: Shell) -> Iterator[Segment]:
    """Yield every simple command in `command`, including those hidden in
    `$(...)`, backticks, `<(...)`, `bash -c`, `pwsh -Command/-EncodedCommand`,
    `cmd /c`, `wsl`, `su -c`, `env -S`, `iex`/`eval` payloads. Wrapper commands
    themselves (e.g. `bash -c ...`) are yielded too, before their payload.
    Bounded by the same nesting/size/substitution limits as `parse_installs`;
    anything beyond them is silently skipped (use `too_deeply_nested` /
    `install_mentioned_unparsed` to detect that)."""
    ctx = _Ctx()
    yield from _walk(ctx, command, shell, 0, True)


def iter_simple_commands(command: str, shell: Shell) -> Iterator[list[str]]:
    """Like `iter_command_segments` but yields only the unwrapped argv lists."""
    for seg in iter_command_segments(command, shell):
        if seg.argv:
            yield seg.argv


def _walk(ctx: _Ctx, command: str, shell: Shell, depth: int, scan_subs: bool) -> Iterator[Segment]:
    if depth > MAX_NEST_DEPTH or len(command) > MAX_INPUT_CHARS or ctx.aborted:
        return
    if scan_subs:
        subs = _substitutions(command, shell)
        ctx.nsubs += len(subs)
        if ctx.nsubs > MAX_SUBSTITUTIONS:
            ctx.aborted = True
            return
        for sub in subs:
            yield from _walk(ctx, sub, shell, depth + 1, False)
    for tokens, piped in _split(command, shell):
        if ctx.aborted:
            return
        u = _unwrap(tokens)
        if u.inner is not None:
            yield from _walk(ctx, u.inner[0], u.inner[1], depth + 1, True)
            continue
        yield Segment(u.tokens, piped, shell, tokens, _redirect_targets(tokens))
        if not u.tokens:
            continue  # bare assignment or redirect-only statement: argv is empty
        try:
            inner = _inner_from_wrapper(_exe_name(u.tokens[0]), u.tokens[1:])
        except _Unparseable:
            continue
        if inner is not None:
            yield from _walk(ctx, inner[0], inner[1], depth + 1, True)
