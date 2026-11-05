"""Always-ask rules (non-package): commands and file writes that a Claude Code
hook must stop for confirmation. Pure apart from reading `.git/config` and
resolving symlinks for path checks; no network.

`command_flags` returns human-readable reasons for a shell command;
`path_flags` returns reasons for a file the agent wants to write.
An empty list means "no opinion".
"""
from __future__ import annotations

import os
import posixpath
import re
import sys
from pathlib import Path

from gatekeeper.commands import Segment, Shell, _exe_name, iter_command_segments

R_DOWNLOADED = "runs a downloaded script"
R_SSH = "runs a command on another machine"
R_INDEX = "custom package index"
R_GIT_CONNECT = "changes how git connects"

# --------------------------------------------------------------------------
# Command rules
# --------------------------------------------------------------------------

_DOWNLOADERS = ("curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod",
                "start-bitstransfer")
_DL_NAME = r"(?:curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|start-bitstransfer)"
# a download used as a value: $(curl ..), `curl ..`, <(curl ..), (iwr ..), .DownloadString(
_DL_SUBST = re.compile(rf"(?:\$\(|`|<\(|\()\s*{_DL_NAME}(?![\w-])|\.download(?:string|file|data)\b",
                       re.IGNORECASE)
_SHELLS = {"bash", "sh", "zsh", "dash", "ash", "ksh", "fish", "csh", "tcsh"}
_PS = {"pwsh", "powershell"}
_EVALS = {"iex", "invoke-expression", "eval"}
_SOURCERS = {"source", "."}
# interpreters that take a script on stdin; a code/module flag means stdin is data
_INTERPRETERS = {"python", "python2", "python3", "py", "node", "nodejs", "perl", "ruby", "php",
                 "deno", "bun", "lua"}
_CODE_FLAGS = {"-c", "-m", "-e", "-E", "-p", "-pe", "-ne", "-pi", "-r", "-i", "--eval", "--print",
               "--command"}
_POSIX_C = re.compile(r"^-[a-zA-Z]*c[a-zA-Z]*$")


def _is_interp(exe: str) -> bool:
    return exe in _INTERPRETERS or re.fullmatch(r"(python|py|node|perl|ruby)[\d.]+", exe) is not None


_DL_START = re.compile(rf"^\(?\s*{_DL_NAME}(?![\w-])", re.IGNORECASE)
_DL_METHOD = re.compile(r"\.download(?:string|file|data)\(", re.IGNORECASE)
_CALL_GLUED = re.compile(r"^(iex|invoke-expression|&)\(", re.IGNORECASE)


def _split_glued_call(argv: list[str]) -> list[str]:
    """`iex(irm x)` / `&(iwr x)` tokenise as one word; separate the call from its argument."""
    m = _CALL_GLUED.match(argv[0])
    if not m:
        return argv
    head = m.group(1)
    rest = "(" + argv[0][m.end():]
    return ([head] if head != "&" else []) + [rest] + argv[1:]


def _is_downloader(argv: list[str]) -> bool:
    text = " ".join(argv)
    return bool(_DL_START.match(text) or _DL_METHOD.search(text))


def _has_code_flag(args: list[str], pattern: "re.Pattern[str] | set[str]") -> bool:
    """Scan only real option words: stop at `--`, `-s`, `-` or the first non-option (a script path)."""
    for a in args:
        if a in ("--", "-s", "-") or not a.startswith("-"):
            return False
        if (pattern.match(a) if isinstance(pattern, re.Pattern) else a in pattern):
            return True
    return False


def _downloaded_script(seg: Segment, exe: str, args: list[str], dl_in_pipeline: bool) -> bool:
    joined = " ".join(args)
    if exe in _SHELLS | _EVALS | _PS | _SOURCERS:
        if _DL_SUBST.search(joined):
            return True
        if any(a.startswith("<(") and re.search(rf"^<\(\s*{_DL_NAME}(?![\w-])", a, re.IGNORECASE)
               for a in args):
            return True
    if seg.piped and dl_in_pipeline:
        if exe in _EVALS:
            return True
        if exe in _SHELLS:
            return not _has_code_flag(args, _POSIX_C)
        if exe in _PS:
            return True
        if _is_interp(exe):
            return not _has_code_flag(args, _CODE_FLAGS)
    return False


_SSH_VALUE = {"-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O",
              "-o", "-p", "-Q", "-R", "-S", "-W", "-w"}


def _ssh_flags(args: list[str]) -> list[str]:
    out: list[str] = []
    pos: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if pos:
            pos.append(a)
        elif a == "--":
            pos.extend(args[i + 1:])
            break
        elif a.startswith("-") and len(a) > 1:
            # a cluster like -NL: the first value-taking letter consumes the rest of the
            # word, or the next argument if nothing follows it
            k = next((n for n, ch in enumerate(a[1:], 1) if "-" + ch in _SSH_VALUE), None)
            if k is not None:
                letter, attached = a[k], a[k + 1:]
                value = attached
                if not attached and i + 1 < len(args):
                    value = args[i + 1]
                    i += 1
                if letter == "o" and re.match(r"(?i)^\s*(proxycommand|localcommand)\b", value):
                    out.append("ssh option runs a local command")
        else:
            pos.append(a)
        i += 1
    if len(pos) > 1:
        out.append(R_SSH)
    return out


# ---- package index -------------------------------------------------------------

_PIPLIKE_FLAGS = ("--index-url", "--extra-index-url", "--find-links", "--trusted-host",
                  "--index", "--default-index")
_PIPLIKE_SHORT = {"-i", "-f"}
_INSTALL_SUBS = {"install", "add", "sync", "lock", "download", "wheel", "compile"}
_INDEX_ENV = re.compile(
    r"^(PIP_(?:EXTRA_)?INDEX_URL|PIP_FIND_LINKS|PIP_TRUSTED_HOST|UV_(?:DEFAULT_|EXTRA_)?INDEX(?:_URL)?|"
    r"UV_FIND_LINKS|npm_config_registry|NPM_CONFIG_REGISTRY|YARN_NPM_REGISTRY_SERVER)=", re.I)
_NODE_PMS = {"npm", "pnpm", "yarn", "bun", "npx", "bunx", "corepack"}


def _flag_matches(a: str, flags: tuple[str, ...]) -> bool:
    return any(a == f or a.startswith(f + "=") for f in flags)


def _index_flags(exe: str, args: list[str], raw: list[str]) -> bool:
    if any(_INDEX_ENV.match(t) for t in raw):
        return True
    low = [a.lower() for a in args]
    if exe in ("pip", "pip3", "uv", "uvx", "pipx", "pdm", "poetry") or re.fullmatch(r"pip[\d.]+", exe):
        pass
    elif re.fullmatch(r"(python|py)[\d.]*", exe) and "-m" in args and "pip" in args:
        pass
    elif exe in _NODE_PMS:
        if "--" in low:
            low = low[:low.index("--")]  # the rest belongs to the script being run
        if any(a.startswith("--registry") or re.match(r"^--?@[^:]+:registry", a) for a in low):
            return True
        pos = [a for a in low if not a.startswith("-")]
        if pos[:1] == ["set"] or pos[:2] == ["config", "set"]:
            return any("registry" in x for x in pos[1:])
        return False
    else:
        return False
    if any(_flag_matches(a, _PIPLIKE_FLAGS) for a in low):
        return True
    before_dd = low[:low.index("--")] if "--" in low else low
    # fail closed: any install-like word before `--` makes it an install (option values are
    # positionals too, so position is unreliable); run-like words never exempt on their own
    install_like = any(a in _INSTALL_SUBS for a in before_dd)
    if any(a in _PIPLIKE_SHORT for a in before_dd) and install_like:
        return True
    if exe == "pipx" and any("--pip-args" in a or "index-url" in a for a in low):
        return True
    for i, a in enumerate(low):  # pip config set global.index-url ...
        if a == "config" and "set" in low[i + 1:i + 2] and \
                any(re.search(r"index-url|find-links|trusted-host", x) for x in low[i + 2:i + 4]):
            return True
    return False


# ---- git -----------------------------------------------------------------------

# Single source of truth: git environment variables that run programs or change connections/config.
_GIT_ENV_VARS = (
    "SSH_COMMAND", "SSH", "PROXY_COMMAND", "ASKPASS", "CONFIG_COUNT", r"CONFIG_KEY_\d+",
    r"CONFIG_VALUE_\d+", "CONFIG_PARAMETERS", "CONFIG_GLOBAL", "CONFIG_SYSTEM", "EXEC_PATH",
    "EXTERNAL_DIFF", "PAGER", "EDITOR", "SEQUENCE_EDITOR", "TEMPLATE_DIR",
)
_GIT_CONN = "GIT_(?:" + "|".join(_GIT_ENV_VARS) + ")"
_GIT_ENV = re.compile(rf"^{_GIT_CONN}=", re.I)
_GIT_CONN_ASSIGN = re.compile(rf"^{_GIT_CONN}=", re.I)
_GIT_CONN_NAME = re.compile(rf"^{_GIT_CONN}$", re.I)
_GIT_CONN_PS = re.compile(rf"^\$\{{?env:{_GIT_CONN}\}}?(=|$)", re.I)
_GIT_CONN_ENVDRIVE = re.compile(rf"^(?:-path:?)?env:{_GIT_CONN}$", re.I)
_GIT_CONN_SETENV = re.compile(rf"setenvironmentvariable\(\s*['\"]?{_GIT_CONN}", re.I)
_ENV_SETTERS = {"export", "declare", "typeset", "readonly", "local", "set", "setx"}
_PS_ITEM_CMDS = {"set-item", "si", "new-item", "ni", "set-content", "add-content"}


def _git_env_statement(seg: Segment, exe: str, args: list[str]) -> bool:
    """An assignment of a git connection variable as its own statement."""
    if not exe:
        return any(_GIT_CONN_ASSIGN.match(t) for t in seg.raw)
    if exe in _ENV_SETTERS:
        return any(_GIT_CONN_ASSIGN.match(a) for a in args) or             (exe == "setx" and bool(args) and bool(_GIT_CONN_NAME.match(args[0])))
    if _GIT_CONN_PS.match(seg.argv[0]):
        return True
    if exe in _PS_ITEM_CMDS and any(_GIT_CONN_ENVDRIVE.match(a) for a in args):
        return True
    return bool(_GIT_CONN_SETENV.search(" ".join(seg.argv)))


_GIT_GLOBAL_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path",
                     "--super-prefix", "--config-env"}
_GIT_RISKY_KEYS = re.compile(
    r"^(core\.(hookspath|sshcommand|fsmonitor|editor|pager|askpass)|sequence\.editor|"
    r"filter\..+\.(clean|smudge|process)|diff\..+\.(textconv|command)|"
    r"url\..+\.(insteadof|pushinsteadof)|credential(\..+)?\.helper|gpg\.program|"
    r"core\.gitproxy)$")


def _git_cfg_risky(key: str, value: str | None) -> str | None:
    k = key.lower()
    if k.startswith("alias.") and value is not None and value.lstrip().startswith("!"):
        return "git alias runs a shell command"
    if k == "core.hookspath":
        return "changes git hooks location"
    if re.match(r"^remote\..+\.(url|pushurl|receivepack|uploadpack|proxy)$", k) and value is not None:
        return "adds or changes a git remote"
    if k.startswith("url.") and ("insteadof" in k):
        return "rewrites git remote URLs"
    if _GIT_RISKY_KEYS.match(k):
        return f"git config {k} can run commands"
    if value is not None and value.lstrip().startswith("!") and k.startswith(("credential", "core", "diff")):
        return f"git config {k} can run commands"
    return None


def _git_dir(cwd: Path) -> Path | None:
    for d in [cwd, *cwd.parents]:
        g = d / ".git"
        try:
            if g.is_dir():
                return g
            if g.is_file():
                m = re.match(r"gitdir:\s*(.+)", g.read_text(errors="replace").strip())
                if m:
                    p = Path(m.group(1).strip())
                    return p if p.is_absolute() else (d / p)
        except OSError:
            return None
    return None


def _git_remotes(cwd: Path) -> set[str]:
    gd = _git_dir(cwd)
    if gd is None:
        return set()
    try:
        common = gd
        cd = gd / "commondir"
        if cd.is_file():
            common = (gd / cd.read_text().strip()).resolve()
        text = (common / "config").read_text(errors="replace")
    except OSError:
        return set()
    return {m.group(1) for m in re.finditer(r'^\s*\[remote\s+"([^"]+)"\]', text, re.M | re.I)}


def _git_flags(args: list[str], cwd: Path) -> list[str]:
    out: list[str] = []
    i = 0
    sub = None
    while i < len(args):
        a = args[i]
        if a == "-C" and i + 1 < len(args):
            cwd = Path(os.path.join(str(cwd), args[i + 1]))
            i += 2
            continue
        if a == "-c" and i + 1 < len(args):
            k, _, v = args[i + 1].partition("=")
            r = _git_cfg_risky(k, v if "=" in args[i + 1] else None)
            if r:
                out.append(r)
            i += 2
            continue
        if a.startswith("-c") and len(a) > 2 and "=" in a and not a.startswith("--"):
            k, _, v = a[2:].partition("=")  # -ckey=value
            r = _git_cfg_risky(k, v)
            if r:
                out.append(r)
            i += 1
            continue
        if a == "--config-env" or a.startswith("--config-env="):
            spec = args[i + 1] if a == "--config-env" and i + 1 < len(args) else a.partition("=")[2]
            r = _git_cfg_risky(spec.partition("=")[0], "$env")
            if r:
                out.append(r)
            i += 2 if a == "--config-env" else 1
            continue
        if a in _GIT_GLOBAL_VALUE:
            i += 2
            continue
        if a.startswith("-"):
            i += 1
            continue
        sub = a
        i += 1
        break
    if sub is None:
        return out
    rest = args[i:]
    pos = [a for a in rest if not a.startswith("-")]

    if sub == "config":
        read_flags = {"--get", "--get-all", "--get-regexp", "--get-urlmatch", "-l", "--list",
                      "--unset", "--unset-all", "--remove-section", "--rename-section", "--edit-for-read"}
        if any(a in read_flags for a in rest):
            return out
        value_flags = {"-f", "--file", "--blob", "--type", "--default", "--comment"}
        p, j = [], 0
        while j < len(rest):
            if rest[j] in value_flags:
                j += 2
                continue
            if not rest[j].startswith("-"):
                p.append(rest[j])
            j += 1
        if p:
            r = _git_cfg_risky(p[0], p[1] if len(p) > 1 else None)
            if r:
                out.append(r)
    elif sub == "remote":
        if pos and pos[0] in ("add", "set-url"):
            out.append("adds or changes a git remote")
    elif sub == "push":
        remotes = _git_remotes(cwd)
        value_flags = {"--repo", "-o", "--push-option", "--receive-pack", "--exec", "--signed"}
        target: str | None = None
        p, j = [], 0
        while j < len(rest):
            a = rest[j]
            if a == "--repo" and j + 1 < len(rest):
                target = rest[j + 1]
                j += 2
                continue
            if a.startswith("--repo="):
                target = a.split("=", 1)[1]
            elif a in value_flags:
                j += 2
                continue
            elif not a.startswith("-"):
                p.append(a)
            j += 1
        if target is None and p:
            target = p[0]
        if target is None:
            target = "origin"
        if target not in remotes:
            out.append("pushes to a remote that is not configured")
    return out


# ---- the rest --------------------------------------------------------------------

_RUN_KEY = re.compile(r"\\(run|runonce|runservices|runonceex)(\\|$)|\\winlogon(\\|$)|"
                      r"image file execution options|\\windows defender|\\policies\\microsoft\\windows defender",
                      re.I)
_RUN_PROP = re.compile(r"currentversion\\(run|runonce)(\\|$)|\\winlogon(\\|$)|image file execution options", re.I)
_DEFENDER_SVCS = re.compile(r"^(windefend|sense|wdnissvc|mpssvc|wdfilter|securityhealthservice)$", re.I)
_WRITERS = {"tee", "cp", "mv", "ln", "install", "touch", "rm", "dd",
            "set-content", "add-content", "out-file", "new-item", "copy-item", "move-item",
            "remove-item", "rename-item", "ac", "ni", "cpi", "mi", "ri", "del", "copy", "move",
            "ren", "xcopy", "robocopy", "mklink", "export-clixml", "tee-object"}


def _persistence_flags(exe: str, args: list[str]) -> list[str]:
    out: list[str] = []
    low = [a.lower() for a in args]
    if exe == "schtasks" and any(a.split(":")[0] in ("/create", "/change") for a in low):
        out.append("creates a scheduled task")
    elif exe in ("register-scheduledtask", "register-scheduledjob", "set-scheduledtask",
                 "register-wmievent"):
        out.append("creates a scheduled task")
    elif exe == "reg" and low[:1] == ["add"]:
        key = args[1] if len(args) > 1 else ""
        if _RUN_KEY.search(key):
            out.append("adds a startup/registry persistence entry")
    elif exe == "reg" and low[:1] == ["import"]:
        out.append("imports a registry file")
    elif exe in ("new-itemproperty", "set-itemproperty", "sp", "new-item") and \
            any(_RUN_PROP.search(a) for a in args):
        out.append("adds a startup/registry persistence entry")
    elif exe == "systemctl" and any(a in ("enable", "link", "edit") for a in low if not a.startswith("-")):
        out.append("enables a systemd unit")
    elif exe == "crontab" and "-l" not in low and "-r" not in low:
        out.append("edits the crontab")
    elif exe in ("sc", "new-service") and (exe == "new-service" or low[:1] in (["create"], ["config"])):
        out.append("creates a service")
    return out


def _security_flags(exe: str, args: list[str]) -> list[str]:
    low = [a.lower() for a in args]
    if exe in ("set-mppreference", "add-mppreference"):
        for i, a in enumerate(low):
            if a.startswith("-exclusion"):
                return ["adds a Defender exclusion"]
            if a.startswith("-disable"):
                val = a.partition(":")[2] or (low[i + 1] if i + 1 < len(low) and not low[i + 1].startswith("-")
                                              else "$true")
                if val not in ("$false", "0", "false"):
                    return ["disables Defender protection"]
    elif exe == "netsh":
        j = " ".join(low)
        if re.search(r"advfirewall\s+set\s+\S+\s+state\s+off", j) or re.search(r"firewall\s+set\s+opmode\s+(mode=)?disable", j):
            return ["turns the firewall off"]
    elif exe == "set-netfirewallprofile":
        for i, a in enumerate(low):
            if a.startswith("-enabled") and (a.partition(":")[2] or (low[i + 1:i + 2] or [""])[0]) in ("false", "$false", "0"):
                return ["turns the firewall off"]
    elif exe in ("stop-service", "set-service") and any(_DEFENDER_SVCS.match(a) for a in low):
        return ["stops a Windows security service"]
    elif exe == "sc" and low[:1] in (["stop"], ["config"]) and len(low) > 1 and _DEFENDER_SVCS.match(low[1]):
        return ["stops a Windows security service"]
    elif exe == "ufw" and low[:1] == ["disable"]:
        return ["turns the firewall off"]
    elif exe == "setenforce" and low[:1] in (["0"], ["permissive"]):
        return ["disables SELinux enforcement"]
    return []


def _writer_targets(exe: str, args: list[str]) -> list[str]:
    if exe == "sed" or exe == "perl":
        if any(re.match(r"^-[a-zA-Z]*i", a) or a.startswith("--in-place") for a in args):
            return [a for a in args if not a.startswith("-")]
        return []
    if exe in _WRITERS:
        return [a for a in args if not a.startswith("-")]
    return []


# ---- Claude's own CLI -------------------------------------------------------------

R_CLAUDE_CLI = "changes Claude MCP/plugin config"
_CLAUDE_MCP_WRITES = {"add", "add-json", "add-from-claude-desktop", "remove", "reset-project-choices"}
_CLAUDE_PLUGIN_READS = {"list", "validate", "help"}


def _claude_cli_flags(args: list[str]) -> list[str]:
    pos = [a.lower() for a in args if not a.startswith("-")]
    if pos[:1] == ["mcp"] and len(pos) > 1 and pos[1] in _CLAUDE_MCP_WRITES:
        return [R_CLAUDE_CLI]
    if pos[:1] in (["plugin"], ["plugins"]) and len(pos) > 1:
        sub = pos[2] if pos[1] == "marketplace" and len(pos) > 2 else pos[1]
        if sub not in _CLAUDE_PLUGIN_READS:
            return [R_CLAUDE_CLI]
    return []


# ---- token backstop: any argument that resolves into protected config ------------

# Commands that only read or navigate: their arguments are never treated as write targets.
_READERS = {"ls", "dir", "cat", "type", "head", "tail", "grep", "egrep", "fgrep", "rg", "less", "more",
            "jq", "diff", "stat", "file", "wc", "test", "[", "realpath", "readlink", "sha256sum",
            "md5sum", "du", "tree", "get-content", "gc", "get-childitem", "gci", "select-string", "sls",
            "get-item", "gi", "test-path", "resolve-path", "get-filehash", "get-acl", "source", "."}
_FIND_ACTIONS = {"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprintf", "-fls"}
_CD = {"cd", "pushd", "set-location", "sl", "chdir"}
_PATH_START = re.compile(r"[~$%/\\.]|[A-Za-z]:")
_EMBEDDED = re.compile(r"""[^\s'"(),;=]*\.claude(?:\.json)?(?![\w-])[^\s'"(),;]*""", re.IGNORECASE)


_GIT_READS = {"status", "diff", "log", "show", "blame", "grep", "ls-files", "ls-tree", "rev-parse"}
_GIT_GLOBAL_VALUE = {"-C", "-c", "--git-dir", "--work-tree", "--namespace"}


def _is_reader(exe: str, args: list[str]) -> bool:
    if exe == "find":
        return not any(a.lower() in _FIND_ACTIONS for a in args)
    if exe == "sed":
        return not any(re.match(r"^-[a-zA-Z]*i", a) or a.startswith("--in-place") for a in args)
    if exe == "git":
        k = 0
        while k < len(args) and args[k].startswith("-"):
            k += 2 if args[k] in _GIT_GLOBAL_VALUE else 1
        return k < len(args) and args[k] in _GIT_READS
    return exe in _READERS


def _token_paths(tok: str) -> list[str]:
    """Path candidates inside one argument: the word itself, a flag's attached value
    (`--output=P`, `-OutFile:P`, `-oP`) and `.claude` paths embedded in inline code."""
    if not tok or "://" in tok:
        return []
    out: list[str] = []
    if not re.search(r"\s", tok) or _PATH_START.match(tok):
        out.append(tok)
    if tok.startswith("-") and len(tok) > 2:
        for sep in ("=", ":"):
            if sep in tok:
                out.append(tok.split(sep, 1)[1])
        if _PATH_START.match(tok[2:]):
            out.append(tok[2:])
    if "(" in tok:  # inline code: [IO.File]::WriteAllText("$HOME\.claude\x", ..), open('~/.claude/x')
        for m in _EMBEDDED.findall(tok):
            k = _PATH_START.search(m)
            out.append(m[k.start():] if m.startswith("-") and k else m)
    return [c for c in dict.fromkeys(out) if c]


def _looks_path(c: str) -> bool:
    return bool(_PATH_START.match(c)) or "/" in c or "\\" in c


def _backstop_reasons(args: list[str], cwd: Path, home: Path) -> list[str]:
    out: list[str] = []
    for tok in args:
        for c in _token_paths(tok):
            full = _absolutize(c, cwd)
            rs = path_flags(full, home)
            if not rs and _looks_path(c) and in_claude_tree(full, home):
                rs = [R_CLAUDE_TREE]
            out += [r for r in rs if r not in out]
    return out


def _cd_target(args: list[str], cwd: Path, home: Path) -> Path | None:
    """Directory a cd/pushd/Set-Location moves to (None = unknown, keep the old cwd)."""
    pos = [a for a in args if not a.startswith("-")]
    for k, a in enumerate(args):  # Set-Location -Path P / -LiteralPath P
        if a.lower() in ("-path", "-literalpath", "-lp") and k + 1 < len(args):
            pos = [args[k + 1]]
            break
    if not args:
        return home
    if not pos:
        return None
    return Path(os.path.normpath(_expand(_absolutize(pos[0], cwd), str(home))))


def command_flags(command: str, shell: Shell, cwd: Path, home: Path | None = None) -> list[str]:
    """Reasons this command must be confirmed ([] = no opinion)."""
    home = home if home is not None else Path.home()
    cwd = Path(cwd)
    flags: list[str] = []

    def add(r: str) -> None:
        if r not in flags:
            flags.append(r)

    dl_in_pipeline = False
    piped_from_config: list[str] = []  # protected paths a reader fed into this pipeline
    for seg in iter_command_segments(command, shell):
        if not seg.piped:
            dl_in_pipeline = False
            piped_from_config = []
        argv = seg.argv
        if not argv:  # bare `VAR=x` or redirect-only statement
            if _git_env_statement(seg, "", []):
                add(R_GIT_CONNECT)
            _check_targets(seg.redirects, cwd, home, add)
            continue

        argv = _split_glued_call(argv)
        exe, args = _exe_name(argv[0]), argv[1:]
        if _downloaded_script(seg, exe, args, dl_in_pipeline):
            add(R_DOWNLOADED)
        if exe in _DOWNLOADERS or _is_downloader(argv):
            dl_in_pipeline = True

        if _git_env_statement(seg, exe, args):
            add(R_GIT_CONNECT)
        if exe == "claude":
            for r in _claude_cli_flags(args):
                add(r)
        if exe in _CD:
            cwd = _cd_target(args, cwd, home) or cwd
        elif _is_reader(exe, args):
            piped_from_config = _backstop_reasons(args, cwd, home) or piped_from_config
        else:
            # argv[0] counts only as inline code: [IO.File]::WriteAllText($HOME\.claude\x, ...)
            code = [argv[0]] if "(" in argv[0] else []
            for r in _backstop_reasons(code + args, cwd, home) + (piped_from_config if seg.piped else []):
                add(r)
        if exe == "ssh":
            for r in _ssh_flags(args):
                add(r)
        elif exe == "git":
            for r in _git_flags(args, cwd):
                add(r)
            if any(_GIT_ENV.match(t) for t in seg.raw):
                add("git environment can run commands or rewrite remotes")
        if _index_flags(exe, args, seg.raw):
            add(R_INDEX)
        for r in _persistence_flags(exe, args):
            add(r)
        for r in _security_flags(exe, args):
            add(r)

        _check_targets(list(seg.redirects) + _writer_targets(exe, args), cwd, home, add)
    return flags


def _check_targets(targets: list[str], cwd: Path, home: Path, add) -> None:
    for t in targets:
        if t.lower() in ("/dev/null", "$null", "nul", "") or t.startswith("&"):
            continue
        for r in path_flags(_absolutize(t, cwd), home):
            add(r)


def _absolutize(target: str, cwd: Path) -> str:
    """Join a relative redirect/writer target onto cwd (leave ~, $VAR, %VAR% and absolute alone)."""
    t = target.strip()
    if t.startswith(("~", "$", "%", "/", "\\")) or re.match(r"^[A-Za-z]:", t):
        return t
    return os.path.join(str(cwd), t)


# --------------------------------------------------------------------------
# Path rules
# --------------------------------------------------------------------------

_FOLD = sys.platform in ("win32", "darwin")

_CLAUDE_DIRS = {"hooks", "skills", "plugins", "agents", "commands"}
_PROJECT_CLAUDE_DIRS = {"hooks", "agents", "commands", "skills"}
_SHELL_RC = {".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc",
             ".zprofile", ".zshenv", ".zlogin", ".zlogout", ".kshrc", ".cshrc", ".tcshrc"}
_PS_PROFILE_NAME = "microsoft.powershell_profile.ps1"


def _norm(s: str) -> str:
    s = s.replace("\\", "/")
    if s.startswith("//?/"):
        s = s[4:]
    s = s.replace("::$data", "") if _FOLD else s
    anchor = ""
    m = re.match(r"^([A-Za-z]:)(/|$)", s)
    if m:
        anchor, s = m.group(1), s[2:] or "/"
    elif s.startswith("//"):
        anchor, s = "//", s[2:]
    s = posixpath.normpath(s) if s else ""
    if _FOLD:
        s = "/".join(part.rstrip(". ") if part not in (".", "..") else part for part in s.split("/"))
        s = s.rstrip("/") if len(s) > 1 else s
        return (anchor + s).lower()
    return anchor + s


def _expand(raw: str, home: str) -> str:
    h = home.replace("\\", "/")
    appdata = h + "/AppData/Roaming"
    local = h + "/AppData/Local"
    profile = h + "/Documents/PowerShell/Microsoft.PowerShell_profile.ps1"
    s = raw
    subs = [
        (r"(?i)\$env:(userprofile|home)\b|\$\{env:(userprofile|home)\}|%(userprofile|home)%|\$\{HOME\}|\$HOME\b", h),
        (r"(?i)\$env:appdata\b|%appdata%", appdata),
        (r"(?i)\$env:localappdata\b|%localappdata%", local),
        (r"(?i)\$profile(\.\w+)?\b", profile),
    ]
    for pat, rep in subs:
        s = re.sub(pat, lambda m, r=rep: r, s)
    if s == "~" or s.startswith(("~/", "~\\")):
        s = h + s[1:]
    return s


def _relative_to_home(p: str, home: str) -> str | None:
    if p == home:
        return ""
    if p.startswith(home.rstrip("/") + "/"):
        return p[len(home.rstrip("/")) + 1:]
    return None


def _check_norm(p: str, home: str) -> list[str]:
    out: list[str] = []
    p, home = p.lower(), home.lower()  # Claude-config names match case-insensitively on every platform
    parts = p.split("/")
    base = parts[-1] if parts else ""

    def hit(r: str) -> None:
        if r not in out:
            out.append(r)

    if base == ".mcp.json":
        hit("writes an MCP server config (.mcp.json)")
    if "/start menu/programs/startup/" in p + "/" or p.endswith("/start menu/programs/startup"):
        hit("writes to a Windows Startup folder")
    if ".ssh" in parts[:-1] or base == ".ssh":
        hit("writes under .ssh")
    if "/systemd/user/" in "/" + p + "/" or "/systemd/system/" in "/" + p + "/":
        hit("writes a systemd unit")
    if "/.config/autostart/" in p:
        hit("writes a desktop autostart entry")
    if base == _PS_PROFILE_NAME or base in ("profile.ps1", "microsoft.vscode_profile.ps1") or \
            base.endswith("_profile.ps1"):
        hit("writes a PowerShell profile")

    for i, seg in enumerate(parts[:-1]):  # project-level .claude config, any directory
        sub = parts[i + 1:]
        if seg == ".claude" and ((len(sub) == 1 and re.fullmatch(r"settings[^/]*\.json", sub[0]))
                                 or sub[0] in _PROJECT_CLAUDE_DIRS):  # the dir itself or below it
            hit(f"writes Claude config (.claude/{sub[0]})")
    if base == ".claude":  # a .claude directory itself (copy/extract *into* it)
        hit("writes Claude config (.claude/)")

    rel = _relative_to_home(p, home)
    if rel is None:
        return out
    if rel == ".claude.json":
        hit("writes Claude config (~/.claude.json)")
    elif rel.startswith(".claude/"):
        sub = rel[len(".claude/"):]
        first = sub.split("/")[0]
        if "/" not in sub and (re.fullmatch(r"settings[^/]*\.json", sub) or sub == "claude.md"):
            hit("writes Claude config (~/.claude/" + sub + ")")
        elif first in _CLAUDE_DIRS:  # the directory itself or anything below it
            hit(f"writes Claude config (~/.claude/{first}/)")
    if rel in _SHELL_RC:
        hit("writes a shell startup file")
    if rel == ".gitconfig" or rel.startswith(".config/git/") or rel == ".config/git":
        hit("writes global git config or hooks")
    if rel.startswith(".config/fish/"):
        hit("writes a shell startup file")
    return out


def _normalized(raw: str, home_s: str) -> tuple[str, str, str]:
    """(expanded raw path, normalised path, normalised home) as compared by the path rules."""
    expanded = _expand(raw.strip(), home_s)
    h = _norm(home_s)
    p = _norm(expanded)
    if re.match(r"^[a-z]:", h):
        m = re.match(r"^/(?:mnt/)?([A-Za-z])(/.*|)$", p, re.I)
        if m and len(p) > 2:
            p = _norm(f"{m.group(1)}:{m.group(2) or '/'}")
    return expanded, p, h


R_CLAUDE_TREE = "touches a Claude config directory (.claude/)"


def in_claude_tree(path: "Path | str", home: Path) -> bool:
    """True for ~/.claude.json and anything at or below any `.claude` directory (~/.claude/** or a
    project's .claude/), the scope of the shell backstop."""
    raw = str(path)
    if not raw.strip():
        return False
    _, p, h = _normalized(raw, str(home))
    p = p.lower()
    return ".claude" in p.split("/") or _relative_to_home(p, h.lower()) == ".claude.json"


def path_flags(path: "Path | str", home: Path) -> list[str]:
    """Reasons writing to `path` must be confirmed ([] = no opinion).

    `path` may use `~`, `$HOME`, `%USERPROFILE%`, `$env:USERPROFILE`, `%APPDATA%`,
    `$PROFILE`, Windows or POSIX separators, `..` segments, git-bash (`/c/...`)
    or WSL (`/mnt/c/...`) drive forms; case is ignored on Windows/macOS.
    Existing paths are also checked after resolving symlinks.
    """
    raw = str(path)
    if not raw.strip():
        return []
    home_s = str(home)
    expanded, p, h = _normalized(raw, home_s)
    out = _check_norm(p, h)
    try:
        if os.path.isabs(expanded):
            real = os.path.realpath(expanded)
            if real != expanded:
                for r in _check_norm(_norm(real), _norm(os.path.realpath(home_s))):
                    if r not in out:
                        out.append(r)
    except (OSError, ValueError):
        pass
    return out
