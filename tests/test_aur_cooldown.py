"""Tests for aur-cooldown.

The tool is a single executable script (no .py extension), so it is loaded as a
module here. Network (HTTP/RPC), pacman queries, and AUR clones are stubbed;
git and vercmp are used for real, so these run on an Arch host (or the archlinux
CI container). Run with: make test  (i.e. pytest)
"""
import calendar
import importlib.machinery
import importlib.util
import json
import os
import subprocess
import time
import types
from unittest import mock

import pytest

TOOL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "aur-cooldown")


def load_module():
    loader = importlib.machinery.SourceFileLoader("aur_cooldown", TOOL)
    mod = importlib.util.module_from_spec(importlib.util.spec_from_loader("aur_cooldown", loader))
    loader.exec_module(mod)
    return mod


m = load_module()


# --------------------------------------------------------------------- helpers

def ts(datestr):
    return calendar.timegm(time.strptime(datestr, "%Y-%m-%d"))


def git(repo, *args):
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
    return subprocess.run(["git", "-C", repo, *args], check=True, env=env,
                          stdout=subprocess.PIPE, text=True).stdout.strip()


def write(path, text):
    with open(path, "w") as fh:
        fh.write(text)


def read(path):
    with open(path) as fh:
        return fh.read()


def row(pkg, version, last_modified, commit="c" * 40, base=None):
    return {"pkg": pkg, "base": base or pkg, "version": version,
            "commit": commit, "last_modified": last_modified, "seen_at": last_modified}


@pytest.fixture(autouse=True)
def isolate_paths(tmp_path):
    """Point every file path the tool touches at a fresh temp dir per test."""
    state, cache, conf = tmp_path / "state", tmp_path / "cache", tmp_path / "config"
    for d in (state, cache, conf):
        d.mkdir()
    m.STATE, m.CACHE, m.CONFDIR = str(state), str(cache), str(conf)
    m.LEDGER = str(state / "ledger.jsonl")
    m.LASTOBS = str(state / "last-observe")
    m.DENY_CACHE = str(state / "denylist.cache.json")
    m.SRCDEST = str(cache / "sources")
    m.PKGCONF = str(conf / "packages")
    m.DENY = str(conf / "revoked")
    m.FEEDSCONF = str(conf / "denylist-feeds")
    m.CONFIGFILE = str(conf / "config")


# --------------------------------------------------------------------- ledger

def test_ledger_loads_valid_skips_malformed():
    with open(m.LEDGER, "w") as fh:
        fh.write(json.dumps(row("foo", "1-1", 100)) + "\n")
        fh.write("not json\n\n")
        fh.write(json.dumps({"pkg": "bar"}) + "\n")          # missing keys
    assert [r["pkg"] for r in m.load_ledger()] == ["foo"]


def test_ledger_missing_file_is_empty():
    assert m.load_ledger() == []


def test_aged_versions_filters_and_orders():
    rows = [row("foo", "1-1", 100, "a" * 40), row("foo", "2-1", 200, "b" * 40),
            row("foo", "3-1", 300, "d" * 40), row("foo", "4-1", 400, "")]  # no commit -> ignored
    assert [e["version"] for e in m.aged_versions("foo", 250, rows)] == ["2-1", "1-1"]


def test_base_for():
    rows = [row("foo", "1-1", 100, base="foo-base")]
    assert m.base_for("foo", rows) == "foo-base"
    assert m.base_for("absent", rows) == ""


# ------------------------------------------------------------- local denylist

def test_local_denylist_parse_and_match():
    write(m.DENY, "# comment\nfoo 1.2.3-1\nbar deadbee\n\n")
    deny = m.local_denylist()
    assert set(deny) == {("foo", "1.2.3-1"), ("bar", "deadbee")}
    assert m.denied_version("foo", "1.2.3-1", "x" * 40, deny)        # exact version
    assert m.denied_version("bar", "9-9", "deadbeef1234", deny)      # commit prefix
    assert not m.denied_version("bar", "9-9", "feed0000", deny)
    assert not m.denied_version("other", "1.2.3-1", "x", deny)


# ------------------------------------------------------------ campaign denylist

CAMPAIGNS = json.dumps({"campaigns": [
    {"id": "c1", "type": "aur", "display": "C1 (June)",
     "lists": ["data/campaigns/c1/packages.txt", "data/campaigns/c1/packages-extra.txt"],
     "date_window": {"start": "2026-06-09", "end": "2026-06-14"}},
    {"id": "c2", "type": "aur", "display": "C2 spam",
     "lists": ["data/campaigns/c2/packages.txt"], "date_window": None},
    {"id": "npm", "type": "npm", "lists": ["data/whatever.txt"],
     "date_window": {"start": "2026-06-09", "end": "2026-06-14"}},
]})
ROOT = "https://raw.githubusercontent.com/lenucksi/aur-malware-check/master/"
FILES = {
    m.DENY_SOURCE: CAMPAIGNS,
    ROOT + "data/campaigns/c1/packages.txt": "foo\nbar\n",
    ROOT + "data/campaigns/c1/packages-extra.txt": "# extra\nextra-pkg\n",
    ROOT + "data/campaigns/c2/packages.txt": "spammy\n",
}


def do_refresh(conf=None, files=None):
    with mock.patch.object(m, "_http_get", lambda url: (files or FILES)[url]):
        return m.refresh_denylist(conf or {})


def test_window_bounds_inclusive():
    start, end = m._window_bounds({"start": "2026-06-09", "end": "2026-06-14"})
    assert start == ts("2026-06-09")
    assert end == ts("2026-06-14") + 86400 - 1


def test_names_parsing():
    assert m._names("# c\nfoo\n bar baz \n\n") == ["foo", "bar"]


def test_windows_advisory_and_inheritance():
    dl = do_refresh()
    assert set(dl["windows"]) == {"foo", "bar", "extra-pkg"}     # extra inherits c1 window
    assert dl["advisory"] == {"spammy": ["C2 spam"]}             # npm campaign ignored
    assert dl["windows"]["foo"][0] == [ts("2026-06-09"), ts("2026-06-14") + 86399]


def test_window_denied():
    dl = do_refresh()
    assert m.window_denied("foo", ts("2026-06-10"), dl)
    assert not m.window_denied("foo", ts("2026-06-08"), dl)      # before
    assert not m.window_denied("foo", ts("2026-06-20"), dl)      # after
    assert not m.window_denied("spammy", ts("2026-06-10"), dl)   # advisory has no window


def test_denylist_persisted_and_loaded():
    do_refresh()
    dl = m.load_denylist()
    assert "foo" in dl["windows"] and "spammy" in dl["advisory"]


def test_corrupt_cache_is_empty():
    write(m.DENY_CACHE, "{ not json")
    assert m.load_denylist() == {"windows": {}, "advisory": {}}


def test_extra_feed_is_advisory():
    write(m.FEEDSCONF, "https://example.org/list.txt\n")
    files = dict(FILES, **{"https://example.org/list.txt": "mypkg\n"})
    assert do_refresh(files=files)["advisory"]["mypkg"] == ["https://example.org/list.txt"]


def test_disabled_returns_empty():
    do_refresh()  # populate a cache first
    assert m.refresh_denylist({"denylist": "off"}) == {"windows": {}, "advisory": {}}


def test_fail_closed_keeps_cache():
    good = do_refresh()
    def boom(_url):
        raise OSError("network down")
    with mock.patch.object(m, "_http_get", boom):
        stale = m.refresh_denylist({})
    assert sorted(stale["windows"]) == sorted(good["windows"])


def test_advisory_hits_intersects_installed():
    dl = do_refresh()
    with mock.patch.object(m, "installed_aur", lambda: ["spammy", "unrelated"]):
        assert m.advisory_hits(dl) == [("spammy", ["C2 spam"])]
    with mock.patch.object(m, "installed_aur", lambda: ["unrelated"]):
        assert m.advisory_hits(dl) == []


# ------------------------------------------------------------------- resolve

def make_repo(tmp_path):
    repo = str(tmp_path / "repo")
    os.makedirs(repo)
    subprocess.run(["git", "init", "-q", "-b", "master", repo], check=True)
    git(repo, "config", "user.email", "t@t")
    git(repo, "config", "user.name", "t")
    git(repo, "config", "commit.gpgsign", "false")      # CI/host may enable signing
    return repo


def commit(repo, pkgver, pkgrel="1"):
    write(os.path.join(repo, ".SRCINFO"),
          f"pkgbase = demo\n\tpkgver = {pkgver}\n\tpkgrel = {pkgrel}\n\npkgname = demo\n")
    write(os.path.join(repo, "PKGBUILD"), f"pkgver={pkgver}\npkgrel={pkgrel}\n")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", f"{pkgver}-{pkgrel}")
    return git(repo, "rev-parse", "HEAD")


def do_resolve(pkg, cutoff, rows, deny=None, dl=None, is_auto=True, installed=None):
    with mock.patch.object(m, "installed_version", lambda p: installed):
        return m.resolve(pkg, cutoff, rows, deny or [],
                         dl or {"windows": {}, "advisory": {}}, is_auto)


def test_resolve_not_installed_auto():
    action, _ = do_resolve("foo", m.now(), [], installed=None, is_auto=True)
    assert action == "not-installed"


def test_resolve_unobserved():
    action, detail = do_resolve("foo", m.now(), [], installed="1-1", is_auto=False)
    assert (action, detail["state"]) == ("none", "unobserved")


def test_resolve_cooling():
    rows = [row("foo", "2-1", m.now() - 3600, "a" * 40)]     # fresh, newer than installed
    action, detail = do_resolve("foo", m.now() - m.DAYS * 86400, rows,
                                installed="1-1", is_auto=False)
    assert (action, detail["state"]) == ("none", "cooling")


def test_resolve_up_to_date():
    rows = [row("foo", "1-1", 100, "a" * 40)]
    action, _ = do_resolve("foo", m.now(), rows, installed="1-1", is_auto=False)
    assert action == "up-to-date"


def test_resolve_build_picks_oldest_commit_for_reused_version(tmp_path):
    repo = make_repo(tmp_path)
    sha_old = commit(repo, "1.0")       # version 1.0-1 (original)
    commit(repo, "2.0")                 # 2.0-1
    sha_reuse = commit(repo, "1.0")     # 1.0-1 again (malicious reuse), now HEAD
    # Even with the *reused* commit recorded, the oldest carrier must be built.
    rows = [row("foo", "1.0-1", 100, sha_reuse)]
    with mock.patch.object(m, "sync_repo", lambda base: repo):
        action, d = do_resolve("foo", m.now(), rows, installed=None, is_auto=False)
    assert action == "build"
    assert d["commit"] == sha_old


def test_resolve_yanked_when_recorded_commit_absent(tmp_path):
    repo = make_repo(tmp_path)
    commit(repo, "1.0")                              # history has 1.0-1 on another sha
    rows = [row("foo", "1.0-1", 100, "0" * 40)]      # recorded sha not in history
    with mock.patch.object(m, "sync_repo", lambda base: repo):
        action, _ = do_resolve("foo", m.now(), rows, installed=None, is_auto=False)
    assert action == "yanked"


def test_resolve_window_denied_before_touching_git():
    dl = {"windows": {"foo": [[ts("2026-06-09"), ts("2026-06-14") + 86399]]}, "advisory": {}}
    rows = [row("foo", "1.0-1", ts("2026-06-10"), "a" * 40)]
    def fail(_base):
        raise AssertionError("sync_repo must not be called for a window-denied version")
    with mock.patch.object(m, "sync_repo", fail):
        action, _ = do_resolve("foo", m.now(), rows, dl=dl, installed=None, is_auto=False)
    assert action == "denied"


def test_cooling_info_states():
    rows = [row("foo", "2-1", 500, "a" * 40)]
    assert m.cooling_info("foo", "1-1", rows)["state"] == "cooling"
    assert m.cooling_info("foo", "2-1", rows)["state"] == "current"
    assert m.cooling_info("bar", None, rows)["state"] == "unobserved"


# -------------------------------------------------------------------- config

def test_read_config():
    write(m.CONFIGFILE, "sudo = su   # inline comment\n\n# full\nsudoflags = -l\n")
    assert m.read_config() == {"sudo": "su", "sudoflags": "-l"}


def test_resolve_sudo_precedence():
    args = types.SimpleNamespace(sudo=None, sudoflags=None)
    write(m.CONFIGFILE, "sudo = su\nsudoflags = -l\n")
    assert m.resolve_sudo(args) == ("su", ["-l"])
    cli = types.SimpleNamespace(sudo="doas", sudoflags="-u root")
    assert m.resolve_sudo(cli) == ("doas", ["-u", "root"])
    os.remove(m.CONFIGFILE)
    with mock.patch.object(m.shutil, "which", lambda b: "/usr/bin/sudo"):
        assert m.resolve_sudo(args) == ("sudo", [])
    with mock.patch.object(m.shutil, "which", lambda b: None):
        assert m.resolve_sudo(args) == ("su", [])


def test_as_root_forms():
    assert m.as_root(["pacman", "-U", "a"], "sudo", []) == ["sudo", "pacman", "-U", "a"]
    assert m.as_root(["pacman", "-U", "a b"], "su", []) == ["su", "-c", "pacman -U 'a b'"]
    assert m.as_root(["pacman", "-U", "a"], "doas", ["-u", "root"]) == \
        ["doas", "-u", "root", "pacman", "-U", "a"]


# --------------------------------------------------------------------- setup

def test_write_block_idempotent_and_revert(tmp_path):
    path = str(tmp_path / "rc")
    write(path, "existing line\n")
    start, end = "# >>>", "# <<<"
    m.write_block(path, start, end, "BODY1", "apply")
    assert "BODY1" in read(path)
    m.write_block(path, start, end, "BODY2", "apply")       # replace, not duplicate
    text = read(path)
    assert "BODY1" not in text
    assert text.count(start) == 1
    assert "existing line" in text
    m.write_block(path, start, end, "BODY2", "revert")
    assert start not in read(path)
    assert "existing line" in read(path)


def test_extract_block():
    start, end = "-- >>>", "-- <<<"
    assert m.extract_block("noise\n", start, end) is None       # no markers
    text = f"pre\n{start}\n line one\n line two \n{end}\npost\n"
    assert m.extract_block(text, start, end) == "line one\n line two"
    assert m.extract_block(f"{start}\n{end}\n", start, end) == ""  # empty but present


def test_hook_stale(tmp_path):
    share = tmp_path / "share"
    share.mkdir()
    write(str(share / "yay-init.lua"), "HOOK BODY\n")
    cfg = tmp_path / "config"
    init = cfg / "yay" / "init.lua"
    init.parent.mkdir(parents=True)
    start, end = "-- >>> aur-cooldown >>>", "-- <<< aur-cooldown <<<"

    with mock.patch.object(m, "share_dir", lambda: str(share)), \
         mock.patch.object(m, "XDG_CONFIG", str(cfg)):
        assert m.hook_stale() is False                          # no init.lua yet
        write(str(init), f"{start}\nHOOK BODY\n{end}\n")
        assert m.hook_stale() is False                          # copy matches package
        write(str(init), f"{start}\nOLD BODY\n{end}\n")
        assert m.hook_stale() is True                           # copy drifted -> nag
        write(str(init), "yay.create_autocmd('UpgradeSelect', {})\n")
        assert m.hook_stale() is False                          # merged by hand, no block


def test_detect_yay_escalator(tmp_path):
    rc = str(tmp_path / "zshrc")
    write(rc, "alias ls='ls --color'\nalias yay='yay --sudo=su'\n")
    with mock.patch.object(m, "shell_rc", lambda: (rc, "zsh")):
        assert m.detect_yay_escalator() == ("su", "")
    write(rc, "alias yay='yay'\n")
    with mock.patch.object(m, "shell_rc", lambda: (rc, "zsh")):
        assert m.detect_yay_escalator() is None


# ---------------------------------------------------------------------- deps

def srcinfo_build(tmp_path, srcinfo):
    build = str(tmp_path / "build")
    os.makedirs(build, exist_ok=True)
    write(os.path.join(build, ".SRCINFO"), srcinfo)
    return build


def test_install_deps_no_srcinfo(tmp_path):
    assert m.install_deps(str(tmp_path / "empty"), "sudo", [])


def test_install_deps_all_satisfied(tmp_path):
    build = srcinfo_build(tmp_path, "pkgbase = x\n\tdepends = bash\n")
    with mock.patch.object(m, "run", lambda *a, **k: types.SimpleNamespace(stdout="")):
        assert m.install_deps(build, "sudo", [])


def test_install_deps_installs_missing(tmp_path):
    build = srcinfo_build(tmp_path, "pkgbase = x\n\tdepends = foo>=1\n\tmakedepends = bar\n")
    calls = {}
    def fake_root(cmd, sudo, flags):
        calls["cmd"] = cmd
        return 0
    with mock.patch.object(m, "run", lambda *a, **k: types.SimpleNamespace(stdout="foo>=1\nbar")), \
         mock.patch.object(m, "run_root", fake_root):
        assert m.install_deps(build, "su", [])
    assert "foo" in calls["cmd"] and "bar" in calls["cmd"] and "-S" in calls["cmd"]


# ----------------------------------------------------------- upgrade installs

def test_artifact_pkgname():
    assert m.artifact_pkgname("/b/espanso-x11-2.4.1-2-x86_64.pkg.tar.zst") == "espanso-x11"
    assert m.artifact_pkgname("electron37-37.5.1-1-x86_64.pkg.tar.zst") == "electron37"
    assert m.artifact_pkgname("spotify-1:1.2.96.518-2-x86_64.pkg.tar.zst") == "spotify"
    assert m.artifact_pkgname("foo-debug-1.0-1-any.pkg.tar.xz") == "foo-debug"


def run_upgrade(targets, built):
    """Run cmd_upgrade for `targets` where every makepkg run emits `built`.

    Returns the pacman -U calls, each reduced to the sorted file basenames.
    """
    args = types.SimpleNamespace(dry_run=False, yes=True, pkgs=targets,
                                 sudo=None, sudoflags=None)
    root_calls = []

    def fake_run(cmd, **kwargs):
        if cmd[0] == "makepkg":
            for name in built:
                write(os.path.join(kwargs["cwd"], name), "x")
        return subprocess.CompletedProcess(cmd, 0, stdout=b"", stderr=b"")

    def fake_root(cmd, sudo, flags):
        root_calls.append(cmd)
        return 0

    def fake_resolve(pkg, cutoff, rows, deny, dl, is_auto):
        return ("build", {"version": "1.0-1", "repo": "/dummy", "commit": "a" * 40,
                          "installed": "0.9-1", "last_modified": 0})

    with mock.patch.object(m, "resolve", fake_resolve), \
         mock.patch.object(m, "resolve_sudo", lambda a: ("sudo", [])), \
         mock.patch.object(m, "run_root", fake_root), \
         mock.patch.object(subprocess, "run", fake_run):
        m.cmd_upgrade(args)

    return [sorted(os.path.basename(f) for f in c[3:])
            for c in root_calls if c[:2] == ["pacman", "-U"]]


def test_upgrade_installs_split_artifacts_once():
    """A split PKGBUILD under several plan targets must reach pacman once each."""
    installs = run_upgrade(
        ["mullvad-vpn-bin", "mullvad-vpn-daemon-bin"],
        ["mullvad-vpn-bin-1.0-1-x86_64.pkg.tar.zst",
         "mullvad-vpn-daemon-bin-1.0-1-x86_64.pkg.tar.zst",
         "mullvad-vpn-bin-debug-1.0-1-x86_64.pkg.tar.zst"])
    assert installs == [["mullvad-vpn-bin-1.0-1-x86_64.pkg.tar.zst",
                         "mullvad-vpn-daemon-bin-1.0-1-x86_64.pkg.tar.zst"]]


def test_upgrade_skips_split_siblings_not_targeted():
    """Only the targeted subpackage is installed, not a conflicting sibling."""
    installs = run_upgrade(
        ["espanso-x11"],
        ["espanso-wayland-1.0-1-x86_64.pkg.tar.zst",
         "espanso-x11-1.0-1-x86_64.pkg.tar.zst"])
    assert installs == [["espanso-x11-1.0-1-x86_64.pkg.tar.zst"]]


def test_upgrade_fails_when_target_package_not_built(capsys):
    """A build that emits only other names (e.g. a renamed package) fails loudly."""
    installs = run_upgrade(["oldname"], ["newname-1.0-1-x86_64.pkg.tar.zst"])
    assert installs == []
    out = capsys.readouterr().out
    assert "makepkg produced no oldname package" in out
    assert "failed: oldname" in out
