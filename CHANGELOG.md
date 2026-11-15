# Changelog

## Unreleased

- `upgrade` now installs only the packages it was asked to upgrade from a split
  PKGBUILD, instead of every package the build produces. Before, upgrading
  `espanso-x11` also tried to install the conflicting `espanso-wayland` and
  pacman refused the whole transaction; and a plan with several subpackages of
  one PKGBUILD (e.g. `mullvad-vpn-bin` and `mullvad-vpn-daemon-bin`) passed
  each package to `pacman -U` twice and aborted with "duplicate target". A build
  that does not produce the targeted package (e.g. after an upstream rename) is
  now reported as failed instead of installing something else.

## 0.8.0 — 2026-08-01

- The shell reminder now offers to run `observe` for you instead of only naming
  the command to retype. It takes a single keypress, no Enter needed; `y` or
  Enter accepts, and any other key declines, so a stray keystroke cannot set
  work going. It still speaks up at most once a day, and stamps the day *before*
  asking, so a declined or interrupted prompt does not come back in the next
  shell.
- The reminder never prompts when you have already started typing — those
  keystrokes belong to the shell, not to us — and falls back to the plain
  printed reminder instead. Same for a stdin that is not a terminal, an
  `aur-cooldown` that is not on `PATH`, and `AUR_COOLDOWN_NUDGE_ASK=0`.
- It never offers to `upgrade`: that wants root and can build for minutes, which
  is not something to walk into from a shell prompt.
- Added a test suite for the reminder, driven through a real pty under bash and
  (when installed) zsh.

## 0.7.1 — 2026-07-21

- The post-install banner (run `aur-cooldown setup`) no longer reprints on every
  upgrade — it is first-install guidance and `post_upgrade` is now silent.
- `status` warns when the yay hook copied into `~/.config/yay/init.lua` has
  drifted from the packaged one, the one case where an upgrade needs `setup`
  re-run. The shell reminder sources `nudge.sh` by path, so it already refreshes
  on its own.

## 0.7.0 — 2026-07-20

- Reworked the denylist around aur-malware-check's `campaigns.json`. Denial is
  now **version-scoped by date window**: a version is refused only if its AUR
  push timestamp falls inside a campaign's compromise window, so a package that
  has shipped a clean version since is no longer pinned by name forever (the old
  name-level feed froze listed packages indefinitely). On by default; disable
  with `denylist = off` or repoint with `denylist_source`.
- Campaigns with no date window are no longer frozen. Their entries are
  legitimate hijacked-then-cleaned packages; `observe`/`status`/`upgrade` print
  an advisory naming any installed one and suggest an `IgnorePkg` hard-block,
  rather than silently pinning it.
- `refresh` now reports windowed vs advisory package counts. The cache moved to
  `~/.local/share/aur-cooldown/denylist.cache.json`.
- Ctrl-C (SIGINT) and SIGTERM now exit cleanly instead of printing a traceback.
- Added a pytest test suite (`make test`) and a CI workflow; the release
  workflow runs the tests before publishing.

## 0.6.1 — 2026-07-17

First public release. (0.6.0 was tagged but never published; its release
tarball was missing a packaged file.)

- `observe`, `upgrade`, `status`, `refresh` subcommands; single-file Python,
  standard library only.
- Package age is measured with the AUR RPC `LastModified` timestamp, which is
  set server-side at push time. Git commit dates are never trusted: they are
  chosen by the committer and were forged in the June 2026 AUR incident.
- The ledger binds every observed version to its exact git commit, taken
  between two RPC snapshots so a concurrent push cannot associate a different
  commit with an older timestamp.
- Upgrades build the oldest canonical commit carrying the aged version and
  require the recorded commit to still be part of the package's history.
  Versions removed during incident cleanup are skipped; reusing an aged
  version string on a newer commit has no effect.
- Tracks all installed AUR packages by default (`pacman -Qm`, excluding
  `-debug` split companions); an explicit list can be configured instead.
- Local denylist plus optional remote denylist feeds (package-name level,
  off by default). Feeds can only withhold an install, never cause one.
- Ships a yay v13 hook that holds fresh AUR upgrades in `yay -Syu`, and a
  POSIX shell snippet (bash/zsh) that reminds you when the ledger goes stale.
- `aur-cooldown setup` wires the hook and reminder into your own config in
  reversible, marker-delimited blocks (`--print` to preview, `--revert` to
  undo). Package installation never edits user files, per Arch guidelines.
  `setup` skips the yay hook when yay is not on `PATH`.
- Ships zsh and bash completions (subcommands, flags, and installed AUR
  package names), installed into the standard completion directories.
- `upgrade` asks for confirmation before building anything (pacman-style
  `[Y/n]`); `-y`/`--yes` skips the prompt for unattended runs. Without a
  terminal it refuses unless `-y` is given.
- `upgrade` builds the pinned commit by exporting it (`git archive`) to a
  plain tree and running `makepkg`. `yay -B` was unusable: it treats the
  build directory as a git clone to update to the latest commit, which
  errored on the export and would have defeated the point of building an
  older, vetted revision. `makepkg` builds exactly the exported tree and
  cannot drift off the commit aur-cooldown selected.
- `upgrade` now lists held packages instead of only counting them: which
  version is cooling and the day it becomes eligible, and separately which
  installed packages have not been observed yet.
- `upgrade` escalates the install itself instead of relying on `makepkg -si`:
  it builds as the user, then installs the built package as root through a
  configurable command. Defaults to `sudo`, falling back to `su`, and honours
  `--sudo`/`--sudoflags` or a `sudo` line in `~/.config/aur-cooldown/config`
  (mirroring yay). This makes it work for users who escalate with `su` or
  `doas` rather than `sudo`. Repository dependencies are installed the same
  way; AUR dependencies are still not resolved.
- `aur-cooldown setup` detects a `yay --sudo=<bin>` preference in your shell rc
  and writes the matching `config`, so `upgrade` escalates like your yay does.
- Before every privileged step, `upgrade` prints the exact command it is about
  to run as root (e.g. `running as root: su -c 'pacman -U ...'`).
- `upgrade` downloads sources into a persistent cache (`SRCDEST`,
  `~/.cache/aur-cooldown/sources`) instead of the throwaway build tree, so a
  rebuild after a failure reuses the already-fetched, checksummed files rather
  than downloading them again.
