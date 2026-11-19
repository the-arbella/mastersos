# User layer (settings format 3): VM verification checklist

Branch `feat/user-layer-b`. Spec: `docs/specs/2026-11-19-user-layer-design.md`. Plan: `docs/plans/2026-11-19-user-layer-b-agent.md`.
Run on the test VM from an image built from this branch, with the settings bundles named per item. Everything below was
written from the code on the branch; a command or path that does not match the image is a finding, not a typo to fix silently.

Rules for the run:

- Screenshots are kept. Name them `NN-short-name.png`, numbered from 01 in the order of this document. A retake gets the next
  free number; never overwrite or delete one. List the paths in the report.
- Record the image version, the bundle (format and a hash), and the result of every item as PASS / FAIL / BLOCKED with the
  evidence (command output or screenshot name).
- IT shell: once a person is signed in, no new root shell can be opened (pam-check refuses `login`, `su` and `sshd` while a session
  marker exists; only `cron`, `systemd-user`, `sudo`, `sudo-i`, `polkit-1` and `gdm-launch-environment` pass). PREREQUISITE: before the
  first person signs in after each boot, sign in on tty3 (Ctrl+Alt+F3) as `itadmin`, run `sudo -i`, and keep that root shell open for
  the whole run (use `tmux`/`screen` if you need several windows). Every "as root" step below uses it; reach other uids with
  `sudo -u <name>` from it. A reboot loses it: reopen it before the next sign-in. "Greeter" is the GDM login screen. `<d>` is the config directory name
  `u-<16 hex>` (first 16 hex digits of the SHA-256 of the user config id), or `neutral`.
- No private host names, accounts or school data go into results. Say "the test VM" and "the remote build runner".

Paths used throughout (all verified in the code):

| What | Path |
|---|---|
| Session marker (root 0600, lock `active.lock` next to it) | `/run/mastersos/user-layer/active.json` |
| Facts hand-over (root 0700 dir) | `/run/mastersos/facts/<login name>.json` |
| Pre-rendered public state, per config | `/var/lib/mastersos-public/user-layer/<d>/` (`xdg/`, `login-scripts/`, `session-mode`, `uid`) |
| Current session (symlink to one `<d>`) | `/var/lib/mastersos-public/session` |
| Pre-rendered root-only state and rules | `/var/lib/mastersos-system/user-layer/index.json`, `.../<d>/{chrome.json,dconf.d/,dconf.db}` |
| Active session dconf DB and profile | `/etc/dconf/db/mastersos-session` (no `.d`), `/etc/dconf/profile/user` (written only under format 3) |
| Device dconf DB (format 1/2 and device level) | `/etc/dconf/db/mastersos.d/50-mastersos`, `locks/50-mastersos` |
| Chrome policy | `/etc/opt/chrome/policies/managed/mastersos.json`; staging `/etc/opt/chrome/policies/.mastersos-staging/<d>.json` |
| exec-block mode word (`browser` or `desktop`) | `/var/lib/mastersos-system/exec-block-mode` |
| exec-block lifted caps (`lifted:<cap>,...`) | `/run/mastersos/exec-block-lifted` |
| Exec stub | `/usr/lib/mastersos/interface-denied` |

Useful probes (root):

```bash
# which exec targets are stubbed (a bind mount of the stub over the binary)
findmnt -rno TARGET | grep -E '/usr/bin/(nautilus|gnome-control-center|gnome-terminal|ptyxis|kgx|xterm)$'
cat /var/lib/mastersos-system/exec-block-mode /run/mastersos/exec-block-lifted 2>&1
readlink /var/lib/mastersos-public/session; cat /var/lib/mastersos-public/session/{uid,session-mode}
cat /run/mastersos/user-layer/active.json
journalctl -t mastersos-agent -b --no-pager | tail -50   # the agent
journalctl -b --no-pager | grep pam-session               # pam-session lines (they carry the PAM service's tag)
```

Fixtures needed (bundle side; Plan A `spec_example_v3` shape): a format 2 bundle with one `learning` and one `full` Group; the
format 3 spec example (`teacher`, `primary`, fallback `primary`, guest rule); a variant with `allow = ["file_manager"]`; a
variant with a user config removed; a variant with no `kind = "guest"` rule resolving (for item 9).

Facts caveat: the facts file is read only for an SSO login on a Device with `[school.oidc] mastersos_claims = true`. The authd
patch `0007` broker deletes `/run/mastersos/facts/<login name>.json` (lower-case login name, `[a-z0-9._-]+@[a-z0-9.-]+`) at the start
of every authentication and writes it on a granted card login, so a hand-placed file never survives to `pam-session`. Checks that
depend on `class_role`, `org_node` and the like therefore need a real card login against an issuer that serves the mastersos
profile (scope `org:<[school] id>`, `login_name`, userinfo facts). The format 3 fixtures must set `school.oidc.mastersos_claims = true`
and `[school] id` (`spec_example_v3` lacks them). Without such an issuer mark the fact-dependent parts BLOCKED and run only the rules
that need no facts (`admin`, `kind`, `user`, `device_group`, then the fallback), which still apply in order when facts are missing.

---

## 1. Format 2 bundle on a fresh image: behaviour unchanged

Preconditions: fresh image, format 2 bundle, Group A `learning`, Group B `full` (switch the Device's Group between runs).

Steps:
1. Boot, apply, sign in with a local or SSO account in Group A. Screenshot the Dash and Chrome `chrome://policy`.
2. In the session: try to start a terminal (Ctrl+Alt+T, Dash search) and Files; run `gsettings get org.gnome.desktop.lockdown disable-command-line`.
3. As root: run the probes above; list `/var/lib/mastersos-public/` and `ls -la /etc/opt/chrome/policies/`.
4. Sign out, switch the Device to Group B, apply, repeat steps 1-3.

Expected:
- Group A: terminal and Files blocked (stub message), Dash locked, `disable-command-line` is `true`; Group B: all open, nothing locked. Same as the previous release.
- No user-layer state (`/run/mastersos/user-layer` and `/run/mastersos/facts` exist on every boot from tmpfiles; expect both empty, no `active.json`, no `active.lock`): no `/var/lib/mastersos-public/session`, no `/var/lib/mastersos-public/user-layer`, no `/etc/dconf/profile/user`, no `/etc/dconf/db/mastersos-session`, no `.mastersos-staging`, no `/var/lib/mastersos-system/user-layer`.
- `exec-block-mode` is `browser` (A) or `desktop` (B); no `exec-block-lifted`.
- Home tidy as before (learning: tidied at login; full: kept).
- No dconf "unable to open database" warning in the journal.

Screenshots: `01-fmt2-learning-dash.png`, `02-fmt2-learning-chrome-policy.png`, `03-fmt2-learning-terminal-blocked.png`, `04-fmt2-full-dash.png`.

## 2. Format 3 spec example: each kind of person gets its own config

Preconditions: item 1 done; publish the spec example (format 3), reapply, confirm the item `user-layer` is ok in the report.

Steps, per person (teacher via `class_role` facts, primary via `org_node` facts, admin via `admin_users` or `itadmin`, guest from the greeter):
1. Sign in. As root run the probes; note `active.json` (`user_config`, `dir`, `caps`, `state`) and where `session` points.
2. In the session: screenshot Dash and `chrome://policy`; run `dconf read /org/gnome/desktop/lockdown/disable-command-line` and `gsettings get org.gnome.desktop.lockdown disable-command-line`.
3. Try terminal, Files, Settings.
4. Sign out, wait for neutral (item 4), next person.

Expected, per person:
- The user config the rules name (first match wins; `mastersos explain user --dir <settings dir> --kind ...` offline agrees; note the spec example has no guest rule, so a guest resolves to the fallback `primary`): teacher/admin config preset `full` (terminal open), primary `learning` (all blocked, `disable-command-line` true).
- Chrome policy in `chrome://policy` equals that config's (defaults + config; `drop` applied); web apps only that config's.
- `session` symlink points to that config's `<d>`; `session/uid` equals the person's uid; `session/session-mode` is `full` only if the config lifts `user_apps`, else `learning`.
- The dconf value of `disable-command-line` follows the config (`dconf read` shows the session DB value).
- No facts (BLOCKED case): the SSO admin still gets the admin rule's config, with no reason logged or stored (`reason` null). A non-admin SSO gets the fallback, and only then are the reasons recorded: the journal (`pam-session: ... the issuer handed over no facts`), `active.json` `reason`, and the report item `user-layer:session` ("got the fallback: ...").

Screenshots: `05-teacher-dash.png`, `06-teacher-chrome-policy.png`, `07-primary-dash.png`, `08-primary-chrome-policy.png`, `09-admin-dash.png`, `10-admin-chrome-policy.png`, `11-guest-dash.png`, `12-guest-chrome-policy.png`.

## 3. `allow = ["file_manager"]`: Files only

Preconditions: format 3 bundle where one learning user config has `allow = ["file_manager"]`; sign in as a person it names.

Steps:
1. After sign-in (allow up to ~10 s for the agent to lift): open Files from the Dash; open a terminal.
2. As root: `cat /var/lib/mastersos-system/exec-block-mode /run/mastersos/exec-block-lifted`; `findmnt` probe.
3. Force a Chrome sysext refresh during the session (`systemctl reload systemd-sysext.service` as the root shell, or `mastersos-agent exec-block`, the hook the sysext merge runs); repeat 1-2.
4. Refresh concurrent with a login (final review FR-M3): sign A out and wait for neutral. From the root shell start `time systemctl reload systemd-sysext.service` and, while it runs (immediately after starting it), sign A in at the greeter; repeat with a reapply (`mastersos-agent once`) started just before the reload. Record the reload's duration, whether the login is accepted or refused (a busy lock gives the unavailable message, "This device could not get your session ready. ..."), and the journal lines of `pam-session` and the agent (`journalctl -b -o short-precise | grep -E 'pam-session|user layer|exec-block'`).

Expected:
- Files opens (`/usr/bin/nautilus` not stubbed), terminal and Settings still the stub. `exec-block-lifted` is `lifted:file_manager`; `exec-block-mode` stays `browser`.
- After the sysext refresh the exec-block re-assert keeps the same set: nautilus unstubbed, terminal stubbed.
- The Files entry is in the Dash; the FileManager1 D-Bus override is lifted.
- Step 4 (record, behaviour note): the agent's `follow_session`, `after_login` and revert hold `active.lock` while `apply_lifted` waits for the exec-block lock, and the exec-block re-assert after a sysext refresh can hold that lock while it mounts (up to about 10 s per mount). A login during that waits 2 s for `active.lock` and is refused with the unavailable message (nobody else is signed in); a second attempt after the refresh succeeds. Record what actually happens and how long the window is.

Screenshots: `13-allow-files-open.png`, `14-allow-terminal-stub.png`, `15-allow-after-sysext-refresh.png`.

## 4. Logout reverts to neutral; the second person

Preconditions: item 2 teacher config with terminal lifted (so a revert is visible); a second person ready.

Steps:
1. Sign in as person A (full config). Note the uid.
2. Sign out. Start a clock at the logout click. As root, poll every second: `cat /run/mastersos/user-layer/active.json; readlink /var/lib/mastersos-public/session; systemctl is-active user@<uid>.service; ls /var/lib/systemd/linger/`.
3. Record the time from logout until: the marker is gone, `session` points to `neutral`, exec stubs are all back (`findmnt` probe), `user@<uid>` stopped. Record when the greeter accepts the second person.
4. Immediately after logout, try to sign in as person B (before the 5 s poll has run).
5. Repeat step 4 after neutral is confirmed.

Expected:
- The revert is done by the agent on its next poll (about 5 s) or on the SIGUSR1 wake-up after logout; record the measured time. Order: neutral switched in, linger off, user manager stopped, then the marker removed.
- Final state: no `active.json`; `session` -> `neutral`; all exec targets stubbed; `exec-block-mode` `browser`, no `exec-block-lifted`; `user@<uid>.service` inactive; no `/var/lib/systemd/linger/<name>` file for the person; `managed/mastersos.json` is the neutral baseline policy.
- Step 4: either refused with the busy message (marker still present) or accepted only after the revert; never an A-config session for B. Step 5 succeeds and B gets B's own config.

Screenshots: `16-logout-marker-polling.png` (terminal capture of the poll), `17-second-login-busy-or-ok.png`, `18-second-login-ok.png`.

## 5. Locked screen: "switch user" is refused

Preconditions: person A signed in, screen locked (Super+L).

Steps:
1. At the lock screen use switch user / the greeter's user list and try to sign in as B.
2. Repeat with the system language set to a non-English language that has a translation (for example Thai or Chinese).
3. Unlock A normally with A's credentials; then try tty3 (item 14 covers tty).

Expected:
- B is refused with "Someone is still signed in on this device. They need to sign out first, or restart the device.", in the system language (gettext `mastersos-system`); the other person is not named; no admin override.
- A's unlock works, the session is the same (same `active.json`, uid, `opened_at` unchanged), no config switch.

Screenshots: `19-busy-refused-en.png`, `20-busy-refused-translated.png`, `21-unlock-ok.png`.

## 6. Agent killed mid-session; stale marker

Preconditions: person A signed in under a format 3 config with something lifted.

Steps:
1. As root: `systemctl kill -s KILL mastersos-agent.service` and keep it from restarting (`systemctl stop mastersos-agent.service` after, or mask for the test). Sign A out.
2. `cat /run/mastersos/user-layer/active.json` (state `closing`, or still `open`). Try to sign in as B (refused), and as A (refused only for the closing marker; a same-uid `open` marker is not refused).
3. Start the agent (`systemctl start mastersos-agent.service`); within about 5-10 s check the revert (as item 4). Try B again.
4. Repeat 1-2, then reboot instead of restarting the agent.

Expected:
- While the marker exists and the agent is down: every login of another uid is refused with the busy message, and of the same uid once the marker is `closing` with the unavailable message (pam-check; pam-session re-checks as a backstop), also on a Device whose bundle is format 2 if a stale marker is present (fail closed). The marker cannot be reverted by anything but the agent.
- With the agent back: marker removed, state neutral (item 4 final state), B signs in.
- Reboot: `/run` is tmpfs so the marker is gone; boot starts neutral (`session` -> `neutral`, stubs all in place); logins work.
- `active.json` unreadable (corrupt it deliberately in a second run): login refused (fail closed); after the agent runs the revert it reports `user-layer:revert` or clears it; record which.

Screenshots: `22-stale-marker-refused.png`, `23-after-agent-restart.png`, `24-after-reboot-neutral.png`.

## 7. New bundle published during a session

Preconditions: person A signed in under a config with the terminal lifted and one web app.

Steps:
1. Publish a bundle that changes the config's web app list and Chrome policy: wait for the apply (or `mastersos-agent once` as root).
2. Publish a bundle that removes the terminal capability from A's config; apply.
3. Publish a bundle that adds a capability (for example `file_manager`); apply.
4. Publish a bundle that removes A's user config entirely; apply. Then sign A out and in.

Expected:
- Step 1: web app list and `chrome://policy` update in place (after a Chrome policy reload); the session is not reset, `active.json` `opened_at` and `uid` unchanged.
- Step 2: the terminal is stubbed at once (tighten now).
- Step 3: a gained capability is lifted within the apply (the render step loosens through `session::after_login`), or on the agent's retry if the marker lock was busy; Files appears within one poll (about 5 s). Only the `held` case of step 4 waits for the next login.
- Step 4: the session is switched to the fallback with nothing lifted and `held = true` in `active.json`; report item `user-layer:active` fails with "the signed-in person's user config was removed; they get it at their next login"; at the next login they get what the rules now say.
- Step 4, behaviour note (final review FR-M6, R28): while held, the xdg files (Dash, `Hidden` overrides), the dconf session database and the managed Chrome policy switch to the fallback config at once; only the exec-block capabilities stay at nothing lifted. A fallback wider than the removed config (more web apps, fewer Chrome blocks, unlocked dconf keys) therefore loosens those parts mid-session; schools should keep the fallback no wider than any config. Record what the session can see and open after step 4: Dash entries, `chrome://policy` (`URLBlocklist`), `gsettings get org.gnome.desktop.lockdown disable-command-line`, and the exec stubs.
- The dconf change reaches running apps without a re-login (`gsettings monitor` shows the change, or `gsettings get` is correct after a new `dconf-service` start).

Screenshots: `25-bundle-update-policy.png`, `26-capability-removed-blocked.png`, `27-config-removed-held.png`.

## 8. Facts failure modes

Preconditions: a Device with `school.oidc.mastersos_claims = true` and a test issuer (Plan C) or its stub. A rule `class_role = teacher` precedes the fallback.

Steps:
1. Login with the facts file absent (issuer without `mastersos.facts` scope).
2. Login with a facts file older than 120 s (let the broker write it, then delay the PAM stage, or set the clock back by 3 minutes between grant and open).
3. Login with a facts file in the error form.
4. Normal login with fresh facts; then lock and unlock repeatedly.

Expected:
- 1-3: the fallback config, or the first fact-free rule that matches (such as `admin`). The full reason (with the broker's error text) is logged in the journal; `active.json` `reason` and report item `user-layer:session` carry only a fixed category ("the issuer handed over no facts", "the issuer facts are stale", "the issuer facts are unusable"), never the login name or the error text, and only when the fallback applies; a matching fact-free rule leaves `reason` null. The file is deleted (a symlink in its place too: the link, not its target). The login is not refused for that.
- A facts file whose lists are `null` (an issuer that sends `"classes": null` for a person with no class) still gives facts: the empty list, not an error.
- 4: the session keeps its config; an unlock does not re-resolve (the broker rewrites the facts file on unlock; `pam-session` does not run for it). A leftover facts file after unlock is harmless: confirm it is deleted by the next authentication start.
- The report names no facts and no person (spec §4.10).

Screenshots: `28-facts-missing-fallback.png`, `29-facts-stale-fallback.png`, `30-unlock-keeps-config.png`.

## 9. Login card and guest URLBlocklist

Preconditions: open card mode (`[school.oidc] card_navigation = "open"`, the default; not related to `idp_hint`). A guest rule (`kind = "guest"`) resolves to a user config with `chrome_policy.URLBlocklist = ["example-blocked.test"]`.

Steps:
1. As root read `/var/lib/mastersos-public/login-browser/policies/mastersos-login.json` (the card's Chrome policy; bound over the managed directory by the image's unit). `card.json` next to it holds only `idp_hint`, not the blocklist.
2. At the greeter open the login card. It is an `--app` window with no address bar, so test with a link on a test page served for the purpose (or the issuer's page with a link) to `https://example-blocked.test` and to an allowed site.
3. Unresolvable guest config: this cannot be produced by a valid bundle (`check` requires a fallback). It happens only when the Device's Group id is absent from the bundle (`guest_user_config` is None). Use a Device whose Group id is not in the published bundle, or mark this step not reachable with a valid bundle.
4. Compare with Guest sign-in: the guest session's Chrome policy.

Expected:
- `URLBlocklist` always starts `["*", "chrome://*"]`, followed by the guest config's entries (here `example-blocked.test`). An open card adds `https://*` to `URLAllowlist`, together with the issuer, `card_hosts` and the broker redirect `127.0.0.1:48123/callback`. The card opens no site the guest could not.
- Step 3: the blocklist is only `["*", "chrome://*"]`, no `https://*` in the allowlist; the issuer, `card_hosts` and the redirect still work, so sign-in itself still works. Format 1/2 behaviour is unchanged (the Device config's list).
- The guest's session policy equals the guest config's.

Screenshots: `31-card-blocked-site.png`, `32-card-allowed-site.png`, `33-card-unresolved-blocks-all.png`.

## 10. dconf: session DB, `dconf update`, stale DB files

Preconditions: person A signed in under format 3, with a locked key (for example `favorite-apps`) and a value that differs between configs.

Steps:
1. As root: `ls -la /etc/dconf/db/ /etc/dconf/profile/user; cat /etc/dconf/profile/user; md5sum /etc/dconf/db/mastersos-session`.
2. Run `dconf update` twice (this is what an apply does for the device DB).
3. Repeat step 1; in the session `gsettings get` / `gsettings writable` for the differing key and a locked key.
4. Trigger an apply (publish a no-op bundle change) and sign out and in as person B twice; repeat steps 1 and 3 for B.
5. Look for leftovers: `ls /etc/dconf/db/ | grep mastersos`.

Expected:
- Profile (format 3 only): `user-db:user`, `system-db:mastersos-session`, `system-db:mastersos`. `mastersos-session` has no `.d` directory and is mode 0644; per-config compiled DBs are not in `/etc/dconf/db` (they are in `/var/lib/mastersos-system/user-layer/<d>/dconf.db`, root 0700).
- `dconf update` does not touch or rebuild `mastersos-session`; after two runs the md5 is unchanged and the session still reads A's values and locks (`writable` false for locked keys).
- B's login replaces the DB; a running dconf client (for example `gsettings monitor`, or `dconf-service`) no longer maps the old file: check `/proc/<pid>/maps` shows it as `(deleted)` or re-mapped, not the stale one; no stale `mastersos-<d>` DB or `.d` remains in `/etc/dconf/db`.

Screenshots: `34-dconf-listing.png`, `35-gsettings-session-values.png`.

## 11. Timing of `pam-session`

Steps:
1. Sign in as several kinds of person (SSO with facts, local, guest); capture `journalctl -b -o short-precise --no-pager | grep pam-session` around the login, and the surrounding PAM and `systemd-logind` lines.
2. Take the time between the `pam-session` start and the next PAM module (`pam_systemd` session start in `systemd-logind`, "New session ...") as the duration of the switch. Optionally run `strace -f -tt -e trace=execve` on the greeter's PAM process or `time` the equivalent via `bash -c` on the test VM.

Expected: the switch takes well under 1 s (budget 5 s); nothing in it spawns a command (no `dconf` and no `loginctl`; the only command `pam-session` runs is the wake-up `systemctl kill -s USR1 --kill-whom=main mastersos-agent.service` on close). If the code does not log durations, record the logind "New session" minus the PAM auth timestamp and mark the measurement as indirect.

Screenshots: `36-pam-session-timing.png`.

## 12. Rollback to the previous slot with a format 3 bundle cached

Preconditions: A/B image with a pre-format-3 image in the other slot; the format 3 agent has cached a format 3 bundle and run at least once (a session of a learning config, for example item 3's, was open and closed).

Steps:
1. Sign in with a learning person who has `file_manager` lifted; note the state; sign out.
2. Roll back (select the previous slot and reboot).
3. On the old image: probes (exec-block, mode files); sign in as the same person and as an admin.

Expected:
- The old agent refuses the format 3 bundle (no format 3 support) and runs only the seed steps. Because `exec-block-mode` only ever holds `browser`/`desktop` (a format 3 `learning` session writes `browser`), the old `exec-block` mounts all the stubs: terminal, Files and Settings stay locked for everybody. Record that the learning session stays locked: `cat /var/lib/mastersos-system/exec-block-mode` is `browser`, terminal still the stub.
- The legacy `/var/lib/mastersos-public/session-mode` reads `learning` (never `full`) so old readers keep the session locked.
- Known gap G1 (listed, not fixed): the device xdg `Hidden=true` overrides are absent (installed apps are visible in the Dash search) and the old dconf `mastersos` DB is device-level only (the per-config locks are gone). Also probe and record: `/etc/dconf/profile/user` and `/etc/dconf/db/mastersos-session` persist in `/etc` after the rollback (the old image does not clean them); the managed Chrome policy stays at the neutral baseline after a clean logout; dconf locks may be partly retained. Record exactly what else changes and screenshot it.

Screenshots: `37-rollback-exec-stubs.png`, `38-rollback-dash-g1.png`.

## 13. uid binding of the session mode

Preconditions: person A (uid X) signed in under a config with `user_apps` lifted (session-mode `full`); IT can use tty3.

Steps:
1. `cat /var/lib/mastersos-public/session/uid` (X) and `/var/lib/mastersos-public/session/session-mode` (`full`).
2. From the pre-opened root shell (see the prerequisite; a new `su` or login is refused while A is signed in): `sudo -u <another local user> <generator>` for each of `/usr/local/lib/systemd/user-environment-generators/30-systemd-environment-d-generator` and `.../60-flatpak`. The generators print environment assignments on stdout (`flatpak --print-updated-env` style): read `XDG_DATA_DIRS` from that output, not from `env`.
3. Run `/usr/lib/mastersos/browser-wait` as the other uid (`sudo -u <other>`) and as A. It exits at once when `/usr/bin/google-chrome-stable` is executable or there is no `status.json`, so set `MASTERSOS_CHROME_BIN=/nonexistent`, put a `status.json` in `$MASTERSOS_PUBLIC` (a copy of `/var/lib/mastersos-public/status.json` in a scratch dir), and put `zenity` and `notify-send` stubs first in `PATH` that log their calls. Full mode notifies (`notify-send` stub called); locked mode opens the progress window (`zenity` stub called).
4. Repeat for the owner (uid X) from A's own session.

Expected:
- The `session` mode applies only where `session/uid` equals `$(id -u)`: A's own user manager gets `full`; the other uid gets the locked (`learning`) behaviour, and does not fall back to the legacy file in that case. A missing `uid` file means locked.
- Neutral's directory carries no `uid`.

Screenshots: `39-uid-binding-owner.png`, `40-uid-binding-other.png`.

## 14. tty3 logins and PAM passthrough

Preconditions: IT account can sign in at tty3.

Steps:
1. With nobody signed in graphically (this is also the prerequisite shell): switch to tty3 (Ctrl+Alt+F3) and sign in as `itadmin`; `sudo -i`; sign out.
2. With A signed in graphically: sign in at tty3 as `itadmin`, then as another local person.
3. Read the pam-check refusals in the journal. The passthrough list is `PASSTHROUGH_SERVICES` in `core/mastersos-agent/src/system/login.rs`.

Expected:
- Step 1 succeeds (no marker: pam-check does not deny tty logins). Step 2: the policy is "one human session at a time" for every service not in the passthrough list: the tty `login` service of another human while A has a session is refused with the busy message; `itadmin` is also a human session and follows the same rule (no admin override). Record the actual outcome for `itadmin` precisely: the spec says no override, and the code treats it as any other human. If IT on tty3 must work during a session, that is a finding for the owner.
- Passthrough (never refused as busy): `cron`, `systemd-user`, `sudo`, `sudo-i`, `polkit-1`, `gdm-launch-environment`. `su` is not in the list (record the outcome).
- tty logins in general are not denied: with no marker they succeed (step 1).

Screenshots: `41-tty3-itadmin-no-session.png`, `42-tty3-during-session.png`.

## 15. Status report carries `user_config`

Steps:
1. With a person signed in (marker `state` `open`), trigger a status report (the agent sends it on its own schedule; a `systemctl kill -s USR1 --kill-whom=main mastersos-agent.service` wake-up does not confirm an immediate report, so wait for the next one and record how long it took); read it on the settings server's Device page or in the request the agent sends (journal at debug level, if available).
2. With nobody signed in and the marker `closing` or absent, repeat.

Expected: with an open session the report has `user_config` = the user config id (no facts, no name, no uid); with no session, or while the session is closing, the field is absent (omitted, not null).

Not pinned down from the code: where to read the report on the Device without the server (no local file was found); use the server's Device status view.

Screenshots: `43-report-with-session.png`, `44-report-no-session.png`.

## 16. Kiosk app refused while a session marker exists

Preconditions: a kiosk app configured on the Device (device layer); person A signed in under format 3.

Steps:
1. Create the marker state: either stop the agent, then sign A out (marker stays, as item 6), or lock A's screen and use "switch user" to reach the greeter's kiosk entry.
2. Try to open the kiosk app (kiosk-* account).
3. After the revert (marker gone), open the kiosk app again.

Expected:
- While a marker exists (open, closing, or unreadable) the kiosk session is refused by `pam-session` (journal: "a session is still signed in or being closed; user layer: denied"); the user sees the kiosk refusal on the greeter (record the text).
- After the revert the kiosk app opens as today.

Screenshots: `45-kiosk-refused-with-marker.png`, `46-kiosk-ok-after-revert.png`.

## 17. Chrome policy staging

Steps:
1. As root: `ls -la /etc/opt/chrome/policies/ /etc/opt/chrome/policies/managed/ /etc/opt/chrome/policies/.mastersos-staging/` before sign-in, during a session, and after sign-out.
2. During a switch (sign in as A then B), watch with `inotifywait -m /etc/opt/chrome/policies/managed` if available (or a loop of `ls`).
3. `chrome://policy` after each.

Expected:
- `.mastersos-staging/` exists (mode 0700, root). The switch renames a config's staging copy over `managed/mastersos.json` (consumed), and the next apply re-renders the copies, so expect only the not-yet-switched configs' `<d>.json` there, possibly none right after a switch.
- `managed/` holds only the final policy file `mastersos.json` (and any other final policy files such as the extension policy); never a staging copy, a `.tmp` or a `<d>.json`; at no moment during a switch does Chrome see two policy files for this layer.
- After sign-out `mastersos.json` is the neutral baseline. Chrome shows the person's config policy during the session (item 2 screenshots).

Screenshots: `47-chrome-policy-dirs.png`.
