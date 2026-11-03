// MastersOS login-screen extension. Runs only in the GDM greeter session mode (mastersos-gdm).
//   - one entry, no user list: typing finds the people of this computer below it, a new school email signs someone new in
//   - bottom shelf: Shut down, Browse as Guest, Apps (shelf.js), and "Managed by <school_name>"
//   - sign-in card: the school's page in a locked-down Chrome instead of the login code dialog (card.js)
//   - a school account has no password on this computer: its only way in is that card, online
//   - hides what a student should not see: kiosk accounts and guest in the user list, Not listed?, the broker and
//     auth mode choices, the key icon
//   - people, email, the card and the language screen share one rectangle, the login area (area.js); the shelf, the notice and
//     the accessibility button stay outside it
//   - first run without a language from the school: only the language and keyboard screen (setup.js), and a Language item in
//     the keyboard menu afterwards
//   - when the user types '@' in the username field, pops up the school domains; an explicit pick
//     completes the address, typing the full address by hand always works.
// Never reads passwords or tokens: everything secret stays in PAM, authd and the school's page. Reads
// /var/lib/mastersos-public/branding/branding.json; missing, broken or empty values show nothing and never throw.
//
// The GDM internals patched here are pinned to one gnome-shell version by build.sh: retest when it moves.

import St from 'gi://St';
import Clutter from 'gi://Clutter';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';

import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';
import * as AuthPrompt from 'resource:///org/gnome/shell/gdm/authPrompt.js';
import * as Authd from 'resource:///org/gnome/shell/gdm/authd.js';
import * as GdmUtil from 'resource:///org/gnome/shell/gdm/util.js';
import * as LoginDialog from 'resource:///org/gnome/shell/gdm/loginDialog.js';
import * as SystemActions from 'resource:///org/gnome/shell/misc/systemActions.js';

import {loginArea} from './area.js';
import {LoginCard} from './card.js';
import {LanguageScreen, languageChosen, restartGreeter} from './setup.js';
import {matchPeople, preselect} from './people.js';
import {Shelf} from './shelf.js';
import {agentRefusal, bannerText, brokerText, cleanText, fmt, strings} from './strings.js';

const BRANDING = '/var/lib/mastersos-public/branding/branding.json';
const NM_CONNECTIVITY_NONE = 1;
const STATUS = '/var/lib/mastersos-public/status.json';
const BROKER_CHOICE = 'authd-broker-selection';
const MODE_CHOICE = 'authd-auth-mode-selection';
const LOCAL_BROKER = 'local';
const GUEST = 'guest';
// The device's IT maintenance account (the agent's IT_ACCOUNT_USER, phase B design §10.4).
const IT_ACCOUNT = 'itadmin';
// How often the first-run state is read again, in ticks of 400 ms.
const FIRST_RUN_TICKS = 5;
const OFFLINE_PROBLEM = /connecting to provider/i;
// The ways a person ends up refused for who they are rather than for what they typed. The domain check is the agent's
// pam-check (account stage, after a successful sign-in; DENY_DOMAIN in core/mastersos-agent/src/system/login.rs), the other
// two are the broker's. All vanish with the reset that follows, so these get a line of their own under the email field.
const NOT_ALLOWED = /not allowed in broker configuration|Accounts from this domain cannot sign in/i;
const WRONG_ACCOUNT = /does not match the authenticated user/i;

function readJson(path) {
    try {
        const f = Gio.File.new_for_path(path);
        const [ok, bytes] = f.load_contents(null);
        if (!ok)
            return null;
        const data = JSON.parse(new TextDecoder().decode(bytes));
        return data && typeof data === 'object' && !Array.isArray(data) ? data : null;
    } catch (e) {
        if (!e.matches?.(Gio.IOErrorEnum, Gio.IOErrorEnum.NOT_FOUND))
            log(`mastersos-login: ${path} unreadable: ${e.message ?? e}`);
        return null;
    }
}

function readBranding() {
    return readJson(BRANDING);
}

// Whether to ask for the language now that nobody has chosen one. A machine with neither file has no school. A machine with a
// school waits for its first settings: only they can say the school keeps the language (the seed cannot), and the agent's status
// says "ok" once there are any.
// NetworkManager says there is none. Anything else, including no answer, lets the app try.
function noNetwork() {
    try {
        const v = Gio.DBus.system.call_sync('org.freedesktop.NetworkManager', '/org/freedesktop/NetworkManager',
            'org.freedesktop.DBus.Properties', 'Get', new GLib.Variant('(ss)', ['org.freedesktop.NetworkManager', 'Connectivity']),
            null, Gio.DBusCallFlags.NONE, 1000, null);
        return v.deepUnpack()[0].unpack() === NM_CONNECTIVITY_NONE;
    } catch (e) {
        log(`mastersos-login: connectivity: ${e.message ?? e}`);
        return false;
    }
}

export function shouldAskLanguage(branding, status) {
    if (branding?.locale_managed === true)
        return false;
    return (branding === null && status === null) || status?.settings === 'ok';
}

// The school set the language: the agent keeps it, so nothing here may offer to change it.
function localeManaged(b) {
    return b?.locale_managed === true;
}

function schoolName(b) {
    return cleanText(b?.school_name, 100);
}

function domainList(b) {
    if (!Array.isArray(b?.domains))
        return [];
    return b.domains
        .filter(d => typeof d === 'string' && d.length <= 253 && d === cleanText(d, 253) && !/[\s@]/.test(d))
        .slice(0, 20);
}

// Which choice to make for the person: an address goes to the school's broker, anything else (the IT account, a local
// user) to the local one; among auth modes the first is what the broker prefers (for a school account, the card).
export function pickChoice(id, choices, userName) {
    const keys = Object.keys(choices);
    if (id === MODE_CHOICE)
        return keys[0] ?? null;
    if (id !== BROKER_CHOICE)
        return null;
    if (!userName?.includes('@'))
        return keys.includes(LOCAL_BROKER) ? LOCAL_BROKER : null;
    const school = keys.filter(k => k !== LOCAL_BROKER);
    return school.length === 1 ? school[0] : null;
}

export default class MastersosLoginExtension extends Extension {
    enable() {
        this.initTranslations();
        this._text = strings();
        this._menu = null;
        this._menuManager = null;
        this._hookedText = null;
        this._textChangedId = 0;
        this._keyPressId = 0;
        this._matchBox = null;
        this._shown = [];
        this._more = false;
        this._sel = -1;
        this._picked = null;
        this._dismissed = false;
        this._pollId = 0;
        this._domains = [];
        this._closeId = 0;
        this._dialog = null;
        this._shelf = null;
        this._restore = [];
        this._dialogIds = [];
        this._pending = null;
        this._language = null;
        this._firstRun = false;
        this._firstRunTicks = 0;
        const b = readBranding();
        const name = schoolName(b);
        this._domains = domainList(b);
        this._managed = name ? fmt(this._text.managed, name) : null;
        this._localeManaged = localeManaged(b);
        this._card = new LoginCard(this._text);
        try {
            this._patchGreeter();
        } catch (e) {
            log(`mastersos-login: patching the greeter failed: ${e.message ?? e}`);
        }
        // The login dialog and the username entry appear later: poll until they do.
        this._pollId = GLib.timeout_add(GLib.PRIORITY_DEFAULT, 400, () => {
            try {
                this._tick();
            } catch (e) {
                log(`mastersos-login: ${e.message ?? e}`);
            }
            return GLib.SOURCE_CONTINUE;
        });
    }

    _tick() {
        const dlg = Main.screenShield?._dialog;
        if (dlg && dlg !== this._dialog)
            this._adoptDialog(dlg);
        if (dlg && this._shelf && dlg._userManager?.is_loaded)
            this._shelf.setGuestAvailable(dlg._userManager.list_users().some(u => u.get_user_name() === GUEST));
        this._tryHookEntry();
        this._syncLanguageItem();
        if (dlg && this._firstRun && ++this._firstRunTicks % FIRST_RUN_TICKS === 0)
            this._syncFirstRun();
    }

    _patch(object, name, replacement) {
        const own = Object.getOwnPropertyDescriptor(object, name);
        const original = object[name];
        object[name] = replacement(original);
        this._restore.push(() => {
            if (own)
                Object.defineProperty(object, name, own);
            else
                delete object[name];
        });
    }

    _patchGreeter() {
        const ext = this;

        // The agent writes the banner in English (dconf has no language): show its sentence in the screen's language.
        if (typeof LoginDialog.LoginDialog.prototype._updateBanner === 'function') {
            this._patch(LoginDialog.LoginDialog.prototype, '_updateBanner', original =>
                function (...args) {
                    original.apply(this, args);
                    const text = this._bannerLabel?.get_text?.();
                    if (text)
                        this._bannerLabel.set_text(bannerText(text));
                });
        } else {
            log('mastersos-login: LoginDialog._updateBanner is missing; the banner stays in English');
        }

        this._patch(AuthPrompt.AuthPrompt.prototype, '_openWebLoginDialog', original =>
            function (verifier, service, message, url, code, autoAck, customButton) {
                // A login code means the broker runs the device flow: that is what the stock dialog is for.
                if (code || !url?.startsWith('https://')) {
                    original.call(this, verifier, service, message, url, code, autoAck, customButton);
                    return;
                }
                if (this._queryingService)
                    this.clear();
                this._closeWebLoginDialog();
                this._queryingService = service;
                this._webLoginPromptWell.remove_all_children();
                ext._openCard(this, verifier, service, url);
                if (this._spinner)
                    this._spinner.stop();
                this.updateSensitivity(true);
                this.emit('prompted');
            });

        this._patch(AuthPrompt.AuthPrompt.prototype, '_closeWebLoginDialog', original =>
            function () {
                ext._card.close();
                original.call(this);
            });

        // No broker or auth mode lists: the person only ever sees their sign-in.
        this._patch(Authd.AuthdSwitchableHandler.prototype, '_showChoiceList', original =>
            function (id, prompt, choices) {
                const key = pickChoice(id, choices, ext._userName());
                if (key === null)
                    original.call(this, id, prompt, choices);
                else if (id === BROKER_CHOICE)
                    this._selectBroker(key);
                else
                    this._selectAuthMode(key);
            });

        // No way to reach the identity provider: say so beside the shelf, with a way to try again.
        this._patch(Authd.AuthdSwitchableHandler.prototype, 'handleProblem', original =>
            function (problem) {
                if (ext._noteRefusal(problem)) {
                    this.reset();
                    return true;
                }
                if (!OFFLINE_PROBLEM.test(problem) && !ext._card.isOpen)
                    return original.call(this, ext._say(problem));
                ext._noteUnreachable();
                this.reset();
                return true;
            });

        this._patch(Authd.AuthdSwitchableHandler.prototype, '_handleAuthResponse', original =>
            function (response) {
                if (response?.msg && !ext._noteRefusal(response.msg))
                    response.msg = ext._say(response.msg);
                else if (response?.msg)
                    response.msg = '';
                original.call(this, response);
            });

        // pam-check speaks through pam_exec, which reaches the shell as an info message. Those are dropped for gdm-authd (not
        // a foreground service), and all that is left is a generic "Sorry, that didn't work".
        this._patch(GdmUtil.ShellUserVerifier.prototype, '_onInfo', original =>
            function (client, service, info) {
                if (!ext._noteRefusal(info))
                    original.call(this, client, service, info);
            });

        this._patch(AuthPrompt.AuthPrompt.prototype, '_onShowMessage', original =>
            function (verifier, service, message, type) {
                if (!message || !ext._noteRefusal(message))
                    original.call(this, verifier, service, ext._say(message), type);
            });

        // Going back leaves the sign-in, it does not step back through lists that are never shown.
        this._patch(Authd.AuthdSwitchableHandler.prototype, 'cancelRequested', () =>
            function () {
                this.emit('verification-failed', /* should retry */ false);
                return false;
            });

        this._patch(Authd.AuthdSwitchableHandler.prototype, '_showChallenge', original =>
            function () {
                if (this._uiLayout?.label)
                    this._uiLayout.label = ext._say(this._uiLayout.label);
                original.call(this);
            });

        this._patch(LoginDialog.LoginDialog.prototype, '_askForUsernameAndBeginVerification', original =>
            function () {
                original.call(this);
                this._authPrompt.setQuestion(ext._text.email);
                ext._setAddPerson(true);
                ext._takeUsernameStep(this);
            });

        this._patch(LoginDialog.LoginDialog.prototype, '_beginVerification', original =>
            function (params) {
                ext._hideMatches();
                ext._setAddPerson(false);
                ext._clearNotice();
                original.call(this, params);
            });

        // The stock layout stays (the accessibility button keeps its corner); only the centre goes into the login area.
        this._patch(LoginDialog.LoginDialog.prototype, '_getCenterActorAllocation', original =>
            function (dialogBox, actor) {
                const a = loginArea();
                const mon = Main.layoutManager.primaryMonitor;
                const x1 = a.x - mon.x, y1 = a.y - mon.y;
                return original.call(this, new Clutter.ActorBox({x1, y1, x2: x1 + a.width, y2: y1 + a.height}), actor);
            });
    }

    _say(message) {
        return brokerText(message);
    }

    // Remember why the broker refused this person; true when it was one of the refusals explained on the email screen.
    _noteRefusal(message) {
        let text;
        if (NOT_ALLOWED.test(message)) {
            const domain = this._domains[0];
            text = domain ? fmt(this._text.notAllowedUse, `@${domain}`) : this._text.notAllowed;
        } else if (WRONG_ACCOUNT.test(message)) {
            text = this._text.wrongAccount;
        } else if (agentRefusal(message)) {
            text = this._say(message);
        } else {
            return false;
        }
        this._afterReset({text, toEmail: true, retryAs: null});
        return true;
    }

    _noteUnreachable() {
        this._afterReset({text: this._text.offline, toEmail: false, retryAs: this._userName()});
    }

    // The sign-in ends in a reset of its own: tell the person once that has run.
    _afterReset(notice) {
        this._pending = notice;
        if (this._pendingId)
            return;
        this._pendingId = GLib.timeout_add(GLib.PRIORITY_DEFAULT, 300, () => {
            this._pendingId = 0;
            this._showPending();
            return GLib.SOURCE_REMOVE;
        });
    }

    _showPending() {
        const notice = this._pending;
        this._pending = null;
        if (!notice || !this._dialog)
            return;
        this._card.close();
        this._leaveCurrentSignIn();
        if (notice.toEmail)
            this._dialog._hideUserListAskForUsernameAndBeginVerification();
        const retryAs = notice.retryAs;
        this._shelf?.showNotice(notice.text, retryAs ? () => this._signInAs(retryAs) : null);
    }

    _clearNotice() {
        this._shelf?.hideNotice();
    }

    _userName() {
        return this._dialog?._authPrompt?._userVerifier?._userName ?? null;
    }

    _adoptDialog(dlg) {
        this._dialog = dlg;

        // The list keeps people; guest and the locked apps have their own buttons.
        const hidden = user => {
            const n = user.get_user_name();
            return n === GUEST || n.startsWith('kiosk-');
        };
        const list = dlg._userList;
        this._patch(list, 'addUser', original =>
            function (user) {
                if (!hidden(user))
                    original.call(this, user);
            });
        if (dlg._userManager?.is_loaded) {
            for (const u of dlg._userManager.list_users()) {
                if (hidden(u))
                    list.removeUser(u);
            }
        }

        dlg._notListedButton.hide();
        this._patch(dlg._notListedButton, 'show', () => () => {});

        // No session gear: the Ubuntu session is the only one people use, and a kiosk account's session comes from its
        // AccountsService record, not from this menu. GNOME 50 sets `visible` from _shouldShowSessionMenuButton() in
        // _onPrompted and calls updateSensitivity(true) (opacity 255) in _onReset, so all three are covered.
        const sessions = dlg._sessionMenuButton;
        if (sessions) {
            sessions.hide();
            this._patch(sessions, 'show', () => () => {});
            this._patch(sessions, 'updateSensitivity', original =>
                function (sensitive) {
                    original.call(this, sensitive);
                    this.hide();
                });
            if (typeof dlg._shouldShowSessionMenuButton === 'function')
                this._patch(dlg, '_shouldShowSessionMenuButton', () => () => false);
            else
                log('mastersos-login: LoginDialog._shouldShowSessionMenuButton is missing; the session gear may show');
        } else {
            log('mastersos-login: LoginDialog._sessionMenuButton is missing; the session gear may show');
        }

        const options = dlg._loginOptionsButton;
        options.hide();
        this._patch(options, 'show', () => () => {});
        this._patch(options, 'updateSensitivity', original =>
            function (sensitive) {
                original.call(this, sensitive);
                this.hide();
            });

        const prompt = dlg._authPrompt;
        const link = (text, onClick) => {
            const button = new St.Button({
                label: text,
                style_class: 'mastersos-login-link',
                can_focus: true,
                reactive: true,
                x_align: Clutter.ActorAlign.CENTER,
                visible: false,
            });
            button.connect('clicked', onClick);
            prompt._inputWell.add_child(button);
            return button;
        };
        // The people found as the person types, right under the entry (a plain list: a popup menu would take the keyboard).
        this._matchBox = new St.BoxLayout({
            style_class: 'mastersos-people',
            orientation: Clutter.Orientation.VERTICAL,
            x_align: Clutter.ActorAlign.CENTER,
            visible: false,
        });
        prompt._inputWell.add_child(this._matchBox);
        // "Local manager" goes straight to the IT account's password: nobody types its user name.
        this._itLink = link(this._text.itLink, () => {
            this._itLink.hide();
            this._signInAs(IT_ACCOUNT);
        });

        this._dialogIds = [
            prompt.connect('reset', () => {
                // Coming back to this VT resets the prompt too. The card's sign-in ended with it, so its page could only fail.
                // GNOME's _onReset ran first (it connected earlier) and, with disable-user-list, is back on the username
                // step that shows "Local manager": leave it shown. Leaving that step hides it (_beginVerification).
                this._card?.close();
                this._hideMatches();
                this._shelf?.refreshApps();
            }),
        ];

        Main.screenShield._lockDialogGroup?.add_style_class_name('mastersos-login-background');

        this._shelf = new Shelf(this._text, this._managed, {
            shutDown: () => SystemActions.getDefault().activatePowerOff(),
            guest: () => this._signInAs(GUEST),
            openApp: app => this._openApp(app),
        });

        // A long list scrolls inside the area; the box around it grows to the whole dialog.
        const fitList = () => {
            dlg._userList.style = `max-height: ${loginArea().height}px;`;
        };
        fitList();
        this._monitorsId = Main.layoutManager.connect('monitors-changed', fitList);

        this._firstRun = !languageChosen();
        this._syncFirstRun();
    }

    // A web app with no network would sit on Chrome's error page, where the extension's Exit button cannot exist.
    _openApp(app) {
        if (app.needsNetwork && noNetwork()) {
            this._shelf?.showNotice(this._text.appOffline, () => this._openApp(app));
            return;
        }
        this._shelf?.hideNotice();
        this._signInAs(app.user);
    }

    // Until a language is chosen: the screen is up exactly when it should be. Once the agent lays the school's language down,
    // the greeter comes back in it.
    _syncFirstRun() {
        if (!this._firstRun)
            return;
        if (languageChosen()) {
            this._firstRun = false;
            if (!this._card.isOpen)
                restartGreeter();
            return;
        }
        const b = readBranding();
        this._localeManaged = localeManaged(b);
        if (shouldAskLanguage(b, readJson(STATUS)))
            this._showLanguageScreen(false);
        else if (this._language)
            this._closeLanguageScreen();
    }

    _showLanguageScreen(mayCancel) {
        if (this._language)
            return;
        this._card.close();
        this._leaveCurrentSignIn();
        this._clearNotice();
        this._dialog.hide();
        this._shelf.actor.hide();
        this._language = new LanguageScreen(this._text, mayCancel ? () => this._closeLanguageScreen() : null);
    }

    _closeLanguageScreen() {
        this._language?.destroy();
        this._language = null;
        this._dialog.show();
        this._shelf.actor.show();
    }

    // The keyboard menu carries the Language item, so it has to be there with one layout too (the stock indicator hides then).
    _syncLanguageItem() {
        const indicator = Main.panel.statusArea.keyboard;
        // With one layout the shell shows no label, so the menu that holds Language would have nothing to click.
        const labels = Object.values(indicator?._indicatorLabels ?? {});
        if (this._languageItem && labels.length && !labels.some(l => l.visible))
            labels[0].show();
        if (this._languageItem || this._localeManaged || this._firstRun || !indicator || !this._dialog)
            return;
        this._patch(indicator, 'hide', () => () => {});
        indicator.show();
        this._languageItem = new PopupMenu.PopupMenuItem(this._text.language);
        this._languageItem.connect('activate', () => this._showLanguageScreen(true));
        indicator.menu.addMenuItem(this._languageItem, 0);
    }

    _setAddPerson(on) {
        this._itLink?.set({visible: on});
    }

    _leaveCurrentSignIn() {
        const prompt = this._dialog._authPrompt;
        if (prompt.verificationStatus === AuthPrompt.AuthPromptStatus.NOT_VERIFYING)
            return;
        prompt.verificationStatus = AuthPrompt.AuthPromptStatus.VERIFICATION_CANCELLED;
        prompt.reset({beginRequestType: AuthPrompt.BeginRequestType.PROVIDE_USERNAME});
    }

    // Guest and the locked apps sign in without a password, the same way the user list did.
    _signInAs(userName) {
        const dlg = this._dialog;
        this._leaveCurrentSignIn();
        // Leaving the username step for a set account: its Enter handler must not take the password as a user name.
        if (dlg._nextSignalId) {
            dlg._authPrompt.disconnect(dlg._nextSignalId);
            dlg._nextSignalId = 0;
        }
        this._hideMatches();
        // What was typed must not become the start of the password (AuthPrompt copies the text entry into it).
        dlg._authPrompt.clear();
        const user = dlg._userManager.get_user(userName);
        dlg._user = user;
        dlg._hideUserList();
        dlg._authPrompt.setUser(user);
        dlg._beginVerification({userName});
    }

    _openCard(prompt, verifier, service, url) {
        const retryAs = this._userName();
        this._card.open(url, () => this._cardCancelled(prompt), () => {
            this._cardCancelled(prompt);
            this._shelf?.showNotice(this._text.openFailed, retryAs ? () => this._signInAs(retryAs) : null);
        });
        verifier.connectObject(
            `service-request::${service}`, () => this._card.close(),
            'verification-complete', () => this._card.close(),
            'verification-failed', () => {
                this._card.close();
                prompt.showLoginFailedNotification();
                prompt.reset();
            },
            this._card.owner);
        verifier.webLoginOpened(service);
    }

    _cardCancelled(prompt) {
        prompt.verificationStatus = AuthPrompt.AuthPromptStatus.VERIFICATION_CANCELLED;
        prompt.reset({beginRequestType: AuthPrompt.BeginRequestType.PROVIDE_USERNAME});
    }

    // Password and one-time-code entries must never be hooked or read.
    _isSecret(entry) {
        return entry instanceof St.PasswordEntry || !!entry.clutter_text?.password_char;
    }

    _findVisibleEntry() {
        const found = [];
        const walk = a => {
            if (!a || a.visible === false)
                return;
            if (a instanceof St.Entry && !this._isSecret(a) && a.clutter_text?.editable)
                found.push(a);
            for (const c of a.get_children?.() ?? [])
                walk(c);
        };
        walk(Main.uiGroup);
        return found.length ? found[0] : null;
    }

    _unhookEntry() {
        if (this._hookedText && this._textChangedId)
            this._hookedText.disconnect(this._textChangedId);
        if (this._hookedText && this._keyPressId)
            this._hookedText.disconnect(this._keyPressId);
        this._hookedText = null;
        this._textChangedId = 0;
        this._keyPressId = 0;
        this._closeMenu();
        this._hideMatches();
    }

    _tryHookEntry() {
        const entry = this._findVisibleEntry();
        if (!entry) {
            this._unhookEntry(); // back to the user list
            return;
        }
        const ct = entry.clutter_text;
        if (ct === this._hookedText)
            return;
        this._unhookEntry();
        this._hookedText = ct;
        const onText = () => {
            try {
                // Left the username stage (password / code prompt now uses this entry): do nothing and read nothing.
                if (this._isSecret(entry) || !entry.visible) {
                    this._scheduleClose();
                    this._hideMatches();
                    return;
                }
                const t = ct.get_text();
                // Only a single trailing '@' on a non-empty name opens the school domains, and then the people
                // step aside: one list under the entry at a time.
                if (this._domains.length && t.length > 1 && t.endsWith('@') && !t.slice(0, -1).includes('@')) {
                    this._hideMatches();
                    this._showDomains(entry, ct);
                    return;
                }
                if (this._menu && !t.endsWith('@'))
                    this._scheduleClose();
                this._dismissed = false;
                if (this._atUsernameStep(entry))
                    this._showMatches(t);
                else
                    this._hideMatches();
            } catch (e) {
                log(`mastersos-login: ${e.message ?? e}`);
            }
        };
        this._textChangedId = ct.connect('text-changed', onText);
        // Letters typed before this poll found the entry count too.
        if (ct.get_text())
            onText();
        this._keyPressId = ct.connect('key-press-event', (actor, event) => {
            if (!this._matchBox?.visible)
                return Clutter.EVENT_PROPAGATE;
            const key = event.get_key_symbol();
            if (key === Clutter.KEY_Down || key === Clutter.KEY_Up) {
                this._moveSelection(key === Clutter.KEY_Down ? 1 : -1);
                return Clutter.EVENT_STOP;
            }
            if (key === Clutter.KEY_Escape) {
                this._hideMatches();
                this._dismissed = true;
                return Clutter.EVENT_STOP;
            }
            return Clutter.EVENT_PROPAGATE;
        });
    }

    // The entry asks for who is signing in: no sign-in has started and it is the prompt's own (plain) entry.
    _atUsernameStep(entry) {
        const prompt = this._dialog?._authPrompt;
        return !!prompt && entry === prompt._entry && !this._isSecret(entry) &&
            prompt.verificationStatus === AuthPrompt.AuthPromptStatus.NOT_VERIFYING;
    }

    // Enter on the username step: the person picked below the entry, else what was typed (a new school email, a local
    // account name). The body is Ubuntu gnome-shell 50.1-0ubuntu1.4 loginDialog.js _askForUsernameAndBeginVerification's
    // 'next' handler, with the picked person in place of the typed text; anything else there stays GNOME's.
    _takeUsernameStep(dlg) {
        const prompt = dlg._authPrompt;
        if (!dlg._nextSignalId) {
            log('mastersos-login: LoginDialog._nextSignalId is missing; Enter signs in what was typed');
            return;
        }
        prompt.disconnect(dlg._nextSignalId);
        dlg._nextSignalId = prompt.connect('next', () => {
            prompt.disconnect(dlg._nextSignalId);
            dlg._nextSignalId = 0;
            prompt.updateSensitivity(false);
            const typed = prompt.getAnswer();
            const answer = this._picked ?? this._defaultPick(typed) ?? typed;
            this._hideMatches();
            dlg._user = dlg._userManager.get_user(answer);
            if (answer !== typed)
                prompt.setUser(dlg._user);
            prompt.clear();
            dlg._beginVerification({userName: answer});
        });
    }

    // The person Enter takes when none was chosen with the arrow keys or the mouse, worked out from the text itself.
    // Never a different account than the text names: not after Escape put the list away, and not when the text is
    // exactly an account of this computer (hidden ones such as itadmin and guest included).
    _defaultPick(typed) {
        if (this._dismissed || this._sel >= 0 || this._matchBox?.visible)
            return null; // the list was shown and nobody is chosen in it: Enter means what was typed
        const name = typed.trim();
        if (this._dialog?._userManager?.list_users().some(u => u.get_user_name() === name))
            return null;
        const found = matchPeople(this._people(), typed);
        const i = preselect(typed, found.shown);
        return i >= 0 ? found.shown[i].userName : null;
    }

    _people() {
        const users = this._dialog?._userManager;
        if (!users?.is_loaded)
            return [];
        return users.list_users()
            .filter(u => !u.is_system_account?.())
            .map(u => ({
                user: u,
                userName: u.get_user_name(),
                realName: u.get_real_name() || u.get_user_name(),
                loginTime: u.get_login_time?.() ?? 0,
            }));
    }

    _showMatches(text) {
        const found = matchPeople(this._people(), text);
        this._shown = found.shown;
        this._more = found.more;
        this._sel = preselect(text, found.shown);
        this._renderMatches();
    }

    _moveSelection(delta) {
        const n = this._shown.length;
        if (!n)
            return;
        this._sel = this._sel < 0 ? (delta > 0 ? 0 : n - 1) : (this._sel + delta + n) % n;
        this._renderMatches();
    }

    _hideMatches() {
        this._dismissed = false;
        this._shown = [];
        this._more = false;
        this._sel = -1;
        this._picked = null;
        if (this._matchBox) {
            this._matchBox.destroy_all_children();
            this._matchBox.hide();
        }
    }

    _renderMatches() {
        const box = this._matchBox;
        if (!box)
            return;
        box.destroy_all_children();
        this._picked = this._sel >= 0 ? this._shown[this._sel].userName : null;
        if (!this._shown.length) {
            box.hide();
            return;
        }
        this._shown.forEach((p, i) => {
            const row = new St.BoxLayout({style_class: 'mastersos-person-content'});
            const file = p.user.get_icon_file?.();
            row.add_child(file && GLib.file_test(file, GLib.FileTest.IS_REGULAR)
                ? new St.Icon({gicon: new Gio.FileIcon({file: Gio.File.new_for_path(file)}), style_class: 'mastersos-person-icon'})
                : new St.Icon({icon_name: 'avatar-default-symbolic', style_class: 'mastersos-person-icon'}));
            const names = new St.BoxLayout({orientation: Clutter.Orientation.VERTICAL, y_align: Clutter.ActorAlign.CENTER});
            names.add_child(new St.Label({text: p.realName, style_class: 'mastersos-person-name'}));
            if (p.realName !== p.userName)
                names.add_child(new St.Label({text: p.userName, style_class: 'mastersos-person-user'}));
            row.add_child(names);
            // Not focusable: the keyboard stays in the entry, where typing goes on.
            const button = new St.Button({child: row, style_class: 'mastersos-person', can_focus: false, x_expand: true});
            if (i === this._sel)
                button.add_style_pseudo_class('selected');
            button.connect('clicked', () => {
                this._sel = i;
                this._picked = p.userName;
                // The same way as Enter, so the same 'next' handler starts the sign-in.
                this._dialog?._authPrompt?._entry?.clutter_text?.activate();
            });
            box.add_child(button);
        });
        if (this._more)
            box.add_child(new St.Label({text: this._text.narrow, style_class: 'mastersos-person-more'}));
        box.show();
    }

    _showDomains(entry, ct) {
        this._closeMenu();
        const menu = new PopupMenu.PopupMenu(entry, 0.0, St.Side.BOTTOM);
        for (const d of this._domains) {
            const item = new PopupMenu.PopupMenuItem(d);
            item.connect('activate', () => {
                ct.set_text(ct.get_text() + d);
                ct.set_cursor_position(-1);
                this._scheduleClose();
                entry.grab_key_focus();
            });
            menu.addMenuItem(item);
        }
        Main.uiGroup.add_child(menu.actor);
        menu.actor.hide();
        this._menu = menu;
        this._menuManager = new PopupMenu.PopupMenuManager(entry);
        this._menuManager.addMenu(menu);
        // The open menu holds the keyboard: typing the rest of the address by hand must keep working.
        menu.actor.connect('key-press-event', (a, event) => {
            const ch = event.get_key_unicode();
            if (!ch || ch < ' ' || ch === '\u007f')
                return Clutter.EVENT_PROPAGATE;
            this._closeMenu();
            entry.grab_key_focus();
            ct.insert_text(ch, -1);
            return Clutter.EVENT_STOP;
        });
        menu.open();
    }

    // Never destroy the menu inside its own activate / text-changed emission: defer to idle.
    _scheduleClose() {
        if (!this._menu || this._closeId)
            return;
        this._closeId = GLib.idle_add(GLib.PRIORITY_DEFAULT, () => {
            this._closeId = 0;
            this._closeMenu();
            return GLib.SOURCE_REMOVE;
        });
    }

    _closeMenu() {
        if (this._menu) {
            const m = this._menu;
            this._menu = null;
            m.close();
            m.destroy();
        }
        this._menuManager = null;
    }

    disable() {
        if (this._pollId) {
            GLib.source_remove(this._pollId);
            this._pollId = 0;
        }
        if (this._closeId) {
            GLib.source_remove(this._closeId);
            this._closeId = 0;
        }
        if (this._pendingId) {
            GLib.source_remove(this._pendingId);
            this._pendingId = 0;
        }
        this._language?.destroy();
        this._language = null;
        this._languageItem?.destroy();
        this._languageItem = null;
        this._unhookEntry();
        this._card?.close();
        this._card = null;
        this._shelf?.destroy();
        this._shelf = null;
        const prompt = this._dialog?._authPrompt;
        for (const id of this._dialogIds)
            prompt?.disconnect(id);
        this._dialogIds = [];
        if (this._monitorsId) {
            Main.layoutManager.disconnect(this._monitorsId);
            this._monitorsId = 0;
        }
        this._itLink?.destroy();
        this._itLink = null;
        this._matchBox?.destroy();
        this._matchBox = null;
        for (const undo of this._restore.reverse())
            undo();
        this._restore = [];
        this._dialog = null;
        this._domains = [];
    }
}
