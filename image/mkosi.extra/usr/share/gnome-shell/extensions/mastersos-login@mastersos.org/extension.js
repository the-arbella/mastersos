// MastersOS login-screen extension. Runs only in the GDM greeter session mode (mastersos-gdm).
//   - bottom shelf: Shut down, Browse as Guest, Add person, Apps (shelf.js), and "Managed by <school_name>"
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
import {Shelf} from './shelf.js';
import {agentRefusal, brokerText, cleanText, fmt, strings} from './strings.js';

const BRANDING = '/var/lib/mastersos-public/branding/branding.json';
const NM_CONNECTIVITY_NONE = 1;
const STATUS = '/var/lib/mastersos-public/status.json';
const BROKER_CHOICE = 'authd-broker-selection';
const MODE_CHOICE = 'authd-auth-mode-selection';
const LOCAL_BROKER = 'local';
const GUEST = 'guest';
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
        if (this._domains.length)
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
            });

        this._patch(LoginDialog.LoginDialog.prototype, '_beginVerification', original =>
            function (params) {
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
        this._itLink = link(this._text.itLink, () => {
            prompt.setQuestion(this._text.itPrompt);
            this._itLink.hide();
        });

        this._dialogIds = [
            prompt.connect('reset', () => {
                // Coming back to this VT resets the prompt too. The card's sign-in ended with it, so its page could only fail.
                this._card?.close();
                this._setAddPerson(false);
                this._shelf?.refreshApps();
            }),
        ];

        Main.screenShield._lockDialogGroup?.add_style_class_name('mastersos-login-background');

        this._shelf = new Shelf(this._text, this._managed, {
            shutDown: () => SystemActions.getDefault().activatePowerOff(),
            guest: () => this._signInAs(GUEST),
            addPerson: () => this._addPerson(),
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

    _addPerson() {
        this._clearNotice();
        this._leaveCurrentSignIn();
        this._dialog._hideUserListAskForUsernameAndBeginVerification();
    }

    // Guest and the locked apps sign in without a password, the same way the user list did.
    _signInAs(userName) {
        const dlg = this._dialog;
        this._leaveCurrentSignIn();
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
        this._hookedText = null;
        this._textChangedId = 0;
        this._closeMenu();
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
        this._textChangedId = ct.connect('text-changed', () => {
            try {
                // Left the username stage (password / code prompt now uses this entry): do nothing and read nothing.
                if (this._isSecret(entry) || !entry.visible) {
                    this._scheduleClose();
                    return;
                }
                const t = ct.get_text();
                // Only a single trailing '@' on a non-empty name opens the list; "itadmin" and
                // everything else without '@' never triggers anything.
                if (t.length > 1 && t.endsWith('@') && !t.slice(0, -1).includes('@'))
                    this._showDomains(entry, ct);
                else if (this._menu && !t.endsWith('@'))
                    this._scheduleClose();
            } catch (e) {
                log(`mastersos-login: ${e.message ?? e}`);
            }
        });
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
        for (const undo of this._restore.reverse())
            undo();
        this._restore = [];
        this._dialog = null;
        this._domains = [];
    }
}
