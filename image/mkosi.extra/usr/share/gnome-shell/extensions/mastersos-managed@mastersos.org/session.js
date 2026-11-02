// What a school account's desktop does for the login screen. These accounts have no password on this computer, so the stock
// lock screen has nothing to check and shows a sign-in it cannot finish. Locking therefore goes where the school's page is:
// the desktop stays in the background behind a blank cover and GDM shows the login screen, the way Switch User does. Whatever
// locks (Super+L, idle, the lid), and whenever the locked desktop comes back to the screen (VT switch, resume), it ends there.
// Local accounts have a password and keep the stock lock.
//
// The keyboard is a system setting too: the desktop takes the layouts localectl holds.

import Clutter from 'gi://Clutter';
import Gdm from 'gi://Gdm';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import St from 'gi://St';

import * as Layout from 'resource:///org/gnome/shell/ui/layout.js';
import * as LoginManager from 'resource:///org/gnome/shell/misc/loginManager.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import {UnlockDialog} from 'resource:///org/gnome/shell/ui/unlockDialog.js';

const INPUT_SOURCES = 'org.gnome.desktop.input-sources';
// Input on the cover tries again, at most this often: GDM may still be bringing the login screen up.
const RETRY_MS = 3000;
const SWITCH_DELAY_MS = 150;

// [['xkb', 'th'], ['xkb', 'us']] for layouts 'th,us' and variants ','.
export function sourcesFromKeymap(layouts, variants) {
    const v = variants.split(',');
    return layouts.split(',').filter(l => l).map((l, i) => ['xkb', v[i] ? `${l}+${v[i]}` : l]);
}

// School accounts sign in with their address: the same test the login screen uses to pick the broker.
export function isSchoolAccount(userName) {
    return userName.includes('@');
}

export function syncKeyboard() {
    try {
        const v = Gio.DBus.system.call_sync(
            'org.freedesktop.locale1', '/org/freedesktop/locale1', 'org.freedesktop.DBus.Properties', 'GetAll',
            new GLib.Variant('(s)', ['org.freedesktop.locale1']), null, Gio.DBusCallFlags.NONE, 2000, null);
        const [props] = v.deepUnpack();
        const sources = sourcesFromKeymap(props['X11Layout'].unpack(), props['X11Variant'].unpack());
        if (!sources.length)
            return;
        const settings = new Gio.Settings({schema_id: INPUT_SOURCES});
        const want = new GLib.Variant('a(ss)', sources);
        if (!settings.get_value('sources').equal(want))
            settings.set_value('sources', want);
    } catch (e) {
        log(`mastersos-managed: keyboard: ${e.message ?? e}`);
    }
}

export class LockToGreeter {
    enable() {
        const ss = Main.screenShield;
        this._lastTry = 0;
        // The hidden unlock dialog must never talk to authd. The broker has one fixed redirect port, so a key press reaching the
        // locked desktop would start a sign-in with no card to show it, and that ends the one open on the login screen. _onReset
        // is the dialog's only way to begin. Unlocking does not need it: GDM unlocks when the school's page signs the person in.
        this._beginPrompt = UnlockDialog.prototype._onReset;
        UnlockDialog.prototype._onReset = function () {};
        ss.connectObject('locked-changed', () => this._sync(), this);
        LoginManager.getLoginManager().connectObject('prepare-for-sleep', (m, aboutToSuspend) => {
            if (!aboutToSuspend)
                this._sync();
        }, this);
        this._watchSession();
        this._sync();
    }

    async _watchSession() {
        const session = await LoginManager.getLoginManager().getCurrentSessionProxy();
        if (!session || this._disabled)
            return;
        this._session = session;
        this._sessionId = session.connect('g-properties-changed', () => this._sync());
    }

    _sync() {
        if (!Main.screenShield.locked) {
            this._uncover();
            return;
        }
        this._cover();
        if (!this._session || this._session.Active)
            this._toGreeter();
    }

    _cover() {
        if (this._blank)
            return;
        this._blank = new St.Widget({style: 'background-color: black;', reactive: true});
        this._blank.add_constraint(new Layout.MonitorConstraint({primary: true}));
        Main.layoutManager.screenShieldGroup.add_child(this._blank);
        this._capturedId = global.stage.connect('captured-event', (stage, event) => {
            const type = event.type();
            if (type === Clutter.EventType.KEY_PRESS || type === Clutter.EventType.BUTTON_PRESS)
                this._toGreeter();
            return Clutter.EVENT_PROPAGATE;
        });
    }

    _uncover() {
        if (!this._blank)
            return;
        global.stage.disconnect(this._capturedId);
        this._capturedId = 0;
        this._blank.destroy();
        this._blank = null;
    }

    _toGreeter() {
        const now = GLib.get_monotonic_time() / 1000;
        if (now - this._lastTry < RETRY_MS)
            return;
        this._lastTry = now;
        // After a moment so the cover reaches the screen first. Not a repaint function, as the shell's Switch User uses: a
        // session coming back from a VT switch may paint nothing, and then the switch would never happen.
        GLib.timeout_add(GLib.PRIORITY_DEFAULT, SWITCH_DELAY_MS, () => {
            try {
                Gdm.goto_login_session_sync(null);
            } catch (e) {
                log(`mastersos-managed: no login screen: ${e.message ?? e}`);
            }
            return GLib.SOURCE_REMOVE;
        });
    }

    disable() {
        this._disabled = true;
        UnlockDialog.prototype._onReset = this._beginPrompt;
        Main.screenShield.disconnectObject(this);
        LoginManager.getLoginManager().disconnectObject(this);
        if (this._session && this._sessionId)
            this._session.disconnect(this._sessionId);
        this._session = null;
        this._uncover();
    }
}
