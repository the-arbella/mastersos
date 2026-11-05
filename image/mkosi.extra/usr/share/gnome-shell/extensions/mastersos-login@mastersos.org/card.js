// The sign-in card: the school's sign-in page in a locked-down Chrome, in the middle of the login screen. The panel
// (Wi-Fi, input method, volume, power) stays usable and Cancel is always there.
//
// The browser is mastersos-login-browser@<greeter user>.service (a system unit, so it gets its own Chrome policy directory); this file
// only hands it the URL, places its window and takes it down. Touching the greeter's internals here
// (Main.screenShield._dialog, ._grab, sessionMode.hasWindows, layoutManager._updateVisibility) is pinned to one
// gnome-shell version by build.sh: retest the card when that version moves.

import Clutter from 'gi://Clutter';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Meta from 'gi://Meta';
import Shell from 'gi://Shell';
import St from 'gi://St';

import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import {Spinner} from 'resource:///org/gnome/shell/ui/animation.js';

import {loginArea, underArea} from './area.js';
import {CARD_SETTINGS, idpHintFrom, withIdpHint} from './card-url.js';

const UNIT = `mastersos-login-browser@${GLib.get_user_name()}.service`;
const URL_FILE = 'mastersos-login-url';
// The page fills the login area. The inset keeps the window's square corners inside the area's round ones.
const CARD_INSET = 5;
// Chrome draws its own title bar in --app mode; the card crops that strip off the window.
const TITLE_BAR = 37;
const IDLE_CANCEL_MS = 3 * 60 * 1000;
const WINDOW_TIMEOUT_S = 30;
// The way out from the keyboard. Focus is inside Chrome, so only a compositor-level grab sees it, and a grab swallows the
// key: plain Esc belongs to the page (open lists, dialogs), Ctrl+Esc is unused by Chrome and web pages never get it.
const CANCEL_ACCELERATOR = '<Control>Escape';

// The school's idp_hint (card-url.js), read each time a card opens so new settings apply without a greeter restart.
// No file (no hint, or no SSO): null.
function readIdpHint() {
    try {
        const [, bytes] = GLib.file_get_contents(CARD_SETTINGS);
        return idpHintFrom(new TextDecoder().decode(bytes));
    } catch (e) {
        if (!e.matches?.(GLib.FileError, GLib.FileError.NOENT))
            log(`mastersos-login: ${CARD_SETTINGS} unreadable: ${e.message ?? e}`);
        return null;
    }
}

function systemd(method, unit) {
    Gio.DBus.system.call(
        'org.freedesktop.systemd1', '/org/freedesktop/systemd1', 'org.freedesktop.systemd1.Manager',
        method, new GLib.Variant('(ss)', [unit, 'replace']), null, Gio.DBusCallFlags.NONE, -1, null,
        (conn, res) => {
            try {
                conn.call_finish(res);
            } catch (e) {
                log(`mastersos-login: ${method} ${unit}: ${e.message}`);
            }
        });
}

export class LoginCard {
    constructor(text) {
        this._text = text;
        this._frame = null;
    }

    get isOpen() {
        return this._frame !== null;
    }

    // The object verifier signals are tied to; destroyed when the card closes.
    get owner() {
        return this._frame;
    }

    // Show the page at url; onCancel runs when the person leaves (Cancel, idle, window closed), onFailed when the browser
    // never shows a window. The card is closed by then in both cases.
    open(url, onCancel, onFailed) {
        this.close();
        this._onCancel = onCancel;
        this._onFailed = onFailed;
        this._enterCardMode();
        this._build();
        this._setStatus(this._text.opening, true);
        this._watchWindows();
        this._watchIdle();
        this._windowTimeoutId = GLib.timeout_add_seconds(GLib.PRIORITY_DEFAULT, WINDOW_TIMEOUT_S, () => {
            this._windowTimeoutId = 0;
            this._failed();
            return GLib.SOURCE_REMOVE;
        });
        try {
            const path = GLib.build_filenamev([GLib.get_user_runtime_dir(), URL_FILE]);
            GLib.file_set_contents_full(path, `${withIdpHint(url, readIdpHint())}\n`, GLib.FileSetContentsFlags.CONSISTENT, 0o600);
            systemd('RestartUnit', UNIT);
        } catch (e) {
            log(`mastersos-login: cannot start the browser: ${e.message}`);
            GLib.idle_add(GLib.PRIORITY_DEFAULT, () => {
                this._failed();
                return GLib.SOURCE_REMOVE;
            });
        }
    }

    close() {
        if (!this._frame)
            return;
        const frame = this._frame;
        this._frame = null;
        this._ungrabCancelKey();
        if (this._windowTimeoutId) {
            GLib.source_remove(this._windowTimeoutId);
            this._windowTimeoutId = 0;
        }
        if (this._idleWatch) {
            global.backend.get_core_idle_monitor().remove_watch(this._idleWatch);
            this._idleWatch = 0;
        }
        if (this._windowCreatedId) {
            global.display.disconnect(this._windowCreatedId);
            this._windowCreatedId = 0;
        }
        if (this._restackedId) {
            global.display.disconnect(this._restackedId);
            this._restackedId = 0;
        }
        if (this._capturedId) {
            global.stage.disconnect(this._capturedId);
            this._capturedId = 0;
        }
        this._forgetWindow();
        systemd('StopUnit', UNIT);
        Main.layoutManager.removeChrome(this._cancelBox);
        this._cancelBox.destroy();
        this._cancelBox = null;
        this._cancelButton = null;
        frame.destroy();
        this._scrim.destroy();
        this._scrim = null;
        this._status = null;
        this._leaveCardMode();
    }

    // The greeter normally shows no windows and holds a modal grab on the whole stage. Lift both for as long as the
    // card is up; the panel stays above everything.
    _enterCardMode() {
        const ss = Main.screenShield;
        Main.sessionMode.hasWindows = true;
        Main.layoutManager._updateVisibility();
        Main.layoutManager.screenShieldGroup.hide();
        for (const holder of [ss._dialog, ss]) {
            if (holder?._grab) {
                Main.popModal(holder._grab);
                holder._grab = null;
            }
        }
    }

    _leaveCardMode() {
        const dlg = Main.screenShield._dialog;
        Main.sessionMode.hasWindows = false;
        Main.layoutManager._updateVisibility();
        Main.layoutManager.screenShieldGroup.show();
        if (dlg)
            dlg._grab = Main.pushModal(global.stage, {actionMode: Shell.ActionMode.LOGIN_SCREEN});
    }

    _build() {
        const g = loginArea();
        const mon = Main.layoutManager.primaryMonitor;

        // Without something opaque under the panel the stage is not repainted behind it (the clock ghosts).
        this._scrim = new St.Widget({
            style_class: 'mastersos-card-scrim',
            x: mon.x, y: mon.y, width: mon.width, height: mon.height,
        });
        // The same darkening as the username step (.login-dialog), which the screen shield hides while the card shows
        this._scrim.add_child(new St.Widget({
            style_class: 'mastersos-card-scrim-shade',
            width: mon.width, height: mon.height,
        }));
        global.window_group.insert_child_below(this._scrim, null);

        this._frame = new St.BoxLayout({
            style_class: 'mastersos-card',
            orientation: Clutter.Orientation.VERTICAL,
            x: g.x, y: g.y, width: g.width, height: g.height,
        });
        global.window_group.insert_child_above(this._frame, this._scrim);

        this._status = new St.BoxLayout({
            orientation: Clutter.Orientation.VERTICAL,
            style_class: 'mastersos-card-status',
            x_expand: true,
            y_expand: true,
            x_align: Clutter.ActorAlign.CENTER,
            y_align: Clutter.ActorAlign.CENTER,
        });
        this._frame.add_child(this._status);

        const band = underArea();
        this._cancelBox = new St.Bin({
            width: band.width,
            height: band.height,
            x_align: Clutter.ActorAlign.CENTER,
            y_align: Clutter.ActorAlign.CENTER,
        });
        this._cancelButton = new St.Button({
            label: `${this._text.cancel}  (${this._text.cancelKey})`,
            style_class: 'mastersos-card-cancel',
            can_focus: true,
            reactive: true,
        });
        this._cancelButton.connect('clicked', () => this._cancelled());
        this._cancelBox.set_child(this._cancelButton);
        this._grabCancelKey();
        Main.layoutManager.addTopChrome(this._cancelBox);
        this._cancelBox.set_position(band.x, band.y);
    }

    _grabCancelKey() {
        const display = global.display;
        this._cancelAction = display.grab_accelerator(CANCEL_ACCELERATOR, Meta.KeyBindingFlags.NONE);
        if (this._cancelAction === Meta.KeyBindingAction.NONE) {
            log('mastersos-login: could not grab the cancel key');
            return;
        }
        Main.wm.allowKeybinding(Meta.external_binding_name_for_action(this._cancelAction), Shell.ActionMode.ALL);
        this._acceleratorId = display.connect('accelerator-activated', (d, action) => {
            if (action === this._cancelAction)
                this._cancelled();
        });
    }

    _ungrabCancelKey() {
        if (this._acceleratorId) {
            global.display.disconnect(this._acceleratorId);
            this._acceleratorId = 0;
        }
        if (this._cancelAction) {
            global.display.ungrab_accelerator(this._cancelAction);
            this._cancelAction = 0;
        }
    }

    _setStatus(body, busy) {
        if (!this._status)
            return;
        this._status.destroy_all_children();
        if (busy) {
            const spinner = new Spinner(32, {hideOnStop: true});
            spinner.play();
            spinner.x_align = Clutter.ActorAlign.CENTER;
            this._status.add_child(spinner);
        }
        const label = new St.Label({
            text: body,
            style_class: 'mastersos-card-status-body',
            x_align: Clutter.ActorAlign.CENTER,
        });
        label.clutter_text.line_wrap = true;
        this._status.add_child(label);
    }

    _watchIdle() {
        const monitor = global.backend.get_core_idle_monitor();
        this._idleWatch = monitor.add_idle_watch(IDLE_CANCEL_MS, () => {
            this._idleWatch = 0;
            this._cancelled();
        });
        // A click on the card goes to Chrome, not to the panel's menu: close that menu here.
        this._capturedId = global.stage.connect('captured-event', (stage, event) => {
            if (event.type() === Clutter.EventType.BUTTON_PRESS)
                this._closePanelMenusOutside(event);
            return Clutter.EVENT_PROPAGATE;
        });
    }

    _closePanelMenusOutside(event) {
        const [x, y] = event.get_coords();
        const g = loginArea();
        if (x >= g.x && x < g.x + g.width && y >= g.y && y < g.y + g.height)
            Main.panel.menuManager?.activeMenu?.close();
    }

    _keepBehind() {
        if (!this._frame)
            return;
        global.window_group.set_child_below_sibling(this._frame, null);
        global.window_group.set_child_below_sibling(this._scrim, null);
    }

    _watchWindows() {
        this._windowCreatedId = global.display.connect('window-created', (d, win) => this._adopt(win));
        // Mutter restacks the window group whenever a window is focused: keep the card behind the window.
        this._restackedId = global.display.connect('restacked', () => this._keepBehind());
    }

    // The card is one window. Anything else the browser opens is closed on sight, whatever the policy missed.
    _adopt(win) {
        if (this._window) {
            log(`mastersos-login: closing an extra window (${win.get_wm_class()})`);
            GLib.idle_add(GLib.PRIORITY_DEFAULT, () => {
                win.delete(global.get_current_time());
                return GLib.SOURCE_REMOVE;
            });
            return;
        }
        this._window = win;
        this._windowIds = [
            win.connect('size-changed', () => this._place()),
            win.connect('position-changed', () => this._place()),
            win.connect('unmanaging', () => {
                this._forgetWindow();
                if (this._frame)
                    this._cancelled();
            }),
        ];
        const actor = win.get_compositor_private();
        if (actor)
            this._firstFrameId = actor.connect('first-frame', () => this._shown());
        this._place();
    }

    _forgetWindow() {
        if (!this._window)
            return;
        const win = this._window;
        this._window = null;
        for (const id of this._windowIds)
            win.disconnect(id);
        this._windowIds = [];
        const actor = win.get_compositor_private();
        if (actor && this._firstFrameId) {
            actor.disconnect(this._firstFrameId);
            actor.remove_clip();
        }
        this._firstFrameId = 0;
    }

    _shown() {
        if (this._windowTimeoutId) {
            GLib.source_remove(this._windowTimeoutId);
            this._windowTimeoutId = 0;
        }
        this._setStatus('', false);
        this._window?.activate(global.get_current_time());
        this._place();
    }

    // The window sits inside the card with its title bar cropped off the top of the card's body.
    _place() {
        const win = this._window;
        if (!win || !this._frame || this._placing)
            return;
        this._placing = true;
        try {
            const g = loginArea();
            const width = g.width - 2 * CARD_INSET;
            const height = g.height - 2 * CARD_INSET + TITLE_BAR;
            const x = g.x + CARD_INSET;
            const y = g.y + CARD_INSET - TITLE_BAR;
            if (win.is_fullscreen())
                win.unmake_fullscreen();
            if (win.get_maximize_flags?.())
                win.unmaximize();
            const r = win.get_frame_rect();
            if (r.x !== x || r.y !== y || r.width !== width || r.height !== height)
                win.move_resize_frame(true, x, y, width, height);
            const actor = win.get_compositor_private();
            if (actor) {
                const b = win.get_buffer_rect();
                const f = win.get_frame_rect();
                const dx = f.x - b.x, dy = f.y - b.y;
                actor.set_clip(dx, dy + TITLE_BAR, f.width, f.height - TITLE_BAR);
            }
        } finally {
            this._placing = false;
        }
    }

    _cancelled() {
        const cb = this._onCancel;
        this._onCancel = this._onFailed = null;
        this.close();
        cb?.();
    }

    _failed() {
        const cb = this._onFailed;
        this._onCancel = this._onFailed = null;
        this.close();
        cb?.();
    }
}
