// The row of pill buttons at the bottom left of the login screen: Shut down, Browse as Guest, Apps. The notice
// (why a sign-in did not go through, with Retry when trying again can help) sits beside it, outside the login area.
// Apps lists the locked apps the school shows on the login screen, read from /var/lib/mastersos-public/kiosk/<id>/.

import Clutter from 'gi://Clutter';
import Gio from 'gi://Gio';
import Pango from 'gi://Pango';
import GLib from 'gi://GLib';
import St from 'gi://St';

import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import * as PopupMenu from 'resource:///org/gnome/shell/ui/popupMenu.js';
import {setShelfHeight} from './area.js';
import {cleanText} from './strings.js';

export const KIOSK_DIR = '/var/lib/mastersos-public/kiosk';
const APP_ID = /^[a-z0-9][a-z0-9-]{0,30}$/;
const SHELF_MARGIN = 24;
const NOTICE_GAP = 16;
// Room for the accessibility button in the far corner.
const NOTICE_END = 88;

// One entry per app the login screen should show. An app the school keeps off the login screen has
// SystemAccount=true in its AccountsService record (kiosk.rs render_accounts).
export function readApps(dir = KIOSK_DIR) {
    const apps = [];
    try {
        const e = Gio.File.new_for_path(dir).enumerate_children('standard::name', Gio.FileQueryInfoFlags.NONE, null);
        for (let info = e.next_file(null); info; info = e.next_file(null)) {
            const id = info.get_name();
            if (APP_ID.test(id)) {
                const app = readApp(dir, id);
                if (app)
                    apps.push(app);
            }
        }
        e.close(null);
    } catch (err) {
        if (!err.matches?.(Gio.IOErrorEnum, Gio.IOErrorEnum.NOT_FOUND))
            log(`mastersos-login: kiosk list unreadable: ${err.message ?? err}`);
    }
    return apps.sort((a, b) => a.name.localeCompare(b.name));
}

function readApp(dir, id) {
    try {
        const base = `${dir}/${id}`;
        const [, bytes] = Gio.File.new_for_path(`${base}/launch.json`).load_contents(null);
        const name = cleanText(JSON.parse(new TextDecoder().decode(bytes))?.name, 80);
        const kf = new GLib.KeyFile();
        kf.load_from_file(`${base}/accountsservice`, GLib.KeyFileFlags.NONE);
        if (!name || kf.get_boolean('User', 'SystemAccount'))
            return null;
        const icon = GLib.file_test(`${base}/icon`, GLib.FileTest.IS_REGULAR) ? `${base}/icon` : null;
        const kind = JSON.parse(new TextDecoder().decode(bytes))?.kind?.type;
        return {id, name, user: `kiosk-${id}`, icon, needsNetwork: kind === 'web' || kind === 'pwa'};
    } catch (err) {
        log(`mastersos-login: kiosk app ${id} unreadable: ${err.message ?? err}`);
        return null;
    }
}

function pill(iconName, label, onClick) {
    const box = new St.BoxLayout({style_class: 'mastersos-pill-content'});
    box.add_child(new St.Icon({icon_name: iconName, style_class: 'mastersos-pill-icon'}));
    box.add_child(new St.Label({text: label, y_align: Clutter.ActorAlign.CENTER}));
    const button = new St.Button({
        style_class: 'mastersos-pill',
        child: box,
        can_focus: true,
        reactive: true,
        accessible_name: label,
    });
    button.connect('clicked', onClick);
    return button;
}

export class Shelf {
    // actions: {shutDown(), guest(), openApp(app)}
    constructor(text, managedLine, actions) {
        this._actions = actions;
        this._text = text;
        this._apps = [];

        this.actor = new St.BoxLayout({style_class: 'mastersos-shelf', orientation: Clutter.Orientation.VERTICAL});
        this._managed = new St.Label({
            style_class: 'mastersos-login-managed',
            x_align: Clutter.ActorAlign.START,
            visible: false,
        });
        this.actor.add_child(this._managed);
        this._row = new St.BoxLayout({style_class: 'mastersos-shelf-row'});
        this.actor.add_child(this._row);

        this._row.add_child(pill('system-shutdown-symbolic', text.shutDown, () => actions.shutDown()));
        this._guest = pill('avatar-default-symbolic', text.guest, () => actions.guest());
        this._guest.hide();
        this._row.add_child(this._guest);
        this._appsButton = pill('view-app-grid-symbolic', text.apps, () => this._toggleApps());
        this._appsButton.hide();
        this._row.add_child(this._appsButton);

        this._noticeBox = new St.BoxLayout({style_class: 'mastersos-notice', visible: false});
        this._notice = new St.Label({
            style_class: 'mastersos-login-refusal',
            x_expand: true,
            y_align: Clutter.ActorAlign.CENTER,
        });
        this._notice.clutter_text.line_wrap = true;
        this._notice.clutter_text.ellipsize = Pango.EllipsizeMode.NONE;
        this._noticeBox.add_child(this._notice);
        this._retry = new St.Button({
            label: text.retry,
            style_class: 'mastersos-notice-retry',
            can_focus: true,
            reactive: true,
            y_align: Clutter.ActorAlign.CENTER,
        });
        this._retry.connect('clicked', () => this._onRetry?.());
        this._noticeBox.add_child(this._retry);

        // Lives in the shield group, so it goes away together with the login dialog when the card is up.
        Main.layoutManager.screenShieldGroup.add_child(this.actor);
        Main.layoutManager.screenShieldGroup.add_child(this._noticeBox);
        this._monitorsId = Main.layoutManager.connect('monitors-changed', () => this._reposition());
        this._allocId = this.actor.connect('notify::height', () => this._reposition());
        this.actor.connect('notify::width', () => this._reposition());
        this.setManaged(managedLine);
        this.refreshApps();
    }

    // "Managed by <school>", or nothing when there is no school name.
    setManaged(line) {
        this._managed.text = line ?? '';
        this._managed.visible = !!line;
        this._reposition();
    }

    // onRetry null: no Retry button.
    showNotice(text, onRetry) {
        this._notice.text = text;
        this._onRetry = onRetry;
        this._retry.visible = onRetry !== null;
        this._noticeBox.show();
        this._reposition();
        if (onRetry)
            this._retry.grab_key_focus();
    }

    hideNotice() {
        this._onRetry = null;
        this._noticeBox.hide();
    }

    setGuestAvailable(available) {
        this._guest.visible = available;
        this._reposition();
    }

    // An open Apps menu closes when the apps changed under it (new settings while the login screen is up).
    refreshApps() {
        const apps = readApps();
        if (this._menu && JSON.stringify(apps) !== JSON.stringify(this._apps))
            this._scheduleClose();
        this._apps = apps;
        this._appsButton.visible = this._apps.length > 0;
        this._reposition();
    }

    _reposition() {
        const mon = Main.layoutManager.primaryMonitor;
        if (!mon)
            return;
        const [, natH] = this.actor.get_preferred_height(-1);
        const [, natW] = this.actor.get_preferred_width(-1);
        setShelfHeight(natH + 2 * SHELF_MARGIN);
        const rtl = Clutter.get_default_text_direction() === Clutter.TextDirection.RTL;
        const bottom = mon.y + mon.height - SHELF_MARGIN;
        const x = rtl ? mon.x + mon.width - SHELF_MARGIN - natW : mon.x + SHELF_MARGIN;
        this.actor.set_position(x, bottom - natH);
        // The parent is a bin layout, which in RTL pushes a child to the far edge whatever its x: put it back.
        this.actor.translation_x = rtl ? -SHELF_MARGIN : 0;

        const width = Math.max(mon.width - natW - 2 * SHELF_MARGIN - NOTICE_GAP - NOTICE_END, 0);
        this._noticeBox.width = width;
        // A horizontal box asks its children for their height without a width, which is one line however long the text is.
        const [, retryW] = this._retry.visible ? this._retry.get_preferred_width(-1) : [0, 0];
        const noticeH = Math.max(this._noticeBox.get_preferred_height(width)[1],
            this._notice.get_preferred_height(width - retryW - NOTICE_GAP)[1]);
        this._noticeBox.height = noticeH;
        this._noticeBox.set_position(
            rtl ? mon.x + NOTICE_END : mon.x + SHELF_MARGIN + natW + NOTICE_GAP, bottom - noticeH);
        this._noticeBox.translation_x = rtl ? NOTICE_END - (mon.width - width) : 0;
    }

    _toggleApps() {
        if (this._menu) {
            this._closeMenu();
            return;
        }
        const menu = new PopupMenu.PopupMenu(this._appsButton, 0.0, St.Side.BOTTOM);
        // The box pointer aims at the middle of its source by default: line the menu up with the button instead.
        menu.setSourceAlignment(0.0);
        for (const app of this._apps) {
            const item = new PopupMenu.PopupBaseMenuItem();
            const icon = new St.Icon({style_class: 'mastersos-app-icon'});
            if (app.icon)
                icon.gicon = new Gio.FileIcon({file: Gio.File.new_for_path(app.icon)});
            else
                icon.icon_name = 'application-x-executable-symbolic';
            item.add_child(icon);
            const label = new St.Label({text: app.name, y_align: Clutter.ActorAlign.CENTER});
            item.add_child(label);
            item.label_actor = label;
            item.connect('activate', () => {
                this._scheduleClose();
                this._actions.openApp(app);
            });
            menu.addMenuItem(item);
        }
        Main.uiGroup.add_child(menu.actor);
        menu.actor.hide();
        this._menu = menu;
        this._menuManager = new PopupMenu.PopupMenuManager(this._appsButton);
        this._menuManager.addMenu(menu);
        menu.connect('open-state-changed', (m, open) => {
            if (!open)
                this._scheduleClose();
        });
        menu.open();
    }

    // Never destroy the menu inside its own signal emission.
    _scheduleClose() {
        if (this._closeId)
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
            m.destroy();
        }
        this._menuManager = null;
    }

    destroy() {
        if (this._closeId)
            GLib.source_remove(this._closeId);
        this._closeId = 0;
        this._closeMenu();
        Main.layoutManager.disconnect(this._monitorsId);
        this.actor.destroy();
        this._noticeBox.destroy();
    }
}
