// MastersOS managed-indicator extension, user session (loaded through the ubuntu.json session
// mode, so it also runs under the locked learning profile). Adds one row
// "This device is managed by <school>" (with the school's quick menu icon when there is one) to the quick
// settings menu. Reads /var/lib/mastersos-public/branding/branding.json; missing, broken or
// empty school_name adds nothing and never throws. Also runs while locked, for session.js.

import St from 'gi://St';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Clutter from 'gi://Clutter';

import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';

import {LockToGreeter, isSchoolAccount, syncKeyboard} from './session.js';

const BRANDING = '/var/lib/mastersos-public/branding/branding.json';

const STRINGS = {
    en: {managed: 'This device is managed by %s'},
    'zh-Hans': {managed: '此设备由 %s 管理'},
};

function pickLang() {
    try {
        for (const l of GLib.get_language_names()) {
            if (/^zh([_-]|@|\.|$)/.test(l) && /(TW|HK|MO|Hant)/.test(l))
                return 'en';
            if (/^zh(_(CN|SG))?([.@]|$)/.test(l))
                return 'zh-Hans';
            if (/^en([_.@]|$)/.test(l))
                return 'en';
        }
    } catch (e) {
        // fall through to English
    }
    return 'en';
}

// Strip control and bidi characters, cap the length: the name is shown as plain text only.
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]/g;
function cleanText(v, max) {
    return typeof v === 'string' ? v.replace(UNSAFE, '').trim().slice(0, max) : '';
}

function fmt(template, name) {
    return template.split('%s').join(name);
}

function readBranding() {
    try {
        const f = Gio.File.new_for_path(BRANDING);
        const [ok, bytes] = f.load_contents(null);
        if (!ok)
            return null;
        const data = JSON.parse(new TextDecoder().decode(bytes));
        return data && typeof data === 'object' && !Array.isArray(data) ? data : null;
    } catch (e) {
        log(`mastersos-managed: branding unreadable: ${e.message ?? e}`);
        return null;
    }
}

// The MastersOS mark at the start of the top bar while the screen is locked, and a translucent top bar in the session
// (design 2026-11-04 visual identity §5.4–5.5). The login screen's mark is mastersos-login's; same class names.
function brandMark() {
    const box = new St.BoxLayout({style_class: 'mastersos-brand-corner', y_align: Clutter.ActorAlign.CENTER, reactive: false});
    box.add_child(new St.Icon({icon_name: 'mastersos-logo', icon_size: 20, y_align: Clutter.ActorAlign.CENTER}));
    box.add_child(new St.Bin({style_class: 'mastersos-brand-wordmark', y_align: Clutter.ActorAlign.CENTER}));
    return box;
}

export default class MastersosManagedExtension extends Extension {
    enable() {
        this._item = null;
        this._brand = null;
        this._modeId = 0;
        try {
            this._syncLook();
            this._modeId = Main.sessionMode.connect('updated', () => this._syncLook());
        } catch (e) {
            log(`mastersos-managed: look: ${e.message ?? e}`);
        }
        syncKeyboard();
        if (isSchoolAccount(GLib.get_user_name())) {
            this._lock = new LockToGreeter();
            this._lock.enable();
        }
        // Every account keeps this extension while locked: the lock screen shows the MastersOS mark (_syncLook)
        this._stayWhileLocked();
        try {
            const b = readBranding();
            const name = cleanText(b?.school_name, 100);
            if (!name)
                return;
            const qs = Main.panel?.statusArea?.quickSettings;
            if (!qs?.menu?.box) {
                log('mastersos-managed: quickSettings not available');
                return;
            }
            const box = new St.BoxLayout({style_class: 'mastersos-managed-row', x_expand: true});
            box.set_style('padding: 8px 16px; spacing: 8px;');
            // logo_icon is the 40 x 40 quick menu icon (shown at 20 px, 40 px on HiDPI); the
            // 96 px high sign-in logo in `logo` is GDM's and is not used here.
            let schoolIcon = null;
            if (typeof b.logo_icon === 'string' && b.logo_icon) {
                const file = Gio.File.new_for_path(b.logo_icon);
                if (file.query_exists(null)) {
                    schoolIcon = new St.Icon({icon_size: 20});
                    schoolIcon.gicon = new Gio.FileIcon({file});
                }
            }
            // Without the school's icon, the MastersOS one (symbolic, follows the menu's colour)
            box.add_child(schoolIcon ?? new St.Icon({icon_name: 'mastersos-logo-symbolic', icon_size: 20}));
            box.add_child(new St.Label({
                text: fmt(STRINGS[pickLang()].managed, name),
                y_align: Clutter.ActorAlign.CENTER,
            }));
            this._item = new St.Bin({child: box, reactive: false});
            qs.menu.box.insert_child_at_index(this._item, 0);
        } catch (e) {
            log(`mastersos-managed: enable failed: ${e.message ?? e}`);
            this.disable();
        }
    }

    // This extension is enabled through ubuntu.json, and the lock screen's session mode has no such list of its own: session-modes
    // in metadata.json lets it run there, this keeps it on the list while the mode is unlock-dialog.
    _stayWhileLocked() {
        const manager = Main.extensionManager;
        if (this._modeExtensions)
            return;
        this._modeExtensions = manager._getModeExtensions;
        const original = this._modeExtensions;
        const {uuid} = this;
        manager._getModeExtensions = function () {
            const list = original.call(this);
            return list.includes(uuid) ? list : [...list, uuid];
        };
    }

    // Locked: the mark in the top bar. In the session: the translucent bar. Elsewhere (overview styles, login) nothing.
    _syncLook() {
        const panel = Main.panel;
        if (!panel)
            return;
        const locked = Main.sessionMode.currentMode === 'unlock-dialog';
        if (locked && !this._brand && panel._leftBox) {
            this._brand = brandMark();
            panel._leftBox.insert_child_at_index(this._brand, 0);
        } else if (!locked && this._brand) {
            this._brand.destroy();
            this._brand = null;
        }
        if (Main.sessionMode.currentMode === 'user')
            panel.add_style_class_name('mastersos-panel');
        else
            panel.remove_style_class_name('mastersos-panel');
    }

    disable() {
        if (this._modeId) {
            Main.sessionMode.disconnect(this._modeId);
            this._modeId = 0;
        }
        this._brand?.destroy();
        this._brand = null;
        Main.panel?.remove_style_class_name('mastersos-panel');
        if (this._modeExtensions) {
            delete Main.extensionManager._getModeExtensions;
            this._modeExtensions = null;
        }
        this._lock?.disable();
        this._lock = null;
        if (this._item) {
            this._item.destroy();
            this._item = null;
        }
    }
}
