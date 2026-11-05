// MastersOS managed-indicator extension, user session (loaded through the ubuntu.json session
// mode, so it also runs under the locked learning profile). Adds one row
// "This device is managed by <school>" (with the school's quick menu icon when there is one) to the quick
// settings menu. Reads /var/lib/mastersos-public/branding/branding.json; missing, broken or
// empty school_name adds nothing and never throws. Also runs while locked, for session.js.
// A "Get help" row under it opens the Get help dialog (help.js, the same file as the login screen's), when the school allows it
// (support.json) and the screen is not locked. Its text comes from the login extension's catalogues (gettext domain
// mastersos-login, one translation of every Get help text for both screens); the managed line keeps its own two languages.

import Gettext from 'gettext';
import St from 'gi://St';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import Clutter from 'gi://Clutter';

import * as BoxPointer from 'resource:///org/gnome/shell/ui/boxpointer.js';
import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import {Extension} from 'resource:///org/gnome/shell/extensions/extension.js';

import {LockToGreeter, isSchoolAccount, syncKeyboard} from './session.js';
import {HelpDialog, readSupportEnabled} from './help.js';
import {COPY} from './help-model.js';

const BRANDING = '/var/lib/mastersos-public/branding/branding.json';
// mkosi.build compiles login-i18n/*.po there; the login extension is installed (not enabled) in every session.
const LOGIN_LOCALE = '/usr/share/gnome-shell/extensions/mastersos-login@mastersos.org/locale';

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
    // Small and at 85 % opacity (design 2026-11-04 visual identity §5.4); St's CSS has no opacity, so the actor carries it
    const box = new St.BoxLayout({style_class: 'mastersos-brand-corner', y_align: Clutter.ActorAlign.CENTER, reactive: false, opacity: 217});
    box.add_child(new St.Icon({icon_name: 'mastersos-logo', icon_size: 20, y_align: Clutter.ActorAlign.CENTER}));
    box.add_child(new St.Bin({style_class: 'mastersos-brand-wordmark', y_align: Clutter.ActorAlign.CENTER}));
    return box;
}

// gettext for the mastersos-login domain, whatever the shell has bound for this extension.
function loginGettext() {
    Gettext.bindtextdomain('mastersos-login', LOGIN_LOCALE);
    const domain = Gettext.domain('mastersos-login');
    return s => domain.gettext(s);
}

export default class MastersosManagedExtension extends Extension {
    enable() {
        this._item = null;
        this._help = null;
        this._helpMenuId = 0;
        this._helpDialog = null;
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
            this._addHelp();
        } catch (e) {
            log(`mastersos-managed: Get help: ${e.message ?? e}`);
        }
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

    // A row at the top of the quick settings menu (under the managed line, which enable() inserts above it), shown each time
    // the menu opens if the school allows help requests and the screen is not locked.
    _addHelp() {
        const qs = Main.panel?.statusArea?.quickSettings;
        if (!qs?.menu?.box)
            return;
        const _ = loginGettext();
        const box = new St.BoxLayout({style_class: 'mastersos-help-row-content', x_expand: true});
        box.add_child(new St.Icon({
            icon_name: 'help-browser-symbolic',
            fallback_icon_name: 'dialog-question-symbolic',
            icon_size: 16,
            y_align: Clutter.ActorAlign.CENTER,
        }));
        box.add_child(new St.Label({text: _(COPY.entry), y_align: Clutter.ActorAlign.CENTER}));
        this._help = new St.Button({
            style_class: 'mastersos-help-row',
            child: box,
            x_expand: true,
            can_focus: true,
            reactive: true,
            accessible_name: _(COPY.entry),
        });
        this._help.connect('clicked', () => {
            // Closed at once, without the animation: the screenshot taken next is of the screen the student was looking at.
            qs.menu.close(BoxPointer.PopupAnimation.NONE);
            if (this._helpDialog)
                return;
            this._helpDialog = new HelpDialog({session: 'desktop', gettext: _});
            this._helpDialog.connect('destroy', () => {
                this._helpDialog = null;
            });
            this._helpDialog.open();
        });
        const sync = () => {
            if (this._help)
                this._help.visible = !Main.sessionMode.isLocked && readSupportEnabled();
        };
        sync();
        this._helpMenuId = qs.menu.connect('open-state-changed', (menu, open) => {
            if (open)
                sync();
        });
        qs.menu.box.insert_child_at_index(this._help, 0);
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
        // The desktop runs the ubuntu mode (ubuntu.json, parentMode user): currentMode alone is never 'user' there
        const mode = Main.sessionMode;
        if (mode.currentMode === 'user' || Main.sessionMode.parentMode === 'user')
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
        if (this._helpMenuId) {
            Main.panel?.statusArea?.quickSettings?.menu?.disconnect(this._helpMenuId);
            this._helpMenuId = 0;
        }
        this._helpDialog?.destroy();
        this._helpDialog = null;
        this._help?.destroy();
        this._help = null;
        if (this._item) {
            this._item.destroy();
            this._item = null;
        }
    }
}
