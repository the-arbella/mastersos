// The language and keyboard screen: first run, and the Language item in the top bar's keyboard menu. Both are system settings
// and localectl is where they live, so this file only offers the choice, writes it and ends the greeter's own session; GDM
// starts the greeter again, in the new language, and nothing here switches languages live. The language list comes from
// the image (the language packs it carries, for the locales it really has), the keyboards from evdev.xml through
// libgnome-desktop.

import Clutter from 'gi://Clutter';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import GnomeDesktop from 'gi://GnomeDesktop?version=4.0';
import St from 'gi://St';

import * as Main from 'resource:///org/gnome/shell/ui/main.js';
import {ensureActorVisibleInScrollView} from 'resource:///org/gnome/shell/misc/animationUtils.js';

import {loginArea} from './area.js';
import {cleanText} from './strings.js';

const LANGUAGE_PACKS = '/usr/share/locale-langpack';
const LOCALE_CONF = '/etc/locale.conf';
const DEFAULT_LOCALE = 'en_US.UTF-8';
const DEFAULT_LAYOUT = 'us';
// The evdev.xml layouts whose first level has no Latin letters (found by compiling each layout with libxkbcommon and reading
// the letter keys). Nobody can type a school address on these alone, so US comes along as the second layout.
const NON_LATIN = new Set(
    'af am ara bd bg brai bt by eg et ge gn gr il in iq ir kg kh kz la lk ma mk mm mn mv my np pk rs ru sy th tj tz ua uz'.split(' '));

// Where the first country in the alphabet is not the language's home (ca_AD, el_CY, sv_FI).
const MAIN_COUNTRY = {ar: 'EG', ca: 'ES', crh: 'UA', el: 'GR', en: 'US', sr: 'RS', sv: 'SE'};

// The locale for a language pack's directory name ('th', 'zh_CN', 'sr@latin'), among the locales the image has: the exact
// one, else the language's own country ('de' -> de_DE), else the first with that language. null when there is none.
export function localeForPack(pack, locales) {
    const [name, modifier] = pack.split('@');
    const tail = modifier ? `.UTF-8@${modifier}` : '.UTF-8';
    const [lang, country] = name.split('_');
    const own = `${lang}_${country ?? MAIN_COUNTRY[lang] ?? lang.toUpperCase()}${tail}`;
    if (locales.includes(own))
        return own;
    if (country)
        return null;
    return locales.find(l => l.startsWith(`${lang}_`) && l.endsWith(tail)) ?? null;
}

// What localectl gets for a keyboard id ('th', 'us+dvorak'): layouts and variants, US added after a non-Latin layout.
export function keymapArgs(id) {
    const [layout, variant = ''] = id.split('+');
    return NON_LATIN.has(layout) ? [`${layout},us`, `${variant},`] : [layout, variant];
}

// 'be_BY.UTF-8@latin' and 'be_BY.utf8@latin' are the same locale.
function normal(locale) {
    return locale.replace(/\.[^@]*/, '');
}

function languages() {
    const locales = GnomeDesktop.get_all_locales().sort();
    const out = [];
    try {
        const e = Gio.File.new_for_path(LANGUAGE_PACKS).enumerate_children('standard::name', Gio.FileQueryInfoFlags.NONE, null);
        for (let info = e.next_file(null); info; info = e.next_file(null)) {
            const pack = info.get_name();
            // English has one line: the regional English directories are not languages of their own.
            const locale = pack.startsWith('en') && /^en(_|@|$)/.test(pack)
                ? pack === 'en' ? DEFAULT_LOCALE : null
                : localeForPack(pack, locales);
            if (locale)
                out.push({pack, locale, code: pack.replace(/[_@].*/, ''), country: locale.slice(3, 5)});
        }
        e.close(null);
    } catch (err) {
        log(`mastersos-login: language packs unreadable: ${err.message}`);
    }
    if (!out.some(l => l.locale === DEFAULT_LOCALE))
        out.push({pack: 'en', locale: DEFAULT_LOCALE, code: 'en', country: 'US'});
    const name = l => cleanText(GnomeDesktop.get_language_from_code(l.code, l.locale), 60);
    return out
        .map(l => ({
            ...l,
            label: (out.some(o => o !== l && o.code === l.code)
                ? cleanText(GnomeDesktop.get_language_from_locale(l.locale, l.locale), 60) : name(l)) || l.pack,
        }))
        .sort((a, b) => a.label.localeCompare(b.label));
}

function suggestedKeyboard(language, xkb) {
    if (language.code === 'en')
        return DEFAULT_LAYOUT;
    const [ok, type, id] = GnomeDesktop.get_input_source_from_locale(language.locale);
    if (ok && type === 'xkb')
        return id;
    const ids = xkb.get_layouts_for_language(language.code);
    const country = language.country.toLowerCase();
    return ids.find(i => i === country) ?? ids.find(i => !i.includes('+')) ?? DEFAULT_LAYOUT;
}

function keyboards(language, xkb, selected) {
    const name = id => xkb.get_layout_info(id)[1] ?? id;
    const own = xkb.get_layouts_for_language(language.code);
    const rest = xkb.get_all_layouts().filter(id => !id.includes('+') && !own.includes(id));
    const byName = (a, b) => name(a).localeCompare(name(b));
    const ids = [selected, ...own.sort(byName), ...rest.sort(byName)];
    return [...new Set(ids)].map(id => ({id, label: cleanText(name(id), 80) || id}));
}

function currentLocale() {
    try {
        const [, bytes] = GLib.file_get_contents(LOCALE_CONF);
        return new TextDecoder().decode(bytes).match(/^LANG="?([^"\n]+)/m)?.[1] ?? null;
    } catch {
        return null; // no file yet: not set
    }
}

// The system language is set: the first-run choice has been made, here or by the school, and a factory reset clears it.
export function languageChosen() {
    return currentLocale() !== null;
}

function currentKeyboard() {
    try {
        const v = Gio.DBus.system.call_sync(
            'org.freedesktop.locale1', '/org/freedesktop/locale1', 'org.freedesktop.DBus.Properties', 'GetAll',
            new GLib.Variant('(s)', ['org.freedesktop.locale1']), null, Gio.DBusCallFlags.NONE, 2000, null);
        const [props] = v.deepUnpack();
        const layout = props['X11Layout'].unpack().split(',')[0];
        const variant = props['X11Variant'].unpack().split(',')[0];
        return layout ? `${layout}${variant ? `+${variant}` : ''}` : DEFAULT_LAYOUT;
    } catch (e) {
        log(`mastersos-login: keyboard unreadable: ${e.message}`);
        return DEFAULT_LAYOUT;
    }
}

async function localectl(...args) {
    const proc = Gio.Subprocess.new(
        ['localectl', '--no-ask-password', ...args], Gio.SubprocessFlags.STDERR_PIPE);
    const [, , stderr] = await new Promise((resolve, reject) => {
        proc.communicate_utf8_async(null, null, (p, res) => {
            try {
                resolve(p.communicate_utf8_finish(res));
            } catch (e) {
                reject(e);
            }
        });
    });
    if (!proc.get_successful())
        throw new Error(`localectl ${args[0]}: ${stderr?.trim()}`);
}

// Ends the session this greeter runs in. GDM brings the greeter back; the desktops kept behind it are other sessions.
export function restartGreeter() {
    Gio.DBus.system.call(
        'org.freedesktop.login1', '/org/freedesktop/login1/session/auto', 'org.freedesktop.login1.Session', 'Terminate',
        null, null, Gio.DBusCallFlags.NONE, -1, null, (conn, res) => {
            try {
                conn.call_finish(res);
            } catch (e) {
                log(`mastersos-login: cannot end the greeter session: ${e.message}`);
            }
        });
}

function item(label, onPick) {
    const button = new St.Button({
        style_class: 'mastersos-setup-item',
        child: new St.Label({text: label, x_align: Clutter.ActorAlign.START, x_expand: true}),
        can_focus: true,
        reactive: true,
        toggle_mode: true,
        x_expand: true,
        x_align: Clutter.ActorAlign.FILL,
    });
    button.connect('clicked', () => onPick());
    return button;
}

function column(heading) {
    const box = new St.BoxLayout({orientation: Clutter.Orientation.VERTICAL, style_class: 'mastersos-setup-column', x_expand: true, y_expand: true});
    box.add_child(new St.Label({text: heading, style_class: 'mastersos-setup-heading'}));
    const list = new St.BoxLayout({orientation: Clutter.Orientation.VERTICAL, x_expand: true});
    const scroll = new St.ScrollView({
        child: list,
        hscrollbar_policy: St.PolicyType.NEVER,
        vscrollbar_policy: St.PolicyType.AUTOMATIC,
        x_expand: true,
        y_expand: true,
    });
    box.add_child(scroll);
    return {box, list, scroll};
}

export class LanguageScreen {
    // onCancel null: first run, the choice cannot be skipped.
    constructor(text, onCancel) {
        this._text = text;
        this._onCancel = onCancel;
        this._xkb = new GnomeDesktop.XkbInfo();
        this._languages = languages();
        const locale = currentLocale() ?? DEFAULT_LOCALE;
        const lang = locale.split('.')[0];
        // One row per language: a machine set to another country's variant still opens on its language, not on English.
        this._language = this._languages.find(l => l.locale.split('.')[0] === lang) ??
            this._languages.find(l => l.code === lang.split('_')[0]) ??
            this._languages.find(l => l.locale === DEFAULT_LOCALE) ?? this._languages[0];
        this._was = {locale: currentLocale(), keyboard: currentKeyboard()};
        this._keyboard = this._was.keyboard;

        const a = loginArea();
        this.actor = new St.BoxLayout({
            style_class: 'mastersos-setup',
            orientation: Clutter.Orientation.VERTICAL,
            x: a.x, y: a.y, width: a.width, height: a.height,
        });
        const columns = new St.BoxLayout({style_class: 'mastersos-setup-columns', x_expand: true, y_expand: true});
        this._languageColumn = column(text.language);
        this._keyboardColumn = column(text.keyboard);
        columns.add_child(this._languageColumn.box);
        columns.add_child(this._keyboardColumn.box);
        this.actor.add_child(columns);

        const footer = new St.BoxLayout({style_class: 'mastersos-setup-footer', x_expand: true});
        this._problem = new St.Label({style_class: 'mastersos-login-refusal', x_expand: true, y_align: Clutter.ActorAlign.CENTER});
        footer.add_child(this._problem);
        if (onCancel) {
            const cancel = new St.Button({label: text.cancel, style_class: 'mastersos-card-cancel', can_focus: true, reactive: true});
            cancel.connect('clicked', () => onCancel());
            footer.add_child(cancel);
        }
        this._continue = new St.Button({label: text.continueLabel, style_class: 'mastersos-setup-continue', can_focus: true, reactive: true});
        this._continue.connect('clicked', () => this._apply());
        footer.add_child(this._continue);
        this.actor.add_child(footer);

        for (const l of this._languages) {
            l.button = item(l.label, () => this._pickLanguage(l));
            l.button.connect('key-focus-in', () => ensureActorVisibleInScrollView(this._languageColumn.scroll, l.button));
            this._languageColumn.list.add_child(l.button);
        }
        this._syncLanguage();
        this._fillKeyboards();

        // The shield group's bin layout would stretch anything with an expanding child: a fixed layout keeps the area.
        this._holder = new St.Widget({layout_manager: new Clutter.FixedLayout(), x_expand: true, y_expand: true});
        this._holder.add_child(this.actor);
        Main.layoutManager.screenShieldGroup.add_child(this._holder);
        global.focus_manager.add_group(this.actor);
        GLib.idle_add(GLib.PRIORITY_DEFAULT, () => {
            this._language?.button?.grab_key_focus();
            if (this._language?.button)
                ensureActorVisibleInScrollView(this._languageColumn.scroll, this._language.button);
            return GLib.SOURCE_REMOVE;
        });
    }

    _syncLanguage() {
        for (const l of this._languages)
            l.button.checked = l === this._language;
    }

    _pickLanguage(language) {
        this._language = language;
        this._keyboard = suggestedKeyboard(language, this._xkb);
        this._syncLanguage();
        this._fillKeyboards();
    }

    _fillKeyboards() {
        const list = this._keyboardColumn.list;
        list.destroy_all_children();
        this._keyboardButtons = new Map();
        for (const k of keyboards(this._language, this._xkb, this._keyboard)) {
            const button = item(k.label, () => this._pickKeyboard(k.id));
            button.checked = k.id === this._keyboard;
            button.connect('key-focus-in', () => ensureActorVisibleInScrollView(this._keyboardColumn.scroll, button));
            this._keyboardButtons.set(k.id, button);
            list.add_child(button);
        }
    }

    _pickKeyboard(id) {
        this._keyboard = id;
        for (const [k, button] of this._keyboardButtons)
            button.checked = k === id;
    }

    async _apply() {
        const {locale} = this._language;
        const sameKeyboard = this._keyboard === this._was.keyboard && this._was.locale !== null;
        const sameLanguage = locale === this._was.locale;
        if (sameLanguage && sameKeyboard) {
            this._onCancel?.();
            return;
        }
        this._continue.reactive = false;
        this._problem.text = '';
        try {
            // The keyboard first: LANG in place is what says the choice was made.
            if (!sameKeyboard) {
                const [layouts, variants] = keymapArgs(this._keyboard);
                await localectl('--no-convert', 'set-x11-keymap', layouts, '', variants);
            }
            if (!sameLanguage)
                await localectl('set-locale', `LANG=${locale}`);
            restartGreeter();
        } catch (e) {
            log(`mastersos-login: ${e.message}`);
            this._problem.text = this._text.settingsFailed;
            this._continue.reactive = true;
        }
    }

    destroy() {
        this._holder?.destroy();
        this._holder = null;
        this.actor = null;
    }
}
