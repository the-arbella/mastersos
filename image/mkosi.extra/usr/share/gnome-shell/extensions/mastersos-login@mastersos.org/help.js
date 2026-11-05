// The Get help dialog (plan 2026-11-05 Task 6, design 4–5): a category (required), a short description (optional) and, if the
// student ticks it, a screenshot of the screen as it was before the dialog opened; sent to the agent over
// /run/mastersos-support/support.sock and answered with a ticket number, "saved" (offline) or why not. The same file is in
// mastersos-login@mastersos.org (session "login") and mastersos-managed@mastersos.org (session "desktop"); the caller passes
// its gettext for the mastersos-login catalogue. The logic is help-model.js; this file is only the widgets and the IO, all of
// it asynchronous: nothing here blocks the shell. Who is asking is the agent's business (peer credentials), not this dialog's.
//
// Every state is on screen as it happens (form, sending, the outcome), so each can be seen and screenshotted from the real flow.

import Atk from 'gi://Atk';
import Clutter from 'gi://Clutter';
import Cogl from 'gi://Cogl';
import GdkPixbuf from 'gi://GdkPixbuf';
import Gio from 'gi://Gio';
import GLib from 'gi://GLib';
import GObject from 'gi://GObject';
import Pango from 'gi://Pango';
import Shell from 'gi://Shell';
import St from 'gi://St';

import * as Animation from 'resource:///org/gnome/shell/ui/animation.js';
import * as ModalDialog from 'resource:///org/gnome/shell/ui/modalDialog.js';
import {CheckBox} from 'resource:///org/gnome/shell/ui/checkBox.js';

import {
    CATEGORIES, COPY, MAX_SCREENSHOT_BYTES, MAX_TEXT, POLL_MS,
    afterStatus, afterSubmit, buildSubmit, canSend, counterText, encode, message, parseReply, statusRequest, supportEnabled,
} from './help-model.js';

export const SOCKET = '/run/mastersos-support/support.sock';
export const SUPPORT_JSON = '/var/lib/mastersos-public/support.json';
const PREVIEW_WIDTH = 160;
// A screenshot over the limit is scaled down to this width once; still too big, and there is nothing to attach.
const SHRINK_WIDTH = 1920;
// Connect, write and read, each.
const IO_TIMEOUT_S = 10;

Gio._promisify(Gio.SocketClient.prototype, 'connect_async');
Gio._promisify(Gio.OutputStream.prototype, 'write_bytes_async');
Gio._promisify(Gio.DataInputStream.prototype, 'read_line_async');
Gio._promisify(Shell.Screenshot.prototype, 'screenshot');

const ICONS = {
    sent: 'check-symbolic',
    queued: 'network-offline-symbolic',
    rate_limited: 'alarm-symbolic',
    disabled: 'action-unavailable-symbolic',
    error: 'dialog-warning-symbolic',
};

// Whether the school lets students ask for help (the agent writes support.json from [config.support]). No file: no.
export function readSupportEnabled(path = SUPPORT_JSON) {
    try {
        const [, bytes] = Gio.File.new_for_path(path).load_contents(null);
        return supportEnabled(parseReply(new TextDecoder().decode(bytes)));
    } catch (e) {
        if (!e.matches?.(Gio.IOErrorEnum, Gio.IOErrorEnum.NOT_FOUND))
            log(`mastersos-help: ${path} unreadable: ${e.message ?? e}`);
        return false;
    }
}

// One request line, one reply line. Throws when the socket is missing or refuses; null for a reply that is not JSON.
async function request(req, cancellable) {
    const client = new Gio.SocketClient({timeout: IO_TIMEOUT_S});
    const conn = await client.connect_async(new Gio.UnixSocketAddress({path: SOCKET}), cancellable);
    try {
        const out = conn.get_output_stream();
        let data = new TextEncoder().encode(encode(req));
        while (data.length > 0) {
            const n = await out.write_bytes_async(new GLib.Bytes(data), GLib.PRIORITY_DEFAULT, cancellable);
            data = data.subarray(n);
        }
        const input = new Gio.DataInputStream({base_stream: conn.get_input_stream(), close_base_stream: false});
        const [line] = await input.read_line_async(GLib.PRIORITY_DEFAULT, cancellable);
        return parseReply(line ? new TextDecoder().decode(line) : '');
    } finally {
        conn.close(null);
    }
}

function pixbufAt(bytes, width) {
    return GdkPixbuf.Pixbuf.new_from_stream_at_scale(Gio.MemoryInputStream.new_from_bytes(bytes), width, -1, true, null);
}

// The whole screen as PNG bytes in memory, never on disk; null when it cannot be had within MAX_SCREENSHOT_BYTES.
async function captureScreen() {
    const stream = Gio.MemoryOutputStream.new_resizable();
    await new Shell.Screenshot().screenshot(false, stream);
    stream.close(null);
    const bytes = stream.steal_as_bytes();
    if (bytes.get_size() <= MAX_SCREENSHOT_BYTES)
        return bytes;
    const [ok, buffer] = pixbufAt(bytes, SHRINK_WIDTH).save_to_bufferv('png', [], []);
    const smaller = ok ? new GLib.Bytes(buffer) : null;
    return smaller && smaller.get_size() <= MAX_SCREENSHOT_BYTES ? smaller : null;
}

// A PREVIEW_WIDTH (logical px) thumbnail of the PNG, sharp on HiDPI.
function thumbnail(bytes) {
    const scale = St.ThemeContext.get_for_stage(global.stage).scale_factor;
    const pb = pixbufAt(bytes, PREVIEW_WIDTH * scale);
    const content = St.ImageContent.new_with_preferred_size(pb.width, pb.height);
    content.set_bytes(global.stage.context.get_backend().get_cogl_context(), pb.read_pixel_bytes(),
        pb.has_alpha ? Cogl.PixelFormat.RGBA_8888 : Cogl.PixelFormat.RGB_888, pb.width, pb.height, pb.rowstride);
    return new St.Widget({content, width: pb.width, height: pb.height});
}

export const HelpDialog = GObject.registerClass(
class HelpDialog extends ModalDialog.ModalDialog {
    _init({session, gettext}) {
        super._init({styleClass: 'mastersos-help', destroyOnClose: true});
        this._session = session;
        this._ = gettext;
        this._category = null;
        this._png = null;
        this._capturing = false;
        this._sending = false;
        this._gone = false;
        this._timeoutId = 0;
        this._cancellable = new Gio.Cancellable();
        this.connect('destroy', () => this._onDestroy());
        const _ = this._;

        const body = new St.BoxLayout({style_class: 'mastersos-help-body', orientation: Clutter.Orientation.VERTICAL});
        this.contentLayout.add_child(body);
        const title = new St.Label({text: _(COPY.title), style_class: 'mastersos-help-title'});
        body.add_child(title);
        this.accessible_name = title.text;

        this._form = new St.BoxLayout({style_class: 'mastersos-help-form', orientation: Clutter.Orientation.VERTICAL});
        body.add_child(this._form);

        // The categories wrap like words: long translations take a second row instead of overflowing.
        const flow = new Clutter.FlowLayout({orientation: Clutter.Orientation.HORIZONTAL, column_spacing: 8, row_spacing: 8});
        const cats = new St.Widget({style_class: 'mastersos-help-categories', layout_manager: flow, x_expand: true});
        cats.request_mode = Clutter.RequestMode.HEIGHT_FOR_WIDTH;
        this._pills = CATEGORIES.map(c => {
            const pill = new St.Button({
                style_class: 'mastersos-help-category',
                label: _(c.label),
                toggle_mode: true,
                can_focus: true,
                reactive: true,
                accessible_role: Atk.Role.RADIO_BUTTON,
            });
            pill.connect('clicked', () => this._pick(c.id));
            cats.add_child(pill);
            return {id: c.id, pill};
        });
        this._form.add_child(cats);

        this._entry = new St.Entry({style_class: 'mastersos-help-text', can_focus: true, x_expand: true});
        const hint = new St.Label({text: _(COPY.placeholder), style_class: 'mastersos-help-hint'});
        hint.clutter_text.line_wrap = true;
        hint.clutter_text.ellipsize = Pango.EllipsizeMode.NONE;
        this._entry.hint_actor = hint;
        this._entry.accessible_name = hint.text;
        const ct = this._entry.clutter_text;
        ct.set({single_line_mode: false, activatable: false, line_wrap: true, max_length: MAX_TEXT});
        ct.line_wrap_mode = Pango.WrapMode.WORD_CHAR;
        ct.connect('text-changed', () => this._syncForm());
        this._form.add_child(this._entry);

        this._counter = new St.Label({style_class: 'mastersos-help-counter', x_align: Clutter.ActorAlign.END, visible: false});
        this._form.add_child(this._counter);

        this._attach = new CheckBox(_(COPY.attach));
        this._attach.add_style_class_name('mastersos-help-attach');
        this._attach.visible = false;
        this._attach.connect('notify::checked', () => this._syncForm());
        this._form.add_child(this._attach);

        this._preview = new St.Bin({style_class: 'mastersos-help-preview', x_align: Clutter.ActorAlign.START, visible: false});
        this._form.add_child(this._preview);

        // The outcome, in place of the form: an icon (a spinner while sending) and one sentence.
        this._result = new St.BoxLayout({style_class: 'mastersos-help-result', visible: false});
        this._resultIcon = new St.Bin({style_class: 'mastersos-help-result-icon', y_align: Clutter.ActorAlign.START});
        this._result.add_child(this._resultIcon);
        this._resultText = new St.Label({style_class: 'mastersos-help-result-text', x_expand: true,
            y_align: Clutter.ActorAlign.CENTER});
        this._resultText.clutter_text.line_wrap = true;
        this._resultText.clutter_text.ellipsize = Pango.EllipsizeMode.NONE;
        this._result.add_child(this._resultText);
        body.add_child(this._result);

        this._showForm();
        this.setInitialKeyFocus(this._pills[0].pill);
    }

    // The screen is taken before the dialog shows, whether or not the student will attach it.
    open() {
        if (this._capturing || this.state !== ModalDialog.State.CLOSED)
            return true;
        this._capturing = true;
        captureScreen().catch(e => {
            log(`mastersos-help: screenshot failed: ${e.message ?? e}`);
            return null;
        }).then(bytes => {
            this._capturing = false;
            if (this._gone)
                return;
            this._setScreenshot(bytes);
            super.open();
        });
        return true;
    }

    _setScreenshot(bytes) {
        this._png = null;
        if (!bytes)
            return;
        try {
            this._preview.set_child(thumbnail(bytes));
            this._png = bytes;
        } catch (e) {
            log(`mastersos-help: screenshot preview failed: ${e.message ?? e}`);
        }
        // Without a screenshot there is nothing to tick.
        this._attach.visible = this._png !== null;
    }

    _pick(id) {
        this._category = id;
        for (const {id: other, pill} of this._pills)
            pill.checked = other === id;
        this._syncForm();
    }

    _syncForm() {
        const text = this._entry.get_text();
        const counter = counterText(text);
        this._counter.text = counter ?? '';
        this._counter.visible = counter !== null;
        this._preview.visible = this._png !== null && this._attach.checked;
        const ready = canSend({category: this._category, text});
        if (this._sendButton) {
            this._sendButton.reactive = ready;
            this._sendButton.can_focus = ready;
        }
    }

    _showForm() {
        this._form.show();
        this._result.hide();
        this.setButtons([
            {label: this._(COPY.cancel), action: () => this.close(), key: Clutter.KEY_Escape},
            // The buttons are replaced once sending starts: not inside the click that started it.
            {label: this._(COPY.send), action: () => this._later(() => this._send())},
        ]);
        this._sendButton = this.buttonLayout.get_last_child();
        this._sendButton.add_style_class_name('mastersos-help-send');
        this._syncForm();
    }

    // outcome: {state: 'sending'} or what help-model's afterSubmit / afterStatus decided.
    _showResult(outcome) {
        if (this._gone)
            return;
        this._form.hide();
        this._result.show();
        this._result.set_style_class_name(`mastersos-help-result mastersos-help-${outcome.state.replace('_', '-')}`);
        if (outcome.state === 'sending') {
            const spinner = new Animation.Spinner(24);
            this._resultIcon.set_child(spinner);
            spinner.play();
        } else {
            this._resultIcon.set_child(new St.Icon({
                icon_name: ICONS[outcome.state] ?? ICONS.error,
                fallback_icon_name: 'dialog-information-symbolic',
                style_class: 'mastersos-help-icon',
            }));
        }
        this._resultText.text = message(outcome, this._);
        this._sendButton = null;
        this.setButtons([{label: this._(COPY.close), action: () => this.close(), key: Clutter.KEY_Escape}]);
        this.buttonLayout.get_first_child()?.grab_key_focus();
    }

    async _send() {
        if (this._sending || !canSend({category: this._category, text: this._entry.get_text()}))
            return;
        this._sending = true;
        let req;
        try {
            const attach = this._png !== null && this._attach.checked;
            req = buildSubmit({
                category: this._category,
                text: this._entry.get_text(),
                session: this._session,
                screenshot: attach ? GLib.base64_encode(this._png.toArray()) : null,
                attach,
            });
        } catch (e) {
            log(`mastersos-help: ${e.message ?? e}`);
            this._showResult({state: 'error'});
            return;
        }
        this._showResult({state: 'sending'});
        // Not cancelled by closing: a request the student sent goes, even if the dialog is closed at once.
        const submitted = afterSubmit(await this._ask(req, null));
        if (submitted.state !== 'queued') {
            this._showResult(submitted);
            return;
        }
        const start = GLib.get_monotonic_time();
        for (;;) {
            if (!await this._wait(POLL_MS))
                return;
            const reply = await this._ask(statusRequest(submitted.clientId), this._cancellable);
            const next = afterStatus(reply, (GLib.get_monotonic_time() - start) / 1000);
            if (next.state !== 'poll') {
                this._showResult(next);
                return;
            }
        }
    }

    // null when the socket is missing, refuses or breaks: help-model decides what that means.
    async _ask(req, cancellable) {
        try {
            return await request(req, cancellable);
        } catch (e) {
            if (!e.matches?.(Gio.IOErrorEnum, Gio.IOErrorEnum.CANCELLED))
                log(`mastersos-help: ${SOCKET}: ${e.message ?? e}`);
            return null;
        }
    }

    _later(fn) {
        GLib.idle_add(GLib.PRIORITY_DEFAULT, () => {
            if (!this._gone)
                fn();
            return GLib.SOURCE_REMOVE;
        });
    }

    // false once the dialog is gone.
    _wait(ms) {
        return new Promise(resolve => {
            if (this._gone) {
                resolve(false);
                return;
            }
            this._timeoutId = GLib.timeout_add(GLib.PRIORITY_DEFAULT, ms, () => {
                this._timeoutId = 0;
                resolve(!this._gone);
                return GLib.SOURCE_REMOVE;
            });
        });
    }

    _onDestroy() {
        this._gone = true;
        this._cancellable.cancel();
        if (this._timeoutId) {
            GLib.source_remove(this._timeoutId);
            this._timeoutId = 0;
        }
    }
});
