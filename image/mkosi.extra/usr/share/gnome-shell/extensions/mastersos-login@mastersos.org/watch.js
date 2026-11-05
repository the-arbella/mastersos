// Settings the agent writes while the login screen is already up (branding.json, the locked apps under kiosk/<id>/).
// Watches directories rather than files: a file replaced by rename and a directory that appears or goes away later are both
// seen (GIO keeps polling a path that does not exist yet). Each watched directory's subdirectories are watched too, since an
// app's files are written one level down after its directory appears. The agent writes several files in a row: onChange runs
// once they have been quiet for SETTLE_MS.

import Gio from 'gi://Gio';
import GLib from 'gi://GLib';

export const SETTLE_MS = 400;

export class Watch {
    constructor(dirs, onChange) {
        this._onChange = onChange;
        this._timeoutId = 0;
        this._top = dirs.map(path => ({path, monitor: this._monitor(path), subs: new Map()}));
        this._syncSubdirs();
    }

    _monitor(path) {
        try {
            const m = Gio.File.new_for_path(path).monitor_directory(Gio.FileMonitorFlags.NONE, null);
            m.connect('changed', () => this._schedule());
            return m;
        } catch (e) {
            log(`mastersos-login: cannot watch ${path}: ${e.message ?? e}`);
            return null;
        }
    }

    // Watch every subdirectory that is there now, stop watching the ones that are gone.
    _syncSubdirs() {
        for (const top of this._top) {
            const now = new Set();
            try {
                const e = Gio.File.new_for_path(top.path).enumerate_children('standard::name,standard::type',
                    Gio.FileQueryInfoFlags.NOFOLLOW_SYMLINKS, null);
                for (let info = e.next_file(null); info; info = e.next_file(null)) {
                    if (info.get_file_type() === Gio.FileType.DIRECTORY)
                        now.add(info.get_name());
                }
                e.close(null);
            } catch (err) {
                if (!err.matches?.(Gio.IOErrorEnum, Gio.IOErrorEnum.NOT_FOUND))
                    log(`mastersos-login: ${top.path} unreadable: ${err.message ?? err}`);
            }
            for (const [name, m] of top.subs) {
                if (!now.has(name)) {
                    m?.cancel();
                    top.subs.delete(name);
                }
            }
            for (const name of now) {
                if (!top.subs.has(name))
                    top.subs.set(name, this._monitor(`${top.path}/${name}`));
            }
        }
    }

    // Wait until the writes have been quiet for SETTLE_MS.
    _schedule() {
        if (this._timeoutId)
            GLib.source_remove(this._timeoutId);
        this._timeoutId = GLib.timeout_add(GLib.PRIORITY_DEFAULT, SETTLE_MS, () => {
            this._timeoutId = 0;
            // Watch new subdirectories before reading them: whatever is written after this is seen again.
            this._syncSubdirs();
            try {
                this._onChange();
            } catch (e) {
                log(`mastersos-login: applying new settings failed: ${e.message ?? e}`);
            }
            return GLib.SOURCE_REMOVE;
        });
    }

    destroy() {
        if (this._timeoutId)
            GLib.source_remove(this._timeoutId);
        this._timeoutId = 0;
        for (const top of this._top) {
            top.monitor?.cancel();
            for (const m of top.subs.values())
                m?.cancel();
            top.subs.clear();
        }
        this._top = [];
    }
}
