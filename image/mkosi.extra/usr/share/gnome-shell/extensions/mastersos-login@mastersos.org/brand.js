// The MastersOS mark (logo and wordmark) for the start of the top bar on the login screen (design 2026-11-04 visual
// identity §5.4). The shelf at the bottom holds the school's line and the buttons; the mark stays small and out of the way.

import St from 'gi://St';
import Clutter from 'gi://Clutter';

import * as Main from 'resource:///org/gnome/shell/ui/main.js';

export function brandMark() {
    // Small and at 85 % opacity (design 2026-11-04 visual identity §5.4); St's CSS has no opacity, so the actor carries it
    const box = new St.BoxLayout({style_class: 'mastersos-brand-corner', y_align: Clutter.ActorAlign.CENTER, reactive: false, opacity: 217});
    box.add_child(new St.Icon({icon_name: 'mastersos-logo', icon_size: 20, y_align: Clutter.ActorAlign.CENTER}));
    box.add_child(new St.Bin({style_class: 'mastersos-brand-wordmark', y_align: Clutter.ActorAlign.CENTER}));
    return box;
}

// Put the mark first in the top bar's start box (the left one, the right one in RTL: the panel mirrors itself). Returns the
// actor, or null when there is no panel.
export function addBrandMark() {
    const start = Main.panel?._leftBox;
    if (!start)
        return null;
    const mark = brandMark();
    start.insert_child_at_index(mark, 0);
    return mark;
}
