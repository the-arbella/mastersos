// The one rectangle the login screen draws its screens in: language choice, people, email and the school's page all share
// it, so nothing jumps between them. Plain percentages of the screen, centred between the top bar and the shelf: no pixel
// sizes, no per-resolution rules and nothing that knows about one identity provider. The top bar, the shelf, the accessibility
// button and the notices stay outside it.

import * as Main from 'resource:///org/gnome/shell/ui/main.js';

const WIDTH = 0.76;
const HEIGHT = 0.80;

// The shelf's height with its margin: set once by shelf.js when it knows.
let shelfHeight = 0;

export function setShelfHeight(height) {
    shelfHeight = height;
}

export function loginArea() {
    const mon = Main.layoutManager.primaryMonitor;
    const panel = Main.layoutManager.panelBox.height;
    const free = mon.height - panel - shelfHeight;
    const width = Math.round(mon.width * WIDTH);
    const height = Math.min(Math.round(mon.height * HEIGHT), free);
    return {
        x: mon.x + Math.round((mon.width - width) / 2),
        y: mon.y + panel + Math.round((free - height) / 2),
        width,
        height,
    };
}

// The band under the area, where Cancel sits while the school's page is up.
export function underArea() {
    const mon = Main.layoutManager.primaryMonitor;
    const a = loginArea();
    const y = a.y + a.height;
    return {x: a.x, y, width: a.width, height: mon.y + mon.height - y};
}
