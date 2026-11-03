// Login-screen text through gettext (domain mastersos-login, catalogues in locale/; English is the source and the fallback)
// and the small pure helpers. The school's page speaks for itself: everything here is text this computer shows.

import {gettext as _} from 'resource:///org/gnome/shell/extensions/extension.js';

export function strings() {
    return {
        managed: _('Managed by %s'),
        shutDown: _('Shut down'),
        guest: _('Browse as Guest'),
        addPerson: _('Add person'),
        apps: _('Apps'),
        cancel: _('Cancel'),
        cancelKey: 'Ctrl+Esc',
        retry: _('Retry'),
        opening: _('Opening the sign-in page…'),
        openFailed: _('The sign-in page could not be opened.'),
        offline: _('Cannot reach the school. Connect to Wi-Fi from the top bar, then retry.'),
        appOffline: _('This app needs a network. Connect to Wi-Fi from the top bar, then retry.'),
        email: _('School email'),
        itLink: _('IT local account'),
        itPrompt: _('Username'),
        notAllowed: _('This account cannot sign in on this computer.'),
        notAllowedUse: _('This account cannot sign in on this computer. Use your school email (%s).'),
        wrongAccount: _('You signed in with a different account. Sign in again with the account you chose here.'),
        language: _('Language'),
        keyboard: _('Keyboard'),
        continueLabel: _('Continue'),
        settingsFailed: _('The setting could not be saved. Try again.'),
    };
}

// What the broker and the agent say on the login screen, word for word: they have no translations of their own. Listed here so
// that they reach the catalogues; a string that moves falls back to the English, it never disappears.
const OTHERS = [
    [/^Your user account is disabled in /, () => _('Your account is disabled. Contact your administrator.')],
    [/^This device is disabled in /, () => _('This device is disabled. Contact your administrator.')],
];
export const OTHERS_EXACT = () => [
    _('Sign in with your school account.'),
    _('Could not sign in. Please try again.'),
    _('Authentication request cancelled'),
    _('Maximum number of authentication attempts reached'),
    _('Error retrieving access token. Please try again.'),
    _('Invalid user name'),
    _('This computer has been locked by the school; please contact IT'),
    _('Guest sign-in is not allowed on this computer'),
    _('Local accounts cannot sign in on this computer'),
    _('School accounts cannot sign in on this computer'),
    _('This app can only be opened from the sign-in screen'),
];

// The agent's login-screen banner (core/mastersos-agent/src/status.rs BANNER_SENTENCES): its first line is one of these
// sentences, the lines after it are technical detail and stay as they are. A lock message from the school is not a msgid
// and comes back unchanged.
export const BANNER = () => [
    _('No network. Choose a Wi-Fi network in the top-right menu, or plug in a network cable or a phone with USB tethering.'),
    _('Waiting for school settings.'),
    _('Installing the web browser. You can sign in; it will appear when ready.'),
    _('The web browser could not be installed yet; it will try again. You can sign in.'),
];

export function bannerText(text) {
    if (!text)
        return text;
    const i = text.indexOf('\n');
    const first = i < 0 ? text : text.slice(0, i);
    return _(first) + (i < 0 ? '' : text.slice(i));
}

// The agent's pam-check refusals come as "中文 / English": the English half is the msgid.
function english(message) {
    const i = message?.indexOf(' / ') ?? -1;
    if (i < 0 || !/[\u4e00-\u9fff]/.test(message.slice(0, i)))
        return message;
    return message.slice(i + 3);
}

export function agentRefusal(message) {
    return english(message) !== message;
}

export function brokerText(raw) {
    const message = english(raw);
    return OTHERS.find(([re]) => re.test(message ?? ''))?.[1]() ?? (message ? _(message) : message);
}

// Strip control and bidi characters, cap the length: school and app names are shown as plain text only.
const UNSAFE = /[\u0000-\u001f\u007f-\u009f\u061c\u200b-\u200f\u2028-\u202e\u2066-\u2069\ufeff]/g;
export function cleanText(v, max) {
    return typeof v === 'string' ? v.replace(UNSAFE, '').trim().slice(0, max) : '';
}

export function fmt(template, name) {
    return template.split('%s').join(name);
}
