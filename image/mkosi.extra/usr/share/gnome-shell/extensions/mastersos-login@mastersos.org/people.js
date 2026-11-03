// Who the login screen's one entry finds as the person types (design 2026-11-03, login single field).
// Pure computation, no gi:// imports: extension.js and image/tests/login-people-test.mjs share it.

export const LIMIT = 5;

// Guest, the locked apps and the IT account have their own ways in and are never offered.
export const HIDDEN = name => name === 'guest' || name === 'itadmin' || name.startsWith('kiosk-');

// Scripts written without spaces between words (Thai, Chinese ...): any part of the name may be what the person types.
const UNSPACED = /[^\u0000-\u024f]/u;

function matches(p, q) {
    const user = p.userName.toLowerCase();
    const real = (p.realName || '').toLowerCase();
    if (user.startsWith(q) || real.startsWith(q))
        return true;
    if (real.split(/\s+/u).some(word => word.startsWith(q)))
        return true;
    return UNSPACED.test(real) && real.includes(q);
}

// Typing someone's whole user name or name signs that person in, not a more recent "Bobby" for "bob".
const exact = (p, q) => p.userName.toLowerCase() === q || (p.realName || '').toLowerCase() === q;

// people: [{userName, realName, loginTime}]. Nothing before the first character; an exact match, then the most recent
// sign-in first.
export function matchPeople(people, query) {
    const q = (query ?? '').trim().toLowerCase();
    if (!q)
        return {shown: [], more: false};
    const found = people
        .filter(p => !HIDDEN(p.userName) && matches(p, q))
        .sort((a, b) => (exact(b, q) - exact(a, q)) || (b.loginTime - a.loginTime) || (a.realName || '').localeCompare(b.realName || ''));
    return {shown: found.slice(0, LIMIT), more: found.length > LIMIT};
}

// The person Enter signs in without arrow keys: none while an address is being typed (it may be someone new).
export function preselect(query, shown) {
    return shown.length && !(query ?? '').includes('@') ? 0 : -1;
}
