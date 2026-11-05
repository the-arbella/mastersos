// Who the login screen's one entry finds as the person types, and the school addresses it offers (design 2026-11-03, login
// single field); why a person who signed in was refused.
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

// What may come before the '@' of an address (RFC 5322 atext and dots, at most 64): anything else is no school address.
const LOCAL_PART = /^[a-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}$/i;

// The school addresses offered under the entry as a name is typed: the name with each school domain, once an '@' is typed only
// the domains that start with what follows it. None for an address already complete or already listed as a person (taken).
export function suggestDomains(query, domains, taken = []) {
    const t = (query ?? '').trim();
    const at = t.indexOf('@');
    const local = at < 0 ? t : t.slice(0, at);
    const rest = at < 0 ? '' : t.slice(at + 1).toLowerCase();
    if (!domains?.length || !LOCAL_PART.test(local) || rest.includes('@'))
        return [];
    const skip = new Set([t, ...taken].map(a => a.toLowerCase()));
    return domains
        .filter(d => d.toLowerCase().startsWith(rest))
        .map(d => `${local}@${d}`)
        .filter(a => !skip.has(a.toLowerCase()))
        .slice(0, LIMIT);
}

// The person Enter signs in without arrow keys: none while an address is being typed (it may be someone new).
export function preselect(query, shown) {
    return shown.length && !(query ?? '').includes('@') ? 0 : -1;
}

// Why the person was refused for who they are rather than for what they typed, from the broker's or the agent's English text:
//   'not-allowed'   not of the school's domains: the broker's allowed_domains (patch 0006) or the agent's pam-check
//                   (DENY_DOMAIN in core/mastersos-agent/src/system/login.rs, checked by login-people-test.mjs);
//   'unverified'    the school's provider does not say the email address is verified (authd-oidc's generic provider);
//   'wrong-account' the school's page signed in another account than the one picked here (patch 0004);
//   null            anything else.
const REFUSALS = [
    ['not-allowed', /not allowed in broker configuration|Accounts from this domain cannot sign in/i],
    ['unverified', /email not verified/i],
    ['wrong-account', /does not match the authenticated user/i],
];

export function refusalKind(message) {
    return REFUSALS.find(([, re]) => re.test(message ?? ''))?.[0] ?? null;
}
