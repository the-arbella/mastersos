// Who the login screen's one entry finds as the person types, and the school addresses it offers (design 2026-11-03, login
// single field); why a person who signed in was refused, and which school domains the refusal names.
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

// Typing someone's whole user name or name signs that person in, not a more recent "Bobby" for "bob". Text without '@' is
// also exactly a school account whose part before the '@' it is, at one of the school domains: "bob" is
// bob@<school domain>. 2: the whole user name (a local "bob" first); 1: the real name or the part before the '@'; 0: neither.
const exact = (p, q, domains = []) => {
    const user = p.userName.toLowerCase();
    if (user === q)
        return 2;
    if ((p.realName || '').toLowerCase() === q)
        return 1;
    const at = user.indexOf('@');
    return !q.includes('@') && at > 0 && user.slice(0, at) === q &&
        (domains ?? []).some(d => typeof d === 'string' && d.toLowerCase() === user.slice(at + 1)) ? 1 : 0;
};

// people: [{userName, realName, loginTime}]. Nothing before the first character; an exact match, then the most recent
// sign-in first. domains: the school domains (see exact).
export function matchPeople(people, query, domains = []) {
    const q = (query ?? '').trim().toLowerCase();
    if (!q)
        return {shown: [], more: false};
    const found = people
        .filter(p => !HIDDEN(p.userName) && matches(p, q))
        .sort((a, b) => (exact(b, q, domains) - exact(a, q, domains)) || (b.loginTime - a.loginTime) ||
            (a.realName || '').localeCompare(b.realName || ''));
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

// The person Enter signs in without arrow keys: none while an address is being typed (it may be someone new). With school
// domains, a name that could be the part before the '@' never preselects a school account it only starts: "bob" is not
// a more recent bobby@<school domain>, whose sign-in the school's page would refuse for bob; the school addresses
// bob@<domain> are offered under the people instead (suggestDomains). A local account is preselected as before.
export function preselect(query, shown, domains = []) {
    const t = (query ?? '').trim();
    if (!shown.length || t.includes('@'))
        return -1;
    const first = shown[0];
    if (domains?.length && LOCAL_PART.test(t) && first.userName.includes('@') && !exact(first, t.toLowerCase(), domains))
        return -1;
    return 0;
}

// Why the person was refused for who they are rather than for what they typed, from the broker's or the agent's English text:
//   'not-allowed'   not of the school's domains: the broker's allowed_domains (patch 0006) or the agent's pam-check, or another
//                   organisation than this school's (the issuer profile, patch 0007)
//                   (DENY_DOMAIN in core/mastersos-agent/src/system/login.rs, checked by login-people-test.mjs);
//   'unverified'    the school's provider does not say the email address is verified (authd-oidc's generic provider);
//   'wrong-account' the school's page signed in another account than the one picked here (patch 0004);
//   null            anything else.
const REFUSALS = [
    ['not-allowed', /not allowed in broker configuration|Accounts from this domain cannot sign in|not a member of this school/i],
    ['unverified', /email not verified/i],
    ['wrong-account', /does not match the authenticated user/i],
];

export function refusalKind(message) {
    return REFUSALS.find(([, re]) => re.test(message ?? ''))?.[0] ?? null;
}

// At most this many school domains are named in a refusal; with more, the refusal names none.
export const REFUSAL_DOMAINS = 3;

// The school domains a refused person is pointed to, as one text ("@a.ac.th, @b.ac.th"): all of them, so that a teacher on the
// second domain does not read the refusal as meant for them. Empty with none, or with more than REFUSAL_DOMAINS (a long list
// would not fit the line: the plain refusal is clearer).
export function refusalDomains(domains) {
    const list = (domains ?? []).filter(d => typeof d === 'string' && d);
    if (!list.length || list.length > REFUSAL_DOMAINS)
        return '';
    return list.map(d => `@${d}`).join(', ');
}
