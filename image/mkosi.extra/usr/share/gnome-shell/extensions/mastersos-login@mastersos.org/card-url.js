// The sign-in card's authorization URL: the school's [school.oidc] idp_hint, when set, tells an identity broker (Rauthy, for
// one) which upstream provider to open, so the person never sees the broker's provider choice. The agent writes the hint to
// /var/lib/mastersos-public/login-browser/card.json (core/mastersos-agent/src/system/login.rs, render_login_card).
// Pure computation, no gi:// imports: card.js and image/tests/card-url-test.mjs share it.

export const CARD_SETTINGS = '/var/lib/mastersos-public/login-browser/card.json';

// The same rule as the settings check (checks::idp_hint in core/mastersos-bundle/src/checks.rs).
const IDP_HINT = /^[A-Za-z0-9_-]{1,64}$/;
const PARAM = 'idp_hint';

// card.json's text: the hint, or null when the file is missing, broken or the value is not a valid hint.
export function idpHintFrom(text) {
    if (typeof text !== 'string')
        return null;
    let data;
    try {
        data = JSON.parse(text);
    } catch {
        return null;
    }
    const hint = data && typeof data === 'object' && !Array.isArray(data) ? data.idp_hint : null;
    return typeof hint === 'string' && IDP_HINT.test(hint) ? hint : null;
}

function hasParam(query, name) {
    return query.split('&').some(part => {
        const key = part.split('=')[0];
        try {
            return decodeURIComponent(key.replace(/\+/g, ' ')) === name;
        } catch {
            return key === name;
        }
    });
}

// url with idp_hint=<hint> added to its query. Anything else is left exactly as it was (state, PKCE challenge and
// login_hint included): a URL that is not https, a missing or invalid hint, a URL that already has an idp_hint.
export function withIdpHint(url, hint) {
    if (typeof url !== 'string' || !url.startsWith('https://'))
        return url;
    if (typeof hint !== 'string' || !IDP_HINT.test(hint))
        return url;
    const hash = url.indexOf('#');
    const base = hash < 0 ? url : url.slice(0, hash);
    const fragment = hash < 0 ? '' : url.slice(hash);
    const q = base.indexOf('?');
    if (q >= 0 && hasParam(base.slice(q + 1), PARAM))
        return url;
    let sep = '&';
    if (q < 0)
        sep = '?';
    else if (base.endsWith('?') || base.endsWith('&'))
        sep = '';
    return `${base}${sep}${PARAM}=${encodeURIComponent(hint)}${fragment}`;
}
