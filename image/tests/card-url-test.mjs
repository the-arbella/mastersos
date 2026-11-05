// Unit tests for the sign-in card's authorization URL (mastersos-login@mastersos.org/card-url.js).
// Run with: bash image/tests/card-url-test.sh

import test from 'node:test';
import assert from 'node:assert/strict';

// card-url-test.sh copies card-url.js to a .mjs first: node before 22 reads a bare .js as CommonJS.
const {CARD_SETTINGS, idpHintFrom, withIdpHint} = await import(process.env.MASTERSOS_CARD_URL_MJS);

// What authd's patch 0003 hands the card (oauth2 AuthCodeURL with PKCE S256 and login_hint).
const AUTHORIZE = 'https://sso.school.ac.th/auth/v1/oidc/authorize?client_id=mastersos&code_challenge=E9Mel0Q_x-yZ' +
    '&code_challenge_method=S256&login_hint=ann%40school.org&redirect_uri=http%3A%2F%2F127.0.0.1%3A48123%2Fcallback' +
    '&response_type=code&scope=openid+profile+email&state=Zx81_k-q';

test('no hint leaves the URL as it is', () => {
    for (const hint of [null, undefined, ''])
        assert.equal(withIdpHint(AUTHORIZE, hint), AUTHORIZE);
});

test('a hint is appended with & and nothing else changes', () => {
    const got = withIdpHint(AUTHORIZE, 'school-sso');
    assert.equal(got, `${AUTHORIZE}&idp_hint=school-sso`);
    assert.ok(got.startsWith(AUTHORIZE), 'state, PKCE and login_hint stay byte for byte');
});

test('a URL without a query gets ?', () => {
    assert.equal(withIdpHint('https://sso.school.ac.th/authorize', 'up_1'), 'https://sso.school.ac.th/authorize?idp_hint=up_1');
    assert.equal(withIdpHint('https://sso.school.ac.th/authorize?', 'up_1'), 'https://sso.school.ac.th/authorize?idp_hint=up_1');
    assert.equal(withIdpHint('https://sso.school.ac.th/a?x=1&', 'up_1'), 'https://sso.school.ac.th/a?x=1&idp_hint=up_1');
});

test('the hint goes before a fragment', () => {
    assert.equal(withIdpHint('https://sso.school.ac.th/a?x=1#top', 'h'), 'https://sso.school.ac.th/a?x=1&idp_hint=h#top');
    assert.equal(withIdpHint('https://sso.school.ac.th/a#top', 'h'), 'https://sso.school.ac.th/a?idp_hint=h#top');
});

test('an invalid hint is ignored', () => {
    const long = 'a'.repeat(65);
    for (const bad of ['a b', 'a&b', 'a=b', 'a#b', 'a.b', 'a/b', 'a%20b', 'ไทย', 'a\nb', long, 7, {}, ['x']])
        assert.equal(withIdpHint(AUTHORIZE, bad), AUTHORIZE, String(bad));
    assert.equal(withIdpHint(AUTHORIZE, 'a'.repeat(64)), `${AUTHORIZE}&idp_hint=${'a'.repeat(64)}`);
});

test('a URL that is not https is left alone', () => {
    for (const url of ['http://sso.lab/authorize?state=1', 'javascript:alert(1)', 'HTTPS://sso.lab/a', '', null, undefined])
        assert.equal(withIdpHint(url, 'school-sso'), url);
});

test('never twice', () => {
    const once = withIdpHint(AUTHORIZE, 'school-sso');
    assert.equal(withIdpHint(once, 'school-sso'), once);
    assert.equal(withIdpHint(once, 'other'), once);
    const encoded = 'https://sso.school.ac.th/a?idp%5Fhint=x';
    assert.equal(withIdpHint(encoded, 'y'), encoded);
    // A parameter that only ends in idp_hint is another parameter.
    assert.equal(withIdpHint('https://sso.school.ac.th/a?my_idp_hint=x', 'y'), 'https://sso.school.ac.th/a?my_idp_hint=x&idp_hint=y');
});

test('card.json: the hint or null', () => {
    assert.equal(idpHintFrom('{"idp_hint": "school-sso"}'), 'school-sso');
    for (const text of [null, undefined, '', 'not json', '[]', 'null', '"x"', '{}', '{"idp_hint": 3}',
        '{"idp_hint": "a b"}', '{"idp_hint": ""}', `{"idp_hint": "${'a'.repeat(65)}"}`])
        assert.equal(idpHintFrom(text), null, String(text));
});

test('card.json is beside the browser policy directory, not in it', () => {
    assert.equal(CARD_SETTINGS, '/var/lib/mastersos-public/login-browser/card.json');
});
