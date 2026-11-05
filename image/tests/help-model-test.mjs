// Unit tests for the Get help dialog's pure logic (mastersos-login@mastersos.org/help-model.js, the same file in
// mastersos-managed@mastersos.org). The wire format is the agent's support socket (plan 2026-11-05 Task 5).
// Run with: bash image/tests/help-model-test.sh

import test from 'node:test';
import assert from 'node:assert/strict';

// help-model-test.sh copies help-model.js to a .mjs first: node before 22 reads a bare .js as CommonJS.
const M = await import(process.env.MASTERSOS_HELP_MODEL_MJS);
const {
    CATEGORIES, COPY, MAX_TEXT, MAX_SCREENSHOT_BYTES, POLL_MS, POLL_LIMIT_MS,
    afterStatus, afterSubmit, b64Bytes, buildSubmit, canSend, collectingFor, counterText, encode, message, parseReply,
    statusRequest, supportEnabled, textLength,
} = M;

const form = (over = {}) => ({category: 'wifi', text: 'It keeps dropping', session: 'login', screenshot: null, attach: false,
    ...over});

test('the six categories, in order, with their wire ids and the fixed English labels', () => {
    assert.deepEqual(CATEGORIES.map(c => c.id), ['wifi', 'sign_in', 'app', 'hardware', 'battery', 'other']);
    assert.deepEqual(CATEGORIES.map(c => c.label),
        ['Wi-Fi', "Can't sign in", 'An app', 'Screen, keys or sound', 'Battery', 'Other']);
});

test('the fixed English copy, word for word', () => {
    assert.equal(COPY.entry, 'Get help');
    assert.equal(COPY.title, 'Get help from IT');
    assert.equal(COPY.placeholder, "What happened? Please don't include passwords or personal details.");
    assert.equal(COPY.attach, 'Attach a screenshot');
    assert.equal(COPY.cancel, 'Cancel');
    assert.equal(COPY.send, 'Send');
    assert.equal(COPY.collecting, 'IT is collecting diagnostic info from this computer.');
});

test('limits and timing', () => {
    assert.equal(MAX_TEXT, 1000);
    assert.equal(MAX_SCREENSHOT_BYTES, 5 * 1024 * 1024);
    assert.equal(POLL_MS, 3000);
    assert.equal(POLL_LIMIT_MS, 60000);
});

test('buildSubmit: exactly op, category, text, session, screenshot_png_b64, in that order', () => {
    assert.equal(JSON.stringify(buildSubmit(form())),
        '{"op":"submit","category":"wifi","text":"It keeps dropping","session":"login","screenshot_png_b64":null}');
    const withShot = buildSubmit(form({session: 'desktop', screenshot: 'iVBORw0KGgo=', attach: true}));
    assert.deepEqual(Object.keys(withShot), ['op', 'category', 'text', 'session', 'screenshot_png_b64']);
    assert.equal(withShot.screenshot_png_b64, 'iVBORw0KGgo=');
    assert.equal(withShot.session, 'desktop');
});

test('buildSubmit: the screenshot goes only when ticked', () => {
    assert.equal(buildSubmit(form({screenshot: 'iVBORw0KGgo=', attach: false})).screenshot_png_b64, null);
    assert.equal(buildSubmit(form({screenshot: null, attach: true})).screenshot_png_b64, null);
});

test('buildSubmit: a screenshot over 5 MiB is refused', () => {
    const big = 'A'.repeat(Math.ceil(MAX_SCREENSHOT_BYTES / 3) * 4 + 4);
    assert.ok(b64Bytes(big) > MAX_SCREENSHOT_BYTES);
    assert.throws(() => buildSubmit(form({screenshot: big, attach: true})), /screenshot/);
    const fits = 'A'.repeat(Math.floor(MAX_SCREENSHOT_BYTES / 3) * 4);
    assert.ok(b64Bytes(fits) <= MAX_SCREENSHOT_BYTES);
    assert.equal(buildSubmit(form({screenshot: fits, attach: true})).screenshot_png_b64, fits);
});

test('b64Bytes counts the decoded bytes', () => {
    assert.equal(b64Bytes(''), 0);
    assert.equal(b64Bytes('QQ=='), 1);
    assert.equal(b64Bytes('QUI='), 2);
    assert.equal(b64Bytes('QUJD'), 3);
});

test('category is required and must be one of the six', () => {
    assert.equal(canSend(form({category: null})), false);
    assert.equal(canSend(form({category: 'printer'})), false);
    assert.throws(() => buildSubmit(form({category: null})), /category/);
    assert.throws(() => buildSubmit(form({category: 'printer'})), /category/);
    assert.equal(canSend(form()), true);
});

test('an empty description may be sent', () => {
    assert.equal(canSend(form({text: ''})), true);
    assert.equal(buildSubmit(form({text: ''})).text, '');
    assert.equal(buildSubmit(form({text: '   \n '})).text, '');
});

test('the description is trimmed, its inner lines kept', () => {
    assert.equal(buildSubmit(form({text: '  line one\nline two  '})).text, 'line one\nline two');
});

test('at most 1000 characters, counted as Unicode code points', () => {
    assert.equal(textLength('😀😀'), 2);
    assert.equal(textLength('ภาษาไทย'), 7);
    const emoji = '😀'.repeat(1000); // 2000 UTF-16 units
    assert.equal(canSend(form({text: emoji})), true);
    assert.equal(buildSubmit(form({text: emoji})).text, emoji);
    assert.equal(canSend(form({text: `${emoji}x`})), false);
    assert.throws(() => buildSubmit(form({text: 'x'.repeat(1001)})), /1000/);
});

test('the counter shows only near the limit', () => {
    assert.equal(counterText('x'.repeat(899)), null);
    assert.equal(counterText('x'.repeat(900)), '900/1000');
    assert.equal(counterText('😀'.repeat(1000)), '1000/1000');
});

test('session is login or desktop', () => {
    assert.throws(() => buildSubmit(form({session: 'kiosk:exam'})), /session/);
    assert.throws(() => buildSubmit(form({session: ''})), /session/);
});

test('encode: one JSON line', () => {
    assert.equal(encode({op: 'enabled'}), '{"op":"enabled"}\n');
    assert.equal(encode(statusRequest('c-1')), '{"op":"status","client_id":"c-1"}\n');
});

test('parseReply: one JSON object, or null', () => {
    assert.deepEqual(parseReply('{"ok":true,"enabled":true}\n'), {ok: true, enabled: true});
    assert.equal(parseReply(''), null);
    assert.equal(parseReply('not json'), null);
    assert.equal(parseReply('[1]'), null);
    assert.equal(parseReply(null), null);
});

test('afterSubmit: queued with its client id, or the error kind', () => {
    assert.deepEqual(afterSubmit({ok: true, client_id: 'c-1', state: 'queued'}), {state: 'queued', clientId: 'c-1'});
    assert.deepEqual(afterSubmit({ok: false, error: 'rate_limited'}), {state: 'rate_limited'});
    assert.deepEqual(afterSubmit({ok: false, error: 'disabled'}), {state: 'disabled'});
    assert.deepEqual(afterSubmit({ok: false, error: 'invalid'}), {state: 'error'});
    assert.deepEqual(afterSubmit({ok: false, error: 'something new'}), {state: 'error'});
    assert.deepEqual(afterSubmit({ok: true}), {state: 'error'});
    // No socket, a refused connection, a broken reply.
    assert.deepEqual(afterSubmit(null), {state: 'error'});
});

test('afterStatus: a ticket ends it, queued keeps polling until 60 s', () => {
    assert.deepEqual(afterStatus({ok: true, state: 'sent', ticket: '1042'}, 3000), {state: 'sent', ticket: '1042'});
    assert.deepEqual(afterStatus({ok: true, state: 'sent', ticket: 1042}, 3000), {state: 'sent', ticket: '1042'});
    assert.deepEqual(afterStatus({ok: true, state: 'queued'}, 3000), {state: 'poll'});
    assert.deepEqual(afterStatus({ok: true, state: 'queued'}, 57000), {state: 'poll'});
    assert.deepEqual(afterStatus({ok: true, state: 'queued'}, 60000), {state: 'queued'});
    assert.deepEqual(afterStatus({ok: true, state: 'disabled'}, 3000), {state: 'disabled'});
    assert.deepEqual(afterStatus({ok: true, state: 'failed'}, 3000), {state: 'error'});
});

test('afterStatus: the request is saved, so anything unclear is polled again, then "saved"', () => {
    assert.deepEqual(afterStatus(null, 3000), {state: 'poll'});
    assert.deepEqual(afterStatus({ok: false, error: 'invalid'}, 3000), {state: 'poll'});
    assert.deepEqual(afterStatus(null, 60000), {state: 'queued'});
    // A ticket that is not a short plain id is not shown.
    assert.deepEqual(afterStatus({ok: true, state: 'sent', ticket: '<b>1</b>'}, 3000), {state: 'poll'});
    assert.deepEqual(afterStatus({ok: true, state: 'sent'}, 60000), {state: 'queued'});
});

test('message: each outcome has its exact words', () => {
    assert.equal(message({state: 'sent', ticket: '1042'}), 'Sent. Ticket #1042. IT has been told.');
    assert.equal(message({state: 'queued'}), 'Saved. It will be sent when this computer is online.');
    assert.equal(message({state: 'rate_limited'}), "You've sent 3 requests this hour. Please try again later.");
    assert.equal(message({state: 'disabled'}), 'Help requests are turned off at this school.');
    assert.equal(message({state: 'error'}), "Couldn't send. Please tell a teacher.");
    assert.equal(message({state: 'sending'}), 'Sending…');
});

test('message: through the gettext it is given, %s filled in after', () => {
    const fr = {'Sent. Ticket #%s. IT has been told.': 'Envoyé. Ticket n° %s.'};
    assert.equal(message({state: 'sent', ticket: '7'}, s => fr[s] ?? s), 'Envoyé. Ticket n° 7.');
});

test('supportEnabled: only an explicit true shows the entry', () => {
    assert.equal(supportEnabled({enabled: true}), true);
    assert.equal(supportEnabled({enabled: false}), false);
    assert.equal(supportEnabled({enabled: 'yes'}), false);
    assert.equal(supportEnabled({}), false);
    assert.equal(supportEnabled(null), false);
});

test('collectingFor: how long the collecting notice stays up', () => {
    const now = Date.parse('2026-11-05T10:00:00Z');
    assert.equal(collectingFor({diag_collecting_until: '2026-11-05T10:05:00Z'}, now), 300000);
    assert.equal(collectingFor({diag_collecting_until: '2026-11-05T10:05:00+00:00'}, now), 300000);
    assert.equal(collectingFor({diag_collecting_until: '2026-11-05T09:59:59Z'}, now), 0);
    assert.equal(collectingFor({diag_collecting_until: null}, now), 0);
    assert.equal(collectingFor({diag_collecting_until: 'soon'}, now), 0);
    assert.equal(collectingFor({}, now), 0);
    assert.equal(collectingFor(null, now), 0);
    // A clock far off (or a bad file) never pins the notice for days.
    assert.equal(collectingFor({diag_collecting_until: '2026-11-09T10:00:00Z'}, now), 24 * 3600 * 1000);
});
