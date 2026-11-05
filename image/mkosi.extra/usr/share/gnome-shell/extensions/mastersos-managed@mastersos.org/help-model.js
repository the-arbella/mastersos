// The Get help dialog's pure logic (plan 2026-11-05 Ruling P3): the request it sends to the agent's support socket, what it
// accepts, and what it says afterwards. No GNOME imports: image/tests/help-model-test.mjs runs it under node. The same file
// is in mastersos-login@mastersos.org and mastersos-managed@mastersos.org (check-tree.sh asserts they are identical).
//
// Socket protocol (agent side: core/mastersos-agent/src/support/): one JSON line in, one JSON line out.
//   {"op":"submit","category":…,"text":…,"session":"login|desktop","screenshot_png_b64":null|"…"}
//     → {"ok":true,"client_id":"…","state":"queued"} | {"ok":false,"error":"rate_limited|invalid|disabled"}
//   {"op":"status","client_id":"…"} → {"ok":true,"state":"queued|sent|failed|disabled","ticket":"1042"?}
// Who is asking comes from the socket's peer credentials, never from the request.
//
// Every text here is an English msgid of the mastersos-login catalogue, marked N_ so that check-tree.sh finds it in
// login-i18n/mastersos-login.pot; the caller passes its gettext.

const N_ = s => s;

export const COPY = {
    entry: N_('Get help'),
    title: N_('Get help from IT'),
    placeholder: N_("What happened? Please don't include passwords or personal details."),
    attach: N_('Attach a screenshot'),
    cancel: N_('Cancel'),
    send: N_('Send'),
    close: N_('Close'),
    sending: N_('Sending…'),
    sent: N_('Sent. Ticket #%s. IT has been told.'),
    queued: N_('Saved. It will be sent when this computer is online.'),
    disabled: N_('Help requests are turned off at this school.'),
    rateLimited: N_("You've sent 3 requests this hour. Please try again later."),
    error: N_("Couldn't send. Please tell a teacher."),
    collecting: N_('IT is collecting diagnostic info from this computer.'),
};

// Wire ids are SupportRequest's categories (mastersos_bundle::diag); the order is the order on screen.
export const CATEGORIES = [
    {id: 'wifi', label: N_('Wi-Fi')},
    {id: 'sign_in', label: N_("Can't sign in")},
    {id: 'app', label: N_('An app')},
    {id: 'hardware', label: N_('Screen, keys or sound')},
    {id: 'battery', label: N_('Battery')},
    {id: 'other', label: N_('Other')},
];

export const SESSIONS = ['login', 'desktop'];
export const MAX_TEXT = 1000;
// The counter appears from here on.
export const COUNTER_FROM = 900;
export const MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024;
export const POLL_MS = 3000;
export const POLL_LIMIT_MS = 60000;
// The longest the collecting notice stays up from one status.json, whatever its clock says.
const COLLECTING_CAP_MS = 24 * 3600 * 1000;
const TICKET = /^[A-Za-z0-9-]{1,32}$/;

// Unicode code points, the way the agent counts (Rust chars), not UTF-16 units.
export function textLength(text) {
    return [...text ?? ''].length;
}

export function counterText(text) {
    const n = textLength(text);
    return n >= COUNTER_FROM ? `${n}/${MAX_TEXT}` : null;
}

// Decoded size of a base64 string.
export function b64Bytes(b64) {
    const s = b64 ?? '';
    const pad = s.endsWith('==') ? 2 : s.endsWith('=') ? 1 : 0;
    return Math.floor(s.length / 4) * 3 - pad;
}

function validCategory(category) {
    return CATEGORIES.some(c => c.id === category);
}

export function canSend({category, text}) {
    return validCategory(category) && textLength(text) <= MAX_TEXT;
}

// The submit request, keys in the order of the protocol and no others (the agent refuses unknown fields). Throws when the
// form cannot be sent; the dialog never lets that happen.
export function buildSubmit({category, text, session, screenshot, attach}) {
    if (!validCategory(category))
        throw new Error(`help: no such category: ${category}`);
    const body = (text ?? '').trim();
    if (textLength(body) > MAX_TEXT)
        throw new Error(`help: the description is over ${MAX_TEXT} characters`);
    if (!SESSIONS.includes(session))
        throw new Error(`help: no such session: ${session}`);
    const png = attach && screenshot ? screenshot : null;
    if (png !== null && b64Bytes(png) > MAX_SCREENSHOT_BYTES)
        throw new Error('help: the screenshot is over 5 MiB');
    return {op: 'submit', category, text: body, session, screenshot_png_b64: png};
}

export function statusRequest(clientId) {
    return {op: 'status', client_id: clientId};
}

export function encode(request) {
    return `${JSON.stringify(request)}\n`;
}

export function parseReply(line) {
    try {
        const v = JSON.parse(line);
        return v && typeof v === 'object' && !Array.isArray(v) ? v : null;
    } catch {
        return null;
    }
}

// null (no socket, refused, a broken reply) is an error: nothing was saved.
export function afterSubmit(reply) {
    if (reply?.ok === true && typeof reply.client_id === 'string' && reply.client_id)
        return {state: 'queued', clientId: reply.client_id};
    if (reply?.ok === false && (reply.error === 'rate_limited' || reply.error === 'disabled'))
        return {state: reply.error};
    return {state: 'error'};
}

// After a submit the request is in the agent's queue: anything short of a ticket, a refusal or a failure is asked again every
// POLL_MS, and after POLL_LIMIT_MS the student is told it is saved.
export function afterStatus(reply, elapsedMs) {
    if (reply?.ok === true) {
        const ticket = typeof reply.ticket === 'number' ? String(reply.ticket) : reply.ticket;
        if (reply.state === 'sent' && typeof ticket === 'string' && TICKET.test(ticket))
            return {state: 'sent', ticket};
        if (reply.state === 'disabled')
            return {state: 'disabled'};
        if (reply.state === 'failed')
            return {state: 'error'};
    }
    return elapsedMs >= POLL_LIMIT_MS ? {state: 'queued'} : {state: 'poll'};
}

const MESSAGES = {
    sending: COPY.sending,
    sent: COPY.sent,
    queued: COPY.queued,
    disabled: COPY.disabled,
    rate_limited: COPY.rateLimited,
    error: COPY.error,
};

export function message(outcome, gettext = s => s) {
    const text = gettext(MESSAGES[outcome.state] ?? COPY.error);
    return outcome.state === 'sent' ? text.split('%s').join(outcome.ticket) : text;
}

// support.json in the public directory, {"enabled": bool}. Missing or unreadable: no entry.
export function supportEnabled(json) {
    return json?.enabled === true;
}

// status.json's diag_collecting_until (RFC 3339): how many ms the notice stays up from now, 0 for none.
export function collectingFor(status, nowMs) {
    const until = status?.diag_collecting_until;
    const t = typeof until === 'string' ? Date.parse(until) : NaN;
    if (!Number.isFinite(t) || t <= nowMs)
        return 0;
    return Math.min(t - nowMs, COLLECTING_CAP_MS);
}
