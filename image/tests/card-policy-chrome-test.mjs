// Starts a headless Chrome under the policy card-policy-chrome-test.sh installed and checks one fixture's cases over the
// DevTools protocol on a pipe (fds 3 and 4: no socket, no network): every `allow <url>` must not be blocked by policy,
// every `block <url>` must be. A navigation the policy blocks fails at once with net::ERR_BLOCKED_BY_ADMINISTRATOR before
// any network access; an allowed one fails later for another reason (no host resolves, loopback ports are closed).
// `media <url>` and `nomedia <url>` ask for the camera and the microphone from a page at that URL (answered by this test,
// still without a network; Chrome's fake devices stand in for hardware, the permission is decided as usual): `media`
// must get both without a question, `nomedia` must be refused.
// Usage: node card-policy-chrome-test.mjs <chrome> <profile dir> <log file> <cases file>
import {spawn} from 'node:child_process';
import {openSync, readFileSync} from 'node:fs';

const BLOCKED = 'net::ERR_BLOCKED_BY_ADMINISTRATOR';
const TIMEOUT_MS = 20000;

const [chrome, profile, logFile, casesFile] = process.argv.slice(2);
if (!casesFile) {
    console.error('usage: node card-policy-chrome-test.mjs <chrome> <profile dir> <log file> <cases file>');
    process.exit(64);
}

function parseCases(text) {
    const out = [];
    for (const [i, raw] of text.split('\n').entries()) {
        const line = raw.trim();
        if (line === '' || line.startsWith('#'))
            continue;
        const m = /^(allow|block|media|nomedia) (\S+)$/.exec(line);
        if (!m)
            throw new Error(`${casesFile}:${i + 1}: expected "allow|block|media|nomedia <url>"`);
        out.push({want: m[1], url: m[2]});
    }
    if (out.length === 0)
        throw new Error(`${casesFile}: no cases`);
    return out;
}

// The DevTools protocol over --remote-debugging-pipe: Chrome reads NUL-terminated JSON on fd 3 and writes it on fd 4.
class Cdp {
    constructor(child) {
        this._in = child.stdio[3];
        this._next = 1;
        this._waiting = new Map();
        this._handlers = new Map();
        let buf = '';
        child.stdio[4].setEncoding('utf8');
        child.stdio[4].on('data', chunk => {
            buf += chunk;
            let end;
            while ((end = buf.indexOf('\0')) >= 0) {
                const msg = JSON.parse(buf.slice(0, end));
                buf = buf.slice(end + 1);
                if (msg.id === undefined) {
                    this._handlers.get(msg.method)?.(msg.params, msg.sessionId);
                    continue;
                }
                const w = this._waiting.get(msg.id);
                if (!w)
                    continue;
                this._waiting.delete(msg.id);
                clearTimeout(w.timer);
                if (msg.error)
                    w.reject(new Error(`${w.method}: ${msg.error.message}`));
                else
                    w.resolve(msg.result);
            }
        });
        child.on('exit', code => {
            for (const w of this._waiting.values()) {
                clearTimeout(w.timer);
                w.reject(new Error(`Chrome exited (${code}) before answering ${w.method}`));
            }
            this._waiting.clear();
        });
    }

    on(method, handler) {
        this._handlers.set(method, handler);
    }
    send(method, params = {}, sessionId) {
        const id = this._next++;
        return new Promise((resolve, reject) => {
            const timer = setTimeout(() => {
                this._waiting.delete(id);
                reject(new Error(`no answer to ${method} in ${TIMEOUT_MS} ms`));
            }, TIMEOUT_MS);
            this._waiting.set(id, {resolve, reject, timer, method});
            this._in.write(`${JSON.stringify({id, method, params, ...(sessionId ? {sessionId} : {})})}\0`);
        });
    }
}

const cases = parseCases(readFileSync(casesFile, 'utf8'));
const log = openSync(logFile, 'a');
// The namespace's root is not the real root: Chrome's own sandbox cannot start inside it.
const child = spawn(chrome, [
    '--headless=new', '--no-sandbox', `--user-data-dir=${profile}`, '--remote-debugging-pipe',
    '--no-first-run', '--no-default-browser-check', '--disable-gpu', '--disable-background-networking',
    '--disable-component-update', '--host-resolver-rules=MAP * ~NOTFOUND', '--use-fake-device-for-media-stream', 'about:blank',
], {stdio: ['ignore', log, log, 'pipe', 'pipe']});
const cdp = new Cdp(child);
// The page of a media case: answered here, before Chrome looks for the host.
cdp.on('Fetch.requestPaused', ({requestId}, sessionId) => {
    cdp.send('Fetch.fulfillRequest', {
        requestId,
        responseCode: 200,
        responseHeaders: [{name: 'Content-Type', value: 'text/html'}],
        body: Buffer.from('<!doctype html><title>card</title>').toString('base64'),
    }, sessionId).catch(() => {});
});
const ASK_FOR_MEDIA = `(async () => {
    if (!window.isSecureContext || !navigator.mediaDevices)
        return 'refused: not a secure page';
    try {
        const stream = await navigator.mediaDevices.getUserMedia({audio: true, video: true});
        const kinds = stream.getTracks().map(t => t.kind).sort().join('+');
        stream.getTracks().forEach(t => t.stop());
        return 'granted: ' + kinds;
    } catch (e) {
        return 'refused: ' + e.name;
    }
})()`;
async function mediaCase(want, url, sessionId) {
    await cdp.send('Fetch.enable', {patterns: [{urlPattern: '*'}]}, sessionId);
    const {errorText = ''} = await cdp.send('Page.navigate', {url}, sessionId);
    if (errorText)
        return {ok: false, note: `the page did not load: ${errorText}`};
    const {result} = await cdp.send('Runtime.evaluate', {expression: ASK_FOR_MEDIA, awaitPromise: true, returnByValue: true}, sessionId);
    const got = String(result.value);
    const ok = want === 'media' ? got === 'granted: audio+video' : got.startsWith('refused: ');
    return {ok, note: got};
}

let failed = 0;
try {
    const {product} = await cdp.send('Browser.getVersion');
    console.log(`${product}, ${casesFile}`);
    for (const {want, url} of cases) {
        // A fresh tab for every case, so one navigation never waits on another.
        const {targetId} = await cdp.send('Target.createTarget', {url: 'about:blank'});
        try {
            const {sessionId} = await cdp.send('Target.attachToTarget', {targetId, flatten: true});
            if (want === 'media' || want === 'nomedia') {
                const {ok, note} = await mediaCase(want, url, sessionId);
                if (!ok)
                    failed++;
                console.log(`${ok ? 'ok  ' : 'FAIL'} ${want} ${url} (${note})`);
                continue;
            }
            const {errorText = ''} = await cdp.send('Page.navigate', {url}, sessionId);
            const got = errorText === BLOCKED ? 'block' : 'allow';
            if (got === want) {
                console.log(`ok   ${want} ${url}${errorText ? ` (${errorText})` : ''}`);
            } else {
                failed++;
                console.log(`FAIL ${want} ${url} (Chrome: ${errorText || 'loaded'})`);
            }
        } catch (e) {
            failed++;
            console.log(`FAIL ${want} ${url}: ${e.message}`);
        } finally {
            await cdp.send('Target.closeTarget', {targetId}).catch(() => {});
        }
    }
} catch (e) {
    failed++;
    console.log(`FAIL ${casesFile}: ${e.message}`);
} finally {
    // Let Chrome finish writing its profile before the shell script removes it.
    const exited = new Promise(resolve => child.exitCode !== null ? resolve() : child.once('exit', resolve));
    await cdp.send('Browser.close').catch(() => {});
    const killer = setTimeout(() => child.kill('SIGKILL'), 5000);
    await exited;
    clearTimeout(killer);
}
console.log(`${casesFile}: ${cases.length - failed}/${cases.length} as expected`);
process.exit(failed ? 1 : 0);
