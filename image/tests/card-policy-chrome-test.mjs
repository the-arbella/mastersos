// Starts a headless Chrome under the policy card-policy-chrome-test.sh installed and checks one fixture's cases over the
// DevTools protocol on a pipe (fds 3 and 4: no socket, no network): every `allow <url>` must not be blocked by policy,
// every `block <url>` must be. A navigation the policy blocks fails at once with net::ERR_BLOCKED_BY_ADMINISTRATOR before
// any network access; an allowed one fails later for another reason (no host resolves, loopback ports are closed).
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
        const m = /^(allow|block) (\S+)$/.exec(line);
        if (!m)
            throw new Error(`${casesFile}:${i + 1}: expected "allow <url>" or "block <url>"`);
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
        let buf = '';
        child.stdio[4].setEncoding('utf8');
        child.stdio[4].on('data', chunk => {
            buf += chunk;
            let end;
            while ((end = buf.indexOf('\0')) >= 0) {
                const msg = JSON.parse(buf.slice(0, end));
                buf = buf.slice(end + 1);
                const w = msg.id !== undefined && this._waiting.get(msg.id);
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
    '--disable-component-update', '--host-resolver-rules=MAP * ~NOTFOUND', 'about:blank',
], {stdio: ['ignore', log, log, 'pipe', 'pipe']});
const cdp = new Cdp(child);

let failed = 0;
try {
    const {product} = await cdp.send('Browser.getVersion');
    console.log(`${product}, ${casesFile}`);
    for (const {want, url} of cases) {
        // A fresh tab for every case, so one navigation never waits on another.
        const {targetId} = await cdp.send('Target.createTarget', {url: 'about:blank'});
        try {
            const {sessionId} = await cdp.send('Target.attachToTarget', {targetId, flatten: true});
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
