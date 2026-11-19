// Unit tests for the login screen's person search and refusals (mastersos-login@mastersos.org/people.js).
// Run with: bash image/tests/login-people-test.sh (from any directory: it runs from the repository root)

import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';

// login-people-test.sh copies people.js to a .mjs first: node before 22 reads a bare .js as CommonJS.
const {HIDDEN, LIMIT, REFUSAL_DOMAINS, expandLoginName, matchPeople, preselect, refusalDomains, refusalKind, suggestDomains} =
    await import(process.env.MASTERSOS_PEOPLE_MJS);

const person = (userName, realName, loginTime = 0) => ({userName, realName, loginTime});
const names = r => r.shown.map(p => p.userName);

const P = [
    person('ann@school.org', 'Ann Lim', 10),
    person('bob', 'Bob Stone', 20),
    person('somchai@school.org', 'สมชาย', 5),
    person('ming@school.org', '李小明', 1),
];

test('empty query shows nobody', () => {
    assert.deepEqual(matchPeople(P, '  '), {shown: [], more: false});
    assert.deepEqual(matchPeople(P, ''), {shown: [], more: false});
});

test('prefix of any word in the real name', () => {
    assert.deepEqual(names(matchPeople(P, 'li')), ['ann@school.org']);
    assert.deepEqual(names(matchPeople(P, 'sto')), ['bob']);
    assert.deepEqual(names(matchPeople(P, 'im')), []);
});

test('prefix of the user name / email', () => {
    assert.deepEqual(names(matchPeople(P, 'ann@')), ['ann@school.org']);
    assert.deepEqual(names(matchPeople(P, 'school')), []);
});

test('case-insensitive', () => {
    assert.deepEqual(names(matchPeople(P, 'ANN')), ['ann@school.org']);
});

test('substring for names without spaces', () => {
    assert.deepEqual(names(matchPeople(P, 'ชาย')), ['somchai@school.org']);
    assert.deepEqual(names(matchPeople(P, '明')), ['ming@school.org']);
});

test('hidden accounts never match', () => {
    const all = [...P, person('guest', 'Guest'), person('kiosk-nwea', 'NWEA'), person('itadmin', 'IT admin')];
    assert.deepEqual(names(matchPeople(all, 'g')), []);
    assert.deepEqual(names(matchPeople(all, 'nwea')), []);
    assert.deepEqual(names(matchPeople(all, 'it')), []);
    assert.equal(HIDDEN('guest'), true);
    assert.equal(HIDDEN('kiosk-x'), true);
    assert.equal(HIDDEN('itadmin'), true);
    assert.equal(HIDDEN('ann@school.org'), false);
});

test('most recent first, then by name', () => {
    const r = matchPeople([person('a1', 'Dan A', 1), person('a2', 'Dan B', 9), person('a3', 'Dan C', 9)], 'dan');
    assert.deepEqual(names(r), ['a2', 'a3', 'a1']);
});

test('at most five, then more', () => {
    const many = n => Array.from({length: n}, (_, i) => person(`u${i}`, `Kim ${i}`, i));
    const seven = matchPeople(many(7), 'kim');
    assert.equal(LIMIT, 5);
    assert.equal(seven.shown.length, 5);
    assert.equal(seven.more, true);
    const five = matchPeople(many(5), 'kim');
    assert.equal(five.shown.length, 5);
    assert.equal(five.more, false);
});

test('preselect', () => {
    const x = person('dan', 'Dan', 0);
    assert.equal(preselect('d', [x]), 0);
    assert.equal(preselect('d@', [x]), -1);
    assert.equal(preselect('d', []), -1);
});

test('an exact user name or full name comes first', () => {
    const r = matchPeople([person('bobby', 'Bobby Lee', 9), person('bob', 'Bob Stone', 1)], 'bob');
    assert.deepEqual(names(r), ['bob', 'bobby']);
    const n = matchPeople([person('u1', 'Ann Lim Two', 9), person('u2', 'Ann Lim', 1)], 'ann lim');
    assert.deepEqual(names(n), ['u2', 'u1']);
});

const D = ['school.example.org', 'students.example.net'];

test('a name is offered every school domain', () => {
    assert.deepEqual(suggestDomains('kim', D), ['kim@school.example.org', 'kim@students.example.net']);
    assert.deepEqual(suggestDomains('k.im-2', D.slice(0, 1)), ['k.im-2@school.example.org']);
});

test('after the @ only the domains that start with what follows', () => {
    assert.deepEqual(suggestDomains('kim@', D), ['kim@school.example.org', 'kim@students.example.net']);
    assert.deepEqual(suggestDomains('kim@sch', D), ['kim@school.example.org']);
    assert.deepEqual(suggestDomains('kim@SCH', D), ['kim@school.example.org']);
    assert.deepEqual(suggestDomains('kim@stu', D), ['kim@students.example.net']);
    assert.deepEqual(suggestDomains('kim@x', D), []);
});

test('nothing once the address is complete', () => {
    assert.deepEqual(suggestDomains('kim@school.example.org', D), []);
    assert.deepEqual(suggestDomains('KIM@School.Example.org', D), []);
});

test('no domain suggestion without domains, text or a possible local part', () => {
    assert.deepEqual(suggestDomains('kim', []), []);
    assert.deepEqual(suggestDomains('', D), []);
    assert.deepEqual(suggestDomains('   ', D), []);
    assert.deepEqual(suggestDomains('@mas', D), []);
    assert.deepEqual(suggestDomains('Ann Lim', D), []);
    assert.deepEqual(suggestDomains('สมชาย', D), []);
    assert.deepEqual(suggestDomains('a@b@mas', D), []);
    assert.deepEqual(suggestDomains('a(b)', D), []);
    assert.deepEqual(suggestDomains('x'.repeat(65), D), []);
});

test('no domain suggestion for an address already listed as a person', () => {
    assert.deepEqual(suggestDomains('ann', D, ['Ann@school.example.org']), ['ann@students.example.net']);
});

test('at most five domain suggestions', () => {
    const many = Array.from({length: 8}, (_, i) => `s${i}.org`);
    assert.equal(suggestDomains('kim', many).length, LIMIT);
});

// The English half of a pam-check refusal in core/mastersos-agent/src/system/login.rs ("中文 / English").
function agentRefusal(name) {
    const src = readFileSync('core/mastersos-agent/src/system/login.rs', 'utf8');
    const m = src.match(new RegExp(`pub const ${name}: &str =\\s*"([^"]*)"`));
    assert.ok(m, `${name} not found in login.rs`);
    return m[1].split(' / ').pop();
}

test('refusals for who the person is, in the words the broker and the agent use', () => {
    // The broker: allowed_users and allowed_domains (patch 0006), the generic provider's email_verified, patch 0004.
    assert.equal(refusalKind('Authentication failure: user not allowed in broker configuration'), 'not-allowed');
    assert.equal(refusalKind('Authentication failure: email not verified'), 'unverified');
    assert.equal(refusalKind('Authentication failure: requested username "a@s.org" does not match the authenticated user "b@s.org"'),
        'wrong-account');
    // The agent's pam-check, as it reaches the greeter: "中文 / English".
    assert.equal(refusalKind(`这个账号的域名不允许登录这台电脑 / ${agentRefusal('DENY_DOMAIN')}`), 'not-allowed');
    assert.equal(refusalKind(agentRefusal('DENY_DOMAIN')), 'not-allowed');
});

// 20261105.15: the refusal named only the first domain, and teachers on the second one read it as meant for them.
test('a domain refusal names every school domain', () => {
    assert.equal(refusalDomains(['school.example.org']), '@school.example.org');
    assert.equal(refusalDomains(['school.example.org', 'staff.example.org']), '@school.example.org, @staff.example.org');
    assert.equal(refusalDomains(['a.org', 'b.org', 'c.org']), '@a.org, @b.org, @c.org');
});

test('a domain refusal names none without domains or with too many', () => {
    assert.equal(refusalDomains([]), '');
    assert.equal(refusalDomains(null), '');
    assert.equal(refusalDomains(['', null]), '');
    assert.equal(refusalDomains(Array.from({length: REFUSAL_DOMAINS + 1}, (_, i) => `s${i}.org`)), '');
});

test('other messages are no refusal of the person', () => {
    for (const m of ['Error retrieving access token. Please try again.', 'Error connecting to provider', '', null, undefined,
        agentRefusal('DENY_LOCKED'), agentRefusal('DENY_SSO')])
        assert.equal(refusalKind(m), null, String(m));
});

test('a bare username becomes <username>@<login_domain>', () => {
    const D = 'school.example';
    assert.equal(expandLoginName('Alice', D, []), 'alice@school.example');
    assert.equal(expandLoginName('  bob.1_x-y  ', D, ['carol']), 'bob.1_x-y@school.example');
    // A local account with exactly that name keeps precedence.
    assert.equal(expandLoginName('alice', D, ['alice']), null);
    // A case variant ("Alice" with a local "alice") is not refused here: while the list is up, preselect picks the local
    // person (an exact match, case-insensitive) and Enter signs that person in without reaching this; after Escape put the
    // list away, Enter takes the text and this completes it. On its own it only refuses exact names.
    assert.equal(expandLoginName('Alice', D, ['alice']), 'alice@school.example');
    assert.equal(expandLoginName('alice', null, []), null);
    assert.equal(expandLoginName('alice', '', []), null);
    assert.equal(expandLoginName('itadmin', D, []), null);
    assert.equal(expandLoginName('Guest', D, []), null);
    assert.equal(expandLoginName('kiosk-1', D, []), null);
    assert.equal(expandLoginName('a@b', D, []), null);
    assert.equal(expandLoginName('a b', D, []), null);
    assert.equal(expandLoginName('', D, []), null);
    assert.equal(expandLoginName('a'.repeat(64), D, []), `${'a'.repeat(64)}@${D}`);
    assert.equal(expandLoginName('a'.repeat(65), D, []), null);
});

test('the broker refusing another organisation is a not-allowed refusal', () => {
    assert.equal(refusalKind('Authentication failure: this account is not a member of this school'), 'not-allowed');
});

test('a bare username is not taken by someone whose name only starts with it', () => {
    const D = 'school.example';
    const sso = [person('bobby@school.example', 'Bobby Lee', 9), person('carol@school.example', 'Carol Bobson', 8)];
    const r = matchPeople(sso, 'bob', D);
    assert.deepEqual(names(r), ['bobby@school.example', 'carol@school.example']);
    // Nobody preselected: Enter completes the text instead.
    assert.equal(preselect('bob', r.shown, D, []), -1);
    assert.equal(expandLoginName('bob', D, []), 'bob@school.example');
    // A person chosen with the arrow keys or the mouse still wins (extension.js: the pick comes before the completion).
    // With an '@' typed, nobody as before.
    assert.equal(preselect('bob@', matchPeople(sso, 'bob@', D).shown, D, []), -1);
});

test('a bare username is exactly the school account it completes to', () => {
    const D = 'school.example';
    const people = [person('bobby@school.example', 'Bobby Lee', 9), person('bob@school.example', 'Bob Stone', 1)];
    const r = matchPeople(people, 'bob', D);
    assert.deepEqual(names(r), ['bob@school.example', 'bobby@school.example']);
    assert.equal(preselect('bob', r.shown, D, []), 0);
    assert.equal(preselect('Bob', matchPeople(people, 'Bob', D).shown, D, []), 0);
    // Another domain's bob is not this school's bob.
    const other = [person('bob@other.example', 'Bob Other', 9)];
    assert.equal(preselect('bob', matchPeople(other, 'bob', D).shown, D, []), -1);
});

test('an exact local name keeps precedence over the completion', () => {
    const D = 'school.example';
    const people = [person('bobby@school.example', 'Bobby Lee', 9), person('bob', 'Bob Stone', 1)];
    const r = matchPeople(people, 'bob', D);
    assert.deepEqual(names(r), ['bob', 'bobby@school.example']);
    assert.equal(preselect('bob', r.shown, D, ['bob']), 0);
    assert.equal(expandLoginName('bob', D, ['bob']), null);
    // A case variant of the local name: the local person, preselected.
    assert.equal(preselect('Bob', matchPeople(people, 'Bob', D).shown, D, ['bob']), 0);
});

test('without a login domain, or before the accounts are known, the first person is preselected as before', () => {
    const people = [person('bobby@school.example', 'Bobby Lee', 9)];
    const r = matchPeople(people, 'bob');
    assert.equal(preselect('bob', r.shown), 0);
    assert.equal(preselect('bob', r.shown, null, []), 0);
    assert.equal(preselect('bob', r.shown, '', []), 0);
    // The local accounts not loaded yet (null): no completion is offered, so the old rule holds.
    assert.equal(preselect('bob', matchPeople(people, 'bob', 'school.example').shown, 'school.example', null), 0);
});

test('a bare username that completes is a user name, not a real name', () => {
    const D = 'school.example';
    const mai = person('mai@school.example', 'Mai Tran', 1);
    const x9 = person('x9@school.example', 'Mai', 9);
    const r = matchPeople([mai, x9], 'mai', D);
    assert.equal(r.shown[preselect('mai', r.shown, D, [])].userName, 'mai@school.example');
    // mai@school.example not on this computer: nobody preselected, Enter completes to it.
    assert.equal(preselect('mai', matchPeople([x9], 'mai', D).shown, D, []), -1);
    assert.equal(expandLoginName('mai', D, []), 'mai@school.example');
});

test('without a login domain an exact real name is preselected as before', () => {
    const people = [person('mai@school.example', 'Mai Tran', 1), person('x9@school.example', 'Mai', 9)];
    const r = matchPeople(people, 'mai');
    assert.equal(r.shown[preselect('mai', r.shown)].userName, 'x9@school.example');
    assert.equal(r.shown[preselect('mai', r.shown, null, [])].userName, 'x9@school.example');
});
