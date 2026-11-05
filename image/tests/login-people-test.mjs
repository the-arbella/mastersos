// Unit tests for the login screen's person search (mastersos-login@mastersos.org/people.js).
// Run with: bash image/tests/login-people-test.sh

import test from 'node:test';
import assert from 'node:assert/strict';

// login-people-test.sh copies people.js to a .mjs first: node before 22 reads a bare .js as CommonJS.
const {HIDDEN, LIMIT, matchPeople, preselect, suggestDomains} = await import(process.env.MASTERSOS_PEOPLE_MJS);

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
