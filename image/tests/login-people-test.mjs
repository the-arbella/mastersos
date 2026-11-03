// Unit tests for the login screen's person search (mastersos-login@mastersos.org/people.js).
// Run with: bash image/tests/login-people-test.sh

import test from 'node:test';
import assert from 'node:assert/strict';

// login-people-test.sh copies people.js to a .mjs first: node before 22 reads a bare .js as CommonJS.
const {HIDDEN, LIMIT, matchPeople, preselect} = await import(process.env.MASTERSOS_PEOPLE_MJS);

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
