# A factory reset keeps the settings the machine had

Status: agreed 2026-11-25. Agent only: no change to the protocol, the server, the seed format or the
command line.

## 1. What is wrong today

The seed partition is not wiped by a factory reset. It holds the seed written at install, the fetch token
(replaced when the token is renewed), the machine's identity, and a cache of the last settings bundle the
machine accepted (replaced at every accepted version).

What a reset loses is what the machine learned after the install and kept only on the encrypted root: which
keys it trusts now and which version it reached. After a reset it starts from the seed again, so:

- a key the school replaced is trusted again until the machine has followed the key changes from the server;
- the cached bundle is the newest one, signed by the newer keys, so it fails the check against the seed's keys
  and is thrown away: a reset machine without a network has no settings although they are on its disk;
- the version floor is the seed's `min_version` again.

Separately, when the cached bundle is accepted the machine does not ask the server before the login screen,
so settings published while the machine was off arrive only later.

## 2. The change

1. **The cache records who verified it.** Beside `cache/current.bundle` the agent writes
   `cache/verified-by.json`: the trust keys that verified that bundle and the SHA-256 of its bytes. Both are
   written when a bundle is accepted, the record first.
2. **After a reset the cached bundle is checked against that record.** When the record belongs to exactly
   the cached bytes and its keys verify the bundle, the bundle is accepted with them, and the machine goes on
   from there: its trust is the bundle's trust and its floor is the bundle's version, as before the reset.
   The seed's school id and `min_version` are enforced as before.
3. **Anything else falls back to the seed.** No record, a record for other bytes, an unreadable or empty
   record, or keys that do not verify the bundle: the bundle is checked against the seed's keys, exactly as
   today. The seed file itself is never rewritten.
4. **The first boot after an install or a reset asks the server once.** With cached settings accepted, the
   boot-time step applies them (their Wi-Fi networks bring the machine online), waits for the network and
   asks the server once, all within the existing 45-second budget, and then applies again when the server
   had a newer version. Without a network it goes on with the cached settings. Later boots are unchanged.
5. **Every start completes the record.** When the cache on the seed partition does not hold the current
   bundle together with a record that fits it (a machine set up before this change, a power cut between the
   two writes, a lost file), the agent writes both at its next start, so the change reaches every machine
   without waiting for the school to publish again.

## 3. Why this is not weaker

Nothing on the seed partition is an authority, and the partition is not encrypted. Somebody who can write
the record and the cache can already replace `seed.toml` today, with the same result: after a reset the
machine follows what they wrote. The bundle's signature is still checked; the record only says which keys to
check it against.

One difference is accepted: a machine reports the fingerprints of its seed's keys, which lets a server notice
a replaced seed. A forged record with a forged bundle does not change that report. Such a machine then
refuses every real version from the server and reports the refusals.

## 4. What stays as it is

- A machine that was off when the school changed its Wi-Fi password cannot join the network after a reset,
  nor before it. Somebody joins a network on the login screen (the new password, a hotspot, a cable); the
  machine then fetches the current settings with its seed. Schools avoid it by publishing the new network
  beside the old one before they switch the old one off.
- A machine whose fetch tokens were all dropped still needs a new seed.

## 5. Verification

Unit tests (agent): a reset after a key change continues at the same version with the new keys only; without
the record the bundle is checked against the seed; a start writes a missing record and repairs a cache that holds an older bundle than its record; the record
does not lower the seed's `min_version`; a
record that does not verify the bundle leaves the seed's keys in charge and no refusal; the first boot after
a reset asks the server once and takes a newer version; without a network it keeps the cached version; later
boots do not wait.

On a VM: install, publish a key change, reset from the boot menu with and without a network, and check the
version, the trust and the login screen each time.
