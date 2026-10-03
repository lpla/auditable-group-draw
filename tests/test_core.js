'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { webcrypto } = require('node:crypto');
const { TextEncoder } = require('node:util');

if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
if (!globalThis.TextEncoder) Object.defineProperty(globalThis, 'TextEncoder', { value: TextEncoder });

const core = require('../app.js');

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function verifyFixture(filename) {
  const audit = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', filename), 'utf8'));
  assert(core.CONFIG_SCHEMA_VERSION === audit.config.schemaVersion, `${filename}: config schema mismatch`);
  assert(core.AUDIT_SCHEMA_VERSION === audit.auditSchemaVersion, `${filename}: audit schema mismatch`);
  assert(core.ALGORITHM === audit.method, `${filename}: algorithm mismatch`);

  const normalized = core.canonicalJson(audit.config);
  assert(normalized === audit.normalizedConfig, `${filename}: canonical JSON mismatch`);
  const hash = await core.sha256Hex(normalized);
  assert(hash === audit.configHash, `${filename}: config hash mismatch`);

  const valid = core.enumerateValid(audit.config);
  assert(valid.length === audit.validCount, `${filename}: valid count mismatch`);

  const choice = await core.chooseIndex(hash, audit.seed, valid.length);
  assert(choice.index === audit.selectedIndex0, `${filename}: selected index mismatch`);
  assert(choice.counter === audit.counter, `${filename}: counter mismatch`);
  assert(choice.digest === audit.selectionDigest, `${filename}: selection digest mismatch`);
  assert(choice.material === audit.hashMaterial, `${filename}: hash material mismatch`);
  assert(choice.rejectionLimitHex === audit.rejectionLimitHex, `${filename}: rejection limit mismatch`);

  const mask = valid[choice.index];
  assert(mask === audit.selectedMaskInteger, `${filename}: selected mask mismatch`);
  assert(JSON.stringify(core.assignmentFromMask(mask, audit.config.names)) === JSON.stringify(audit.assignment), `${filename}: assignment mismatch`);
  assert(JSON.stringify(core.participantBits(mask, audit.config.names)) === JSON.stringify(audit.participantBits), `${filename}: participant bits mismatch`);
}

(async () => {
  await verifyFixture('test-vector-v0.2.0.json');
  await verifyFixture('test-vector-restricted-v0.2.0.json');

  const oneValid = {
    schemaVersion: '2',
    algorithm: core.ALGORITHM,
    names: ['A', 'B'],
    turnNames: ['Uno', 'Dos'],
    capacities: [1, 1],
    fixed: ['T1', 'T2'],
    together: [],
    apart: []
  };
  assert(JSON.stringify(core.enumerateValid(oneValid)) === JSON.stringify([1]), 'single valid assignment regression');

  assert(core.parseCapacity('0', 'capacity') === 0, 'zero capacity should be valid');
  assert(core.parseCapacity('20', 'capacity') === 20, 'maximum capacity should be valid');
  for (const value of ['', '21', '1e1', '2.5', '-1']) {
    let failed = false;
    try { core.parseCapacity(value, 'capacity'); } catch (_) { failed = true; }
    assert(failed, `invalid capacity ${JSON.stringify(value)} should fail`);
  }

  for (const value of ['Ana, alias', 'Ana + Bruno', 'Ana|Bruno']) {
    let failed = false;
    try { core.assertSafeParticipantName(value); } catch (_) { failed = true; }
    assert(failed, `reserved participant name ${JSON.stringify(value)} should fail`);
  }

  let groupError = '';
  try { core.parseGroups('A + Unknown', ['A', 'B'], 'Together'); } catch (error) { groupError = error.message; }
  assert(groupError.includes('Unknown') && !groupError.includes('repite la misma persona'), 'unknown group member should not trigger duplicate-person error');
  assert(JSON.stringify(core.parseGroups('A + B\nB + A\nA + B', ['A', 'B'], 'Together')) === JSON.stringify([[0, 1]]), 'equivalent groups should canonicalize and deduplicate');

  let namesTooLarge = false;
  try { core.parseNamesText('A'.repeat(5001)); } catch (_) { namesTooLarge = true; }
  assert(namesTooLarge, 'oversized participant input should fail before splitting');
  let constraintsTooLarge = false;
  try { core.parseGroups('A'.repeat(20001), ['A', 'B'], 'Together'); } catch (_) { constraintsTooLarge = true; }
  assert(constraintsTooLarge, 'oversized constraint input should fail before parsing');
  console.log('PASS JavaScript core vectors and constraint regression');
})().catch(error => {
  console.error(error.stack || error);
  process.exitCode = 1;
});
