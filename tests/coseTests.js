const assert = require('assert');
const cose = require('../cose');
const cbor = require('../cbor/cbor');
const { runTest, getTestSummary } = require('./utils');

const exampleCoseKeyEC2Buffer = Buffer.from(cbor.encode(new Map([
    [cose.COSE_KEY_PARAMETERS.kty, cose.COSE_KEY_TYPES.EC2], // kty: EC2 (2)
    [cose.COSE_KEY_PARAMETERS.alg, cose.COSE_ALGORITHMS.ES256], // alg: ES256 (-7)
    [cose.COSE_EC2_KEY_PARAMETERS.crv, cose.COSE_ELLIPTIC_CURVES.P_256], // crv: P-256 (1)
    [cose.COSE_EC2_KEY_PARAMETERS.x, Buffer.from('1'.repeat(64), 'hex')], // x: 32 bytes (example)
    [cose.COSE_EC2_KEY_PARAMETERS.y, Buffer.from('2'.repeat(64), 'hex')] // y: 32 bytes (example)
])));

const exampleCoseKeyOKPBuffer = Buffer.from(cbor.encode(new Map([
    [cose.COSE_KEY_PARAMETERS.kty, cose.COSE_KEY_TYPES.OKP], // kty: OKP (1)
    [cose.COSE_KEY_PARAMETERS.alg, cose.COSE_ALGORITHMS.EdDSA], // alg: EdDSA (-8)
    [cose.COSE_OKP_KEY_PARAMETERS.crv, cose.COSE_ELLIPTIC_CURVES.Ed25519], // crv: Ed25519 (6)
    [cose.COSE_OKP_KEY_PARAMETERS.x, Buffer.from('3'.repeat(64), 'hex')] // x: 32 bytes (example)
])));

const invalidCoseKeyMissingKty = Buffer.from(cbor.encode(new Map([
    [cose.COSE_KEY_PARAMETERS.alg, cose.COSE_ALGORITHMS.ES256]
])));
const invalidCoseKeyNotMap = Buffer.from(cbor.encode([1, 2, 3])); // Encode an array, not a map

runTest('COSE: decodeCoseKey Valid EC2 Key', () => {
    const decodedMap = cose.decodeCoseKey(exampleCoseKeyEC2Buffer);
    assert.ok(decodedMap, 'Failed to decode valid key');
    assert.strictEqual(decodedMap[cose.COSE_KEY_PARAMETERS.kty], cose.COSE_KEY_TYPES.EC2, 'kty mismatch');
    assert.strictEqual(decodedMap[cose.COSE_KEY_PARAMETERS.alg], cose.COSE_ALGORITHMS.ES256, 'alg mismatch');
    assert.strictEqual(decodedMap[cose.COSE_EC2_KEY_PARAMETERS.crv], cose.COSE_ELLIPTIC_CURVES.P_256, 'crv mismatch');
    assert.ok(decodedMap[cose.COSE_EC2_KEY_PARAMETERS.x] instanceof Uint8Array, 'x coord is not Uint8Array');
    assert.ok(decodedMap[cose.COSE_EC2_KEY_PARAMETERS.y] instanceof Uint8Array, 'y coord is not Uint8Array');
});

runTest('COSE: decodeCoseKey Valid OKP Key', () => {
    const decodedMap = cose.decodeCoseKey(exampleCoseKeyOKPBuffer);
    assert.ok(decodedMap, 'Failed to decode valid key');
    assert.strictEqual(decodedMap[cose.COSE_KEY_PARAMETERS.kty], cose.COSE_KEY_TYPES.OKP, 'kty mismatch');
    assert.strictEqual(decodedMap[cose.COSE_KEY_PARAMETERS.alg], cose.COSE_ALGORITHMS.EdDSA, 'alg mismatch');
    assert.strictEqual(decodedMap[cose.COSE_OKP_KEY_PARAMETERS.crv], cose.COSE_ELLIPTIC_CURVES.Ed25519, 'crv mismatch');
    assert.ok(decodedMap[cose.COSE_OKP_KEY_PARAMETERS.x] instanceof Uint8Array, 'x coord is not Uint8Array');
});

runTest('COSE: decodeCoseKey Throws on Missing kty', () => {
    assert.throws(
        () => cose.decodeCoseKey(invalidCoseKeyMissingKty),
        /Missing required parameter "kty"/,
        'Should throw for missing kty'
    );
});

runTest('COSE: decodeCoseKey Throws on Non-Map Input', () => {
    assert.throws(
        () => cose.decodeCoseKey(invalidCoseKeyNotMap),
        /Expected CBOR Map/, // Adjust error message if needed
        'Should throw for non-map input'
    );
});

runTest('COSE: getWebAuthnPublicKeyDetails EC2', () => {
    const decodedMap = cose.decodeCoseKey(exampleCoseKeyEC2Buffer);
    const details = cose.getWebAuthnPublicKeyDetails(decodedMap);
    assert.strictEqual(details.kty, cose.COSE_KEY_TYPES.EC2);
    assert.strictEqual(details.alg, cose.COSE_ALGORITHMS.ES256);
    assert.strictEqual(details.crv, cose.COSE_ELLIPTIC_CURVES.P_256);
    assert.ok(details.x instanceof Uint8Array && details.x.length === 32);
    assert.ok(details.y instanceof Uint8Array && details.y.length === 32);
});

runTest('COSE: getWebAuthnPublicKeyDetails OKP', () => {
    const decodedMap = cose.decodeCoseKey(exampleCoseKeyOKPBuffer);
    const details = cose.getWebAuthnPublicKeyDetails(decodedMap);
    assert.strictEqual(details.kty, cose.COSE_KEY_TYPES.OKP);
    assert.strictEqual(details.alg, cose.COSE_ALGORITHMS.EdDSA);
    assert.strictEqual(details.crv, cose.COSE_ELLIPTIC_CURVES.Ed25519);
    assert.ok(details.x instanceof Uint8Array && details.x.length === 32);
    assert.strictEqual(details.y, undefined, 'OKP should not have y coordinate');
});

runTest('COSE: getWebAuthnPublicKeyDetails Throws on Missing EC2 Params', () => {
    const incompleteKey = Buffer.from(cbor.encode(new Map([
        [cose.COSE_KEY_PARAMETERS.kty, cose.COSE_KEY_TYPES.EC2],
        [cose.COSE_KEY_PARAMETERS.alg, cose.COSE_ALGORITHMS.ES256],
        // Missing crv, x, y
    ])));
    const decodedMap = cose.decodeCoseKey(incompleteKey);
    assert.throws(
        () => cose.getWebAuthnPublicKeyDetails(decodedMap),
        /Invalid EC2 COSE_Key/,
        'Should throw for missing EC2 params'
    );
});

getTestSummary();