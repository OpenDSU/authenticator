const assert = require('assert');
const crypto = require('crypto');
const serverReg = require('../serverSideRegistration');
const cose = require('../cose');
const cbor = require('../cbor');
const { runTest, getTestSummary } = require('./utils');

const exampleCoseKeyEC2Buffer = Buffer.from(cbor.encode(new Map([
    [cose.COSE_KEY_PARAMETERS.kty, cose.COSE_KEY_TYPES.EC2], // kty: EC2 (2)
    [cose.COSE_KEY_PARAMETERS.alg, cose.COSE_ALGORITHMS.ES256], // alg: ES256 (-7)
    [cose.COSE_EC2_KEY_PARAMETERS.crv, cose.COSE_ELLIPTIC_CURVES.P_256], // crv: P-256 (1)
    [cose.COSE_EC2_KEY_PARAMETERS.x, Buffer.from('1'.repeat(64), 'hex')], // x: 32 bytes (example)
    [cose.COSE_EC2_KEY_PARAMETERS.y, Buffer.from('2'.repeat(64), 'hex')] // y: 32 bytes (example)
])));

runTest('ServerReg: base64urlToBuffer', () => {
    const b64url = 'SGVsbG8gV29ybGQ'; // "Hello World" in base64url
    const expectedBuffer = Buffer.from('Hello World', 'utf8');
    const actualBuffer = serverReg.base64urlToBuffer(b64url);
    assert.ok(serverReg.bufferEqual(actualBuffer, expectedBuffer), 'base64url decoding failed');
});

runTest('ServerReg: bufferEqual', () => {
    const buf1 = Buffer.from('abc');
    const buf2 = Buffer.from('abc');
    const buf3 = Buffer.from('def');
    const buf4 = Buffer.from('abcd');
    assert.ok(serverReg.bufferEqual(buf1, buf2), 'Equal buffers failed');
    assert.strictEqual(serverReg.bufferEqual(buf1, buf3), false, 'Unequal buffers failed');
    assert.strictEqual(serverReg.bufferEqual(buf1, buf4), false, 'Different length buffers failed');
});

// --- Test Data for parseAndVerifyAuthenticatorData ---
const testRpId = 'example.com';
const testRpIdHash = crypto.createHash('sha256').update(testRpId).digest();
const testFlagsPresentVerifiedAttested = Buffer.from([0x45]); // 0100 0101 -> AT=1, UV=1, UP=1
const testFlagsPresentAttestedOnly = Buffer.from([0x41]); // 0100 0001 -> AT=1, UV=0, UP=1
const testSignCount = Buffer.from([0x00, 0x00, 0x00, 0x01]);
const testAaguid = Buffer.alloc(16, 0); // Zero AAGUID
const testCredIdLength = Buffer.from([0x00, 0x10]); // Length 16
const testCredId = Buffer.alloc(16, 1); // Cred ID of 16 bytes, all 1s
const testPublicKeyCose = exampleCoseKeyEC2Buffer; // Use the EC2 key from COSE tests

const validAuthDataBuffer = Buffer.concat([
    testRpIdHash,
    testFlagsPresentVerifiedAttested,
    testSignCount,
    testAaguid,
    testCredIdLength,
    testCredId,
    testPublicKeyCose
]);

const authDataMissingUP = Buffer.concat([
    testRpIdHash,
    Buffer.from([0x44]), // 0100 0100 -> AT=1, UV=1, UP=0
    testSignCount, testAaguid, testCredIdLength, testCredId, testPublicKeyCose
]);

const authDataMissingAT = Buffer.concat([
    testRpIdHash,
    Buffer.from([0x05]), // 0000 0101 -> AT=0, UV=1, UP=1
    testSignCount, testAaguid, testCredIdLength, testCredId, testPublicKeyCose
]);

const authDataWrongRpId = Buffer.concat([
    crypto.createHash('sha256').update('wrong.com').digest(),
    testFlagsPresentVerifiedAttested,
    testSignCount, testAaguid, testCredIdLength, testCredId, testPublicKeyCose
]);

runTest('ServerReg: parseAndVerifyAuthenticatorData Valid (UV required & present)', () => {
    const result = serverReg.parseAndVerifyAuthenticatorData(validAuthDataBuffer, testRpId, true);
    assert.ok(result, 'Parsing failed');
    assert.ok(serverReg.bufferEqual(result.rpIdHash, testRpIdHash), 'RP ID Hash mismatch');
    assert.ok(result.flags.up, 'UP flag mismatch');
    assert.ok(result.flags.uv, 'UV flag mismatch');
    assert.ok(result.flags.at, 'AT flag mismatch');
    assert.strictEqual(result.signCount, 1, 'Sign count mismatch');
    assert.ok(serverReg.bufferEqual(result.aaguid, testAaguid), 'AAGUID mismatch');
    assert.ok(serverReg.bufferEqual(result.credentialId, testCredId), 'Credential ID mismatch');
    assert.ok(serverReg.bufferEqual(result.credentialPublicKey, testPublicKeyCose), 'Public Key mismatch');
});

runTest('ServerReg: parseAndVerifyAuthenticatorData Valid (UV not required)', () => {
    const authDataUVNotSet = Buffer.concat([
        testRpIdHash, testFlagsPresentAttestedOnly, testSignCount,
        testAaguid, testCredIdLength, testCredId, testPublicKeyCose
    ]);
    const result = serverReg.parseAndVerifyAuthenticatorData(authDataUVNotSet, testRpId, false);
    assert.ok(result, 'Parsing failed');
    assert.ok(result.flags.up, 'UP flag mismatch');
    assert.strictEqual(result.flags.uv, false, 'UV flag mismatch');
    assert.ok(result.flags.at, 'AT flag mismatch');
});

runTest('ServerReg: parseAndVerifyAuthenticatorData Throws on Wrong RP ID', () => {
    assert.throws(
        () => serverReg.parseAndVerifyAuthenticatorData(authDataWrongRpId, testRpId, true),
        /RP ID hash mismatch/,
        'Should throw for wrong RP ID'
    );
});

runTest('ServerReg: parseAndVerifyAuthenticatorData Throws on Missing UP', () => {
    assert.throws(
        () => serverReg.parseAndVerifyAuthenticatorData(authDataMissingUP, testRpId, true),
        /User Presence flag \(UP\) was not set/,
        'Should throw for missing UP flag'
    );
});

runTest('ServerReg: parseAndVerifyAuthenticatorData Throws on Missing AT', () => {
    assert.throws(
        () => serverReg.parseAndVerifyAuthenticatorData(authDataMissingAT, testRpId, true),
        /Attested Credential Data flag \(AT\) was not set/,
        'Should throw for missing AT flag'
    );
});

runTest('ServerReg: parseAndVerifyAuthenticatorData Throws on Missing UV when required', () => {
     const authDataUVNotSet = Buffer.concat([
        testRpIdHash, testFlagsPresentAttestedOnly, testSignCount,
        testAaguid, testCredIdLength, testCredId, testPublicKeyCose
    ]);
    assert.throws(
        () => serverReg.parseAndVerifyAuthenticatorData(authDataUVNotSet, testRpId, true), // requireUserVerification = true
        /User Verification flag \(UV\) was required but not set/,
        'Should throw for missing UV when required'
    );
});

// --- verifyAttestationStatement tests ---
// These are harder without mocks/frameworks. Focus on simple cases.
const dummyClientDataHash = crypto.createHash('sha256').update('dummyClientData').digest();
const dummyPubKeyDetails = cose.getWebAuthnPublicKeyDetails(cose.decodeCoseKey(exampleCoseKeyEC2Buffer));

runTest('ServerReg: verifyAttestationStatement "none" format', async () => {
    const result = await serverReg.verifyAttestationStatement('none', {}, validAuthDataBuffer, dummyClientDataHash, dummyPubKeyDetails, testRpIdHash, testCredId);
    assert.strictEqual(result, true, '"none" format should return true');
});

runTest('ServerReg: verifyAttestationStatement Throws on Unsupported Format', async () => {
    await assert.rejects(
        serverReg.verifyAttestationStatement('unsupported-fmt', {}, validAuthDataBuffer, dummyClientDataHash, dummyPubKeyDetails, testRpIdHash, testCredId),
        /Unsupported attestation format: unsupported-fmt/,
        'Should throw for unsupported format'
    );
});

getTestSummary();
