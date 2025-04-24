const assert = require('assert');
const crypto = require('crypto');
const serverWebauthn = require('../index');
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

runTest('ServerWebauthn: base64urlToBuffer', () => {
    const b64url = 'SGVsbG8gV29ybGQ'; // "Hello World" in base64url
    const expectedBuffer = Buffer.from('Hello World', 'utf8');
    const actualBuffer = serverWebauthn.base64urlToBuffer(b64url);
    assert.ok(serverWebauthn.bufferEqual(actualBuffer, expectedBuffer), 'base64url decoding failed');
});

runTest('ServerWebauthn: bufferEqual', () => {
    const buf1 = Buffer.from('abc');
    const buf2 = Buffer.from('abc');
    const buf3 = Buffer.from('def');
    const buf4 = Buffer.from('abcd');
    assert.ok(serverWebauthn.bufferEqual(buf1, buf2), 'Equal buffers failed');
    assert.strictEqual(serverWebauthn.bufferEqual(buf1, buf3), false, 'Unequal buffers failed');
    assert.strictEqual(serverWebauthn.bufferEqual(buf1, buf4), false, 'Different length buffers failed');
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

runTest('ServerWebauthn: parseAndVerifyAuthenticatorData Valid (UV required & present)', () => {
    const result = serverWebauthn.parseAndVerifyAuthenticatorData(validAuthDataBuffer, testRpId, true);
    assert.ok(result, 'Parsing failed');
    assert.ok(serverWebauthn.bufferEqual(result.rpIdHash, testRpIdHash), 'RP ID Hash mismatch');
    assert.ok(result.flags.up, 'UP flag mismatch');
    assert.ok(result.flags.uv, 'UV flag mismatch');
    assert.ok(result.flags.at, 'AT flag mismatch');
    assert.strictEqual(result.signCount, 1, 'Sign count mismatch');
    assert.ok(serverWebauthn.bufferEqual(result.aaguid, testAaguid), 'AAGUID mismatch');
    assert.ok(serverWebauthn.bufferEqual(result.credentialId, testCredId), 'Credential ID mismatch');
    assert.ok(serverWebauthn.bufferEqual(result.credentialPublicKey, testPublicKeyCose), 'Public Key mismatch');
});

runTest('ServerWebauthn: parseAndVerifyAuthenticatorData Valid (UV not required)', () => {
    const authDataUVNotSet = Buffer.concat([
        testRpIdHash, testFlagsPresentAttestedOnly, testSignCount,
        testAaguid, testCredIdLength, testCredId, testPublicKeyCose
    ]);
    const result = serverWebauthn.parseAndVerifyAuthenticatorData(authDataUVNotSet, testRpId, false);
    assert.ok(result, 'Parsing failed');
    assert.ok(result.flags.up, 'UP flag mismatch');
    assert.strictEqual(result.flags.uv, false, 'UV flag mismatch');
    assert.ok(result.flags.at, 'AT flag mismatch');
});

runTest('ServerWebauthn: parseAndVerifyAuthenticatorData Throws on Wrong RP ID', () => {
    assert.throws(
        () => serverWebauthn.parseAndVerifyAuthenticatorData(authDataWrongRpId, testRpId, true),
        /RP ID hash mismatch/,
        'Should throw for wrong RP ID'
    );
});

runTest('ServerWebauthn: parseAndVerifyAuthenticatorData Throws on Missing UP', () => {
    assert.throws(
        () => serverWebauthn.parseAndVerifyAuthenticatorData(authDataMissingUP, testRpId, true),
        /User Presence flag \(UP\) was not set/,
        'Should throw for missing UP flag'
    );
});

runTest('ServerWebauthn: parseAndVerifyAuthenticatorData Throws on Missing AT', () => {
    assert.throws(
        () => serverWebauthn.parseAndVerifyAuthenticatorData(authDataMissingAT, testRpId, true),
        /Attested Credential Data flag \(AT\) was not set/,
        'Should throw for missing AT flag'
    );
});

runTest('ServerWebauthn: parseAndVerifyAuthenticatorData Throws on Missing UV when required', () => {
     const authDataUVNotSet = Buffer.concat([
        testRpIdHash, testFlagsPresentAttestedOnly, testSignCount,
        testAaguid, testCredIdLength, testCredId, testPublicKeyCose
    ]);
    assert.throws(
        () => serverWebauthn.parseAndVerifyAuthenticatorData(authDataUVNotSet, testRpId, true), // requireUserVerification = true
        /User Verification flag \(UV\) was required but not set/,
        'Should throw for missing UV when required'
    );
});

// --- verifyAttestationStatement tests ---
// These are harder without mocks/frameworks. Focus on simple cases.
const dummyClientDataHash = crypto.createHash('sha256').update('dummyClientData').digest();
const dummyPubKeyDetails = cose.getWebAuthnPublicKeyDetails(cose.decodeCoseKey(exampleCoseKeyEC2Buffer));

runTest('ServerWebauthn: verifyAttestationStatement "none" format', async () => {
    const result = await serverWebauthn.verifyAttestationStatement('none', {}, validAuthDataBuffer, dummyClientDataHash, dummyPubKeyDetails, testRpIdHash, testCredId);
    assert.strictEqual(result, true, '"none" format should return true');
});

runTest('ServerWebauthn: verifyAttestationStatement Throws on Unsupported Format', async () => {
    await assert.rejects(
        serverWebauthn.verifyAttestationStatement('unsupported-fmt', {}, validAuthDataBuffer, dummyClientDataHash, dummyPubKeyDetails, testRpIdHash, testCredId),
        /Unsupported attestation format: unsupported-fmt/,
        'Should throw for unsupported format'
    );
});

// --- Assertion Verification Tests (verifyAssertionResponse) ---

// Common data for assertion tests
const assertTestRpId = 'localhost';
const assertTestOrigin = 'https://localhost:8443';
const assertTestChallenge = 'assertion_challenge_string_123';
const assertTestChallengeB64 = serverWebauthn.bufferToBase64url(Buffer.from(assertTestChallenge));
const assertTestCredId = Buffer.from('assertionCredId_0987654321', 'utf8');
const assertTestCredIdB64 = serverWebauthn.bufferToBase64url(assertTestCredId);

// Use the same EC2 key as registration for simplicity
const assertStoredCredential = {
    credentialId: assertTestCredId,
    credentialPublicKey: exampleCoseKeyEC2Buffer, // Using the EC2 key defined earlier
    signCount: 10,
    // other fields like userHandle, transports might be stored too
};

// Helper to create a plausible assertion response object (can be modified per test)
function createAssertionResponse({
    credId = assertTestCredIdB64,
    challenge = assertTestChallengeB64,
    origin = assertTestOrigin,
    rpId = assertTestRpId,
    flags = Buffer.from([0x05]), // UP=1, UV=1, AT=0
    signCount = 11,
    signature = 'MEUCIE5Yp1NHzkHlJqFzYKV9X4b0jF+QfT8d+Y1F/u0/Nq4PAiEAq+sX4dY1f1mXhQJ1aG8w9zF4w/fUuRzR6g9z+T8wXfY=', // Plausible ASN.1 DER ECDSA signature (base64)
}) {
    const clientData = {
        type: 'webauthn.get',
        challenge: challenge,
        origin: origin,
        crossOrigin: false,
    };
    const clientDataJsonB64 = serverWebauthn.bufferToBase64url(Buffer.from(JSON.stringify(clientData), 'utf8'));

    const rpIdHash = crypto.createHash('sha256').update(rpId).digest();
    const signCountBuffer = Buffer.alloc(4);
    signCountBuffer.writeUInt32BE(signCount, 0);
    const authDataBuffer = Buffer.concat([rpIdHash, flags, signCountBuffer]);
    const authDataB64 = serverWebauthn.bufferToBase64url(authDataBuffer);

    return {
        id: credId,
        rawId: credId,
        type: 'public-key',
        response: {
            authenticatorData: authDataB64,
            clientDataJSON: clientDataJsonB64,
            signature: signature, // Provide as standard base64 for buffer conversion
            userHandle: null,
        },
    };
}

// --- Negative Assertion Tests ---

runTest('ServerWebauthn Assertion: Throws on Credential ID mismatch', async () => {
    const assertion = createAssertionResponse({ credId: serverWebauthn.bufferToBase64url(Buffer.from('wrongCredId')) });
    await assert.rejects(
        serverWebauthn.verifyAssertionResponse(assertion, assertStoredCredential, assertTestChallengeB64, assertTestOrigin, assertTestRpId, true),
        /Credential ID mismatch/,
        'Should throw for credential ID mismatch'
    );
});

runTest('ServerWebauthn Assertion: Throws on clientData.type mismatch', async () => {
    const baseAssertion = createAssertionResponse({});
    const clientData = JSON.parse(serverWebauthn.base64urlToBuffer(baseAssertion.response.clientDataJSON).toString('utf8'));
    clientData.type = 'webauthn.create'; // Wrong type
    baseAssertion.response.clientDataJSON = serverWebauthn.bufferToBase64url(Buffer.from(JSON.stringify(clientData)));

    await assert.rejects(
        serverWebauthn.verifyAssertionResponse(baseAssertion, assertStoredCredential, assertTestChallengeB64, assertTestOrigin, assertTestRpId, true),
        /Invalid clientData type. Expected 'webauthn.get'/,
        'Should throw for wrong clientData type'
    );
});

runTest('ServerWebauthn Assertion: Throws on Challenge mismatch', async () => {
    const assertion = createAssertionResponse({ challenge: serverWebauthn.bufferToBase64url(Buffer.from('wrong_challenge')) });
    await assert.rejects(
        serverWebauthn.verifyAssertionResponse(assertion, assertStoredCredential, assertTestChallengeB64, assertTestOrigin, assertTestRpId, true),
        /Challenge mismatch/,
        'Should throw for challenge mismatch'
    );
});

runTest('ServerWebauthn Assertion: Throws on Origin mismatch', async () => {
    const assertion = createAssertionResponse({ origin: 'https://wrong.origin.com' });
    await assert.rejects(
        serverWebauthn.verifyAssertionResponse(assertion, assertStoredCredential, assertTestChallengeB64, assertTestOrigin, assertTestRpId, true),
        /Origin mismatch/,
        'Should throw for origin mismatch'
    );
});

runTest('ServerWebauthn Assertion: Throws on RP ID mismatch in AuthData', async () => {
    const assertion = createAssertionResponse({ rpId: 'wrong-rp' }); // Affects authData generation
    await assert.rejects(
        serverWebauthn.verifyAssertionResponse(assertion, assertStoredCredential, assertTestChallengeB64, assertTestOrigin, assertTestRpId, true), // Still expect assertTestRpId
        /RP ID hash mismatch during assertion/,
        'Should throw for RP ID mismatch in authData'
    );
});

runTest('ServerWebauthn Assertion: Throws on missing UV when required', async () => {
    const assertion = createAssertionResponse({ flags: Buffer.from([0x01]) }); // UP=1, UV=0
    await assert.rejects(
        serverWebauthn.verifyAssertionResponse(assertion, assertStoredCredential, assertTestChallengeB64, assertTestOrigin, assertTestRpId, true), // requireUserVerification = true
        /User Verification flag \(UV\) was required for assertion but not set/,
        'Should throw for missing UV when required'
    );
});

runTest('ServerWebauthn Assertion: Throws on invalid Sign Count (equal)', async () => {
    const assertion = createAssertionResponse({ signCount: assertStoredCredential.signCount }); // Count is same as stored
    await assert.rejects(
        serverWebauthn.verifyAssertionResponse(assertion, assertStoredCredential, assertTestChallengeB64, assertTestOrigin, assertTestRpId, true),
        /Invalid signature counter. Stored: 10, Received: 10/,
        'Should throw for sign count equal to stored'
    );
});

runTest('ServerWebauthn Assertion: Throws on invalid Sign Count (lower)', async () => {
    const assertion = createAssertionResponse({ signCount: assertStoredCredential.signCount - 1 }); // Count is lower than stored
    await assert.rejects(
        serverWebauthn.verifyAssertionResponse(assertion, assertStoredCredential, assertTestChallengeB64, assertTestOrigin, assertTestRpId, true),
        /Invalid signature counter. Stored: 10, Received: 9/,
        'Should throw for sign count lower than stored'
    );
});

runTest('ServerWebauthn Assertion: Throws on malformed signature (not ASN.1)', async () => {
    // Provide a signature that is clearly not valid ASN.1 DER for ECDSA
    const assertion = createAssertionResponse({ signature: serverWebauthn.bufferToBase64url(Buffer.from('not_a_valid_signature_buffer')) });
    await assert.rejects(
        serverWebauthn.verifyAssertionResponse(assertion, assertStoredCredential, assertTestChallengeB64, assertTestOrigin, assertTestRpId, true),
        /Failed to decode ASN.1 DER signature using asn1.js/, // Error comes from asn1.js decoding
        'Should throw for malformed signature buffer'
    );
});

getTestSummary();
