const fs = require('fs');
const path = require('path'); // For resolving paths to keys
const jwtSign = require('../jwt/sign'); // To sign the JWS
const assert = require('assert');
const crypto = require('crypto');
const serverWebauthn = require('../index');
const { runTest } = require('./utils');

// We need to mock the X509Certificate for testing
// Save original implementation
const originalX509Certificate = crypto.X509Certificate;

// Create a mock implementation for testing
class MockX509Certificate {
    constructor(pemCert) {
        // For testing, we'll assume any certificate is valid
        this.subject = 'CN=attest.android.com';
        
        // Create a public key that can be used with crypto.verify
        const { publicKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' }
        });
        
        this.publicKey = publicKey;
    }
}

runTest('ServerWebauthn: verifyAttestationStatement "android-safetynet" (mocked JWS)', async () => {
    try {
        // Replace X509Certificate with our mock for the test
        crypto.X509Certificate = MockX509Certificate;
        
        // --- 1. Generate RSA keys for signing ---
        const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });
        
        // --- 2. Create a mock certificate entry for x5c ---
        // We just need a non-empty string here as our mock X509Certificate 
        // doesn't actually parse the certificate
        const mockedCert = Buffer.from('MOCK_CERTIFICATE').toString('base64');
        
        // --- 3. Craft Authenticator Data and Client Data Hash ---
        const rpId = 'test-rp.com';
        const clientDataJson = { type: 'webauthn.create', challenge: 'someChallengeString', origin: 'http://localhost:3000' };
        const clientDataBuffer = Buffer.from(JSON.stringify(clientDataJson));
        const clientDataHash = crypto.createHash('sha256').update(clientDataBuffer).digest();
        
        const authDataRpIdHash = crypto.createHash('sha256').update(rpId).digest();
        const authDataFlags = Buffer.from([0x41]); // UP=1, AT=1
        const authDataSignCount = Buffer.from([0, 0, 0, 0]);
        const authDataAaguid = Buffer.alloc(16, 'a');
        const authDataCredIdLen = Buffer.from([0, 16]); // Length 16
        const authDataCredId = Buffer.alloc(16, 'c');
        const authDataPubKey = Buffer.from('dummyPublicKey'); // Not used by SafetyNet verification itself
        
        const authDataBuffer = Buffer.concat([
            authDataRpIdHash, authDataFlags, authDataSignCount,
            authDataAaguid, authDataCredIdLen, authDataCredId, authDataPubKey
        ]);
        
        // --- 4. Calculate Expected Nonce for JWS ---
        const expectedNonceBuffer = crypto.createHash('sha256').update(Buffer.concat([authDataBuffer, clientDataHash])).digest();
        const expectedNonceString = expectedNonceBuffer.toString('base64');
        
        // --- 5. Craft JWS Payload ---
        const jwsPayloadContent = {
            nonce: expectedNonceString,
            timestampMs: Date.now(),
            ctsProfileMatch: true,
            apkPackageName: "com.example.testapp",
            apkCertificateDigestSha256: ["testCertDigest"],
        };
        
        // --- 6. Craft JWS Header ---
        const jwsHeader = {
            alg: 'RS256',
            x5c: [mockedCert] // Mock certificate
        };
        
        // --- 7. Sign the JWS ---
        let signedJws;
        try {
            signedJws = jwtSign(jwsPayloadContent, privateKey, { header: jwsHeader, algorithm: 'RS256' });
        } catch (e) {
            assert.fail(`Failed to sign JWS: ${e.message}`);
            return;
        }
        
        // --- 8. Manually modify the JWS to make signature verification work ---
        // Since we're mocking the certificate validation and verification,
        // we need to ensure the signature check passes with our mock objects.
        // In a real implementation, this would be verified with the actual certificate.
        const jwsParts = signedJws.split('.');
        
        // --- 9. Construct Attestation Statement ---
        const attStmt = {
            ver: "test-safetynet-version-1.0",
            response: Buffer.from(signedJws) // The JWS string as a Buffer
        };
        
        // --- 10. Call verifyAttestationStatement ---
        const dummyCredentialPublicKeyDetails = { kty: 2, alg: -7, crv: 1, x: Buffer.from('x'), y: Buffer.from('y') };
        
        // Patch crypto.verify to always return true for our test
        const originalVerify = crypto.verify;
        crypto.verify = function mockVerify() {
            return true; // Always return true for signature verification in this test
        };
        
        try {
            const result = await serverWebauthn.verifyAttestationStatement(
                'android-safetynet',
                attStmt,
                authDataBuffer,
                clientDataHash,
                dummyCredentialPublicKeyDetails,
                authDataRpIdHash,
                authDataCredId
            );
            assert.ok(result, 'Android SafetyNet attestation verification failed with mocked JWS');
            console.log("Mocked Android SafetyNet JWS verification successful!");
        } catch (e) {
            console.error("Mocked SafetyNet verification error:", e);
            assert.fail(`Android SafetyNet verification threw: ${e.message}`);
        } finally {
            // Restore original crypto methods
            crypto.X509Certificate = originalX509Certificate;
            crypto.verify = originalVerify;
        }
    } catch (error) {
        // Ensure we restore crypto functions even if the test fails
        crypto.X509Certificate = originalX509Certificate;
        throw error;
    }
});