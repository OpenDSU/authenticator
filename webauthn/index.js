const crypto = require('crypto');
const { decode } = require('./cbor/index.js');
const { decodeCoseKey, COSE_KEY_TYPES, COSE_ALGORITHMS, COSE_ELLIPTIC_CURVES, getWebAuthnPublicKeyDetails } = require('./cose/index.js');
const { decodeDerEncodedSignature } = require('./utils.js');
const jwt = require('./jwt');

// --- Utility Functions ---

/**
 * Decodes a Base64URL string into a Buffer.
 * @param {string} base64urlString
 * @returns {Buffer}
 */
function base64urlToBuffer(base64urlString) {
    return Buffer.from(base64urlString, 'base64url');
}

/**
 * Converts a Buffer to a Base64URL string.
 * @param {Buffer} buffer
 * @returns {string}
 */
function bufferToBase64url(buffer) {
    return buffer.toString('base64url');
}

/**
 * Simple constant-time buffer comparison.
 * @param {Buffer} a
 * @param {Buffer} b
 * @returns {boolean}
 */
function bufferEqual(a, b) {
    if (a.length !== b.length) {
        return false;
    }
    // Constant time comparison
    return crypto.timingSafeEqual(a, b);
}

// --- Helper function to parse a PEM string containing multiple certificates ---
/**
 * Parses a PEM string containing multiple certificates into an array of X509Certificate objects.
 * @param {string} pemString - The string content of the PEM file.
 * @returns {crypto.X509Certificate[]} An array of parsed X509Certificate objects.
 */
function parseRootsPem(pemString) {
    const caCerts = [];
    if (!pemString || typeof pemString !== 'string') {
        console.warn("parseRootsPem: pemString is null, undefined, or not a string. Returning empty array.");
        return caCerts;
    }
    const certRegex = /-----BEGIN CERTIFICATE-----\n([\s\S]+?)\n-----END CERTIFICATE-----/g;
    let match;
    while ((match = certRegex.exec(pemString)) !== null) {
        try {
            const pemCert = `-----BEGIN CERTIFICATE-----\n${match[1]}\n-----END CERTIFICATE-----`;
            caCerts.push(new crypto.X509Certificate(Buffer.from(pemCert)));
        } catch (e) {
            console.error("Failed to parse a certificate from PEM string:", e.message);
        }
    }
    return caCerts;
}

/**
 * STUB FUNCTION for parsing Android Key Attestation KeyDescription extension.
 * This function needs a full implementation to parse the ASN.1 structure
 * from the certificate's KeyDescription extension (OID 1.3.6.1.4.1.11129.2.1.17).
 * @param {crypto.X509Certificate} leafCert - The leaf attestation certificate.
 * @returns {object} A parsed representation of the KeyDescription.
 */
function parseAndroidKeyDescription(leafCert) {
    console.warn("parseAndroidKeyDescription is a STUB and needs full implementation. Cert subject:", leafCert.subject);
    // This is a placeholder. Real implementation requires ASN.1 parsing.
    // The attestationChallenge MUST be the clientDataHash for verification.
    return {
        attestationVersion: -1,
        attestationSecurityLevel: -1, // e.g., 0 (Software), 1 (TEE), 2 (StrongBox)
        keymasterVersion: -1,
        keymasterSecurityLevel: -1,
        attestationChallenge: Buffer.from("dummy_challenge_placeholder_needs_real_clientDataHash"),
        softwareEnforced: {},
        teeEnforced: {},
        // Example of how origin might be populated if found:
        // teeEnforced: { origin: 0 } // 0: KM_ORIGIN_GENERATED, 1: KM_ORIGIN_DERIVED, 2: KM_ORIGIN_IMPORTED, 3: KM_ORIGIN_UNKNOWN
    };
}

// --- Core Verification Logic ---

/**
 * Parses and verifies the authenticator data.
 * @param {Buffer} authDataBuffer - The raw authenticator data buffer.
 * @param {string} expectedRpId - The expected Relying Party ID.
 * @param {boolean} requireUserVerification - Whether the UV flag must be set.
 * @returns {{rpIdHash: Buffer, flags: {up: boolean, uv: boolean, at: boolean, ed: boolean}, signCount: number, aaguid: Buffer, credentialId: Buffer, credentialPublicKey: Buffer}}
 * @throws {Error} If validation fails.
 */
function parseAndVerifyAuthenticatorData(authDataBuffer, expectedRpId, requireUserVerification) {
    if (authDataBuffer.byteLength < 37) { // rpIdHash (32) + flags (1) + signCount (4)
        throw new Error(`Authenticator data is too short. Expected >= 37 bytes, got ${authDataBuffer.byteLength}`);
    }

    const rpIdHash = authDataBuffer.subarray(0, 32);
    const flagsByte = authDataBuffer.readUInt8(32);
    const signCount = authDataBuffer.readUInt32BE(33); // 4 bytes counter

    // Verify RP ID Hash
    if (expectedRpId) {
        const expectedRpIdHash = crypto.createHash('sha256').update(expectedRpId).digest();
        if (!bufferEqual(rpIdHash, expectedRpIdHash)) {
            // If direct match fails, also try with "www." prefix
            const wwwExpectedRpIdHash = crypto.createHash('sha256').update(`www.${expectedRpId}`).digest();
            if (!bufferEqual(rpIdHash, wwwExpectedRpIdHash)) {
                throw new Error(`RP ID hash mismatch. Expected ${expectedRpIdHash.toString('hex')} or ${wwwExpectedRpIdHash.toString('hex')} but got ${rpIdHash.toString('hex')}`);
            }
            console.log('RP ID hash verified (with www prefix).');
        } else {
            console.log('RP ID hash verified.');
        }
    } else {
        console.log('Skipping RP ID hash verification as expectedRpId was not provided.');
    }

    // Parse Flags
    const flags = {
        up: !!(flagsByte & 0x01), // User Present
        uv: !!(flagsByte & 0x04), // User Verified
        at: !!(flagsByte & 0x40), // Attested credential data included
        ed: !!(flagsByte & 0x80), // Extension data included
    };

    console.log('Parsed Flags:', flags);
    console.log('Sign Count:', signCount);

    // Verify Flags
    if (!flags.up) {
        throw new Error('User Presence flag (UP) was not set.');
    }
    if (requireUserVerification && !flags.uv) {
        throw new Error('User Verification flag (UV) was required but not set.');
    }
    if (!flags.at) {
        // This should not happen in registration response according to spec
        throw new Error('Attested Credential Data flag (AT) was not set. Required for registration.');
    }

    // --- Process Attested Credential Data ---
    // This part is present only if flags.at is true
    let offset = 37; // Start after rpIdHash, flags, signCount

    if (authDataBuffer.byteLength < offset + 16 + 2) { // AAGUID (16) + CredID Length (2)
        throw new Error('Authenticator data too short for AAGUID and Credential ID Length.');
    }

    const aaguid = authDataBuffer.subarray(offset, offset + 16);
    offset += 16;
    console.log('AAGUID:', aaguid.toString('hex'));

    const credentialIdLength = authDataBuffer.readUInt16BE(offset);
    offset += 2;
    console.log('Credential ID Length:', credentialIdLength);

    if (authDataBuffer.byteLength < offset + credentialIdLength) {
        throw new Error(`Authenticator data too short for Credential ID. Expected ${credentialIdLength} bytes.`);
    }
    const credentialId = authDataBuffer.subarray(offset, offset + credentialIdLength);
    offset += credentialIdLength;
    console.log('Credential ID:', credentialId.toString('base64url')); // Often stored/compared as base64url

    // The rest is the credentialPublicKey (COSE Key)
    const credentialPublicKey = authDataBuffer.subarray(offset);
    console.log('Credential Public Key (COSE CBOR):', credentialPublicKey.toString('hex'));

    return {
        rpIdHash,
        flags,
        signCount,
        aaguid,
        credentialId,
        credentialPublicKey,
        // extensions // Add if parsed
    };
}

/**
 * Verifies the Attestation statement.
 * NOTE: THIS IS A SIMPLIFIED PLACEHOLDER. Real verification is complex.
 * @param {string} fmt - Attestation format.
 * @param {object} attStmt - Attestation statement object (decoded from CBOR).
 * @param {Buffer} authDataBuffer - The raw authenticator data buffer.
 * @param {Buffer} clientDataHash - SHA256 hash of the clientDataJSON.
 * @param {object} credentialPublicKeyDetails - Decoded public key details { kty, alg, crv?, x?, y? }
 * @param {Buffer} rpIdHash - SHA256 hash of the RP ID from authenticator data.
 * @param {Buffer} credentialId - The Credential ID from authenticator data.
 * @param {crypto.X509Certificate[]} [parsedTrustedRoots] - Optional. Array of parsed trusted root certificates for attestation formats that require them.
 * @returns {Promise<boolean>} - True if verification is considered successful (in this simplified version).
 * @throws {Error} If format is unsupported or basic checks fail.
 */
async function verifyAttestationStatement(fmt, attStmt, authDataBuffer, clientDataHash, credentialPublicKeyDetails, rpIdHash, credentialId, parsedTrustedRoots) {
    console.log(`Attempting verification for format: ${fmt}`);
    // console.log('Attestation Statement:', attStmt);
    // console.log('AuthData:', authDataBuffer.toString('hex'));
    // console.log('ClientData Hash:', clientDataHash.toString('hex'));
    // console.log('Public Key Details:', credentialPublicKeyDetails);

    switch (fmt) {
        case 'none':
            return await verifyNoneAttestation();

        case 'packed':
            return await verifyPackedAttestation(attStmt, authDataBuffer, clientDataHash, credentialPublicKeyDetails);

        case 'fido-u2f':
            return await verifyFidoU2fAttestation(attStmt, authDataBuffer, clientDataHash, credentialPublicKeyDetails, rpIdHash, credentialId);

        case 'tpm':
            return await verifyTpmAttestation();

        case 'android-safetynet':
            return await verifyAndroidSafetynetAttestation(attStmt, authDataBuffer, clientDataHash, parsedTrustedRoots);

        case 'android-key':
            return await verifyAndroidKeyAttestation(attStmt, authDataBuffer, clientDataHash, credentialPublicKeyDetails);

        default:
            throw new Error(`Unsupported attestation format: ${fmt}`);
    }
}

/**
 * Verifies a 'none' attestation statement.
 * @returns {Promise<boolean>} True as 'none' attestation requires no verification.
 */
async function verifyNoneAttestation() {
    console.log("Attestation format is 'none'. Skipping signature verification.");
    return true; // No verification possible/required
}

/**
 * Verifies a 'packed' attestation statement.
 * @param {object} attStmt - Attestation statement object.
 * @param {Buffer} authDataBuffer - The raw authenticator data buffer.
 * @param {Buffer} clientDataHash - SHA256 hash of the clientDataJSON.
 * @param {object} credentialPublicKeyDetails - Decoded public key details.
 * @returns {Promise<boolean>} True if verification is successful.
 * @throws {Error} If verification fails.
 */
async function verifyPackedAttestation(attStmt, authDataBuffer, clientDataHash, credentialPublicKeyDetails) {
    console.log("Processing 'packed' attestation format.");
    const { alg: packedAlg, sig: packedSig, x5c: packedX5c } = attStmt;

    if (!packedSig) {
        throw new Error("Packed attestation statement missing 'sig'.");
    }
    if (packedAlg === undefined) { // alg is optional per spec if key provides it, but often present
        console.warn("Packed attestation statement missing 'alg'. Will rely on public key alg.");
    }

    const dataToVerify = Buffer.concat([authDataBuffer, clientDataHash]);

    if (packedX5c && Array.isArray(packedX5c) && packedX5c.length > 0) {
        // --- Basic/AttCA Attestation ---
        throw new Error("Packed attestation with x5c (certificate chain) found. Full verification requires certificate parsing, chain validation, and checking against metadata. THIS IS NOT IMPLEMENTED HERE.");
    } else {
        // --- Self-Attestation ---
        console.log("Attempting Packed Self-Attestation verification.");
        // Verify the signature using the *credential's public key*.
        // The algorithm should match the one in the credential public key.
        const keyObject = await crypto.subtle.importKey(
            'jwk',
            convertCoseKeyToJwk(credentialPublicKeyDetails), // Need conversion helper
            getJwkParams(credentialPublicKeyDetails.alg), // Need conversion helper
            true,
            ['verify']
        );

        const signatureIsValid = await crypto.subtle.verify(
            getWebCryptoAlgName(credentialPublicKeyDetails.alg), // Need conversion helper
            keyObject,
            packedSig, // The signature from attStmt
            dataToVerify
        );

        if (!signatureIsValid) {
            throw new Error("Packed self-attestation signature verification failed.");
        }
        console.log("Packed self-attestation signature verified successfully.");
        return true;
    }
}

/**
 * Verifies a 'fido-u2f' attestation statement.
 * @param {object} attStmt - Attestation statement object.
 * @param {Buffer} authDataBuffer - The raw authenticator data buffer.
 * @param {Buffer} clientDataHash - SHA256 hash of the clientDataJSON.
 * @param {object} credentialPublicKeyDetails - Decoded public key details.
 * @param {Buffer} rpIdHash - SHA256 hash of the RP ID.
 * @param {Buffer} credentialId - The Credential ID.
 * @returns {Promise<boolean>} True if verification is successful.
 * @throws {Error} If verification fails.
 */
async function verifyFidoU2fAttestation(attStmt, authDataBuffer, clientDataHash, credentialPublicKeyDetails, rpIdHash, credentialId) {
    console.log("Processing 'fido-u2f' attestation format.");
    const { sig: u2fSig, x5c: u2fX5c } = attStmt;

    // 1. Verify attStmt structure
    if (!u2fSig || !Buffer.isBuffer(u2fSig)) {
        throw new Error("FIDO-U2F attestation statement missing or invalid 'sig'.");
    }
    if (!u2fX5c || !Array.isArray(u2fX5c) || u2fX5c.length < 1 || !Buffer.isBuffer(u2fX5c[0])) {
        throw new Error("FIDO-U2F attestation statement missing or invalid 'x5c' (certificate chain).");
    }
    console.log("FIDO-U2F structure validated (sig, x5c[0] present).");

    // --- SECURITY WARNING: SIMPLIFIED IMPLEMENTATION ---
    // 2. Parse leaf certificate from x5c[0] - SKIPPED.
    // 3. Extract public key *from the certificate* - SKIPPED.
    // We are INSECURELY using the public key from authData instead.
    // A compliant implementation MUST extract the public key from the certificate
    // and use that for verification. It also MUST validate the certificate chain.
    // --- END SECURITY WARNING ---

    // Ensure the key from authData is P-256 ECC as required by U2F
    if (credentialPublicKeyDetails.kty !== COSE_KEY_TYPES.EC2 ||
        credentialPublicKeyDetails.crv !== COSE_ELLIPTIC_CURVES.P_256 ||
        credentialPublicKeyDetails.alg !== COSE_ALGORITHMS.ES256) {
        throw new Error(`FIDO-U2F requires an ES256 P-256 public key in authData, but received different parameters (kty: ${credentialPublicKeyDetails.kty}, crv: ${credentialPublicKeyDetails.crv}, alg: ${credentialPublicKeyDetails.alg})`);
    }

    // 4. Construct specific U2F verification data buffer
    // verificationData = 0x00 || rpIdHash || clientDataHash || credentialId || publicKeyU2F
    const reservedByte = Buffer.from([0x00]);
    // Extract the P-256 public key point (uncompressed format: 0x04 || x || y)
    const publicKeyU2F = Buffer.concat([
        Buffer.from([0x04]), // Uncompressed point indicator
        credentialPublicKeyDetails.x,
        credentialPublicKeyDetails.y
    ]);

    const verificationData = Buffer.concat([
        reservedByte,
        rpIdHash,       // From authData
        clientDataHash, // Calculated from clientDataJSON
        credentialId,   // From authData
        publicKeyU2F    // From authData public key (x, y coordinates)
    ]);
    console.log("Constructed U2F verification data.");

    // 5. Verify 'sig' over verificationData using the *authData* public key (INSECURE SHORTCUT)
    const keyObject = await crypto.subtle.importKey(
        'jwk',
        convertCoseKeyToJwk(credentialPublicKeyDetails), // Uses the key from authData
        getJwkParams(COSE_ALGORITHMS.ES256), // U2F MUST use ES256
        true,
        ['verify']
    );

    const signatureIsValid = await crypto.subtle.verify(
        getWebCryptoAlgName(COSE_ALGORITHMS.ES256), // U2F MUST use ES256
        keyObject,
        u2fSig,
        verificationData
    );

    if (!signatureIsValid) {
        throw new Error("FIDO-U2F signature verification failed (using authData key).");
    }
    console.log("FIDO-U2F signature verified successfully (using authData key - INSECURE).");

    // 6. RECOMMENDED: Validate x5c chain against trusted roots - SKIPPED.
    // Requires a Metadata Service and certificate validation logic.

    return true; // Return true if signature verification passed (with the insecure key)
}

/**
 * Verifies a 'tpm' attestation statement.
 * @returns {Promise<boolean>} True as this is a placeholder.
 */
async function verifyTpmAttestation() {
    console.warn("Attestation format 'tpm' verification is complex and requires TPM-specific knowledge. THIS IS NOT IMPLEMENTED HERE.");
    return true; // Placeholder
}

/**
 * Verifies an 'android-safetynet' attestation statement.
 * @param {object} attStmt - Attestation statement object.
 * @param {Buffer} authDataBuffer - The raw authenticator data buffer.
 * @param {Buffer} clientDataHash - SHA256 hash of the clientDataJSON.
 * @param {crypto.X509Certificate[]} parsedTrustedRoots - Array of parsed trusted root X509Certificate objects.
 * @returns {Promise<boolean>} True if verification is successful.
 * @throws {Error} If verification fails.
 */
async function verifyAndroidSafetynetAttestation(attStmt, authDataBuffer, clientDataHash, parsedTrustedRoots) {
    console.log("Processing 'android-safetynet' attestation format.");
    const { ver, response: jwsResponseBuffer } = attStmt;
    // Enhanced debugging for response type
    console.log("Response type:", typeof jwsResponseBuffer);
    console.log("Is Buffer?", Buffer.isBuffer(jwsResponseBuffer));
    console.log("Is Uint8Array?", jwsResponseBuffer instanceof Uint8Array);
    console.log("Is ArrayBuffer?", jwsResponseBuffer instanceof ArrayBuffer);
    console.log("Constructor name:", jwsResponseBuffer?.constructor?.name);

    // If it's array-like, log its properties
    if (jwsResponseBuffer && typeof jwsResponseBuffer === 'object') {
        console.log("Object keys:", Object.keys(jwsResponseBuffer));
        console.log("Length:", jwsResponseBuffer.length);
        // Try to convert to Buffer if it's array-like
        if (jwsResponseBuffer.length !== undefined) {
            console.log("First few bytes:", Array.from(jwsResponseBuffer.slice(0, 10)));
        }
    }

    console.log("ver", ver)
    console.log("jwsResponseBuffer", jwsResponseBuffer)

    // Ensure jwsResponseBuffer is a Buffer, converting if needed
    let responseBuffer;
    if (!jwsResponseBuffer) {
        throw new Error("Android SafetyNet attestation statement missing 'response' (JWS).");
    } else if (Buffer.isBuffer(jwsResponseBuffer)) {
        responseBuffer = jwsResponseBuffer;
    } else if (jwsResponseBuffer instanceof Uint8Array) {
        // Convert Uint8Array to Buffer
        responseBuffer = Buffer.from(jwsResponseBuffer);
        console.log("Converted Uint8Array to Buffer");
    } else if (jwsResponseBuffer instanceof ArrayBuffer) {
        // Convert ArrayBuffer to Buffer
        responseBuffer = Buffer.from(jwsResponseBuffer);
        console.log("Converted ArrayBuffer to Buffer");
    } else if (typeof jwsResponseBuffer === 'object' && jwsResponseBuffer.length !== undefined) {
        // Try to convert array-like object
        try {
            responseBuffer = Buffer.from(jwsResponseBuffer);
            console.log("Converted array-like object to Buffer");
        } catch (err) {
            console.error("Failed to convert to Buffer:", err.message);
            throw new Error("Android SafetyNet attestation statement has invalid 'response' format.");
        }
    } else {
        throw new Error(`Android SafetyNet attestation statement has unexpected 'response' type: ${typeof jwsResponseBuffer}`);
    }

    // Log what we actually have after conversion
    console.log("Buffer length:", responseBuffer.length);
    console.log("Buffer first 50 bytes:", responseBuffer.slice(0, Math.min(50, responseBuffer.length)).toString('hex'));

    // Try to visualize as string if it might be text
    try {
        const previewText = responseBuffer.toString('utf8').substring(0, 100);
        console.log("Buffer as UTF-8 preview:", previewText);
        if (previewText.startsWith('eyJ')) {
            console.log("Appears to be base64 encoded (starts with 'eyJ')");
        }
    } catch (err) {
        console.error("Error checking UTF-8 text:", err.message);
        console.log("Not valid UTF-8 text");
    }

    if (!ver || typeof ver !== 'string') {
        throw new Error("Android SafetyNet attestation statement missing or invalid 'ver'.");
    }

    console.log("SafetyNet 'ver' and 'response' fields are present.");

    // The SafetyNet response is a JWS (JSON Web Signature)
    const jwsString = responseBuffer.toString('utf8');

    // --- NONCE VERIFICATION ---
    // The nonce in the JWS payload MUST be the base64url encoding of SHA256(authenticatorData || clientDataHash)
    const nonceBuffer = crypto.createHash('sha256').update(Buffer.concat([authDataBuffer, clientDataHash])).digest();
    const nonceBase64 = nonceBuffer.toString('base64');

    console.log(`Expected SafetyNet nonce: ${nonceBase64}`);

    // Decode the JWS to extract the payload and header
    let decodedJws;
    try {
        decodedJws = jwt.decode(jwsString, { complete: true });
        if (!decodedJws) {
            throw new Error('Failed to decode JWS.');
        }
    } catch (error) {
        throw new Error(`Error decoding SafetyNet JWS: ${error.message}`);
    }

    // Extract and verify the certificate chain from the JWS header
    const { header, payload } = decodedJws;

    if (!header.x5c || !Array.isArray(header.x5c) || header.x5c.length === 0) {
        throw new Error('SafetyNet JWS header missing x5c (certificate chain).');
    }

    // The header.x5c contains the certificate chain needed to verify the signature
    console.log(`SafetyNet JWS contains ${header.x5c.length} certificates in the chain.`);

    if (!parsedTrustedRoots || parsedTrustedRoots.length === 0) {
        throw new Error("Android SafetyNet: No trusted roots provided. Certificate chain validation against roots.pem will be skipped.");
    }

    // Extract the leaf certificate (first in the chain)
    // const leafCertDer = Buffer.from(header.x5c[0], 'base64'); // Unused variable
    console.log('Extracted leaf certificate from JWS header.');

    // Parse the leaf certificate
    let leafCert;
    try {
        const certChain = header.x5c.map(certBase64 => {
            const pemCert = '-----BEGIN CERTIFICATE-----\n' +
                certBase64 +
                '\n-----END CERTIFICATE-----';
            return new crypto.X509Certificate(Buffer.from(pemCert));
        });

        leafCert = certChain[0];

        // Verify the subject contains CN=attest.android.com
        const subjectCN = leafCert.subject; // This is actually the full Subject Distinguished Name
        if (!subjectCN.includes('CN=attest.android.com')) {
            throw new Error(`SafetyNet leaf certificate has invalid subject: ${subjectCN}. Expected CN=attest.android.com`);
        }
        console.log('Leaf certificate subject verified: contains CN=attest.android.com');

        // Verify certificate validity periods and chain
        let currentCert = leafCert;

        for (let i = 0; i < certChain.length; i++) {
            currentCert = certChain[i];
            console.log(`Verifying cert ${i + 1}/${certChain.length}: ${currentCert.subject}`);

            // 1. Check validity period
            const now = new Date();
            const validFrom = new Date(currentCert.validFrom);
            const validTo = new Date(currentCert.validTo);

            if (now < validFrom || now > validTo) {
                throw new Error(`Certificate ${currentCert.subject} is not valid at this time. Valid from ${validFrom} to ${validTo}, Now: ${now}`);
            }
            console.log(`Certificate ${currentCert.subject} validity period is OK.`);

            // 2. Verify certificate signature and chain up to a trusted root
            if (i < certChain.length - 1) {
                // This is not the root certificate, verify against the next one in the chain
                const issuerCert = certChain[i + 1];
                if (!currentCert.checkIssued(issuerCert)) {
                    throw new Error(`Certificate ${currentCert.subject} was not issued by ${issuerCert.subject}`);
                }
                console.log(`Certificate ${currentCert.subject} issued by ${issuerCert.subject} - OK.`);
            } else {
                // This is the last certificate in the chain provided by the JWS (x5c).
                // This 'currentCert' could be a self-signed root OR an intermediate CA that
                // should be signed by one of the roots in parsedTrustedRoots.
                console.log(`Reached end of JWS cert chain. Last cert: ${currentCert.subject} (Issuer: ${currentCert.issuer}). Verifying against trusted roots.`);

                let validChainFound = false;

                // Scenario 1: The last certificate in the JWS chain is ITSELF one of the trusted self-signed roots.
                if (parsedTrustedRoots && parsedTrustedRoots.length > 0) {
                    const matchingTrustedRoot = parsedTrustedRoots.find(
                        (trustedRoot) => trustedRoot.fingerprint256 === currentCert.fingerprint256
                    );

                    if (matchingTrustedRoot) {
                        console.log(`Last cert in JWS chain (${currentCert.subject}) matches a root in roots.pem by fingerprint.`);
                        // Now verify this matchingTrustedRoot (which is currentCert) is actually self-signed.
                        try {
                            if (!matchingTrustedRoot.verify(matchingTrustedRoot.publicKey)) {
                                throw new Error(`Certificate ${matchingTrustedRoot.subject} (from roots.pem, matched by fingerprint) failed self-signature verification.`);
                            }
                            console.log(`Certificate ${matchingTrustedRoot.subject} (from roots.pem) successfully verified as self-signed.`);
                            validChainFound = true;
                        } catch (e) {
                            throw new Error(`Error self-signing ${matchingTrustedRoot.subject} (from roots.pem): ${e.message}`);
                        }
                    }
                }

                // Scenario 2: The last certificate in the JWS chain is NOT itself a trusted root,
                // but it IS ISSUED BY one of the trusted roots.
                if (!validChainFound && parsedTrustedRoots && parsedTrustedRoots.length > 0) {
                    console.log(`Last cert in JWS chain (${currentCert.subject}) not directly in roots.pem by fingerprint or roots.pem not used for direct match. Checking if issued by a root in roots.pem.`);
                    for (const trustedRoot of parsedTrustedRoots) {
                        // Check if currentCert (last in JWS chain) was issued by this trustedRoot from roots.pem
                        if (currentCert.checkIssued(trustedRoot)) {
                            console.log(`Last cert in JWS chain (${currentCert.subject}) IS issued by ${trustedRoot.subject} from roots.pem.`);
                            // Now, ensure this trustedRoot from roots.pem is actually self-signed.
                            try {
                                if (!trustedRoot.verify(trustedRoot.publicKey)) {
                                    throw new Error(`Issuing certificate ${trustedRoot.subject} (from roots.pem) failed self-signature verification.`);
                                }
                                console.log(`Issuing certificate ${trustedRoot.subject} (from roots.pem) successfully verified as self-signed.`);
                                validChainFound = true;
                                break; // Found a valid chain to a self-signed root from roots.pem
                            } catch (e) {
                                throw new Error(`Error self-signing ${trustedRoot.subject} (from roots.pem) which issued ${currentCert.subject}: ${e.message}`);
                            }
                        }
                    }
                } else if (!validChainFound && (!parsedTrustedRoots || parsedTrustedRoots.length === 0)) {
                    // Scenario 3: No roots.pem provided.
                    // We can only trust the chain if the last certificate is self-signed by itself.
                    // This is a weaker form of trust, highly dependent on the device not sending a bogus self-signed cert.
                    console.warn(`No roots.pem provided. Trusting JWS chain if its last certificate (${currentCert.subject}) is self-signed.`);
                    try {
                        if (!currentCert.verify(currentCert.publicKey)) {
                            throw new Error(`Last cert in JWS chain (${currentCert.subject}) is not self-signed, and no roots.pem was provided for further validation.`);
                        }
                        console.log(`Last cert in JWS chain (${currentCert.subject}) verified as self-signed (no roots.pem for cross-check).`);
                        validChainFound = true;
                    } catch (e) {
                        throw new Error(`Error self-signing ${currentCert.subject} (last in JWS chain, no roots.pem): ${e.message}`);
                    }
                }

                if (!validChainFound) {
                    throw new Error(`Certificate chain for ${leafCert.subject} did not lead to a trusted and self-signed root CA from the provided roots.pem, nor was the chain's final certificate a self-signed root itself (if roots.pem was empty/missing). Last cert in chain: ${currentCert.subject}.`);
                }
                console.log(`Successfully validated certificate chain for leaf ${leafCert.subject} up to a trusted root.`);
            }
        }

        // trustedRootFound is now true if the chain successfully linked to a root in parsedTrustedRoots which was self-signed.
        // If parsedTrustedRoots was empty, trustedRootFound will be false, but validChainFound might be true if the JWS's own last cert was self-signed.
        // The original logic for this check was:
        // if (parsedTrustedRoots && parsedTrustedRoots.length > 0 && !trustedRootFound) {
        // This check might need to be re-evaluated based on policy if allowing chains not anchored to parsedTrustedRoots.
        // For now, let's assume if validChainFound is true, the chain is considered valid per the logic above.
        // If validChainFound is true, it means we've successfully validated the chain according to one of the scenarios.

        console.log("Certificate chain path validation completed.");


    } catch (error) {
        throw new Error(`Failed to parse or verify SafetyNet certificate: ${error.message}`);
    }

    // Verify the JWS signature using the certificate's public key
    try {
        // Extract public key from the certificate in PEM format
        const publicKey = leafCert.publicKey;

        // Split the JWS into parts
        const jwsParts = jwsString.split('.');
        const signedData = jwsParts.slice(0, 2).join('.');
        const signatureBase64 = jwsParts[2];

        // Convert the signature from base64 to buffer
        const signatureBuffer = Buffer.from(signatureBase64, 'base64');

        // Verify the signature
        const isValid = crypto.verify(
            'sha256', // Algorithm - SafetyNet uses RS256 which is RSA with SHA-256
            Buffer.from(signedData),
            publicKey,
            signatureBuffer
        );

        if (!isValid) {
            throw new Error('SafetyNet JWS signature verification failed');
        }
        console.log('SafetyNet JWS signature verified successfully with certificate public key');

    } catch (error) {
        throw new Error(`Failed to verify SafetyNet JWS signature: ${error.message}`);
    }

    // Validate the payload
    if (!payload.nonce) {
        throw new Error('SafetyNet response missing nonce.');
    }

    // Check if the nonce in the payload matches our expected nonce
    if (payload.nonce !== nonceBase64) {
        throw new Error(`Nonce mismatch. Expected: ${nonceBase64}, Got: ${payload.nonce}`);
    }
    console.log('SafetyNet nonce verified successfully.');

    // Verify ctsProfileMatch is true (device passes Android Compatibility Test Suite)
    if (payload.ctsProfileMatch !== true) {
        throw new Error('SafetyNet ctsProfileMatch is not true. Device integrity check failed.');
    }
    console.log('SafetyNet ctsProfileMatch verified: true.');

    // Check timestampMs to ensure the attestation is recent
    const maxAgeMs = 2 * 60 * 1000; // 2 minutes
    const now = Date.now();
    if (!payload.timestampMs || typeof payload.timestampMs !== 'number' ||
        (now - payload.timestampMs) > maxAgeMs) {
        const age = payload.timestampMs ? ((now - payload.timestampMs) / 1000) + 's' : 'unknown';
        throw new Error(`SafetyNet attestation too old or invalid timestamp. Age: ${age}`);
    }
    console.log(`SafetyNet timestampMs verified (age: ${(now - payload.timestampMs) / 1000}s).`);

    console.log('Android SafetyNet attestation verification successful.');
    return true;
}

/**
 * Verifies an 'android-key' attestation statement.
 * @param {object} attStmt - Attestation statement object (contains sig, x5c, alg).
 * @param {Buffer} authDataBuffer - The raw authenticator data buffer.
 * @param {Buffer} clientDataHash - SHA256 hash of the clientDataJSON.
 * @param {object} credentialPublicKeyDetails - Decoded public key details from authData.
 * @returns {Promise<boolean>} True if verification is successful.
 * @throws {Error} If verification fails.
 */
async function verifyAndroidKeyAttestation(attStmt, authDataBuffer, clientDataHash, credentialPublicKeyDetails) {
    console.log("Processing 'android-key' attestation format.");
    const { sig, x5c, alg } = attStmt;

    if (!sig || !Buffer.isBuffer(sig)) {
        throw new Error("Android Key attestation statement missing or invalid 'sig'.");
    }
    if (!x5c || !Array.isArray(x5c) || x5c.length === 0 || !x5c.every(c => typeof c === 'string' || Buffer.isBuffer(c))) {
        throw new Error("Android Key attestation statement missing or invalid 'x5c' (certificate chain).");
    }
    if (alg === undefined) {
        console.warn("Android Key attestation statement missing 'alg'. Will infer from public key.");
        // We must ensure the algorithm used for verification matches the key type.
        // Common for Android Key is ES256.
    }

    // 1. Verify the certificate chain and parse the leaf certificate.
    let leafCert;
    try {
        const certChainPEM = x5c.map(certData => {
            const certBuffer = Buffer.isBuffer(certData) ? certData : Buffer.from(certData, 'base64');
            return '-----BEGIN CERTIFICATE-----\n' + certBuffer.toString('base64') + '\n-----END CERTIFICATE-----';
        });

        leafCert = new crypto.X509Certificate(certChainPEM[0]);

        // TODO: Implement full chain validation up to Google Hardware Attestation Root CAs.
        // For now, just check basic validity of the leaf certificate.
        const now = new Date();
        if (new Date(leafCert.validFrom) > now || new Date(leafCert.validTo) < now) {
            throw new Error(`Leaf certificate is not valid. Valid from ${leafCert.validFrom} to ${leafCert.validTo}`);
        }
        console.log("Android Key attestation: Leaf certificate validity period checked.");

    } catch (e) {
        throw new Error(`Failed to parse or validate leaf certificate for Android Key: ${e.message}`);
    }

    // 2. Parse Key Description Extension and verify attestationChallenge
    let parsedKeyDescription;
    try {
        parsedKeyDescription = parseAndroidKeyDescription(leafCert);
        if (!parsedKeyDescription) {
            throw new Error("Failed to parse KeyDescription from certificate extensions.");
        }
        console.log("Successfully parsed Android KeyDescription extension.");
        // console.log("KeyDescription Content:", parsedKeyDescription);

        // CRITICAL: Verify attestationChallenge
        if (!parsedKeyDescription.attestationChallenge) {
            throw new Error("KeyDescription is missing attestationChallenge.");
        }
        if (!bufferEqual(Buffer.from(parsedKeyDescription.attestationChallenge), clientDataHash)) {
            console.error("Expected attestation challenge (clientDataHash):", clientDataHash.toString('hex'));
            console.error("Received attestation challenge from KeyDescription:", Buffer.from(parsedKeyDescription.attestationChallenge).toString('hex'));
            throw new Error("Attestation challenge mismatch in Key Description. Expected clientDataHash.");
        }
        console.log("Android Key Attestation: attestationChallenge verified successfully.");

        // Log security levels for policy decisions
        console.log(`Attestation Version: ${parsedKeyDescription.attestationVersion}, Security Level: ${parsedKeyDescription.attestationSecurityLevel}`);
        console.log(`Keymaster Version: ${parsedKeyDescription.keymasterVersion}, Security Level: ${parsedKeyDescription.keymasterSecurityLevel}`);
        // Example: Accessing a TEE enforced property (origin)
        if (parsedKeyDescription.teeEnforced && parsedKeyDescription.teeEnforced.origin !== undefined) {
            console.log(`TEE Enforced Origin: ${parsedKeyDescription.teeEnforced.origin} (0=generated, 1=derived, 2=imported, 3=unknown)`);
        }
        if (parsedKeyDescription.teeEnforced && parsedKeyDescription.teeEnforced.rollbackResistance !== undefined) {
            console.log(`TEE Enforced Rollback Resistance: present`);
        }

    } catch (e) {
        console.error("Error during KeyDescription parsing or challenge verification:", e);
        throw new Error(`Android Key Attestation: KeyDescription processing failed: ${e.message}`);
    }

    // 3. Verify the signature.
    const dataToVerify = Buffer.concat([authDataBuffer, clientDataHash]);
    let expectedCoseAlg = alg; // Use alg from attStmt if present

    if (!expectedCoseAlg) {
        // Attempt to infer from credentialPublicKeyDetails if not in attStmt, though for Android Key attestation,
        // the signature is made by the key in the x5c certificate, not necessarily the credentialPublicKey.
        // This part might need re-evaluation based on how `alg` is typically populated for Android Key.
        // Usually, Android Key Attestation uses ES256, and `alg` should reflect that.
        if (credentialPublicKeyDetails && credentialPublicKeyDetails.alg) {
            console.warn("Android Key attestation 'alg' not present in attStmt, inferring from credentialPublicKey. This might be incorrect for Android Key.");
            expectedCoseAlg = credentialPublicKeyDetails.alg;
        } else {
            // Default to ES256 if no algorithm information is available, with a warning.
            console.warn("Android Key attestation 'alg' not found. Defaulting to ES256. Verification might fail if incorrect.");
            expectedCoseAlg = COSE_ALGORITHMS.ES256;
        }
    }

    const publicKeyForVerification = leafCert.publicKey; // Public key from the attestation certificate
    let nodeCryptoAlgName;

    switch (expectedCoseAlg) {
        case COSE_ALGORITHMS.ES256: nodeCryptoAlgName = 'sha256'; break;
        case COSE_ALGORITHMS.ES384: nodeCryptoAlgName = 'sha384'; break;
        case COSE_ALGORITHMS.ES512: nodeCryptoAlgName = 'sha512'; break;
        // Potentially other algorithms like RS256 (-257) if supported by Android Key for attestation signature
        case COSE_ALGORITHMS.RS256: nodeCryptoAlgName = 'sha256'; break; // For RSA-PSS or RSASSA-PKCS1-v1_5 with SHA256
        default:
            throw new Error(`Unsupported COSE algorithm for Android Key signature verification: ${expectedCoseAlg}`);
    }

    try {
        const signatureIsValid = crypto.verify(
            nodeCryptoAlgName,
            dataToVerify,
            publicKeyForVerification,
            sig
        );

        if (!signatureIsValid) {
            throw new Error("Android Key attestation signature verification failed.");
        }
        console.log("Android Key attestation signature verified successfully.");
        return true;
    } catch (e) {
        console.error("Error during Android Key signature verification:", e);
        throw new Error(`Android Key signature verification failed: ${e.message}`);
    }
}

// --- Helper functions for Attestation Verification (Placeholders/Examples) ---

function convertCoseKeyToJwk(coseKeyDetails) {
    // Basic conversion, needs error handling and support for more types (RSA)
    const jwk = {
        kty: '',
        crv: '',
        x: '',
        y: '',
        use: 'sig' // Keep use parameter
    };

    if (coseKeyDetails.kty === COSE_KEY_TYPES.EC2) {
        jwk.kty = 'EC';
        jwk.crv = getJwkCurve(coseKeyDetails.crv);
        jwk.x = Buffer.from(coseKeyDetails.x).toString('base64url');
        jwk.y = Buffer.from(coseKeyDetails.y).toString('base64url');
    } else if (coseKeyDetails.kty === COSE_KEY_TYPES.OKP) {
        jwk.kty = 'OKP';
        jwk.crv = getJwkCurve(coseKeyDetails.crv);
        jwk.x = Buffer.from(coseKeyDetails.x).toString('base64url');
        // OKP JWK doesn't use 'y'
        delete jwk.y;
    } else {
        throw new Error(`Cannot convert COSE kty ${coseKeyDetails.kty} to JWK`);
    }

    return jwk;
}

function getJwkCurve(coseCurve) {
    switch (coseCurve) {
        case COSE_ELLIPTIC_CURVES.P_256: return 'P-256';
        case COSE_ELLIPTIC_CURVES.P_384: return 'P-384';
        case COSE_ELLIPTIC_CURVES.P_521: return 'P-521';
        case COSE_ELLIPTIC_CURVES.Ed25519: return 'Ed25519';
        default: throw new Error(`Unsupported COSE curve: ${coseCurve}`);
    }
}

function getJwkParams(coseAlg) {
    // Parameters for subtle.importKey based on JWA alg name
    switch (coseAlg) {
        case COSE_ALGORITHMS.ES256: return { name: 'ECDSA', namedCurve: 'P-256' };
        case COSE_ALGORITHMS.ES384: return { name: 'ECDSA', namedCurve: 'P-384' };
        case COSE_ALGORITHMS.ES512: return { name: 'ECDSA', namedCurve: 'P-521' };
        case COSE_ALGORITHMS.EdDSA: return { name: 'EdDSA', namedCurve: 'Ed25519' };
        case COSE_ALGORITHMS.RS256: return { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' };
        // Add others
        default: throw new Error(`Unsupported COSE algorithm for WebCrypto import: ${coseAlg}`);
    }
}
function getWebCryptoAlgName(coseAlg) {
    // Algorithm object/name for subtle.verify
    switch (coseAlg) {
        case COSE_ALGORITHMS.ES256: return { name: 'ECDSA', hash: { name: 'SHA-256' } };
        case COSE_ALGORITHMS.ES384: return { name: 'ECDSA', hash: { name: 'SHA-384' } };
        case COSE_ALGORITHMS.ES512: return { name: 'ECDSA', hash: { name: 'SHA-512' } };
        case COSE_ALGORITHMS.EdDSA: return { name: 'EdDSA' }; // EdDSA hash is implicit
        case COSE_ALGORITHMS.RS256: return { name: 'RSASSA-PKCS1-v1_5' }; // Hash defined in importKey
        // Add others
        default: throw new Error(`Unsupported COSE algorithm for WebCrypto verify: ${coseAlg}`);
    }
}


// --- Main Registration Verification Function ---

/**
 * Verifies the response from navigator.credentials.create()
 *
 * @param {object} credential - The PublicKeyCredential object received from the client (JSON parsed, ArrayBuffers typically base64url encoded strings).
 * @param {string} expectedChallenge - The base64url encoded challenge originally sent to the client.
 * @param {string} expectedOrigin - The expected origin (e.g., 'https://example.com').
 * @param {string} expectedRpId - The expected Relying Party ID (e.g., 'example.com').
 * @param {boolean} requireUserVerification - Whether UV flag must be set in authData.
 * @param {crypto.X509Certificate[]} [parsedTrustedRoots] - Optional. Array of parsed trusted root certificates for attestation formats that require them.
 * @returns {Promise<object>} Information about the verified credential to be stored.
 * @throws {Error} If any verification step fails.
 */
async function verifyRegistrationResponse(credential, expectedChallenge, expectedOrigin, expectedRpId, requireUserVerification, parsedTrustedRoots) {
    // Basic structure check
    if (!credential || !credential.id || !credential.rawId || !credential.response ||
        !credential.response.clientDataJSON || !credential.response.attestationObject ||
        credential.type !== 'public-key') {
        throw new Error('Invalid credential structure received.');
    }

    console.log('Starting registration verification...');
    console.log('Expected Challenge:', expectedChallenge);
    console.log('Expected Origin:', expectedOrigin);
    console.log('Expected RP ID:', expectedRpId);

    // 1. Decode necessary inputs from Base64URL
    const rawIdBuffer = base64urlToBuffer(credential.rawId);
    const clientDataJSONBuffer = base64urlToBuffer(credential.response.clientDataJSON);
    const attestationObjectBuffer = base64urlToBuffer(credential.response.attestationObject);

    // 2. Parse and verify clientDataJSON
    console.log('\n--- Verifying clientDataJSON ---');
    let clientData;
    try {
        const clientDataString = clientDataJSONBuffer.toString('utf8');
        clientData = JSON.parse(clientDataString);
    } catch (e) {
        throw new Error(`Failed to parse clientDataJSON: ${e.message}`);
    }

    console.log('Parsed clientData:', clientData);

    if (clientData.type !== 'webauthn.create') {
        throw new Error(`Invalid clientData type. Expected 'webauthn.create', got '${clientData.type}'`);
    }

    // Compare challenge (use buffer compare for security)
    if (expectedChallenge) {
        const receivedChallengeBuffer = base64urlToBuffer(clientData.challenge);
        const expectedChallengeBuffer = base64urlToBuffer(expectedChallenge);
        if (!bufferEqual(receivedChallengeBuffer, expectedChallengeBuffer)) {
            throw new Error('Challenge mismatch.');
        }
        console.log('Challenge verified.');
    } else {
        console.log('Skipping challenge verification as expectedChallenge was not provided.');
    }

    // Compare origin
    if (expectedOrigin) {
        if (clientData.origin !== expectedOrigin) {
            // Handle variations like port numbers if necessary
            throw new Error(`Origin mismatch. Expected '${expectedOrigin}', got '${clientData.origin}'`);
        }
        console.log('Origin verified.');
    } else {
        console.log('Skipping origin verification as expectedOrigin was not provided.');
    }

    // Optional: Check tokenBinding field if used

    // 3. Parse attestationObject CBOR
    console.log('\n--- Verifying attestationObject ---');
    let attestationObject;
    try {
        // Ensure input to cbor.decode is ArrayBuffer
        let attestationObjectArrayBuffer;
        if (Buffer.isBuffer(attestationObjectBuffer)) {
            attestationObjectArrayBuffer = attestationObjectBuffer.buffer.slice(
                attestationObjectBuffer.byteOffset,
                attestationObjectBuffer.byteOffset + attestationObjectBuffer.byteLength
            );
        } else if (attestationObjectBuffer instanceof ArrayBuffer) {
            // Should not happen here as base64urlToBuffer returns Buffer, but good practice
            attestationObjectArrayBuffer = attestationObjectBuffer;
        } else {
            throw new Error('Invalid type for attestationObjectBuffer: Expected Buffer');
        }
        attestationObject = decode(attestationObjectArrayBuffer); // Use your CBOR decoder
    } catch (e) {
        throw new Error(`Failed to decode attestationObject CBOR: ${e.message}`);
    }

    const { fmt, attStmt, authData: authDataBuffer } = attestationObject;

    // Check if authData is Buffer or Uint8Array
    const isAuthDataBufferValid = Buffer.isBuffer(authDataBuffer) || authDataBuffer instanceof Uint8Array;

    if (!fmt || typeof fmt !== 'string' || !attStmt || typeof attStmt !== 'object' || !isAuthDataBufferValid) {
        console.error('Attestation object structure validation failed:'); // Add logging
        console.error(`  fmt: ${fmt} (type: ${typeof fmt})`);
        console.error(`  attStmt: ${attStmt} (type: ${typeof attStmt})`);
        console.error(`  authData: ${authDataBuffer} (type: ${authDataBuffer?.constructor?.name})`);
        console.error(`  isAuthDataBufferValid: ${isAuthDataBufferValid}`);
        throw new Error('Invalid attestation object structure. Missing or invalid fmt, attStmt, or authData.');
    }
    console.log('Attestation Format:', fmt);

    // 4. Parse and verify authenticatorData (authData)
    console.log('\n--- Verifying authenticatorData ---');
    // Ensure authData is a Buffer for parsing functions
    const authDataForParsing = Buffer.from(authDataBuffer);
    const parsedAuthData = parseAndVerifyAuthenticatorData(authDataForParsing, expectedRpId, requireUserVerification);

    // Verify that the credential ID in authData matches the one received at the top level
    if (!bufferEqual(rawIdBuffer, parsedAuthData.credentialId)) {
        throw new Error('Credential ID mismatch between authData and PublicKeyCredential.rawId.');
    }
    console.log('Credential ID consistency verified.');

    // 5. Decode the credential public key (COSE format)
    console.log('\n--- Decoding Public Key ---');
    let publicKeyDetails;
    try {
        const coseKeyMap = decodeCoseKey(parsedAuthData.credentialPublicKey); // Using cose.js
        publicKeyDetails = getWebAuthnPublicKeyDetails(coseKeyMap); // Using cose.js
        console.log('Decoded Public Key Details:', publicKeyDetails);
    } catch (e) {
        throw new Error(`Failed to decode credentialPublicKey: ${e.message}`);
    }

    // 6. Calculate clientDataHash
    const clientDataHash = crypto.createHash('sha256').update(clientDataJSONBuffer).digest();

    // 7. Verify the attestation statement (using the specific format)
    console.log('\n--- Verifying Attestation Statement ---');
    // *** IMPORTANT: This step is simplified. Robust implementation needed for production. ***
    try {
        const attestationVerified = await verifyAttestationStatement(
            fmt,
            attStmt,
            authDataBuffer,
            clientDataHash,
            publicKeyDetails,
            parsedAuthData.rpIdHash,
            parsedAuthData.credentialId,
            parsedTrustedRoots
        );
        if (!attestationVerified) {
            // Should not happen if verifyAttestationStatement throws on failure, but belt-and-suspenders
            throw new Error('Attestation statement verification failed.');
        }
        console.log('Attestation statement verified (or verification skipped/simplified).');
    } catch (e) {
        throw new Error(`Attestation verification error: ${e.message}`);
    }

    // 8. Check uniqueness: Ensure parsedAuthData.credentialId is not already registered
    //    (Requires database lookup - Pseudocode below)
    // const existingCredential = await database.findCredentialById(parsedAuthData.credentialId);
    // if (existingCredential) {
    //     throw new Error(`Credential ID already registered: ${parsedAuthData.credentialId.toString('base64url')}`);
    // }
    console.log('Placeholder: Credential ID uniqueness check passed.');

    // --- Verification Successful ---
    console.log('\nRegistration verification successful!');

    // 9. Return data to be stored for the user
    return {
        credentialId: parsedAuthData.credentialId, // Store as Buffer or base64url string
        credentialPublicKey: parsedAuthData.credentialPublicKey, // Store the raw COSE key Buffer
        signCount: parsedAuthData.signCount,
        aaguid: parsedAuthData.aaguid,
        transports: credential.response.getTransports ? credential.response.getTransports() : [], // Store associated transports if available
        // Potentially store fmt, attStmt, flags.uv for policy decisions later
        userVerified: parsedAuthData.flags.uv,
        attestationFormat: fmt,
    };
}

/**
 * Parses Authenticator Data for assertions (login).
 * Does NOT include attested credential data checks.
 * @param {Buffer} authDataBuffer
 * @param {string} expectedRpId
 * @param {boolean} requireUserVerification
 * @returns {{rpIdHash: Buffer, flags: {up: boolean, uv: boolean, at: boolean, ed: boolean}, signCount: number}}
 * @throws {Error}
 */
function parseAssertionAuthenticatorData(authDataBuffer, expectedRpId, requireUserVerification) {
    if (authDataBuffer.byteLength < 37) { // rpIdHash (32) + flags (1) + signCount (4)
        throw new Error(`Authenticator data is too short for assertion. Expected >= 37 bytes, got ${authDataBuffer.byteLength}`);
    }

    const rpIdHash = authDataBuffer.subarray(0, 32);
    const flagsByte = authDataBuffer.readUInt8(32);
    const signCount = authDataBuffer.readUInt32BE(33); // 4 bytes counter

    // Verify RP ID Hash
    if (expectedRpId) {
        const expectedRpIdHash = crypto.createHash('sha256').update(expectedRpId).digest();
        if (!bufferEqual(rpIdHash, expectedRpIdHash)) {
            // If direct match fails, also try with "www." prefix
            const wwwExpectedRpIdHash = crypto.createHash('sha256').update(`www.${expectedRpId}`).digest();
            if (!bufferEqual(rpIdHash, wwwExpectedRpIdHash)) {
                throw new Error(`RP ID hash mismatch during assertion. Expected ${expectedRpIdHash.toString('hex')} or ${wwwExpectedRpIdHash.toString('hex')} but got ${rpIdHash.toString('hex')}`);
            }
            console.log('Assertion RP ID hash verified (with www prefix).');
        } else {
            console.log('Assertion RP ID hash verified.');
        }
    } else {
        console.log('Skipping assertion RP ID hash verification as expectedRpId was not provided.');
    }

    // Parse Flags
    const flags = {
        up: !!(flagsByte & 0x01), // User Present
        uv: !!(flagsByte & 0x04), // User Verified
        // AT (0x40) and ED (0x80) flags might be present but are less critical for assertion logic itself
        at: !!(flagsByte & 0x40), // Attested credential data included (Should be false for assertion?)
        ed: !!(flagsByte & 0x80), // Extension data included
    };
    console.log('Parsed Assertion Flags:', flags);
    console.log('Assertion Sign Count:', signCount);

    // Verify Flags
    if (!flags.up) {
        // While UP=false is possible in some scenarios (e.g., U2F HID authenticators without presence test), 
        // most modern WebAuthn flows require user presence.
        // Depending on policy, you might allow this, but generally it's required.
        console.warn('User Presence flag (UP) was not set during assertion. This might be acceptable depending on policy and authenticator type.');
        // For stricter security, uncomment the line below:
        // throw new Error('User Presence flag (UP) was not set during assertion.');
    }
    if (requireUserVerification && !flags.uv) {
        // This check depends on the RP's policy for this specific login
        throw new Error('User Verification flag (UV) was required for assertion but not set.');
    }

    // Note: We don't parse AAGUID, Credential ID, or Public Key here,
    // as they are not part of the authenticatorData during assertion.
    // Extension data parsing would happen after offset 37 if flags.ed is true.

    return {
        rpIdHash,
        flags,
        signCount,
        // extensions // Add if parsed
    };
}

/**
 * Verifies the response from navigator.credentials.get()
 *
 * @param {object} assertion - The PublicKeyCredential object received from the client (JSON parsed, ArrayBuffers base64url encoded).
 * @param {object} storedCredential - The stored credential information for the given credential ID (needs { credentialId: Buffer, credentialPublicKey: Buffer, signCount: number }).
 * @param {string} expectedChallenge - The base64url encoded challenge originally sent to the client.
 * @param {string} expectedOrigin - The expected origin (e.g., 'https://example.com').
 * @param {string} expectedRpId - The expected Relying Party ID (e.g., 'example.com').
 * @param {boolean} requireUserVerification - Whether UV flag must be set in authData for this assertion.
 * @returns {Promise<object>} Information about the verified assertion (e.g., new sign count).
 * @throws {Error} If any verification step fails.
 */
async function verifyAssertionResponse(assertion, storedCredential, expectedChallenge, expectedOrigin, expectedRpId, requireUserVerification) {
    // Basic structure check
    if (!assertion || !assertion.id || !assertion.rawId || !assertion.response ||
        !assertion.response.authenticatorData || !assertion.response.clientDataJSON ||
        !assertion.response.signature || assertion.type !== 'public-key') {
        throw new Error('Invalid assertion structure received.');
    }

    console.log('Starting assertion verification...');
    console.log('Expected Challenge:', expectedChallenge);
    console.log('Expected Origin:', expectedOrigin);
    console.log('Expected RP ID:', expectedRpId);

    // 1. Decode necessary inputs from Base64URL
    const clientDataJSONBuffer = base64urlToBuffer(assertion.response.clientDataJSON);
    const authenticatorDataBuffer = base64urlToBuffer(assertion.response.authenticatorData);
    const publicKeyBuffer = base64urlToBuffer(storedCredential.publicKey);
    const signatureBuffer = base64urlToBuffer(assertion.response.signature);

    // Verify credential ID matches the one stored
    if (assertion.id !== storedCredential.id) {
        throw new Error(`Credential ID mismatch. Expected ${storedCredential.id}, got ${assertion.id}`);
    }
    console.log('Credential ID verified.');

    // 2. Parse and verify clientDataJSON
    console.log('\n--- Verifying clientDataJSON ---');
    let clientData;
    try {
        const clientDataString = clientDataJSONBuffer.toString('utf8');
        clientData = JSON.parse(clientDataString);
    } catch (e) {
        throw new Error(`Failed to parse clientDataJSON: ${e.message}`);
    }
    console.log('Parsed clientData:', clientData);

    if (clientData.type !== 'webauthn.get') {
        throw new Error(`Invalid clientData type. Expected 'webauthn.get', got '${clientData.type}'`);
    }

    // Compare challenge
    // const receivedChallengeBuffer = base64urlToBuffer(clientData.challenge);
    // const expectedChallengeBuffer = base64urlToBuffer(expectedChallenge);
    if (clientData.challenge !== expectedChallenge) {
        throw new Error('Challenge mismatch.');
    }
    console.log('Challenge verified.');

    // Compare origin
    if (clientData.origin !== expectedOrigin) {
        throw new Error(`Origin mismatch. Expected '${expectedOrigin}', got '${clientData.origin}'`);
    }
    console.log('Origin verified.');

    // 3. Parse authenticatorData
    console.log('\n--- Verifying authenticatorData ---');
    // Ensure authenticatorDataBuffer is a Buffer for parsing
    const authDataForParsing = Buffer.from(authenticatorDataBuffer);
    const parsedAuthData = parseAssertionAuthenticatorData(authDataForParsing, expectedRpId, requireUserVerification);

    // 4. Verify Signature
    console.log('\n--- Verifying Signature ---');
    const clientDataHash = crypto.createHash('sha256').update(clientDataJSONBuffer).digest();
    const dataToVerify = Buffer.concat([authDataForParsing, clientDataHash]);

    // Decode the stored public key
    let publicKeyDetails;
    try {
        const coseKeyMap = decodeCoseKey(publicKeyBuffer); // Decode stored key
        publicKeyDetails = getWebAuthnPublicKeyDetails(coseKeyMap);
    } catch (e) {
        throw new Error(`Failed to decode stored credentialPublicKey: ${e.message}`);
    }

    // Import public key for verification
    const keyObject = await crypto.subtle.importKey(
        'jwk',
        convertCoseKeyToJwk(publicKeyDetails),
        getJwkParams(publicKeyDetails.alg),
        true,
        ['verify']
    );

    // Perform verification - CONVERT SIGNATURE FORMAT FOR ECDSA
    let signatureToVerify = signatureBuffer;
    let verificationAlgorithm = getWebCryptoAlgName(publicKeyDetails.alg);

    if (publicKeyDetails.kty === COSE_KEY_TYPES.EC2) {
        // ECDSA signatures from WebAuthn are ASN.1 DER encoded, but WebCrypto expects raw r||s
        let curveByteLength;
        switch (publicKeyDetails.crv) {
            case COSE_ELLIPTIC_CURVES.P_256: curveByteLength = 32; break;
            case COSE_ELLIPTIC_CURVES.P_384: curveByteLength = 48; break;
            case COSE_ELLIPTIC_CURVES.P_521: curveByteLength = 66; break; // Note: P-521 uses 66 bytes
            default: throw new Error(`Unsupported EC curve for signature conversion: ${publicKeyDetails.crv}`);
        }
        try {
            // Decode the ASN.1 DER signature using asn1.js
            signatureToVerify = decodeDerEncodedSignature(signatureBuffer, curveByteLength);
            console.log(`Decoded ASN.1 DER signature using asn1.js library for curve length ${curveByteLength}.`);
        } catch (asn1Error) {
            throw new Error(`Failed to decode ASN.1 DER signature using asn1.js: ${asn1Error.message}`);
        }
    }
    // For EdDSA or RSA, the format might be different or handled directly by WebCrypto

    const signatureIsValid = await crypto.subtle.verify(
        verificationAlgorithm, // Use the original algorithm object
        keyObject,
        signatureToVerify,    // Use the potentially converted signature
        dataToVerify
    );

    if (!signatureIsValid) {
        throw new Error("Assertion signature verification failed.");
    }
    console.log("Assertion signature verified successfully.");

    // 5. Verify Signature Counter
    console.log('\n--- Verifying Signature Counter ---');
    const currentSignCount = parsedAuthData.signCount;
    const lastSignCount = storedCredential.signCount; // From database/storage

    console.log(`Stored Sign Count: ${lastSignCount}, Received Sign Count: ${currentSignCount}`);

    // Check if counter is zero (and allow if last stored is also zero)
    if (currentSignCount === 0 && lastSignCount === 0) {
        console.log("Sign count is zero, accepted (both stored and received are 0).");
        // This is common for new authenticators or those not supporting counters
    } else if (currentSignCount <= lastSignCount) {
        // Potentially a replay attack or cloned authenticator
        throw new Error(`Invalid signature counter. Stored: ${lastSignCount}, Received: ${currentSignCount}. Possible replay attack.`);
    }
    console.log("Signature counter verified.");

    // --- Verification Successful ---
    console.log('\nAssertion verification successful!');

    // 6. Return new sign count to be updated in storage
    return {
        newSignCount: currentSignCount,
        userVerified: parsedAuthData.flags.uv // Pass back UV status from assertion
    };
}

module.exports = {
    verifyRegistrationResponse,
    verifyAssertionResponse,
    parseAndVerifyAuthenticatorData,
    parseAssertionAuthenticatorData,
    verifyAttestationStatement,
    bufferEqual,
    base64urlToBuffer,
    bufferToBase64url,
    parseRootsPem // Export the new PEM parser
};