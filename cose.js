const { decode, encode } = require('./cbor/cbor');

const COSE_PARAMETERS = {
    // Header Parameters
    alg: 1, // Algorithm
    crit: 2, // Critical headers
    content_type: 3,
    kid: 4, // Key ID
    iv: 5,
    // Key Parameters
    kty: 1, // Key Type
    key_ops: 4, // Key Operations
    base_iv: 5, // Base IV
};

const COSE_KEY_PARAMETERS = {
    kty: 1, // Key Type Label
    kid: 2, // Key ID Label
    alg: 3, // Algorithm Label
    key_ops: 4, // Key Ops Label
    base_iv: 5, // Base IV Label
};

const COSE_KEY_TYPES = {
    OKP: 1, // Octet Key Pair
    EC2: 2, // Elliptic Curve Keys w/ x- and y-coordinate pair
    Symmetric: 4,
};

const COSE_ALGORITHMS = {
    // ECDSA
    ES256: -7,  // ECDSA w/ SHA-256
    ES384: -35, // ECDSA w/ SHA-384
    ES512: -36, // ECDSA w/ SHA-512
    // EdDSA
    EdDSA: -8,
    // RSASSA-PKCS1-v1_5
    RS256: -257,
    RS384: -258,
    RS512: -259,
    RS1: -65535, // RSASSA-PKCS1-v1_5 using SHA-1 (NOT RECOMMENDED)
    // HMAC
    HS256: 5, // HMAC w/ SHA-256
};

const COSE_ELLIPTIC_CURVES = {
    P_256: 1, // NIST P-256 / secp256r1
    P_384: 2, // NIST P-384 / secp384r1
    P_521: 3, // NIST P-521 / secp521r1
    Ed25519: 6, // Ed25519 for EdDSA
};

// Parameters specific to EC2 Keys
const COSE_EC2_KEY_PARAMETERS = {
    crv: -1, // Curve
    x: -2,   // x-coordinate
    y: -3,   // y-coordinate
    d: -4,   // private key
};

// Parameters specific to OKP Keys
const COSE_OKP_KEY_PARAMETERS = {
    crv: -1, // Curve (e.g., Ed25519)
    x: -2,   // Public key
    d: -4,   // Private key
};

/**
 * Decodes a CBOR buffer containing a COSE_Key map.
 *
 * @param {ArrayBuffer} coseKeyBuffer - The ArrayBuffer containing the CBOR encoded COSE_Key.
 * @returns {object} A JavaScript object representing the COSE_Key map.
 * @throws {Error} If the buffer does not decode to a Map.
 */
function decodeCoseKey(coseKeyBuffer) {
    // Ensure input is ArrayBuffer for cbor.decode
    let inputBuffer;
    if (Buffer.isBuffer(coseKeyBuffer)) {
        // Convert Node.js Buffer to ArrayBuffer
        inputBuffer = coseKeyBuffer.buffer.slice(
            coseKeyBuffer.byteOffset,
            coseKeyBuffer.byteOffset + coseKeyBuffer.byteLength
        );
    } else if (coseKeyBuffer instanceof ArrayBuffer) {
        inputBuffer = coseKeyBuffer;
    } else {
        throw new Error('Invalid input type for decodeCoseKey: Expected Buffer or ArrayBuffer.');
    }

    const decoded = decode(inputBuffer);
    console.log("[decodeCoseKey] CBOR Decoded Object:", decoded); // TEMP LOG 1

    // COSE Keys MUST be maps
    if (!(decoded instanceof Map || (typeof decoded === 'object' && decoded !== null && !Array.isArray(decoded)))) {
        // The provided cbor.js decodes maps to Objects, not Maps. Adjust check.
        throw new Error('Invalid COSE_Key structure: Expected CBOR Map (decoded as Object).');
    }

    // Convert integer keys (if decoded as strings by cbor.js) back to numbers
    // for easier lookup using constants. Note: The provided cbor.js *should*
    // handle integer keys correctly, but this is defensive.
    const keyMap = {};
    for (const key in decoded) {
        if (Object.prototype.hasOwnProperty.call(decoded, key)) {
            const numKey = parseInt(key, 10);
            if (!isNaN(numKey)) {
                keyMap[numKey] = decoded[key];
            } else {
                // Should not happen if CBOR library is correct for integer keys
                keyMap[key] = decoded[key];
            }
        }
    }
    console.log("[decodeCoseKey] Constructed keyMap:", keyMap); // TEMP LOG 2
    console.log("[decodeCoseKey] Checking for kty (key 1):", keyMap[COSE_KEY_PARAMETERS.kty]); // TEMP LOG 3

    // Basic validation: Ensure kty is present
    if (keyMap[COSE_KEY_PARAMETERS.kty] === undefined) {
        throw new Error('Invalid COSE_Key: Missing required parameter "kty" (1)');
    }

    return keyMap;
}

/**
 * Extracts relevant public key details for WebAuthn verification.
 * NOTE: This does NOT perform cryptographic validation.
 *
 * @param {object} coseKeyMap - The decoded COSE_Key object (output of decodeCoseKey).
 * @returns {{kty: number, alg: number, crv: number | undefined, x: Uint8Array | undefined, y: Uint8Array | undefined}} Extracted parameters.
 * @throws {Error} If required parameters for the key type are missing.
 */
function getWebAuthnPublicKeyDetails(coseKeyMap) {
    const kty = coseKeyMap[COSE_KEY_PARAMETERS.kty];
    const alg = coseKeyMap[COSE_KEY_PARAMETERS.alg];

    if (typeof kty !== 'number' || typeof alg !== 'number') {
        throw new Error('Invalid COSE_Key: "kty" (1) and "alg" (3) must be present and be numbers.');
    }

    let details = { kty, alg };

    if (kty === COSE_KEY_TYPES.EC2) {
        details.crv = coseKeyMap[COSE_EC2_KEY_PARAMETERS.crv];
        details.x = coseKeyMap[COSE_EC2_KEY_PARAMETERS.x];
        details.y = coseKeyMap[COSE_EC2_KEY_PARAMETERS.y];
        if (typeof details.crv !== 'number' || !(details.x instanceof Uint8Array) || !(details.y instanceof Uint8Array)) {
            throw new Error('Invalid EC2 COSE_Key: Missing or invalid "crv" (-1), "x" (-2), or "y" (-3).');
        }
    } else if (kty === COSE_KEY_TYPES.OKP) {
        details.crv = coseKeyMap[COSE_OKP_KEY_PARAMETERS.crv];
        details.x = coseKeyMap[COSE_OKP_KEY_PARAMETERS.x];
        if (typeof details.crv !== 'number' || !(details.x instanceof Uint8Array)) {
            throw new Error('Invalid OKP COSE_Key: Missing or invalid "crv" (-1) or "x" (-2).');
        }
    } else if (kty === COSE_KEY_TYPES.RSA) { // RSA is not defined in COSE_KEY_TYPES above, add if needed
        // Add RSA parameter extraction (n, e) if required, e.g., using labels -1, -2
        // details.n = coseKeyMap[-1]; details.e = coseKeyMap[-2];
        // Add validation
        throw new Error(`RSA Key Type (${kty}) WebAuthn details not fully implemented in this example.`);
    }
    else {
        throw new Error(`Unsupported COSE Key Type (kty): ${kty}`);
    }

    return details;
}


module.exports = {
    COSE_PARAMETERS,
    COSE_KEY_PARAMETERS,
    COSE_KEY_TYPES,
    COSE_ALGORITHMS,
    COSE_ELLIPTIC_CURVES,
    COSE_EC2_KEY_PARAMETERS,
    COSE_OKP_KEY_PARAMETERS,
    decodeCoseKey,
    getWebAuthnPublicKeyDetails
};
