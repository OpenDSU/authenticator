const asn1 = require('../asn1/asn1.js');

function decodeDerEncodedSignature(signatureBuffer, curveByteLength) {
    // Define the ASN.1 structure for an ECDSA signature
    const EcdsaSigAsn1 = asn1.define('EcdsaSig', function () {
        this.seq().obj(
            this.key('r').int(),
            this.key('s').int()
        );
    });
    const decodedSig = EcdsaSigAsn1.decode(signatureBuffer, 'der');

    // Get r and s as bignum instances
    const rBn = decodedSig.r;
    const sBn = decodedSig.s;

    // Convert bignum to fixed-length buffers (BE, padded)
    let rBa = rBn.toArrayLike(Buffer, 'be', curveByteLength);
    let sBa = sBn.toArrayLike(Buffer, 'be', curveByteLength);

    const signatureToVerify = Buffer.concat([rBa, sBa]);

    return signatureToVerify;
}

const SecurityLevel = asn1.define('SecurityLevel', function () {
    this.enum({
        0: 'software',
        1: 'trustedEnvironment',
        2: 'strongbox'
    });
});

const VerifiedBootState = asn1.define('VerifiedBootState', function () {
    this.enum({
        0: 'Verified',
        1: 'SelfSigned',
        2: 'Unverified',
        3: 'Failed'
    });
});

const RootOfTrust = asn1.define('RootOfTrust', function () {
    this.seq().obj(
        this.key('verifiedBootKey').octstr(),
        this.key('deviceLocked').bool(),
        this.key('verifiedBootState').use(VerifiedBootState),
        this.key('verifiedBootHash').octstr()
    );
});

// Simplified AuthorizationList for Android Key Attestation
// Includes a few common tags. A full implementation would cover many more.
// See https://source.android.com/security/keystore/tags
const AuthorizationList = asn1.define('AuthorizationList', function () {
    this.seq().obj(
        this.key('purpose').optional().explicit(1).setof(this.int()),          // KM_TAG_PURPOSE
        this.key('algorithm').optional().explicit(2).int(),                // KM_TAG_ALGORITHM
        this.key('keySize').optional().explicit(3).int(),                  // KM_TAG_KEY_SIZE
        this.key('digest').optional().explicit(5).setof(this.int()),           // KM_TAG_DIGEST
        this.key('padding').optional().explicit(6).setof(this.int()),          // KM_TAG_PADDING
        this.key('ecCurve').optional().explicit(10).int(),                 // KM_TAG_EC_CURVE
        this.key('rsaPublicExponent').optional().explicit(200).int(),       // KM_TAG_RSA_PUBLIC_EXPONENT
        this.key('rollbackResistance').optional().explicit(703).null_(),    // KM_TAG_ROLLBACK_RESISTANCE (KM_BOOL type)
        this.key('activeDateTime').optional().explicit(400).int(),           // KM_TAG_ACTIVE_DATETIME (KM_DATE type)
        this.key('originationExpireDateTime').optional().explicit(401).int(),// KM_TAG_ORIGINATION_EXPIRE_DATETIME
        this.key('usageExpireDateTime').optional().explicit(402).int(),    // KM_TAG_USAGE_EXPIRE_DATETIME
        this.key('noAuthRequired').optional().explicit(503).null_(),        // KM_TAG_NO_AUTH_REQUIRED (KM_BOOL type)
        this.key('userAuthType').optional().explicit(504).int(),             // KM_TAG_USER_AUTH_TYPE
        this.key('authTimeout').optional().explicit(505).int(),              // KM_TAG_AUTH_TIMEOUT
        this.key('allowWhileOnBody').optional().explicit(506).null_(),      // KM_TAG_ALLOW_WHILE_ON_BODY (KM_BOOL type)
        this.key('trustedUserPresenceRequired').optional().explicit(507).null_(), // KM_TAG_TRUSTED_USER_PRESENCE_REQUIRED
        this.key('trustedConfirmationRequired').optional().explicit(508).null_(), // KM_TAG_TRUSTED_CONFIRMATION_REQUIRED
        this.key('unlockedDeviceRequired').optional().explicit(509).null_(),  // KM_TAG_UNLOCKED_DEVICE_REQUIRED
        this.key('allApplications').optional().explicit(600).null_(),      // KM_TAG_ALL_APPLICATIONS (KM_BOOL type)
        this.key('applicationId').optional().explicit(601).octstr(),       // KM_TAG_APPLICATION_ID
        this.key('creationDateTime').optional().explicit(701).int(),       // KM_TAG_CREATION_DATE_TIME
        this.key('origin').optional().explicit(702).int(),                 // KM_TAG_ORIGIN (0:generated, 1:derived, 2:imported, 3:unknown)
        this.key('rootOfTrust').optional().explicit(704).use(RootOfTrust), // KM_TAG_ROOT_OF_TRUST
        this.key('osVersion').optional().explicit(705).int(),              // KM_TAG_OS_VERSION
        this.key('osPatchLevel').optional().explicit(706).int(),           // KM_TAG_OS_PATCH_LEVEL
        this.key('vendorPatchLevel').optional().explicit(718).int(),         // KM_TAG_VENDOR_PATCH_LEVEL
        this.key('bootPatchLevel').optional().explicit(719).int()          // KM_TAG_BOOT_PATCH_LEVEL
        // Many other tags exist, add as needed for policy decisions.
    );
});

const KeyDescription = asn1.define('KeyDescription', function () {
    this.seq().obj(
        this.key('attestationVersion').int(),
        this.key('attestationSecurityLevel').use(SecurityLevel),
        this.key('keymasterVersion').int(),
        this.key('keymasterSecurityLevel').use(SecurityLevel),
        this.key('attestationChallenge').octstr(),
        this.key('uniqueId').optional().octstr(),
        this.key('softwareEnforced').use(AuthorizationList),
        this.key('teeEnforced').use(AuthorizationList)
    );
});

// Helper to decode the KeyDescription extension from a certificate
function parseAndroidKeyDescription(leafCertificate) {
    const KeyDescriptionOID = '1.3.6.1.4.1.11129.2.1.17';

    if (typeof leafCertificate.getRawExtensions !== 'function') {
        throw new Error("Cannot parse Android KeyDescription: crypto.X509Certificate.getRawExtensions() is not available. Please update Node.js (v16.17.0+ or v18.7.0+ recommended).");
    }

    const extensions = leafCertificate.getRawExtensions();
    const kdExtensionEntry = extensions.find(ext => ext.oid === KeyDescriptionOID);

    if (!kdExtensionEntry) {
        throw new Error(`Android Key Attestation extension (OID ${KeyDescriptionOID}) not found in certificate.`);
    }

    // kdExtensionEntry.value is a Buffer containing the DER encoding of the OCTET STRING for extnValue.
    // We need to decode this OCTET STRING to get its content, which is the DER-encoded KeyDescription SEQUENCE.
    const OctetStringDecoder = asn1.define('OctetStringDecoder', function () { this.octstr(); });
    const keyDescriptionDERBytes = OctetStringDecoder.decode(kdExtensionEntry.value, 'der');

    if (!keyDescriptionDERBytes || keyDescriptionDERBytes.length === 0) {
        throw new Error('Failed to extract KeyDescription DER bytes from OCTET STRING wrapper.');
    }

    return KeyDescription.decode(keyDescriptionDERBytes, 'der');
}

module.exports = { decodeDerEncodedSignature, parseAndroidKeyDescription };
