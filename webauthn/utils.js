function decodeDerEncodedSignature(signatureBuffer, curveByteLength) {
    const asn1 = require('./asn1/asn1.js'); // Use the local asn1.js library

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

    signatureToVerify = Buffer.concat([rBa, sBa]);

    return signatureToVerify;
}

module.exports = { decodeDerEncodedSignature };
