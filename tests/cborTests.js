const assert = require('assert');
const cbor = require('../cbor');
const { runTest, getTestSummary } = require('./utils');

function bufferLikeEqual(buf1, buf2) {
    if (!buf1 || !buf2 || buf1.byteLength !== buf2.byteLength) {
        return false;
    }
    const view1 = new Uint8Array(buf1);
    const view2 = new Uint8Array(buf2);
    for (let i = 0; i < view1.length; i++) {
        if (view1[i] !== view2[i]) {
            return false;
        }
    }
    return true;
}

runTest('CBOR: Encode/Decode Integer', () => {
    const value = 12345;
    const encoded = cbor.encode(value);
    const decoded = cbor.decode(encoded);
    assert.strictEqual(decoded, value, 'Decoded integer mismatch');
});

runTest('CBOR: Encode/Decode Negative Integer', () => {
    const value = -12345;
    const encoded = cbor.encode(value);
    const decoded = cbor.decode(encoded);
    assert.strictEqual(decoded, value, 'Decoded negative integer mismatch');
});

runTest('CBOR: Encode/Decode Float', () => {
    const value = 123.45;
    const encoded = cbor.encode(value);
    const decoded = cbor.decode(encoded);
    // Floating point comparisons can be tricky, use tolerance if needed
    assert.strictEqual(decoded, value, 'Decoded float mismatch');
});

runTest('CBOR: Encode/Decode String', () => {
    const value = "hello world";
    const encoded = cbor.encode(value);
    const decoded = cbor.decode(encoded);
    assert.strictEqual(decoded, value, 'Decoded string mismatch');
});

runTest('CBOR: Encode/Decode Boolean True', () => {
    const value = true;
    const encoded = cbor.encode(value);
    const decoded = cbor.decode(encoded);
    assert.strictEqual(decoded, value, 'Decoded boolean true mismatch');
});

runTest('CBOR: Encode/Decode Boolean False', () => {
    const value = false;
    const encoded = cbor.encode(value);
    const decoded = cbor.decode(encoded);
    assert.strictEqual(decoded, value, 'Decoded boolean false mismatch');
});

runTest('CBOR: Encode/Decode Null', () => {
    const value = null;
    const encoded = cbor.encode(value);
    const decoded = cbor.decode(encoded);
    assert.strictEqual(decoded, value, 'Decoded null mismatch');
});

runTest('CBOR: Encode/Decode Undefined', () => {
    const value = undefined;
    const encoded = cbor.encode(value);
    const decoded = cbor.decode(encoded);
    assert.strictEqual(decoded, value, 'Decoded undefined mismatch');
});

runTest('CBOR: Encode/Decode Simple Array', () => {
    const value = [1, "two", false, null];
    const encoded = cbor.encode(value);
    const decoded = cbor.decode(encoded);
    assert.deepStrictEqual(decoded, value, 'Decoded simple array mismatch');
});

runTest('CBOR: Encode/Decode Simple Object (Map)', () => {
    const value = { a: 1, b: "two", c: true };
    const encoded = cbor.encode(value);
    const decoded = cbor.decode(encoded);
    assert.deepStrictEqual(decoded, value, 'Decoded simple object mismatch');
});

runTest('CBOR: Encode/Decode Uint8Array (Byte String)', () => {
    const value = new Uint8Array([1, 2, 3, 4, 255]);
    const encoded = cbor.encode(value);
    const decoded = cbor.decode(encoded);
    assert.ok(decoded instanceof Uint8Array, 'Decoded value is not Uint8Array');
    assert.ok(bufferLikeEqual(decoded, value), 'Decoded Uint8Array mismatch');
});

runTest('CBOR: Encode/Decode Nested Structure', () => {
    const value = {
        id: 10,
        items: [{ name: "item1", value: 100 }, { name: "item2", value: null }],
        active: true
    };
    const encoded = cbor.encode(value);
    const decoded = cbor.decode(encoded);
    assert.deepStrictEqual(decoded, value, 'Decoded nested structure mismatch');
});

getTestSummary();
