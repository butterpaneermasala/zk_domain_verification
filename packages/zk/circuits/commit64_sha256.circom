pragma circom 2.1.6;

include "sha256/sha256.circom";
include "bitify.circom";

// Commit 64-byte secret L via SHA-256 and expose digest as two field elements (hi, lo)
// Inputs:
//   - private: in[64] bytes (0..255)
//   - public:  h_hi, h_lo (each 128-bit, big-endian halves of SHA-256 digest)
// The circuit computes sha256(in) and enforces equality to (h_hi||h_lo).

template Commit64() {
    signal input in[64];
    signal input h_hi; // top 128 bits
    signal input h_lo; // low 128 bits

    // Convert 64 bytes to 512 bits (MSB-first per byte) and hash
    component hasher = Sha256(512);
    component n2b[64];
    for (var i = 0; i < 64; i++) {
        n2b[i] = Num2Bits(8);
        n2b[i].in <== in[i];
        // n2b[i].out[0] is LSB; SHA-256 expects MSB-first within byte
        for (var b = 0; b < 8; b++) {
            hasher.in[i*8 + b] <== n2b[i].out[7 - b];
        }
    }

    // hasher.out is 256 bits, out[0] is the most significant bit (MSB)
    // Build two 128-bit big-endian limbs without reassigning the same signal twice
    // hi = sum_{i=0..127} out[i] * 2^{127-i}
    // lo = sum_{i=128..255} out[i] * 2^{255-i}

    signal hi_partials[128];
    for (var i = 0; i < 128; i++) {
        var w = 1 << (127 - i);
        hi_partials[i] <== hasher.out[i] * w;
    }

    signal hi_sum[128];
    hi_sum[0] <== hi_partials[0];
    for (var i = 1; i < 128; i++) {
        hi_sum[i] <== hi_sum[i-1] + hi_partials[i];
    }

    signal digest_hi;
    digest_hi <== hi_sum[127];

    signal lo_partials[128];
    for (var j = 0; j < 128; j++) {
        var w2 = 1 << (127 - j); // same weights for lower half as big-endian within its 128-bit chunk
        lo_partials[j] <== hasher.out[128 + j] * w2;
    }

    signal lo_sum[128];
    lo_sum[0] <== lo_partials[0];
    for (var k = 1; k < 128; k++) {
        lo_sum[k] <== lo_sum[k-1] + lo_partials[k];
    }

    signal digest_lo;
    digest_lo <== lo_sum[127];

    // Enforce equality
    h_hi === digest_hi;
    h_lo === digest_lo;
}

component main = Commit64();
