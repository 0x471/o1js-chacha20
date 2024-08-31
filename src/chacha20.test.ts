import { jest } from '@jest/globals';
import { UInt32 } from 'o1js';
import { chacha20, chacha20Block, ChaChaState } from './chacha20';

jest.useFakeTimers();

function toHexString(value: UInt32): string {
    const numberValue = value.toBigint();
    return numberValue.toString(16).padStart(8, '0');
}

function octetsToUint32Array(octetString: string) {
    const octets = octetString.split(':');

    if (octets.length !== 32 && octets.length !== 12 && octets.length !== 4) {
        throw new Error("Invalid octet string length.");
    }

    let words = [];

    // Convert octets to little-endian 32-bit words
    for (let i = 0; i < octets.length; i += 4) {
        if (i + 3 < octets.length) {
            // Combine 4 octets into a 32-bit word in little-endian order
            const word = (parseInt(octets[i], 16) |
                (parseInt(octets[i + 1], 16) << 8) |
                (parseInt(octets[i + 2], 16) << 16) |
                (parseInt(octets[i + 3], 16) << 24));
            words.push(word);
        }
    }

    return new Uint32Array(words);
}

describe('ChaCha', () => {
    it('should calculate quarter round correctly', async () => {
        const key = new Uint32Array(8).fill(0); // Mock key
        const nonce = new Uint32Array(3).fill(0); // Mock nonce
        const counter = 0; // Mock counter

        const chacha = new ChaChaState(key, nonce, counter);

        chacha.state[0] = UInt32.from(0x11111111);
        chacha.state[1] = UInt32.from(0x01020304);
        chacha.state[2] = UInt32.from(0x9b8d6f43);
        chacha.state[3] = UInt32.from(0x01234567);

        ChaChaState.quarterRound(chacha.state, 0, 1, 2, 3);

        const expectedState = [
            UInt32.from(0xea2a92f4), // expected a
            UInt32.from(0xcb1cf8ce), // expected b
            UInt32.from(0x4581472e), // expected c
            UInt32.from(0x5881c4bb), // expected d
        ];

        expect(toHexString(chacha.state[0])).toBe(toHexString(expectedState[0]));
        expect(toHexString(chacha.state[1])).toBe(toHexString(expectedState[1]));
        expect(toHexString(chacha.state[2])).toBe(toHexString(expectedState[2]));
        expect(toHexString(chacha.state[3])).toBe(toHexString(expectedState[3]));
    });
    it('should add two ChaChaState instances correctly', async () => {
        const state1 = new ChaChaState(new Uint32Array(8).fill(0), new Uint32Array(3).fill(0), 0);
        const state2 = new ChaChaState(new Uint32Array(8).fill(0), new Uint32Array(3).fill(0), 0);


        state1.state[0] = UInt32.from(0x11111111);
        state1.state[1] = UInt32.from(0x01020304);
        state1.state[2] = UInt32.from(0x9b8d6f43);
        state1.state[3] = UInt32.from(0x01234567);

        state2.state[0] = UInt32.from(0x00000001);
        state2.state[1] = UInt32.from(0x00000002);
        state2.state[2] = UInt32.from(0x00000003);
        state2.state[3] = UInt32.from(0x00000004);

        state1.add(state2);

        // Expected values after carryless addition (modulo 2^32)
        const expectedState = [
            UInt32.from((0x11111111n + 0x00000001n) & 0xFFFFFFFFn),
            UInt32.from((0x01020304n + 0x00000002n) & 0xFFFFFFFFn),
            UInt32.from((0x9b8d6f43n + 0x00000003n) & 0xFFFFFFFFn),
            UInt32.from((0x01234567n + 0x00000004n) & 0xFFFFFFFFn),
        ];

        expect(toHexString(state1.state[0])).toBe(toHexString(expectedState[0]));
        expect(toHexString(state1.state[1])).toBe(toHexString(expectedState[1]));
        expect(toHexString(state1.state[2])).toBe(toHexString(expectedState[2]));
        expect(toHexString(state1.state[3])).toBe(toHexString(expectedState[3]));
    });
    it('should initialize state correctly based on key, nonce, and counter', () => {
        let key = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f";
        let nonce = "00:00:00:09:00:00:00:4a:00:00:00:00";
        const counter = 1;

        const keyArray = octetsToUint32Array(key);
        const nonceArray = octetsToUint32Array(nonce);
        const chachaState = new ChaChaState(keyArray, nonceArray, counter);

        const expectedState: UInt32[] = [
            UInt32.from(0x61707865), UInt32.from(0x3320646e), UInt32.from(0x79622d32), UInt32.from(0x6b206574), // ChaCha constants
            UInt32.from(0x03020100), UInt32.from(0x07060504), UInt32.from(0x0b0a0908), UInt32.from(0x0f0e0d0c), // Key
            UInt32.from(0x13121110), UInt32.from(0x17161514), UInt32.from(0x1b1a1918), UInt32.from(0x1f1e1d1c), // Key
            UInt32.from(0x00000001),  // Block count
            UInt32.from(0x09000000), UInt32.from(0x4a000000), UInt32.from(0x00000000)  // Nonce
        ];



        for (let i = 0; i < chachaState.state.length; i++) {
            const receivedHex = toHexString(chachaState.state[i]);
            const expectedHex = toHexString(expectedState[i]);
            expect(receivedHex).toBe(expectedHex);
        }

    });
    it("should calculate the block function correctly", () => {
        let key = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f";
        let nonce = "00:00:00:09:00:00:00:4a:00:00:00:00";
        const counter = 1;

        const keyArray = octetsToUint32Array(key);
        const nonceArray = octetsToUint32Array(nonce);

        const expectedState: UInt32[] = [
            UInt32.from(0x10f1e7e4), UInt32.from(0xd13b5915), UInt32.from(0x500fdd1f), UInt32.from(0xa32071c4),
            UInt32.from(0xc7d1f4c7), UInt32.from(0x33c06803), UInt32.from(0x0422aa9a), UInt32.from(0xc3d46c4e),
            UInt32.from(0xd2826446), UInt32.from(0x079faa09), UInt32.from(0x14c2d705), UInt32.from(0xd98b02a2),
            UInt32.from(0xb5129cd1), UInt32.from(0xde164eb9), UInt32.from(0xcbd083e8), UInt32.from(0xa2503c4e)
        ];


        let chachaState = chacha20Block(keyArray, nonceArray, counter);
        for (let i = 0; i < chachaState.length; i++) {
            const receivedHex = toHexString(chachaState[i]);
            const expectedHex = toHexString(expectedState[i]);
            expect(receivedHex).toBe(expectedHex);
        }
    })
    it("should encrypt and decrypt correctly", () => {
        let key = "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f";
        let nonce = "00:00:00:00:00:00:00:4a:00:00:00:00";
        const counter = 1;

        const keyArray = octetsToUint32Array(key);
        const nonceArray = octetsToUint32Array(nonce);

        const plaintext = new Uint32Array([
            0x4c616469, 0x65732061, 0x6e642047, 0x656e746c,
            0x656d656e, 0x206f6620, 0x74686520, 0x636c6173,
            0x73206f66, 0x20273939, 0x3a204966, 0x20492063,
            0x6f756c64, 0x206f6666, 0x65722079, 0x6f75206f,
            0x6e6c7920, 0x6f6e6520, 0x74697020, 0x666f7220,
            0x74686520, 0x66757475, 0x72652c20, 0x73756e73,
            0x63726565, 0x6e20776f, 0x756c6420, 0x62652069,
            0x742e0000
        ]);

        let expectedCiphertext = new Uint32Array([
            0x6e2e359a, 0x2568f980, 0x41ba0728, 0xdd0d6981,
            0xe97e7aec, 0x1d4360c2, 0x0a27afcc, 0xfd9fae0b,
            0xf91b65c5, 0x524733ab, 0x8f593dab, 0xcd62b357,
            0x1639d624, 0xe65152ab, 0x8f530c35, 0x9f0861d8,
            0x07ca0dbf, 0x500d6a61, 0x56a38e08, 0x8a22b65e,
            0x52bc514d, 0x16ccf806, 0x818ce91a, 0xb7793736,
            0x5af90bbf, 0x74a35be6, 0xb40b8eed, 0xf2785e42,
            0x874d7403
        ]);

        let chachaStateEncrypted = chacha20(keyArray, nonceArray, counter, plaintext);
        for (let i = 0; i < chachaStateEncrypted.length; i++) {
            expect(toHexString(UInt32.from(chachaStateEncrypted[i]))).toBe(toHexString(UInt32.from(expectedCiphertext[i])));
        }

        let chachaStateDecrypted = chacha20(keyArray, nonceArray, counter, chachaStateEncrypted);
        for (let i = 0; i < chachaStateDecrypted.length; i++) {
            expect(toHexString(UInt32.from(chachaStateDecrypted[i]))).toBe(toHexString(UInt32.from(plaintext[i])));
        }
    });

});