import { jest } from '@jest/globals';
import { UInt32 } from 'o1js';
import { chacha20, chacha20Block, ChaChaState } from './chacha20';

jest.useFakeTimers();

function toHex(value: UInt32): string {
    const numberValue = value.toBigint();
    return numberValue.toString(16).padStart(8, '0');
}

describe('ChaCha', () => {
    it('should calculate quarter round correctly', async () => {
        const key: UInt32[] = Array(8).fill(new UInt32(0));
        const nonce: UInt32[] = Array(3).fill(new UInt32(0));
        const counter = 0;

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

        expect(toHex(chacha.state[0])).toBe(toHex(expectedState[0]));
        expect(toHex(chacha.state[1])).toBe(toHex(expectedState[1]));
        expect(toHex(chacha.state[2])).toBe(toHex(expectedState[2]));
        expect(toHex(chacha.state[3])).toBe(toHex(expectedState[3]));
    });

    it('should add two ChaChaState instances correctly', async () => {
        const zeroKey: UInt32[] = Array(8).fill(new UInt32(0));
        const zeroNonce: UInt32[] = Array(3).fill(new UInt32(0));

        const state1 = new ChaChaState(zeroKey, zeroNonce, 0);
        const state2 = new ChaChaState(zeroKey, zeroNonce, 0);

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

        expect(toHex(state1.state[0])).toBe(toHex(expectedState[0]));
        expect(toHex(state1.state[1])).toBe(toHex(expectedState[1]));
        expect(toHex(state1.state[2])).toBe(toHex(expectedState[2]));
        expect(toHex(state1.state[3])).toBe(toHex(expectedState[3]));
    });

    it('should initialize state correctly based on key, nonce, and counter', () => {
        const key: UInt32[] = [
            UInt32.from(0x03020100),
            UInt32.from(0x07060504),
            UInt32.from(0x0B0A0908),
            UInt32.from(0x0F0E0D0C),
            UInt32.from(0x13121110),
            UInt32.from(0x17161514),
            UInt32.from(0x1B1A1918),
            UInt32.from(0x1F1E1D1C),
        ];
        
        const nonce: UInt32[] = [
            UInt32.from(0x09000000),
            UInt32.from(0x4a000000),   
            UInt32.from(0x00000000)
        ];

        const counter = 1;
        const chachaState = new ChaChaState(key, nonce, counter);

        const expectedState: UInt32[] = [
            UInt32.from(0x61707865), UInt32.from(0x3320646e), UInt32.from(0x79622d32), UInt32.from(0x6b206574), // ChaCha constants
            UInt32.from(0x03020100), UInt32.from(0x07060504), UInt32.from(0x0b0a0908), UInt32.from(0x0f0e0d0c), // Key
            UInt32.from(0x13121110), UInt32.from(0x17161514), UInt32.from(0x1b1a1918), UInt32.from(0x1f1e1d1c), // Key
            UInt32.from(0x00000001),  // Block count
            UInt32.from(0x09000000), UInt32.from(0x4a000000), UInt32.from(0x00000000)  // Nonce
        ];

        for (let i = 0; i < chachaState.state.length; i++) {
            const receivedHex = toHex(chachaState.state[i]);
            const expectedHex = toHex(expectedState[i]);
            expect(receivedHex).toBe(expectedHex);
        }
    });

    it('should calculate the block function correctly', () => {
        const key: UInt32[] = [
            UInt32.from(0x03020100),
            UInt32.from(0x07060504),
            UInt32.from(0x0B0A0908),
            UInt32.from(0x0F0E0D0C),
            UInt32.from(0x13121110),
            UInt32.from(0x17161514),
            UInt32.from(0x1B1A1918),
            UInt32.from(0x1F1E1D1C),
        ];
        
        const nonce: UInt32[] = [
            UInt32.from(0x09000000),
            UInt32.from(0x4a000000),   
            UInt32.from(0x00000000)
        ];

        const counter = 1;

        const expectedState: UInt32[] = [
            UInt32.from(0x10f1e7e4), UInt32.from(0xd13b5915), UInt32.from(0x500fdd1f), UInt32.from(0xa32071c4),
            UInt32.from(0xc7d1f4c7), UInt32.from(0x33c06803), UInt32.from(0x0422aa9a), UInt32.from(0xc3d46c4e),
            UInt32.from(0xd2826446), UInt32.from(0x079faa09), UInt32.from(0x14c2d705), UInt32.from(0xd98b02a2),
            UInt32.from(0xb5129cd1), UInt32.from(0xde164eb9), UInt32.from(0xcbd083e8), UInt32.from(0xa2503c4e)
        ];

        let chachaState = chacha20Block(key, nonce, counter);
        for (let i = 0; i < chachaState.length; i++) {
            const receivedHex = toHex(chachaState[i]);
            const expectedHex = toHex(expectedState[i]);
            expect(receivedHex).toBe(expectedHex);
        }
    });
    it("should encrypt and decrypt correctly", () => {
        const key: UInt32[] = [
            UInt32.from(0x03020100),
            UInt32.from(0x07060504),
            UInt32.from(0x0B0A0908),
            UInt32.from(0x0F0E0D0C),
            UInt32.from(0x13121110),
            UInt32.from(0x17161514),
            UInt32.from(0x1B1A1918),
            UInt32.from(0x1F1E1D1C),
        ];
        
        const nonce: UInt32[] = [
            UInt32.from(0x00000000),
            UInt32.from(0x4a000000),   
            UInt32.from(0x00000000)
        ];

        const counter = 1;

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

        let chachaStateEncrypted = chacha20(key, nonce, counter, plaintext);
        for (let i = 0; i < chachaStateEncrypted.length; i++) {
            expect(toHex(UInt32.from(chachaStateEncrypted[i]))).toBe(toHex(UInt32.from(expectedCiphertext[i])));
        }

        let chachaStateDecrypted = chacha20(key, nonce, counter, chachaStateEncrypted);
        for (let i = 0; i < chachaStateDecrypted.length; i++) {
            expect(toHex(UInt32.from(chachaStateDecrypted[i]))).toBe(toHex(UInt32.from(plaintext[i])));
        }
    });
});
