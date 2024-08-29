import { jest } from '@jest/globals';
import { UInt32 } from 'o1js';
import { chacha20Block, ChaChaState } from './chacha20';

jest.useFakeTimers();

export {toHexString}
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

        chacha.state[0] = UInt32.fromValue(0x11111111n);
        chacha.state[1] = UInt32.fromValue(0x01020304n);
        chacha.state[2] = UInt32.fromValue(0x9b8d6f43n);
        chacha.state[3] = UInt32.fromValue(0x01234567n);

        ChaChaState.quarterRound(chacha.state, 0, 1, 2, 3);

        const expectedState = [
            UInt32.fromValue(0xea2a92f4n), // expected a
            UInt32.fromValue(0xcb1cf8cen), // expected b
            UInt32.fromValue(0x4581472en), // expected c
            UInt32.fromValue(0x5881c4bbn), // expected d
        ];

        expect(toHexString(chacha.state[0])).toBe(toHexString(expectedState[0]));
        expect(toHexString(chacha.state[1])).toBe(toHexString(expectedState[1]));
        expect(toHexString(chacha.state[2])).toBe(toHexString(expectedState[2]));
        expect(toHexString(chacha.state[3])).toBe(toHexString(expectedState[3]));
    });
    it('should add two ChaChaState instances correctly', async () => {
        const state1 = new ChaChaState(new Uint32Array(8).fill(0), new Uint32Array(3).fill(0), 0);
        const state2 = new ChaChaState(new Uint32Array(8).fill(0), new Uint32Array(3).fill(0), 0);


        state1.state[0] = UInt32.fromValue(0x11111111n);
        state1.state[1] = UInt32.fromValue(0x01020304n);
        state1.state[2] = UInt32.fromValue(0x9b8d6f43n);
        state1.state[3] = UInt32.fromValue(0x01234567n);

        state2.state[0] = UInt32.fromValue(0x00000001n);
        state2.state[1] = UInt32.fromValue(0x00000002n);
        state2.state[2] = UInt32.fromValue(0x00000003n);
        state2.state[3] = UInt32.fromValue(0x00000004n);

        state1.add(state2);

        // Expected values after carryless addition (modulo 2^32)
        const expectedState = [
            UInt32.fromValue((0x11111111n + 0x00000001n) & 0xFFFFFFFFn),
            UInt32.fromValue((0x01020304n + 0x00000002n) & 0xFFFFFFFFn),
            UInt32.fromValue((0x9b8d6f43n + 0x00000003n) & 0xFFFFFFFFn),
            UInt32.fromValue((0x01234567n + 0x00000004n) & 0xFFFFFFFFn),
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
            UInt32.fromValue(0x61707865n), UInt32.fromValue(0x3320646en), UInt32.fromValue(0x79622d32n), UInt32.fromValue(0x6b206574n), // ChaCha constants
            UInt32.fromValue(0x03020100n), UInt32.fromValue(0x07060504n), UInt32.fromValue(0x0b0a0908n), UInt32.fromValue(0x0f0e0d0cn), // Key
            UInt32.fromValue(0x13121110n), UInt32.fromValue(0x17161514n), UInt32.fromValue(0x1b1a1918n), UInt32.fromValue(0x1f1e1d1cn), // Key
            UInt32.fromValue(0x00000001n),  // Block count
            UInt32.fromValue(0x09000000n), UInt32.fromValue(0x4a000000n), UInt32.fromValue(0x00000000n) // Nonce
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
            UInt32.fromValue(0xe4e7f110n), UInt32.fromValue(0x15593bd1n), UInt32.fromValue(0x1fdd0f50n), UInt32.fromValue(0xc47120a3n),
            UInt32.fromValue(0xc7f4d1c7n), UInt32.fromValue(0x0368c033n), UInt32.fromValue(0x9aaa2204n), UInt32.fromValue(0x4e6cd4c3n),
            UInt32.fromValue(0x466482d2n), UInt32.fromValue(0x09aa9f07n), UInt32.fromValue(0x05d7c214n), UInt32.fromValue(0xa2028bd9n),
            UInt32.fromValue(0xd19c12b5n), UInt32.fromValue(0xb94e16den), UInt32.fromValue(0xe883d0cbn), UInt32.fromValue(0x4e3c50a2n)
        ];
        
        let chachaState = chacha20Block(keyArray, nonceArray, counter);
        for (let i = 0; i < chachaState.length; i++) {
            const receivedHex = toHexString(chachaState[i]);
            const expectedHex = toHexString(expectedState[i]);
            expect(receivedHex).toBe(expectedHex);
        }
    })
});