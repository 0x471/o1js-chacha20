import { jest } from '@jest/globals';
import { UInt32 } from 'o1js';
import { ChaChaState } from './chacha20';

jest.useFakeTimers();

const toHex = (u: UInt32) => u.toBigint().toString(16).padStart(8, '0');

describe('ChaCha', () => {
    it('should calculate quarter round correctly', async () => {
        // Initialize ChaChaState with arbitrary values
        const key = new Uint32Array(8).fill(0); // Mock key
        const nonce = new Uint32Array(3).fill(0); // Mock nonce
        const counter = 0; // Mock counter

        const chacha = new ChaChaState(key, nonce, counter);

        // Set specific values to simulate the state before the quarter round
        chacha.state[0] = UInt32.fromValue(0x11111111n);
        chacha.state[1] = UInt32.fromValue(0x01020304n);
        chacha.state[2] = UInt32.fromValue(0x9b8d6f43n);
        chacha.state[3] = UInt32.fromValue(0x01234567n);

        // Perform the quarter round directly on the state
        ChaChaState.quarterRound(chacha.state, 0, 1, 2, 3);

        // Expected values after the quarter round
        const expectedState = [
            UInt32.fromValue(0xea2a92f4n), // expected a
            UInt32.fromValue(0xcb1cf8cen), // expected b
            UInt32.fromValue(0x4581472en), // expected c
            UInt32.fromValue(0x5881c4bbn), // expected d
        ];

        console.log('Result A:', toHex(chacha.state[0]));
        console.log('Expected A:', toHex(expectedState[0]));
        console.log('Result B:', toHex(chacha.state[1]));
        console.log('Expected B:', toHex(expectedState[1]));
        console.log('Result C:', toHex(chacha.state[2]));
        console.log('Expected C:', toHex(expectedState[2]));
        console.log('Result D:', toHex(chacha.state[3]));
        console.log('Expected D:', toHex(expectedState[3]));

        expect(toHex(chacha.state[0])).toBe(toHex(expectedState[0]));
        expect(toHex(chacha.state[1])).toBe(toHex(expectedState[1]));
        expect(toHex(chacha.state[2])).toBe(toHex(expectedState[2]));
        expect(toHex(chacha.state[3])).toBe(toHex(expectedState[3]));
    });
});
