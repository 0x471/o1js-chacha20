import { jest } from '@jest/globals';
import { UInt32 } from 'o1js';
import { ChaChaState } from './chacha20';

jest.useFakeTimers();

const toHex = (u: UInt32) => u.toBigint().toString(16).padStart(8, '0');
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

        // Expected values after the quarter round
        const expectedState = [
            UInt32.fromValue(0xea2a92f4n), // expected a
            UInt32.fromValue(0xcb1cf8cen), // expected b
            UInt32.fromValue(0x4581472en), // expected c
            UInt32.fromValue(0x5881c4bbn), // expected d
        ];

        expect(toHex(chacha.state[0])).toBe(toHex(expectedState[0]));
        expect(toHex(chacha.state[1])).toBe(toHex(expectedState[1]));
        expect(toHex(chacha.state[2])).toBe(toHex(expectedState[2]));
        expect(toHex(chacha.state[3])).toBe(toHex(expectedState[3]));
    });
    it('should initialize state correctly based on key, nonce, and counter', () => {
        // Define the key, nonce, and counter
        const key = new Uint32Array([
            0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
            0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f
        ]);
        const nonce = new Uint32Array([0x09000000, 0x4a000000, 0x00000000]);
        const counter = 1;  // 32-bit value

        const chachaState = new ChaChaState(key, nonce, counter);

        const expectedValues: number[] = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, // ChaCha constants
            0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f, // Key
            0x10111213, 0x14151617, 0x18191a1b, 0x1c1d1e1f, // Key
            0x00000001,                                    // Block count
            0x09000000, 0x4a000000, 0x00000000            // Nonce
        ];

        const expectedState = expectedValues.map(value => UInt32.fromValue(BigInt(value)));
        const toHexString = (value: UInt32) => {
            return value.toString().padStart(8, '0');
        };

        for (let i = 0; i < chachaState.state.length; i++) {
            const receivedHex = toHexString(chachaState.state[i]);
            const expectedHex = toHexString(expectedState[i]);
            expect(receivedHex).toBe(expectedHex);
        }
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
    
        // Expected values after addition (modulo 2^32)
        const expectedState = [
            UInt32.fromValue((0x11111111n + 0x00000001n) & 0xFFFFFFFFn),
            UInt32.fromValue((0x01020304n + 0x00000002n) & 0xFFFFFFFFn),
            UInt32.fromValue((0x9b8d6f43n + 0x00000003n) & 0xFFFFFFFFn), 
            UInt32.fromValue((0x01234567n + 0x00000004n) & 0xFFFFFFFFn),
        ];
    
        expect(toHex(state1.state[0])).toBe(toHex(expectedState[0]));
        expect(toHex(state1.state[1])).toBe(toHex(expectedState[1]));
        expect(toHex(state1.state[2])).toBe(toHex(expectedState[2]));
        expect(toHex(state1.state[3])).toBe(toHex(expectedState[3]));
    });
    // TODO: add tests for block generation and tole4bytes
});