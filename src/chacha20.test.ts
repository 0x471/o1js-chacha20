import { jest } from '@jest/globals';
import { UInt32, assert } from 'o1js';
import { ChaChaState } from './chacha20';

jest.useFakeTimers();

const toHex = (u: UInt32) => u.toBigint().toString(16).padStart(8, '0');

describe('ChaCha', () => {
    it('should calculate quarter round correctly', async () => {
        let a = UInt32.fromValue(0x11111111n);
        let b = UInt32.fromValue(0x01020304n);
        let c = UInt32.fromValue(0x9b8d6f43n);
        let d = UInt32.fromValue(0x01234567n);

        let [result_a, result_b, result_c, result_d] = ChaChaState.quarterRound(a, b, c, d);

        let expected_a = UInt32.fromValue(0xea2a92f4n);
        let expected_b = UInt32.fromValue(0xcb1cf8cen);
        let expected_c = UInt32.fromValue(0x4581472en);
        let expected_d = UInt32.fromValue(0x5881c4bbn);

        console.log('Result A:', toHex(result_a));
        console.log('Expected A:', toHex(expected_a));
        console.log('Result B:', toHex(result_b));
        console.log('Expected B:', toHex(expected_b));
        console.log('Result C:', toHex(result_c));
        console.log('Expected C:', toHex(expected_c));
        console.log('Result D:', toHex(result_d));
        console.log('Expected D:', toHex(expected_d));

        expect(toHex(result_a)).toBe(toHex(expected_a));
        expect(toHex(result_b)).toBe(toHex(expected_b));
        expect(toHex(result_c)).toBe(toHex(expected_c));
        expect(toHex(result_d)).toBe(toHex(expected_d));
    });
});
