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
            UInt32.from(0x61707865), UInt32.from(0x3320646e), UInt32.from(0x79622d32), UInt32.from(0x6b206574n), // ChaCha constants
            UInt32.from(0x03020100), UInt32.from(0x07060504), UInt32.from(0x0b0a0908), UInt32.from(0x0f0e0d0cn), // Key
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
            UInt32.from(0xe4e7f110), UInt32.from(0x15593bd1), UInt32.from(0x1fdd0f50), UInt32.from(0xc47120a3),
            UInt32.from(0xc7f4d1c7), UInt32.from(0x0368c033), UInt32.from(0x9aaa2204), UInt32.from(0x4e6cd4c3),
            UInt32.from(0x466482d2), UInt32.from(0x09aa9f07), UInt32.from(0x05d7c214), UInt32.from(0xa2028bd9),
            UInt32.from(0xd19c12b5), UInt32.from(0xb94e16de), UInt32.from(0xe883d0cb), UInt32.from(0x4e3c50a2)
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

        const plaintext: UInt32[] = [
            UInt32.from(0x4c616469), UInt32.from(0x65732061), UInt32.from(0x6e642047), UInt32.from(0x656e746c),
            UInt32.from(0x656d656e), UInt32.from(0x206f6620), UInt32.from(0x74686520), UInt32.from(0x636c6173),
            UInt32.from(0x73206f66), UInt32.from(0x20273939), UInt32.from(0x3a204966), UInt32.from(0x20492063),
            UInt32.from(0x6f756c64), UInt32.from(0x206f6666), UInt32.from(0x65722079), UInt32.from(0x6f75206f),
            UInt32.from(0x6e6c7920), UInt32.from(0x6f6e6520), UInt32.from(0x74697020), UInt32.from(0x666f7220),
            UInt32.from(0x74686520), UInt32.from(0x66757475), UInt32.from(0x72652c20), UInt32.from(0x73756e73),
            UInt32.from(0x63726565), UInt32.from(0x6e20776f), UInt32.from(0x756c6420), UInt32.from(0x62652069),
            UInt32.from(0x742e0000)
        ];
        let chachaStateEncrypted = chacha20(keyArray, nonceArray, counter, plaintext);
        for (let i = 0; i < chachaStateEncrypted.length; i++) {
            console.log(toHexString(UInt32.from(chachaStateEncrypted[i])))
        }
        let chachaStateDecrypted = chacha20(keyArray, nonceArray, counter, chachaStateEncrypted);
        for (let i = 0; i < chachaStateDecrypted.length; i++) {
            expect(toHexString(UInt32.from(chachaStateDecrypted[i]))).toBe(toHexString(UInt32.from(plaintext[i])))
        }

    })
});