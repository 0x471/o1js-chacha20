import { UInt32, Gadgets, Field } from 'o1js';

export { ChaChaState, chacha20 };

/**
 * Encrypts or decrypts the given plaintext using the ChaCha20 stream cipher.
 * 
 * @param {UInt32[]} key - The key used for encryption (256-bit).
 * @param {UInt32[]} nonce - The nonce used for encryption (96-bit).
 * @param {UInt32} counter - The initial block counter.
 * @param {UInt32[]} plaintext - The plaintext to be encrypted or decrypted.
 * @returns {UInt32[]} - The resulting ciphertext or decrypted text as an array of UInt32.
 */
function chacha20(key: UInt32[], nonce: UInt32[], counter: UInt32, plaintext: UInt32[]): UInt32[] {
    if (key.length !== 8) {
        throw new Error("Invalid key length: expected 256-bit key (8 UInt32 elements).");
    }
    if (nonce.length !== 3) {
        throw new Error("Invalid nonce length: expected 96-bit nonce (3 UInt32 elements).");
    }
    if (plaintext.length === 0) {
        throw new Error("Plaintext cannot be empty.");
    }
    // Initialize the result array with the same length as the plaintext, filled with zeros.
    const res: UInt32[] = Array(plaintext.length).fill(UInt32.from(0));

    /**
     * Processes a block of 16 UInt32 words, encrypting or decrypting it using the ChaCha20 block function.
     * 
     * @param {UInt32} offset - The block offset in the plaintext, representing which block of 16 words to process.
     * @param {UInt32} length - The number of words to process in this block (typically 16, but could be less for the last block).
     */
    function processBlock(offset: UInt32, length: UInt32) {
        // Generate the keystream block using the ChaCha20 block function.
        const keyStream = ChaChaState.chacha20Block(key, nonce, counter.add(offset));

        // Precompute the base index for this block in the plaintext array.
        const baseIndex = Number(offset.toBigint() * 16n);

        // Process each word in the block.
        for (let t = 0; t < length.toBigint(); t++) {
            const index = baseIndex + Number(t);  // Calculate the index in the plaintext array.
            if (index >= plaintext.length) {
                throw new Error("Index out of bounds during block processing.");
            }
            // XOR the plaintext with the keystream to produce the ciphertext.
            res[index] = plaintext[index].xor(keyStream[Number(t)]);
        }
    }

    // Determine the number of full 16-word blocks in the plaintext.
    const numFullBlocks = Math.floor(plaintext.length / 16);

    // Process each full block of 16 words.
    for (let j = 0; j < numFullBlocks; j++) {
        processBlock(UInt32.from(j), UInt32.from(16));
    }

    // Process any remaining words in the plaintext that do not fill a full block.
    const remaining = plaintext.length % 16;
    if (remaining > 0) {
        processBlock(UInt32.from(numFullBlocks), UInt32.from(remaining));
    }

    return res;
}

class ChaChaState {
    state: UInt32[];

    /**
     * Initializes the ChaCha20 state with the given key, nonce, and counter.
     * 
     * The state is arranged as:
     *  cccccccc  cccccccc  cccccccc  cccccccc
     *  kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
     *  kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
     *  bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn
     * 
     * Where:
     *  c = constant, k = key, b = block count, n = nonce
     * 
     * @param {UInt32[]} key - The key used in encryption.
     * @param {UInt32[]} nonce - The nonce value.
     * @param {UInt32} counter - The block counter.
     */
    constructor(key: UInt32[], nonce: UInt32[], counter: UInt32) {
        if (key.length !== 8) {
            throw new Error("Invalid key length: expected 256-bit key (8 UInt32 elements).");
        }
        if (nonce.length !== 3) {
            throw new Error("Invalid nonce length: expected 96-bit nonce (3 UInt32 elements).");
        }

        // Initialize the state array with ChaCha constants, key, counter, and nonce.
        this.state = [
            UInt32.from(0x61707865), UInt32.from(0x3320646e), UInt32.from(0x79622d32), UInt32.from(0x6b206574), // ChaCha constants
            ...key,
            counter,
            ...nonce,
        ];
    }

    /**
     * Adds the values of another ChaChaState to this one using carryless addition on 32-bit words.
     * 
     * @param {ChaChaState} other - The ChaChaState to be added.
     */
    add(other: ChaChaState) {
        if (other.state.length !== 16) {
            throw new Error("Invalid ChaCha state length: expected 16 UInt32 elements.");
        }
        // Perform element-wise carryless addition of the state arrays.
        this.state = this.state.map((value, i) =>
            value.addMod32(other.state[i])
        );
    }

    /**
     * Converts the state array to little-endian byte order and returns it as an array of UInt32.
     * 
     * @returns {UInt32[]} - The state array in little-endian format.
     */
    toLe4Bytes(): UInt32[] {
        return this.state.map(value => {
            const leValue = ((value.toBigint() & 0xFFn) << 24n) |
                (((value.toBigint() >> 8n) & 0xFFn) << 16n) |
                (((value.toBigint() >> 16n) & 0xFFn) << 8n) |
                ((value.toBigint() >> 24n) & 0xFFn);
            return UInt32.fromValue(leValue);
        });
    }

    /**
     * Performs the ChaCha quarter-round operation on four words in the state array.
     * 
     * @param {UInt32[]} state - The state array on which the quarter-round is applied.
     * @param {number} aIndex - The index of the first word in the state array.
     * @param {number} bIndex - The index of the second word in the state array.
     * @param {number} cIndex - The index of the third word in the state array.
     * @param {number} dIndex - The index of the fourth word in the state array.
     */
    static quarterRound(state: UInt32[], aIndex: number, bIndex: number, cIndex: number, dIndex: number) {
        if (state.length !== 16) {
            throw new Error("Invalid ChaCha state length: expected 16 UInt32 elements.");
        }
        // Rotate function used in the quarter-round operation.
        const rotate = (value: UInt32, bits: number) =>
            UInt32.Unsafe.fromField(Gadgets.rotate32(value.toFields()[0], bits, 'left'));

        let [a, b, c, d] = [state[aIndex], state[bIndex], state[cIndex], state[dIndex]];

        // Step 1: a += b; d ^= a; d <<<= 16;
        a = a.addMod32(b);
        d = d.xor(a);
        d = rotate(d, 16);

        // Step 2: c += d; b ^= c; b <<<= 12;
        c = c.addMod32(d);
        b = b.xor(c);
        b = rotate(b, 12);

        // Step 3: a += b; d ^= a; d <<<= 8;
        a = a.addMod32(b);
        d = d.xor(a);
        d = rotate(d, 8);

        // Step 4: c += d; b ^= c; b <<<= 7;
        c = c.addMod32(d);
        b = b.xor(c);
        b = rotate(b, 7);

        // Update the state with the results of the quarter-round.
        [state[aIndex], state[bIndex], state[cIndex], state[dIndex]] = [a, b, c, d];
    }

    /**
     * Applies the ChaCha inner block function, consisting of column and diagonal rounds.
     * 
     * @param {UInt32[]} state - The state array to be processed.
     */
    static innerBlock(state: UInt32[]) {
        if (state.length !== 16) {
            throw new Error("Invalid ChaCha state length: expected 16 UInt32 elements.");
        }
        // Perform column rounds.
        this.quarterRound(state, 0, 4, 8, 12);
        this.quarterRound(state, 1, 5, 9, 13);
        this.quarterRound(state, 2, 6, 10, 14);
        this.quarterRound(state, 3, 7, 11, 15);

        // Perform diagonal rounds.
        this.quarterRound(state, 0, 5, 10, 15);
        this.quarterRound(state, 1, 6, 11, 12);
        this.quarterRound(state, 2, 7, 8, 13);
        this.quarterRound(state, 3, 4, 9, 14);
    }

    /**
     * Generates a keystream block for the ChaCha20 stream cipher using the given key, nonce, and counter.
     * 
     * @param {UInt32[]} key - The encryption key (256-bit).
     * @param {UInt32[]} nonce - The nonce (96-bit).
     * @param {UInt32} counter - The block counter.
     * @returns {UInt32[]} - The resulting keystream block as an array of UInt32.
     */
    static chacha20Block(key: UInt32[], nonce: UInt32[], counter: UInt32): UInt32[] {
        if (key.length !== 8) {
            throw new Error("Invalid key length: expected 256-bit key (8 UInt32 elements).");
        }
        if (nonce.length !== 3) {
            throw new Error("Invalid nonce length: expected 96-bit nonce (3 UInt32 elements).");
        }

        // Initialize the state and a working copy of the state.
        const state = new ChaChaState(key, nonce, counter);
        const workingState = new ChaChaState(key, nonce, counter);

        // Apply the ChaCha inner block function 10 times (20 rounds).
        for (let i = 0; i < 10; i++) {
            ChaChaState.innerBlock(workingState.state);
        }

        // Add the original state to the transformed state and return the result in little-endian format.
        workingState.add(state);
        return workingState.toLe4Bytes();
    }
}
