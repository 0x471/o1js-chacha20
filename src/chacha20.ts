import {
    UInt32,
    Gadgets,
    Field,
} from 'o1js';

export { ChaChaState };


class ChaChaState {
    /**
    * Performs a quarter round on 32-byte values.
    */
    static quarterRound(a: UInt32, b: UInt32, c: UInt32, d: UInt32): [UInt32, UInt32, UInt32, UInt32] {
        // 1.  a += b; d ^= a; d <<<= 16;
        a = UInt32.fromFields([Field.from((a.toBigint() + b.toBigint()) & 0xFFFFFFFFn)]);
        d = UInt32.from(d.toBigint() ^ a.toBigint());
        d = UInt32.fromFields([Gadgets.rotate32(d.toFields()[0], 16, 'left')]);

        // 2.  c += d; b ^= c; b <<<= 12;
        c = UInt32.fromFields([Field.from((c.toBigint() + d.toBigint()) & 0xFFFFFFFFn)]);
        b = UInt32.from(b.toBigint() ^ c.toBigint());
        b = UInt32.fromFields([Gadgets.rotate32(b.toFields()[0], 12, 'left')]);

        // 3.  a += b; d ^= a; d <<<= 8;
        a = UInt32.fromFields([Field.from((a.toBigint() + b.toBigint()) & 0xFFFFFFFFn)]);
        d = UInt32.from(d.toBigint() ^ a.toBigint());
        d = UInt32.fromFields([Gadgets.rotate32(d.toFields()[0], 8, 'left')]);

        // 4.  c += d; b ^= c; b <<<= 7;
        c = UInt32.fromFields([Field.from((c.toBigint() + d.toBigint()) & 0xFFFFFFFFn)]);
        b = UInt32.from(b.toBigint() ^ c.toBigint());
        b = UInt32.fromFields([Gadgets.rotate32(b.toFields()[0], 7, 'left')]);

        return [a, b, c, d];
    }

    /**
     * Performs the ChaCha20 inner block operations on the state array.
     */
    static innerBlock(chachaState: Uint32Array) {
        // Convert Uint32Array to UInt32 array
        const state = Array.from(chachaState).map(value => UInt32.fromValue(BigInt(value)));

        // Column rounds
        const [a0, a1, a2, a3] = this.quarterRound(state[0], state[4], state[8], state[12]);
        const [b0, b1, b2, b3] = this.quarterRound(state[1], state[5], state[9], state[13]);
        const [c0, c1, c2, c3] = this.quarterRound(state[2], state[6], state[10], state[14]);
        const [d0, d1, d2, d3] = this.quarterRound(state[3], state[7], state[11], state[15]);

        // Reassign results
        state[0] = a0; state[4] = a1; state[8] = a2; state[12] = a3;
        state[1] = b0; state[5] = b1; state[9] = b2; state[13] = b3;
        state[2] = c0; state[6] = c1; state[10] = c2; state[14] = c3;
        state[3] = d0; state[7] = d1; state[11] = d2; state[15] = d3;

        // Diagonal rounds
        const [e0, e1, e2, e3] = this.quarterRound(state[0], state[5], state[10], state[15]);
        const [f0, f1, f2, f3] = this.quarterRound(state[1], state[6], state[11], state[12]);
        const [g0, g1, g2, g3] = this.quarterRound(state[2], state[7], state[8], state[13]);
        const [h0, h1, h2, h3] = this.quarterRound(state[3], state[4], state[9], state[14]);

        // Reassign results
        state[0] = e0; state[5] = e1; state[10] = e2; state[15] = e3;
        state[1] = f0; state[6] = f1; state[11] = f2; state[12] = f3;
        state[2] = g0; state[7] = g1; state[8] = g2; state[13] = g3;
        state[3] = h0; state[4] = h1; state[9] = h2; state[14] = h3;

        // Convert back to Uint32Array
        for (let i = 0; i < chachaState.length; i++) {
            chachaState[i] = Number(state[i].toBigint());
        }
    }

}
