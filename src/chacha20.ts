import {
    UInt32,
    Gadgets,
    Field,
} from 'o1js';

export { ChaChaState };

const ChaChaConstants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];

class ChaChaState {
    state: UInt32[];

    constructor(public key: Uint32Array, nonce: Uint32Array, counter: number) {
        const stateValues: number[] = [
            ChaChaConstants[0], ChaChaConstants[1], ChaChaConstants[2], ChaChaConstants[3],
            ...Array.from(key.slice(0, 8)),
            counter,
            ...Array.from(nonce.slice(0, 3))
        ];
        this.state = stateValues.map(value => UInt32.fromValue(BigInt(value)));
    }

    static quarterRound(state: UInt32[], aIndex: number, bIndex: number, cIndex: number, dIndex: number) {
        let a = state[aIndex];
        let b = state[bIndex];
        let c = state[cIndex];
        let d = state[dIndex];

        a = UInt32.fromFields([Field.from((a.toBigint() + b.toBigint()) & 0xFFFFFFFFn)]);
        d = UInt32.from(d.toBigint() ^ a.toBigint());
        d = UInt32.fromFields([Gadgets.rotate32(d.toFields()[0], 16, 'left')]);

        c = UInt32.fromFields([Field.from((c.toBigint() + d.toBigint()) & 0xFFFFFFFFn)]);
        b = UInt32.from(b.toBigint() ^ c.toBigint());
        b = UInt32.fromFields([Gadgets.rotate32(b.toFields()[0], 12, 'left')]);

        a = UInt32.fromFields([Field.from((a.toBigint() + b.toBigint()) & 0xFFFFFFFFn)]);
        d = UInt32.from(d.toBigint() ^ a.toBigint());
        d = UInt32.fromFields([Gadgets.rotate32(d.toFields()[0], 8, 'left')]);

        c = UInt32.fromFields([Field.from((c.toBigint() + d.toBigint()) & 0xFFFFFFFFn)]);
        b = UInt32.from(b.toBigint() ^ c.toBigint());
        b = UInt32.fromFields([Gadgets.rotate32(b.toFields()[0], 7, 'left')]);

        state[aIndex] = a;
        state[bIndex] = b;
        state[cIndex] = c;
        state[dIndex] = d;
    }

    static innerBlock(state: UInt32[]) {
        // Column rounds
        this.quarterRound(state, 0, 4, 8, 12);
        this.quarterRound(state, 1, 5, 9, 13);
        this.quarterRound(state, 2, 6, 10, 14);
        this.quarterRound(state, 3, 7, 11, 15);

        // Diagonal rounds
        this.quarterRound(state, 0, 5, 10, 15);
        this.quarterRound(state, 1, 6, 11, 12);
        this.quarterRound(state, 2, 7, 8, 13);
        this.quarterRound(state, 3, 4, 9, 14);
    }

    add(other: ChaChaState): void {
        for (let i = 0; i < 16; i++) {
            this.state[i] = UInt32.fromFields([Field.from((this.state[i].toBigint() + other.state[i].toBigint()) & 0xFFFFFFFFn)]);
        }
    }

    toLe4Bytes(): Uint32Array {
        const res = new Uint32Array(16);
        for (let i = 0; i < 16; i++) {
            const value = this.state[i].toBigint();
            res[i] = Number(
                ((value & 0xFFn) << 24n) |
                ((value & 0xFF00n) << 8n) |
                ((value & 0xFF0000n) >> 8n) |
                ((value & 0xFF000000n) >> 24n)
            );
        }
        return res;
    }

    chacha20Block(): Uint32Array {
        const workingState = this.state.map(value => UInt32.fromValue(value.toBigint())); // Copy the state

        for (let i = 0; i < 10; i++) {
            ChaChaState.innerBlock(workingState);
        }

        const newState = new ChaChaState(
            new Uint32Array(workingState.slice(0, 8).map(v => Number(v.toBigint()))),
            new Uint32Array(workingState.slice(8, 11).map(v => Number(v.toBigint()))),
            Number(workingState[11].toBigint())
        );

        this.add(newState);

        return this.toLe4Bytes();
    }
}
