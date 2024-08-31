import { UInt32, Gadgets, Field } from 'o1js';

export { ChaChaState, chacha20Block, chacha20 };

function chacha20(key: UInt32[], nonce: UInt32[], counter: number, plaintext: UInt32[]): UInt32[] {
    const res: UInt32[] = Array(plaintext.length).fill(UInt32.from(0));

    function processBlock(offset: number, length: number) {
        const keyStream = chacha20Block(key, nonce, counter + offset);
        for (let t = 0; t < length; t++) {
            res[offset * 16 + t] = UInt32.from(plaintext[offset * 16 + t].toBigint() ^ keyStream[t].toBigint());
        }
    }

    const numFullBlocks = Math.floor(plaintext.length / 16);
    for (let j = 0; j < numFullBlocks; j++) {
        processBlock(j, 16);
    }

    const remaining = plaintext.length % 16;
    if (remaining > 0) {
        processBlock(numFullBlocks, remaining);
    }

    return res;
}

function chacha20Block(key: UInt32[], nonce: UInt32[], counter: number): UInt32[] {
    const state = new ChaChaState(key, nonce, counter);
    const workingState = new ChaChaState(key, nonce, counter);

    for (let i = 0; i < 10; i++) {
        ChaChaState.innerBlock(workingState.state);
    }

    workingState.add(state);
    return workingState.toLe4Bytes();
}

class ChaChaState {
    state: UInt32[];

    constructor(key: UInt32[], nonce: UInt32[], counter: number) {
        this.state = [
            UInt32.from(0x61707865), UInt32.from(0x3320646e), UInt32.from(0x79622d32), UInt32.from(0x6b206574), // ChaCha constants
            ...key,
            UInt32.from(counter),
            ...nonce,
        ];
    }

    static quarterRound(state: UInt32[], aIndex: number, bIndex: number, cIndex: number, dIndex: number) {
        const rotate = (value: UInt32, bits: number) =>
            UInt32.fromFields([Gadgets.rotate32(value.toFields()[0], bits, 'left')]);

        let [a, b, c, d] = [state[aIndex], state[bIndex], state[cIndex], state[dIndex]];

        a = UInt32.from((a.toBigint() + b.toBigint()) & 0xFFFFFFFFn);
        d = UInt32.from(d.toBigint() ^ a.toBigint());
        d = rotate(d, 16);

        c = UInt32.from((c.toBigint() + d.toBigint()) & 0xFFFFFFFFn);
        b = UInt32.from(b.toBigint() ^ c.toBigint());
        b = rotate(b, 12);

        a = UInt32.from((a.toBigint() + b.toBigint()) & 0xFFFFFFFFn);
        d = UInt32.from(d.toBigint() ^ a.toBigint());
        d = rotate(d, 8);

        c = UInt32.from((c.toBigint() + d.toBigint()) & 0xFFFFFFFFn);
        b = UInt32.from(b.toBigint() ^ c.toBigint());
        b = rotate(b, 7);

        [state[aIndex], state[bIndex], state[cIndex], state[dIndex]] = [a, b, c, d];
    }

    toLe4Bytes(): UInt32[] {
        return this.state.map(value => {
            const leValue = ((value.toBigint() & 0xFFn) << 24n) |
                            (((value.toBigint() >> 8n) & 0xFFn) << 16n) |
                            (((value.toBigint() >> 16n) & 0xFFn) << 8n) |
                            ((value.toBigint() >> 24n) & 0xFFn);
            return UInt32.fromValue(leValue);
        });
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

    add(other: ChaChaState) {
        this.state = this.state.map((value, i) =>
            UInt32.fromFields([Field.from((value.toBigint() + other.state[i].toBigint()) & 0xFFFFFFFFn)])
        );
    }
}
