import {
    UInt32,
    Gadgets,
    Field,
    UInt8,
} from 'o1js';
import { toHexString } from './chacha20.test';

export { ChaChaState, chacha20Block };

function chacha20Block(key: Uint32Array, nonce: Uint32Array, counter: number): UInt32[] {
    let state = new ChaChaState(key, nonce, counter);
    let workingState = new ChaChaState(key, nonce, counter);

    for (let i = 0; i < 10; i++) {
        ChaChaState.innerBlock(workingState.state);
    }

    workingState.add(state);
    return workingState.state;
}

class ChaChaState {
    state: UInt32[];
    constructor(key: Uint32Array, nonce: Uint32Array, counter: number) {
        const stateValues: number[] = [
            0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, // ChaCha constants
            key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
            counter, nonce[0], nonce[1], nonce[2],
        ];

        this.state = stateValues
            .filter(value => value !== undefined)
            .map(value => UInt32.fromValue(BigInt(value)));
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

    add(other: ChaChaState) {
        for (let i = 0; i < 16; i++) {
            this.state[i] = UInt32.fromFields([Field.from((this.state[i].toBigint() + other.state[i].toBigint()) & 0xFFFFFFFFn)]);
        }
    }
}
