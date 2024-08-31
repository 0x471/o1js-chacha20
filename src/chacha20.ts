import {
    UInt32,
    Gadgets,
    Field,
} from 'o1js';

export { ChaChaState, chacha20Block, chacha20 };

function chacha20(key: Uint32Array, nonce: Uint32Array, counter: number, plaintext: Uint32Array): Uint32Array {
    let res = new Uint32Array(plaintext.length);
    for (let j = 0; j < plaintext.length / 16; j++) {
        let keyStream = chacha20Block(key, nonce, counter+j);
        for (let t = 0; t < 16; t++) {
            res[16*j+t] = plaintext[16*j+t] ^ Number(keyStream[t].toBigint());
        }
    }
    if(plaintext.length % 16 !== 0) {
        let j = Math.floor(plaintext.length / 16);
        let keyStream = chacha20Block(key, nonce, counter+j);
        for (let t = 0; t < (plaintext.length % 16); t++) {
            res[16*j+t] = plaintext[16*j+t] ^ Number(keyStream[t].toBigint());
        }
    }
    return res
}


function chacha20Block(key: Uint32Array, nonce: Uint32Array, counter: number): UInt32[] {
    let state = new ChaChaState(key, nonce, counter);
    let workingState = new ChaChaState(key, nonce, counter);

    for (let i = 0; i < 10; i++) {
        ChaChaState.innerBlock(workingState.state);
    }

    workingState.add(state);
    return workingState.toLe4Bytes();;
}

class ChaChaState {
    state: UInt32[];
    constructor(key: Uint32Array, nonce: Uint32Array, counter: number) {
        const stateValues: UInt32[] = [
            UInt32.from(0x61707865), UInt32.from(0x3320646e), UInt32.from(0x79622d32), UInt32.from(0x6b206574), // ChaCha constants
            UInt32.from(key[0]), UInt32.from(key[1]), UInt32.from(key[2]), UInt32.from(key[3]), UInt32.from(key[4]), UInt32.from(key[5]), UInt32.from(key[6]), UInt32.from(key[7]),
            UInt32.from(counter), UInt32.from(nonce[0]), UInt32.from(nonce[1]), UInt32.from(nonce[2]),
        ];

        this.state = stateValues
            .filter(value => value !== undefined)
            .map(value => value);
    }

    static quarterRound(state: UInt32[], aIndex: number, bIndex: number, cIndex: number, dIndex: number) {
        let a = state[aIndex];
        let b = state[bIndex];
        let c = state[cIndex];
        let d = state[dIndex];

        a = UInt32.from((a.toBigint() + b.toBigint()) & 0xFFFFFFFFn);
        d = UInt32.from(d.toBigint() ^ a.toBigint());
        d = UInt32.fromFields([Gadgets.rotate32(d.toFields()[0], 16, 'left')]);

        c = UInt32.from((c.toBigint() + d.toBigint()) & 0xFFFFFFFFn);
        b = UInt32.from(b.toBigint() ^ c.toBigint());
        b = UInt32.fromFields([Gadgets.rotate32(b.toFields()[0], 12, 'left')]);

        a = UInt32.from((a.toBigint() + b.toBigint()) & 0xFFFFFFFFn);
        d = UInt32.from(d.toBigint() ^ a.toBigint());
        d = UInt32.fromFields([Gadgets.rotate32(d.toFields()[0], 8, 'left')]);

        c = UInt32.from((c.toBigint() + d.toBigint()) & 0xFFFFFFFFn);
        b = UInt32.from(b.toBigint() ^ c.toBigint());
        b = UInt32.fromFields([Gadgets.rotate32(b.toFields()[0], 7, 'left')]);

        state[aIndex] = a;
        state[bIndex] = b;
        state[cIndex] = c;
        state[dIndex] = d;
    }

    toLe4Bytes(): UInt32[] {
        const res: UInt32[] = [];

        for (let i = 0; i < 16; i++) {
            const value = this.state[i].toBigint();

            // Convert to little-endian 4 bytes
            const byte0 = (value & 0xFFn);
            const byte1 = (value >> 8n) & 0xFFn;
            const byte2 = (value >> 16n) & 0xFFn;
            const byte3 = (value >> 24n) & 0xFFn;

            const leValue = (byte0 << 24n) | (byte1 << 16n) | (byte2 << 8n) | byte3;
            res.push(UInt32.fromValue(leValue));
        }

        return res;
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
