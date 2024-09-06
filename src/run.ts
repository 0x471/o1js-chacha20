import { Provable, UInt32, ZkProgram } from 'o1js';
import { chacha20 } from './chacha20.js';

let chacha20ZkProgram = ZkProgram({
    name: 'chacha20-verify',

    methods: {
        verifyChacha20: {
            privateInputs: [
                Provable.Array(UInt32, 8),
                Provable.Array(UInt32, 3),
                UInt32,
                Provable.Array(UInt32, 29),
            ],

            async method(
                key: UInt32[],
                nonce: UInt32[],
                counter: UInt32,
                plaintext: UInt32[]
            ) {
                chacha20(key, nonce, counter, plaintext);
            },
        },
    },
});

let { verifyChacha20 } = await chacha20ZkProgram.analyzeMethods();

console.log(verifyChacha20.summary());

console.time('compile');
const forceRecompileEnabled = false;
await chacha20ZkProgram.compile({ forceRecompile: forceRecompileEnabled });
console.timeEnd('compile');

const key: UInt32[] = [
    UInt32.from(0x03020100),
    UInt32.from(0x07060504),
    UInt32.from(0x0B0A0908),
    UInt32.from(0x0F0E0D0C),
    UInt32.from(0x13121110),
    UInt32.from(0x17161514),
    UInt32.from(0x1B1A1918),
    UInt32.from(0x1F1E1D1C),
];

const nonce: UInt32[] = [
    UInt32.from(0x00000000),
    UInt32.from(0x4a000000),
    UInt32.from(0x00000000)
];

const counter = UInt32.from(1);

const plaintext: UInt32[] = [
    UInt32.from(0x4c616469), UInt32.from(0x65732061), UInt32.from(0x6e642047), UInt32.from(0x656e746c),
    UInt32.from(0x656d656e), UInt32.from(0x206f6620), UInt32.from(0x74686520), UInt32.from(0x636c6173),
    UInt32.from(0x73206f66), UInt32.from(0x20273939), UInt32.from(0x3a204966), UInt32.from(0x20492063),
    UInt32.from(0x6f756c64), UInt32.from(0x206f6666), UInt32.from(0x65722079), UInt32.from(0x6f75206f),
    UInt32.from(0x6e6c7920), UInt32.from(0x6f6e6520), UInt32.from(0x74697020), UInt32.from(0x666f7220),
    UInt32.from(0x74686520), UInt32.from(0x66757475), UInt32.from(0x72652c20), UInt32.from(0x73756e73),
    UInt32.from(0x63726565), UInt32.from(0x6e20776f), UInt32.from(0x756c6420), UInt32.from(0x62652069),
    UInt32.from(0x742e0000),
];


console.time('prove');
let proof = await chacha20ZkProgram.verifyChacha20(key, nonce, counter, plaintext);
console.timeEnd('prove');

console.time('verify');
await chacha20ZkProgram.verify(proof);
console.timeEnd('verify');
