import {

    UInt32,
    Gadgets,
    Field,
} from 'o1js';

export { quarterRound };

/**
 * Performs a quarter round on 32-byte values.
 */
function quarterRound(a: UInt32, b: UInt32, c: UInt32, d: UInt32): [UInt32, UInt32, UInt32, UInt32] {
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

