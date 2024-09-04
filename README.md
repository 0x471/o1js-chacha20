# ChaCha20 Stream Cipher - o1js

## What is ChaCha20?
ChaCha20 is a stream cipher and a descendant of Salsa20. It is widely used and recognized for its security and efficiency.

The inputs to ChaCha20 are:
- A 256-bit key, represented as a concatenation of eight 32-bit little-endian integers.
- A 96-bit nonce, represented as a concatenation of three 32-bit little-endian integers.
- A 32-bit block count parameter, represented as a 32-bit little-endian integer.

The output is a sequence of 64 bytes of pseudorandom data.

More details can be found here: https://www.rfc-editor.org/rfc/rfc7539

**Funfact:**  BLAKE(2), relies on a core algorithm borrowed from the ChaCha stream cipher :)

## How does ChaCha20 differ from AES?
- **Simpler Design**: ChaCha20 has a simpler structure compared to AES.
- **ARX Design**: ChaCha20 uses an ARX (Addition-Rotation-XOR) design, which avoids the use of S-Boxes and reduces cache footprint.
- **Efficient Key Setup**: ChaCha20 features free key setup, meaning it does not incur significant overhead during key initialization.

Here is a detailed comparison of symmetric encryption methods: https://soatok.blog/2020/07/12/comparison-of-symmetric-encryption-methods/

## ToDo
- Add test coverage for error handling

## How to build
```sh
npm run build
```

## How to run tests

```sh
npm run test
npm run testw # watch mode
```

## How to run coverage

```sh
npm run coverage
```

## License

[Apache-2.0](LICENSE)
    