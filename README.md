# Bitcoin Decode Address

The `extract` util is a utility for decoding and extracting information from Bitcoin SCRIPTPUBKEY (HEX). It is designed to help developers analyze Bitcoin addresses and retrieve useful metadata such as address type and validity.

## Features

- Decode Bitcoin addresses.
- Identify the type of Bitcoin address (e.g., P2PKH, P2SH, Bech32).
- Validate Bitcoin addresses.

## Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/your-repo/bitcoin-decode-address.git
   cd bitcoin-decode-address
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Run the `extract.ts` script:
   ```bash
   npx ts-node extract.ts <bitcoin-address>
   ```

   Replace `<bitcoin-address>` with the Bitcoin address you want to decode.

## Example

```bash
npx ts-node extract.ts 4104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac
```

Output:
```
Address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
Type: P2PK
```

## Requirements

- Node.js (v14 or higher)
- TypeScript

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## License

This project is licensed under the MIT License.
