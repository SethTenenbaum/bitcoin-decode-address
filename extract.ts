// Import required methods
import { base58 } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2';
import { bech32m } from '@scure/base'; // Import Bech32m encoder

// TypeScript typedefs
type ScriptPubKey = Buffer; // A Bitcoin scriptPubKey is represented as a Buffer
type BitcoinAddress = string; // A Bitcoin address is a string

/**
 * Base58Check encode function with checksum calculation
 * @param payload - The payload to encode
 * @returns The Base58Check-encoded string
 */
export const base58CheckEncode = (payload: Buffer): BitcoinAddress => {
    const checksum = sha256(sha256(payload)).subarray(0, 4);
    const binaryAddress = Buffer.concat([payload, checksum]);
    return base58.encode(binaryAddress);
};

/**
 * Bech32m encode function
 * @param hrp - Human-readable part (e.g., "bc" for mainnet, "tb" for testnet)
 * @param data - The data to encode (5-bit values)
 * @returns The Bech32m-encoded string
 */
export const bech32mEncode = (hrp: string, data: number[]): BitcoinAddress => {
    return bech32m.encode(hrp, data);
};

/**
 * Convert 8-bit values to 5-bit values for Bech32m encoding
 * @param data - The input data (8-bit values)
 * @param fromBits - The number of bits in the input values
 * @param toBits - The number of bits in the output values
 * @param pad - Whether to pad the output
 * @returns The converted data (5-bit values)
 */
const convertBits = (data: number[], fromBits: number, toBits: number, pad = true): number[] => {
    let acc = 0;
    let bits = 0;
    const result: number[] = [];
    const maxv = (1 << toBits) - 1;

    for (const value of data) {
        if (value < 0 || value >> fromBits !== 0) {
            throw new Error(`Invalid value: ${value}`);
        }
        acc = (acc << fromBits) | value;
        bits += fromBits;
        while (bits >= toBits) {
            bits -= toBits;
            result.push((acc >> bits) & maxv);
        }
    }

    if (pad) {
        if (bits > 0) {
            result.push((acc << (toBits - bits)) & maxv);
        }
    } else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) !== 0) {
        throw new Error("Invalid padding");
    }

    return result;
};

/**
 * Decode a Bitcoin scriptPubKey and derive the corresponding Bitcoin address
 * @param scriptPubKey - The scriptPubKey to decode
 * @returns The derived Bitcoin address
 */
const decodeScriptPubKey = (scriptPubKey: ScriptPubKey): BitcoinAddress => {
    if (!Buffer.isBuffer(scriptPubKey)) {
        throw new Error("scriptPubKey must be a Buffer");
    }

    let publicKeyHash: Buffer;
    let versionByte: number;
    let address: BitcoinAddress;

    // Check if the scriptPubKey is P2PKH
    if (scriptPubKey.length >= 25 && scriptPubKey[0] === 0x76 && scriptPubKey[1] === 0xa9 && scriptPubKey[2] === 0x14) {
        console.log("Detected P2PKH format");
        publicKeyHash = scriptPubKey.subarray(3, 23);
        versionByte = 0x00; // Version byte for P2PKH
        const versionedPayload = Buffer.concat([Buffer.from([versionByte]), publicKeyHash]);
        address = base58CheckEncode(versionedPayload);
    }
    // Check if the scriptPubKey is P2SH
    else if (scriptPubKey.length === 23 && scriptPubKey[0] === 0xa9 && scriptPubKey[1] === 0x14 && scriptPubKey[22] === 0x87) {
        console.log("Detected P2SH format");
        publicKeyHash = scriptPubKey.subarray(2, 22);
        versionByte = 0x05; // Version byte for P2SH
        const versionedPayload = Buffer.concat([Buffer.from([versionByte]), publicKeyHash]);
        address = base58CheckEncode(versionedPayload);
    }
    // Check if the scriptPubKey is P2PK
    else if (scriptPubKey.length >= 35 && scriptPubKey[0] === 0x41 && scriptPubKey[scriptPubKey.length - 1] === 0xac) {
        console.log("Detected P2PK format");
        const publicKey = scriptPubKey.subarray(1, scriptPubKey.length - 1); // Extract the public key
        publicKeyHash = Buffer.from(sha256(publicKey)).subarray(0, 20); // Hash the public key
        versionByte = 0x00; // Version byte for P2PKH (treated as P2PKH for address generation)
        const versionedPayload = Buffer.concat([Buffer.from([versionByte]), publicKeyHash]);
        address = base58CheckEncode(versionedPayload);
    }
    // Check if the scriptPubKey is P2TR (Taproot)
    else if (scriptPubKey.length === 34 && scriptPubKey[0] === 0x51 && scriptPubKey[1] === 0x20) {
        console.log("Detected P2TR format");
        const witnessVersion = 1; // Taproot uses SegWit v1
        const hrp = "bc"; // Human-readable part for mainnet (use "tb" for testnet)
        publicKeyHash = scriptPubKey.subarray(2, 34); // Extract the 32-byte public key hash

        // Convert publicKeyHash (8-bit values) to 5-bit values
        const data = [witnessVersion].concat(convertBits(Array.from(publicKeyHash), 8, 5, true));
        address = bech32mEncode(hrp, data);
    }
    else {
        throw new Error("Unsupported scriptPubKey format");
    }

    return address;
};

// Example scriptPubKey for P2TR (Taproot)
const scriptPubKey: ScriptPubKey = Buffer.from("51200f9dab1a72f7c48da8a1df2f913bef649bfc0d77072dffd11329b8048293d7a3", "hex");
try {
    const address: BitcoinAddress = decodeScriptPubKey(scriptPubKey);
    console.log("Derived Bitcoin Address:", address);
} catch (error) {
    console.error("Error decoding scriptPubKey:", (error as Error).message);
}