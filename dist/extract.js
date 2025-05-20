// Import required methods
import { base58 } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2';
import { bech32m, bech32 } from '@scure/base'; // Import Bech32m and Bech32 encoders
import { createHash } from 'crypto'; // Import createHash from the crypto module
/**
 * Base58Check encode function with checksum calculation
 * @param payload - The payload to encode
 * @returns The Base58Check-encoded string
 */
export const base58CheckEncode = (payload) => {
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
export const bech32mEncode = (hrp, data) => {
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
const convertBits = (data, fromBits, toBits, pad = true) => {
    let acc = 0;
    let bits = 0;
    const result = [];
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
    }
    else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv) !== 0) {
        throw new Error("Invalid padding");
    }
    return result;
};
/**
 * Decode a Bitcoin scriptPubKey and derive the corresponding Bitcoin address
 * @param scriptPubKey - The scriptPubKey to decode
 * @returns The derived Bitcoin address
 */
const decodeScriptPubKey = (scriptPubKey) => {
    if (!Buffer.isBuffer(scriptPubKey)) {
        throw new Error("scriptPubKey must be a Buffer");
    }
    let publicKeyHash;
    let versionByte;
    let address;
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
        const publicKeyHash = sha256(publicKey); // Hash the public key using SHA-256
        const ripemd160Hash = Buffer.from(createHash('ripemd160').update(publicKeyHash).digest()); // Apply RIPEMD-160
        const versionByte = 0x00; // Version byte for P2PKH (treated as P2PKH for address generation)
        const versionedPayload = Buffer.concat([Buffer.from([versionByte]), ripemd160Hash]);
        address = base58CheckEncode(versionedPayload); // Encode using Base58Check
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
    // Check if the scriptPubKey is P2WPKH or P2WSH (SegWit v0)
    // Check if the scriptPubKey is P2WSH (SegWit v0)
    else if (scriptPubKey.length === 34 && // Ensure the length matches a P2WSH scriptPubKey
        scriptPubKey[0] === 0x00 && // Witness version 0
        scriptPubKey[1] === 0x20 // 32-byte script hash
    ) {
        console.log("Detected P2WSH format");
        const witnessVersion = 0; // SegWit v0
        const hrp = "bc"; // Human-readable part for mainnet (use "tb" for testnet)
        publicKeyHash = scriptPubKey.subarray(2, 34); // Extract the 32-byte script hash
        // Convert publicKeyHash (8-bit values) to 5-bit values
        const data = [witnessVersion].concat(convertBits(Array.from(publicKeyHash), 8, 5, true));
        address = bech32.encode(hrp, data); // Use Bech32 for SegWit v0
    }
    // Check if the scriptPubKey is OP_RETURN
    else if (scriptPubKey.length >= 2 && scriptPubKey[0] === 0x6a) {
        console.log("Detected OP_RETURN format");
        const dataLength = scriptPubKey[1]; // Length of the embedded data
        const embeddedData = scriptPubKey.subarray(2, 2 + dataLength); // Extract the embedded data
        address = `OP_RETURN: ${embeddedData.toString("hex")}`; // Return the embedded data as a hex string
    }
    else {
        throw new Error("Unsupported scriptPubKey format");
    }
    return address;
};
const args = process.argv.slice(2); // Skip the first two arguments (node and script path)
if (args.length === 0) {
    console.error("Usage: decodeScriptPubKey <scriptPubKey>");
    process.exit(1);
}
const scriptPubKeyHex = args[0];
try {
    const scriptPubKey = Buffer.from(scriptPubKeyHex, "hex");
    const address = decodeScriptPubKey(scriptPubKey);
    console.log("Derived Bitcoin Address:", address);
}
catch (error) {
    if (error instanceof Error) {
        console.error("Error decoding scriptPubKey:", error.message);
    }
    else {
        console.error("Error decoding scriptPubKey:", error);
    }
    process.exit(1);
}
