import type { Point } from "./types.js";
import { bytesToBigInt } from "./utils.js";

/**
 * Pedersen commitment utilities
 */

/**
 * Converts a 32-byte array to a scalar (bigint), matching Rust's bytes2scalar.
 */
export function bytes32ToBigInt(bytes: Uint8Array): bigint {
  if (bytes.length !== 32) {
    throw new Error(`Expected 32 bytes, got ${bytes.length}`);
  }

  const limbs: bigint[] = [];

  for (let i = 3; i >= 0; i--) {
    const start = i * 8;
    const chunk = bytes.slice(start, start + 8);
    let limb = 0n;
    for (let j = 0; j < 8; j++) {
      limb = (limb << 8n) | BigInt(chunk[j]);
    }
    limbs.push(limb);
  }

  let result = 0n;
  for (let i = 0; i < 4; i++) {
    result = result | (limbs[i] << BigInt(i * 64));
  }

  return result;
}

/**
 * Generates the basis of 2^i powers as bigints for batch_size elements.
 */
export function generateExp(batchSize: number): bigint[] {
  const vec: bigint[] = [];
  
  for (let i = 0; i < batchSize; i++) {
    const j = Math.floor(i / 8);
    const k = i % 8;
    const bytes = new Uint8Array(32);
    bytes[31 - j] |= 1 << k;

    const scalar = bytes32ToBigInt(bytes);
    vec.push(scalar);
  }
  
  return vec;
}

/**
 * Splits a JSON response string into field element chunks using bit packing.
 * Matches the Rust split_json_response function.
 */
export function computeMsgsChunks(jsonResponse: string, batchSize: number): bigint[] {
  let bytes = Array.from(new TextEncoder().encode(jsonResponse));
  bytes.reverse();

  const bits: boolean[] = [];
  for (const byte of bytes) {
    for (let i = 0; i < 8; i++) {
      const b = (byte >> i) & 1;
      bits.push(b !== 0);
    }
  }

  const exp = generateExp(batchSize);

  const vec: bigint[] = [];
  const chunkLen = Math.ceil(bits.length / batchSize);
  let index = 0;

  for (let _ = 0; _ < chunkLen; _++) {
    let scalar = 0n;
    for (let j = 0; j < batchSize; j++) {
      if (index >= bits.length) break;
      if (bits[index]) {
        scalar = scalar + exp[j];
      }
      index++;
    }
    vec.push(scalar);
  }

  return vec;
}

/**
 * Parses commitment points from hex-encoded verification array.
 * Each point is expected to be an uncompressed EC point (04 | x | y).
 */
export function parseCommitments(verificationArray: string[]): Point[] {
  return verificationArray.map((hex: string) => {
    const bytes = Buffer.from(hex, "hex");

    if (bytes.length !== 65 || bytes[0] !== 0x04) {
      throw new Error("Expected uncompressed EC point (04 | x | y)");
    }

    const xBytes = new Uint8Array(bytes.slice(1, 33));
    const yBytes = new Uint8Array(bytes.slice(33, 65));

    return {
      x: bytesToBigInt(xBytes),
      y: bytesToBigInt(yBytes),
      is_infinite: false,
    };
  });
}

/**
 * Parses random scalars from hex array.
 */
export function parseRandomScalars(randomHexArray: string[]): bigint[] {
  return randomHexArray.map((hex: string) => BigInt("0x" + hex));
}