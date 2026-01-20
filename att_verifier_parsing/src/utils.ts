import { keccak_256 } from "@noble/hashes/sha3";
import { secp256k1 } from "@noble/curves/secp256k1";
import type { Barretenberg } from "@aztec/bb.js";
import type { AttestationData, AttestationRequest } from "./types.js";
import { Fr } from "@aztec/aztec.js/fields";
/**
 * Encoding utilities
 */

export function encodePacked(publicData: AttestationData): number[] {
  const out: number[] = [];

  out.push(...Buffer.from(publicData.recipient.slice(2), "hex"));

  if (Array.isArray(publicData.request)) {
    const requestConcat = publicData.request
      .map((req) => req.url + req.header + req.method + req.body)
      .join("");
    out.push(...keccak_256(Buffer.from(requestConcat, "utf8")));
  } else {
    const req = publicData.request;
    out.push(...keccak_256(Buffer.from(req.url + req.header + req.method + req.body, "utf8")));
  }

  if (Array.isArray(publicData.responseResolves)) {
    const responseConcat = publicData.responseResolves
      .flatMap((r) => r.oneUrlResponseResolve)
      .map((rr) => rr.keyName + rr.parseType + rr.parsePath)
      .join("");
    out.push(...keccak_256(Buffer.from(responseConcat, "utf8")));
  } else {
    const rr = publicData.responseResolves.oneUrlResponseResolve[0];
    out.push(...keccak_256(Buffer.from(rr.keyName + rr.parseType + rr.parsePath, "utf8")));
  }

  out.push(...Buffer.from(publicData.data, "utf8"));
  out.push(...Buffer.from(publicData.attConditions, "utf8"));

  const buf = Buffer.alloc(8);
  buf.writeBigUInt64BE(BigInt(publicData.timestamp));
  out.push(...buf);

  out.push(...Buffer.from(publicData.additionParams, "utf8"));

  return out;
}

/**
 * Signature utilities
 */

export function parseSignature(signatureHex: string) {
  const sigHex = signatureHex.startsWith("0x") ? signatureHex.slice(2) : signatureHex;
  const sigBytes = Buffer.from(sigHex, "hex");

  if (sigBytes.length !== 65) {
    throw new Error(`Invalid signature length: expected 65 bytes, got ${sigBytes.length}`);
  }

  const r = BigInt("0x" + sigBytes.slice(0, 32).toString("hex"));
  const s = BigInt("0x" + sigBytes.slice(32, 64).toString("hex"));
  let v = sigBytes[64];
  
  if (v === 27 || v === 28) v -= 27;

  const sig = new secp256k1.Signature(r, s).addRecoveryBit(v);
  return { sig, compactBytes: Array.from(sig.toCompactRawBytes()) };
}

export function recoverPublicKey(sig: InstanceType<typeof secp256k1.Signature>, messageHash: Uint8Array): { x: number[]; y: number[] } {
  const pubkey = sig.recoverPublicKey(messageHash);
  const pubBytes = pubkey.toRawBytes(false);
  
  if (pubBytes[0] !== 0x04) {
    throw new Error("Expected uncompressed public key format");
  }

  return {
    x: Array.from(pubBytes.slice(1, 33)),
    y: Array.from(pubBytes.slice(33, 65)),
  };
}

/**
 * URL utilities
 */

export function parseRequestUrls(
  requests: AttestationRequest | AttestationRequest[],
  maxResponseNum: number
): number[][] {
  const requestArray = Array.isArray(requests) ? requests : [requests];

  if (requestArray.length > maxResponseNum) {
    throw new Error(
      `Request length (${requestArray.length}) exceeds MAX_RESPONSE_NUM (${maxResponseNum})`
    );
  }

  const requestUrls: number[][] = [];
  
  for (const req of requestArray) {
    const urlBytes = Array.from(new TextEncoder().encode(req.url));
    requestUrls.push(urlBytes);
  }

  const diff = maxResponseNum - requestUrls.length;
  const lastElement = requestUrls[requestUrls.length - 1];
  
  for (let i = 0; i < diff; i++) {
    requestUrls.push([...lastElement]);
  }

  return requestUrls;
}

export function parseAllowedUrls(allowedUrls: string[]): number[][] {
  return allowedUrls.map((url) => Array.from(new TextEncoder().encode(url)));
}

export function padUrl(url: number[], targetLength: number = 1024): number[] {
  const paddedUrl = [...url];
  while (paddedUrl.length < targetLength) {
    paddedUrl.push(0);
  }
  return paddedUrl;
}

/**
 * Hashing utilities
 */

export async function hashUrlsWithPoseidon2(
  bb: Barretenberg,
  allowedUrls: number[][]
): Promise<bigint[]> {
  const hashedUrls: bigint[] = [];

  for (const url of allowedUrls) {
    const paddedUrl = padUrl(url, 1024);
    const frArray = paddedUrl.map((b) => new Fr(BigInt(b)).toBuffer());
    const hashFr = await bb.poseidon2Hash({ inputs: frArray });
    const hashBigInt = BigInt(Fr.fromBuffer(Buffer.from(hashFr.hash)).toString());
    hashedUrls.push(hashBigInt);
  }

  return hashedUrls;
}

/**
 * Hashing case utilities
 */

export function parseDataHashes(attestationData: any, maxResponseNum: number): number[][] {
  const dataHashes: number[][] = [];
  const attData = JSON.parse(attestationData);
  
  for (const [key, value] of Object.entries(attData)) {
    // Support both uuid- and hash-of-response prefixes
    if ((key.startsWith("uuid-") || key.startsWith("hash-of-response")) 
        && typeof value === "string" 
        && value.length === 64) {
      const hashBytes = Array.from(Buffer.from(value as string, "hex"));
      dataHashes.push(hashBytes);
    }
  }
  
  // Pad by repeating the last element
  const diff = maxResponseNum - dataHashes.length;
  const lastElement = dataHashes[dataHashes.length - 1];
  for (let i = 0; i < diff; i++) {
    dataHashes.push([...lastElement]);
  }
  
  return dataHashes;
}

export function parsePlainJsonResponses(privateData: any, maxResponseNum: number): number[][] {
  const plainJsonResponse: number[][] = [];
  
  if (privateData && privateData.plain_json_response && Array.isArray(privateData.plain_json_response)) {
    for (const entry of privateData.plain_json_response) {
      if (entry.id && entry.content) {
        const jsonBytes = Array.from(new TextEncoder().encode(entry.content));
        plainJsonResponse.push(jsonBytes);
      }
    }
  }
  
  // Pad by repeating the last element
  if (plainJsonResponse.length > 0) {
    const diff = maxResponseNum - plainJsonResponse.length;
    const lastElement = plainJsonResponse[plainJsonResponse.length - 1];
    for (let i = 0; i < diff; i++) {
      plainJsonResponse.push([...lastElement]);
    }
  }
  
  return plainJsonResponse;
}

/**
 * Simple conversion utilities
 */

export function bytesToBigInt(bytes: Uint8Array): bigint {
  return BigInt("0x" + Buffer.from(bytes).toString("hex"));
}