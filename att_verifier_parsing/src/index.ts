import { keccak_256 } from "@noble/hashes/sha3";
import {
  encodePacked,
  parseSignature,
  recoverPublicKey,
  parseRequestUrls,
  parseAllowedUrls,
} from "./utils.js";
import {
  computeMsgsChunks,
  parseCommitments,
  parseRandomScalars,
} from "./commitment.js";
import type {
  AttestationFile,
  ParseConfig,
  ParsedAttestationData,
} from "./types.js";

/**
 * Parses complete attestation file data into format ready for smart contract verification.
 * This is the main entry point for parsing attestation data.
 * 
 * @param attestationData - The attestation file data
 * @param config - Configuration for parsing
 * @returns Parsed attestation data ready for verification
 */
export function parseAttestationData(
  attestationData: AttestationFile,
  config: ParseConfig
): ParsedAttestationData {
  const publicData = attestationData.public_data[0];
  const privateData = attestationData.private_data[0];

  // Step 1: Encode and hash the attestation
  const packedArr = encodePacked(publicData.attestation);
  const msgHash = keccak_256(new Uint8Array(packedArr));
  const hash = Array.from(msgHash);

  // Step 2: Parse signature and recover public key
  const { sig, compactBytes } = parseSignature(publicData.signature);
  const pubKey = recoverPublicKey(sig, msgHash);

  // Step 3: Parse URLs
  const requestUrls = parseRequestUrls(
    publicData.attestation.request,
    config.maxResponseNum
  );
  const allowedUrls = parseAllowedUrls(config.allowedUrls);

  // Step 4: Parse attestation data
  const attDataParsed = JSON.parse(publicData.attestation.data);
  const verificationArray = JSON.parse(attDataParsed["#verification_id"]);

  // Step 5: Parse commitments and randoms
  const commitments = parseCommitments(verificationArray);
  const randomScalars = parseRandomScalars(privateData.random);

  // Step 6: Compute message chunks from content
  const msgsChunks = computeMsgsChunks(
    privateData.content,
    config.grumpkinBatchSize
  );

  // Step 7: Extract reveal string for msgs array
  let revealJsonRaw = attDataParsed["#reveal_id"];
  if (typeof revealJsonRaw === "string") {
    try {
      revealJsonRaw = JSON.parse(revealJsonRaw);
    } catch {
      throw new Error("Invalid JSON in #reveal_id");
    }
  }
  const revealStr = JSON.stringify(revealJsonRaw);
  const msgs = Array.from(Buffer.from(revealStr, "utf8"));

  // Generate random ID
  const id = Math.floor(Math.random() * 9999999999);

  return {
    publicKeyX: pubKey.x,
    publicKeyY: pubKey.y,
    hash,
    signature: compactBytes,
    requestUrls,
    allowedUrls,
    commitments,
    randomScalars,
    msgsChunks,
    msgs,
    id,
    attestationData: attDataParsed,
  };
}

// Re-export everything from other modules
export * from "./types.js";
export * from "./utils.js";
export * from "./commitment.js";