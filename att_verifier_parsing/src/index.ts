import { keccak_256 } from "@noble/hashes/sha3";
import {
  encodePacked,
  parseSignature,
  recoverPublicKey,
  parseRequestUrls,
  parseAllowedUrls,
  parseDataHashes,
  parsePlainJsonResponses,
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
  ParsedHashingData,
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
  
  // Handle both array and object structures for private_data
  const privateData = Array.isArray(attestationData.private_data) 
    ? attestationData.private_data[0] 
    : attestationData.private_data;

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
  
  if (!config.grumpkinBatchSize) {
    throw new Error("grumpkinBatchSize is required for commitment-based parsing. Use parseHashingData for hash-based attestations.");
  }
  
  if (!attDataParsed["grumpkin-commitment"]) {
    throw new Error("grumpkin-commitment field not found in attestation data");
  }

  const verificationArray = JSON.parse(attDataParsed["grumpkin-commitment"]);

  // Step 5: Parse commitments and randoms
  const commitments = parseCommitments(verificationArray);
  const randomScalars = parseRandomScalars(privateData.random!);

  // Step 6: Compute message chunks from content
  const msgsChunks = computeMsgsChunks(
    privateData.content!,
    config.grumpkinBatchSize
  );

  // Step 7: Extract reveal string for msgs array from private_data content.
  if (!privateData.content) {
    throw new Error("private_data.content is missing");
  }
  const msgs = Array.from(Buffer.from(privateData.content, "utf8"));

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

/**
 * Parses attestation data for the hashing verification case.
 * 
 * @param attestationData - The attestation file data
 * @param config - Configuration for parsing
 * @returns Parsed hashing data ready for verification
 */
export function parseHashingData(
  attestationData: AttestationFile,
  config: ParseConfig
): ParsedHashingData {
  const publicData = attestationData.public_data[0];
  
  // Handle both array and object structures for private_data
  const privateData = Array.isArray(attestationData.private_data) 
    ? attestationData.private_data[0] 
    : attestationData.private_data;

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

  // Step 4: Parse data hashes
  const dataHashes = parseDataHashes(
    publicData.attestation.data,
    config.maxResponseNum
  );

  // Step 5: Parse plain JSON responses
  const plainJsonResponses = parsePlainJsonResponses(
    privateData,
    config.maxResponseNum
  );

  // Step 6: Parse attestation data
  const attDataParsed = JSON.parse(publicData.attestation.data);

  // Generate random ID
  const id = Math.floor(Math.random() * 9999999999);

  return {
    publicKeyX: pubKey.x,
    publicKeyY: pubKey.y,
    hash,
    signature: compactBytes,
    requestUrls,
    allowedUrls,
    dataHashes,
    plainJsonResponses,
    id,
    attestationData: attDataParsed,
  };
}

// Re-export everything from other modules
export * from "./types.js";
export * from "./utils.js";
export * from "./commitment.js";