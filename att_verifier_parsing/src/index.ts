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
  ParsedCommitmentData,
  ParsedHashingData,
} from "./types.js";

interface ParsedCommon {
  publicKeyX: number[];
  publicKeyY: number[];
  hash: number[];
  signature: number[];
  requestUrls: number[][];
  allowedUrls: number[][];
  attDataParsed: any;
  id: number;
}

function parseCommon(attestationData: AttestationFile, config: ParseConfig): ParsedCommon {
  const publicData = attestationData.public_data[0];

  const packedArr = encodePacked(publicData.attestation);
  const msgHash = keccak_256(new Uint8Array(packedArr));
  const hash = Array.from(msgHash);

  const { sig, compactBytes } = parseSignature(publicData.signature);
  const pubKey = recoverPublicKey(sig, msgHash);

  const requestUrls = parseRequestUrls(publicData.attestation.request, config.maxResponseNum);
  const allowedUrls = parseAllowedUrls(config.allowedUrls);

  const attDataParsed = JSON.parse(publicData.attestation.data);
  const id = Math.floor(Math.random() * 9999999999);

  return {
    publicKeyX: pubKey.x,
    publicKeyY: pubKey.y,
    hash,
    signature: compactBytes,
    requestUrls,
    allowedUrls,
    attDataParsed,
    id,
  };
}

/**
 * Parses a commitment-based attestation into format ready for smart contract verification.
 *
 * Iterates private_data in order. For each entry keyName gets the commitments (public) 
 *  and the random scalars & content (private)
 */
export function parseCommitmentData(
  attestationData: AttestationFile,
  config: ParseConfig
): ParsedCommitmentData {
  const {
    publicKeyX,
    publicKeyY,
    hash,
    signature,
    requestUrls,
    allowedUrls,
    attDataParsed,
    id,
  } = parseCommon(attestationData, config);

  const batchSize = config.grumpkinBatchSize ?? 253;

  const coms_per_group: any[] = [];
  const rnds_per_group: any[] = [];
  const msgs_chunks_per_group: any[] = [];
  const msgs_per_group: number[][] = [];

  for (const entry of attestationData.private_data) {
    const rawValue = attDataParsed[entry.id];
    if (rawValue === undefined) {
      throw new Error(`Key '${entry.id}' not found in attestation data`);
    }

    const commitmentArray: string[] = JSON.parse(rawValue);
    const commitments = parseCommitments(commitmentArray);

    if (!entry.random) {
      throw new Error(`private_data entry '${entry.id}' is missing 'random' field`);
    }

    const randomScalars = parseRandomScalars(entry.random);

    if (commitments.length !== randomScalars.length) {
      throw new Error(
        `Commitment/random count mismatch for '${entry.id}': ${commitments.length} vs ${randomScalars.length}`
      );
    }

    const msgsChunks = computeMsgsChunks(entry.content, batchSize);
    const msgs = Array.from(Buffer.from(entry.content, "utf8"));

    coms_per_group.push(commitments);
    rnds_per_group.push(randomScalars);
    msgs_chunks_per_group.push(msgsChunks);
    msgs_per_group.push(msgs);
  }

  return {
    publicKeyX,
    publicKeyY,
    hash,
    signature,
    requestUrls,
    allowedUrls,
    coms_per_group,
    rnds_per_group,
    msgs_chunks_per_group,
    msgs_per_group,
    id,
    attestationData: attDataParsed,
  };
}

/**
 * Parses a hash-based attestation into format ready for smart contract verification.
 *
 * Iterates private_data in order. For each keyName gets the hash (public) and the content (private)
 */
export function parseHashingData(
  attestationData: AttestationFile,
  config: ParseConfig
): ParsedHashingData {
  const { publicKeyX, publicKeyY, hash, signature, requestUrls, allowedUrls, attDataParsed, id } =
    parseCommon(attestationData, config);

  const dataHashes = parseDataHashes(attestationData.public_data[0].attestation.data, attestationData.private_data);
  const plainJsonResponses = parsePlainJsonResponses(attestationData.private_data);

  return {
    publicKeyX,
    publicKeyY,
    hash,
    signature,
    requestUrls,
    allowedUrls,
    dataHashes,
    plainJsonResponses,
    id,
    attestationData: attDataParsed,
  };
}

// Re-export 
export * from "./types.js";
export * from "./utils.js";
