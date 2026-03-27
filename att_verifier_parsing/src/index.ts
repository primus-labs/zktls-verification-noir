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
  const { publicKeyX, publicKeyY, hash, signature, requestUrls, allowedUrls, attDataParsed, id } =
    parseCommon(attestationData, config);

  const groups = attestationData.private_data.map((entry) => {
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

    const batchSize = config.grumpkinBatchSize ?? 253;

    return {
      commitments,
      randomScalars,
      msgsChunks: computeMsgsChunks(entry.content, batchSize),
      msgs: Array.from(Buffer.from(entry.content, "utf8")),
    };
  });

  return {
    publicKeyX,
    publicKeyY,
    hash,
    signature,
    requestUrls,
    allowedUrls,
    groups,
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
