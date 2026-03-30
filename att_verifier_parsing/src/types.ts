/**
 * Types for attestation data structures
 */

export interface AttestationRequest {
  url: string;
  header: string | Record<string, string>;
  method: string;
  body: string;
}

export interface ResponseResolve {
  keyName: string;
  parseType: string;
  parsePath: string;
}

export interface OneUrlResponseResolves {
  oneUrlResponseResolve: ResponseResolve[];
}

export interface AttestationData {
  recipient: string;
  request: AttestationRequest | AttestationRequest[];
  responseResolves: OneUrlResponseResolves | OneUrlResponseResolves[];
  data: string;
  attConditions: string;
  timestamp: number | string;
  additionParams: string;
}

export interface PublicData {
  attestation: AttestationData;
  signature: string;
}

/**
 * An entry in private_data, one per responseResolve.
 * - `id`      matches the responseResolve.keyName
 * - `random`  optional, present for commitment-based attestations (one scalar per commitment point)
 * - `content` the plaintext value attested to (always a string, even for numeric fields)
 */
export interface PrivateDataEntry {
  id: string;
  random?: string[];
  content: string;
}

export interface AttestationFile {
  verification_type: string | string[];
  public_data: PublicData[];
  /** Always an array of PrivateDataEntry, one element per responseResolve. */
  private_data: PrivateDataEntry[];
}

export interface Point {
  x: bigint;
  y: bigint;
  is_infinite: boolean;
}

export interface ParseConfig {
  maxResponseNum: number;
  allowedUrls: string[];
  grumpkinBatchSize?: number;
}

/** Result of parsing a commitment-based attestation. */
export interface ParsedCommitmentData {
  publicKeyX: number[];
  publicKeyY: number[];
  hash: number[];
  signature: number[];

  requestUrls: number[][];
  allowedUrls: number[][];

  /**
   * Indexed by responseResolve order (must match contract expectations)
   */
  coms_per_group: Point[][];
  rnds_per_group: bigint[][];
  msgs_chunks_per_group: bigint[][];
  msgs_per_group: number[][];

  id: number;
  attestationData: any;
}

/** Result of parsing a hash-based attestation. */
export interface ParsedHashingData {
  publicKeyX: number[];
  publicKeyY: number[];
  hash: number[];
  signature: number[];
  requestUrls: number[][];
  allowedUrls: number[][];
  /**
   * One 32-byte hash ResponseResolve.keyName (uses the order as in the json)
   * Derived by looking up attestation.data[keyName] for each private_data entry.
   */
  dataHashes: number[][];
  // The private values that correspond to the hashes above
  plainJsonResponses: number[][];
  id: number;
  attestationData: any;
}
