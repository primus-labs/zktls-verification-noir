/**
 * Types for attestation data structures
 */

export interface AttestationRequest {
  url: string;
  header: string;
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

export interface PrivateData {
  random: string[];
  content: string;
}

export interface AttestationFile {
  public_data: PublicData[];
  private_data: PrivateData[];
}

export interface Point {
  x: bigint;
  y: bigint;
  is_infinite: boolean;
}

export interface ParseConfig {
  maxResponseNum: number;
  allowedUrls: string[];
  grumpkinBatchSize: number;
}

export interface ParsedAttestationData {
  publicKeyX: number[];
  publicKeyY: number[];
  hash: number[];
  signature: number[];
  requestUrls: number[][];
  allowedUrls: number[][];
  commitments: Point[];
  randomScalars: bigint[];
  msgsChunks: bigint[];
  msgs: number[];
  id: number;
  attestationData: any;
}