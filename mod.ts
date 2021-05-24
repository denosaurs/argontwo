import { alloc, hashRaw, memory } from "./wasm/mod.ts";

function transferToWasm(arr: Uint8Array): [number, number] {
  const len = arr.length;
  const ptr = alloc(len);
  new Uint8Array(memory.buffer, ptr, len).set(arr);
  return [ptr, len];
}

/**
 * The three different Argon2 algorithm variants:
 *
 * - **argon2d**: maximizes resistance to GPU cracking attacks
 * - **argon2i**: optimized to resist side-channel attacks
 * - **argon2id**: (default) hybrid version
 */
export const variant = {
  argon2d: 0,
  argon2i: 1,
  argon2id: 2,
} as const;

/**
 * The two different versions of the Argon2 algorithm:
 *
 * - **V0x10** - Version 16, performs overwrites internally
 * - **V0x13** - Version 19, performs XOR internally
 */
export const version = {
  V0x10: 0,
  V0x13: 1,
} as const;

/**
 * The Argon2 parameters
 */
export interface Argon2Params {
  /**
   * The secret key
   */
  secret?: Uint8Array;
  /**
   * The associated data
   */
  ad: Uint8Array;
  /**
   * The Argon2 variant, see {@link variant}
   */
  variant: typeof variant[keyof typeof variant];
  /**
   * Memory size, expressed in kilobytes, between 1 and (2^32)-1.
   */
  m: number;
  /**
   * Number of iterations, between 1 and (2^32)-1.
   */
  t: number;
  /**
   * Degree of parallelism, between 1 and 255
   */
  p: number;
  /**
   * The length of the output in bytes
   */
  outputLength: number;
  /**
   *  The Argon2 version, see {@link version}
   */
  version: typeof version[keyof typeof version];
}

function defaultParams(params?: Partial<Argon2Params>): Argon2Params {
  return {
    secret: params?.secret,
    ad: params?.ad ?? new Uint8Array(),
    variant: params?.variant ?? variant.argon2id,
    m: params?.m ?? 4096,
    t: params?.t ?? 3,
    p: params?.p ?? 1,
    outputLength: params?.outputLength ?? 32,
    version: params?.version ?? version.V0x13,
  };
}

/**
 * Computes the hash for the password, salt and parameters
 */
export function hash(
  password: Uint8Array,
  salt: Uint8Array,
  partialParams?: Partial<Argon2Params>,
): Uint8Array {
  const params = defaultParams(partialParams);

  const [pwdPtr, pwdLen] = transferToWasm(password);
  const [saltPtr, saltLen] = transferToWasm(salt);

  let secretPtr = 0;
  let secretLen = 0;
  if (params.secret !== undefined) {
    [secretPtr, secretLen] = transferToWasm(params.secret);
  }

  const adLen = params.ad.length;
  const adPtr = alloc(adLen);
  const adArr = new Uint8Array(memory.buffer, adPtr, adLen);
  adArr.set(params.ad);

  const outPtr = hashRaw(
    pwdPtr,
    pwdLen,
    saltPtr,
    saltLen,
    secretPtr,
    secretLen,
    adPtr,
    adLen,
    params.variant,
    params.m,
    params.t,
    params.p,
    params.outputLength,
    params.version,
  );

  return new Uint8Array(memory.buffer, outPtr, params.outputLength);
}
