import * as wasm from "./wasm/mod.ts";

function bufferSourceArrayBuffer(data: BufferSource) {
  if (ArrayBuffer.isView(data)) {
    return data.buffer;
  } else if (data instanceof ArrayBuffer) {
    return data;
  }

  throw new TypeError(
    `Could extract ArrayBuffer from alleged BufferSource type. Got ${data} instead.`,
  );
}

/**
 * Transfers an {@link ArrayBufferLike} to wasm, automatically allocating it in memory.
 *
 * Remember to unallocate the transfered buffer with {@link wasm.dealloc}
 */
function transfer(buffer: BufferSource): [number, number] {
  const length = buffer.byteLength;
  const pointer = wasm.alloc(length);
  new Uint8Array(wasm.memory.buffer, pointer, length).set(
    new Uint8Array(bufferSourceArrayBuffer(buffer)),
  );
  return [pointer, length];
}

function maybeTransfer(buffer?: BufferSource): [number, number] {
  if (buffer != null) {
    return transfer(buffer);
  }
  return [0, 0];
}

/**
 * The three different Argon2 algorithm variants as described by [wikipedia](https://en.wikipedia.org/wiki/Argon2):
 *
 * - **Argon2d**: Argon2d maximizes resistance to GPU cracking attacks. It accesses the memory array in a password dependent order, which reduces the possibility of time–memory trade-off (TMTO) attacks, but introduces possible side-channel attacks.
 * - **Argon2i**: Argon2i is optimized to resist side-channel attacks. It accesses the memory array in a password independent order.
 * - **Argon2id**: (default) Argon2id is a hybrid version. It follows the Argon2i approach for the first half pass over memory and the Argon2d approach for subsequent passes. RFC 9106 recommends using Argon2id if you do not know the difference between the types or you consider side-channel attacks to be a viable threat.
 */
export type Argon2Algorithm = "Argon2d" | "Argon2i" | "Argon2id";

/**
 * The two different versions of the Argon2 algorithm:
 *
 * - **0x10**: Version 16, performs overwrites internally.
 * - **0x13** (default): Version 19, performs XOR internally.
 */
export type Argon2Version = 0x10 | 0x13;

export type Argon2Params = {
  algorithm: Argon2Algorithm;
  version: Argon2Version;
  secret?: ArrayBufferLike;
  /**
   * The length of the output hash.
   *
   * @default 32
   */
  outputLength?: number;
  /**
   * Memory size in 1 KiB blocks. Between 1 and (2^32)-1.
   *
   * When {@link Argon2Params.algorithm} is Argon2i the default is changed to 12288 as per OWASP recommendations.
   *
   * @default 19456
   */
  mCost?: number;
  /**
   * Number of iterations. Between 1 and (2^32)-1.
   *
   * When {@link Argon2Params.algorithm} is Argon2i the default is changed to 3 as per OWASP recommendations.
   *
   * @default 2
   */
  tCost?: number;
  /**
   * Degree of parallelism. Between 1 and 255.
   *
   * @default 1
   */
  pCost?: number;
};

const argon2AlgorithmEnum: Record<Lowercase<Argon2Algorithm>, number> = {
  "argon2d": 0,
  "argon2i": 1,
  "argon2id": 2,
};

/**
 * Computes the Argon2 hash for the password, salt and parameters.
 */
export function hash(
  password: BufferSource,
  salt: BufferSource,
  params?: Argon2Params,
) {
  params ??= {
    algorithm: "Argon2id",
    version: 0x13,
  };
  params.outputLength ??= 32;
  // These defaults come from https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id
  params.mCost ??= params.algorithm === "Argon2i" ? 12288 : 19456;
  params.tCost ??= params.algorithm === "Argon2i" ? 3 : 2;
  params.pCost ??= 1;

  const [passwordPtr, passwordLen] = transfer(password);
  const [saltPtr, saltLen] = transfer(salt);
  const [secretPtr, secretLen] = maybeTransfer(params?.secret);
  const outputPtr = wasm.alloc(params.outputLength);

  wasm.hash(
    passwordPtr,
    passwordLen,
    saltPtr,
    saltLen,
    secretPtr,
    secretLen,
    outputPtr,
    params.outputLength,
    argon2AlgorithmEnum[
      params.algorithm.toLowerCase() as Lowercase<Argon2Algorithm>
    ],
    params.version,
    params.mCost,
    params.tCost,
    params.pCost,
  );

  wasm.dealloc(passwordPtr, passwordLen);
  wasm.dealloc(saltPtr, saltLen);
  if (secretPtr !== 0) {
    wasm.dealloc(secretPtr, secretLen);
  }

  const output = new ArrayBuffer(params.outputLength);
  // Copy output from wasm memory into js
  new Uint8Array(output).set(
    new Uint8Array(wasm.memory.buffer, outputPtr, params.outputLength),
  );

  wasm.dealloc(outputPtr, params.outputLength);

  return output;
}
