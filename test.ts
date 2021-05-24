import { assertEquals } from "https://deno.land/std@0.97.0/testing/asserts.ts";

import { algorithm, hash, version } from "./mod.ts";

const encoder = new TextEncoder();
const encode = (str: string) => encoder.encode(str);

const hex = (arr: Uint8Array) =>
  arr.reduce((m, i) => m + ("0" + i.toString(16)).slice(-2), "");

const password = encode("password");
const salt = encode("somesalt");

Deno.test({
  name: "argon2d V0x10",
  fn: () => {
    assertEquals(
      hex(hash(password, salt, {
        algorithm: algorithm.argon2d,
        version: version.V0x10,
        timeCost: 2,
        memoryCost: 65536,
        lanes: 1,
      })),
      "2ec0d925358f5830caf0c1cc8a3ee58b34505759428b859c79b72415f51f9221",
    );
  },
});

Deno.test({
  name: "argon2d V0x13",
  fn: () => {
    assertEquals(
      hex(hash(password, salt, {
        algorithm: algorithm.argon2d,
        version: version.V0x13,
        timeCost: 2,
        memoryCost: 65536,
        lanes: 1,
      })),
      "955e5d5b163a1b60bba35fc36d0496474fba4f6b59ad53628666f07fb2f93eaf",
    );
  },
});

Deno.test({
  name: "argon2i V0x10",
  fn: () => {
    assertEquals(
      hex(hash(password, salt, {
        algorithm: algorithm.argon2i,
        version: version.V0x10,
        timeCost: 2,
        memoryCost: 65536,
        lanes: 1,
      })),
      "f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694",
    );
  },
});

Deno.test({
  name: "argon2i V0x13",
  fn: () => {
    assertEquals(
      hex(hash(password, salt, {
        algorithm: algorithm.argon2i,
        version: version.V0x13,
        timeCost: 2,
        memoryCost: 65536,
        lanes: 1,
      })),
      "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0",
    );
  },
});

Deno.test({
  name: "argon2id V0x10",
  fn: () => {
    assertEquals(
      hex(hash(password, salt, {
        algorithm: algorithm.argon2id,
        version: version.V0x10,
        timeCost: 2,
        memoryCost: 65536,
        lanes: 1,
      })),
      "980ebd24a4e667f16346f9d4a78b175728783613e0cc6fb17c2ec884b16435df",
    );
  },
});

Deno.test({
  name: "argon2id V0x13",
  fn: () => {
    assertEquals(
      hex(hash(password, salt, {
        algorithm: algorithm.argon2id,
        version: version.V0x13,
        timeCost: 2,
        memoryCost: 65536,
        lanes: 1,
      })),
      "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7",
    );
  },
});
