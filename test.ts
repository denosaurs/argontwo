import { assertEquals } from "jsr:@std/assert@0.221";

import { hash } from "./mod.ts";

const encoder = new TextEncoder();
const encode = (str: string) => encoder.encode(str);

const hex = (arr: ArrayBuffer) =>
  new Uint8Array(arr).reduce(
    (m, i) => m + ("0" + i.toString(16)).slice(-2),
    "",
  );

const password = encode("password");
const salt = encode("somesalt");

Deno.test({
  name: "Argon2d 0x10",
  fn: () => {
    assertEquals(
      hex(hash(password, salt, {
        algorithm: "Argon2d",
        version: 0x10,
        tCost: 2,
        mCost: 65536,
        pCost: 1,
      })),
      "2ec0d925358f5830caf0c1cc8a3ee58b34505759428b859c79b72415f51f9221",
    );
  },
});

Deno.test({
  name: "Argon2d 0x13",
  fn: () => {
    assertEquals(
      hex(hash(password, salt, {
        algorithm: "Argon2d",
        version: 0x13,
        tCost: 2,
        mCost: 65536,
        pCost: 1,
      })),
      "955e5d5b163a1b60bba35fc36d0496474fba4f6b59ad53628666f07fb2f93eaf",
    );
  },
});

Deno.test({
  name: "Argon2i 0x10",
  fn: () => {
    assertEquals(
      hex(hash(password, salt, {
        algorithm: "Argon2i",
        version: 0x10,
        tCost: 2,
        mCost: 65536,
        pCost: 1,
      })),
      "f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694",
    );
  },
});

Deno.test({
  name: "Argon2i 0x13",
  fn: () => {
    assertEquals(
      hex(hash(password, salt, {
        algorithm: "Argon2i",
        version: 0x13,
        tCost: 2,
        mCost: 65536,
        pCost: 1,
      })),
      "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0",
    );
  },
});

Deno.test({
  name: "Argon2id 0x10",
  fn: () => {
    assertEquals(
      hex(hash(password, salt, {
        algorithm: "Argon2id",
        version: 0x10,
        tCost: 2,
        mCost: 65536,
        pCost: 1,
      })),
      "980ebd24a4e667f16346f9d4a78b175728783613e0cc6fb17c2ec884b16435df",
    );
  },
});

Deno.test({
  name: "Argon2id 0x13",
  fn: () => {
    assertEquals(
      hex(hash(password, salt, {
        algorithm: "Argon2id",
        version: 0x13,
        tCost: 2,
        mCost: 65536,
        pCost: 1,
      })),
      "09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7",
    );
  },
});
