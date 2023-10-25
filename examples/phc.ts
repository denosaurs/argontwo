import { timingSafeEqual } from "https://deno.land/std@0.204.0/crypto/timing_safe_equal.ts";
import { Buffer } from "node:buffer";
import phc from "npm:@phc/format";
import { hash } from "../mod.ts";

const encoder = new TextEncoder();

// Store the salt and hash, this could be done with a PHC string or just as is.
// Using a PHC string you would use the `phc.serialize` function to encode it
const salt1 = new Uint8Array(40);
crypto.getRandomValues(salt1);
const hash1 = hash(encoder.encode("example password 1"), salt1);

// Serializing as PHC, this is when you would want to store it in the database
const phc1 = phc.serialize({
  id: "argon2id",
  version: 19,
  params: {
    m: 4096,
    t: 3,
    p: 1,
  },
  salt: Buffer.from(salt1),
  hash: Buffer.from(hash1),
});

// Deserializing the PHC string, probably directly fetched from a database in a real-life scenario
const { salt: _salt2, hash: hash2 } = phc.deserialize(phc1);

// Using timing safe equal protects against timing based attacks
console.log(timingSafeEqual(hash1, hash2));

// You would probably not compare the `hash1` variable with `hash2` as they should be identical
// Instead you would hash the plaintext password which has been sent in with the deserialized salt
// and compare it with the deserialized hash which you have fetched from the database and earlier
// stored as an PHC string.
