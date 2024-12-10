import * as crypto from "crypto";

/**
 * Derives a cryptographic key from a user-provided key using PBKDF2.
 *
 * @param userKey - The user's input key to be used for key derivation.
 * @param salt - Optional. A cryptographic salt. If not provided, a random 16-byte salt is generated.
 * @returns An object containing the derived key and the base64-encoded salt.
 */
function deriveKey(userKey: string, salt = crypto.randomBytes(16)) {
  const iterations = 100000;
  const keyLength = 32; // 256-bit key
  const derivedKey = crypto.pbkdf2Sync(
    userKey,
    salt,
    iterations,
    keyLength,
    "sha256"
  );
  return { derivedKey, salt: salt.toString("base64") };
}

/**
 * Encrypts the given data using AES-256-CBC encryption and returns a token.
 *
 * @param data - The data to be encrypted.
 * @param userKey - The user's key used for deriving the encryption key.
 * @param expiresInSeconds - The time in seconds after which the token expires.
 * @returns A base64-encoded token containing the encrypted data, initialization vector,
 *          salt, and HMAC signature.
 */
export function encrypt(data: any, userKey: string, expiresInSeconds: number) {
  const { derivedKey, salt } = deriveKey(userKey);
  const iv = crypto.randomBytes(16);

  const cipher = crypto.createCipheriv("aes-256-cbc", derivedKey, iv);

  const metadata = {
    issuedAt: Date.now(),
    expiresAt: Date.now() + expiresInSeconds * 1000,
  };

  const payload = JSON.stringify({ data, metadata });
  const encrypted = Buffer.concat([
    cipher.update(payload, "utf8"),
    cipher.final(),
  ]);

  const hmac = crypto.createHmac("sha256", derivedKey);
  hmac.update(encrypted);

  // Construct token
  const token = Buffer.from(
    JSON.stringify({
      encryptedData: encrypted.toString("base64"),
      iv: iv.toString("base64"),
      salt: salt,
      signature: hmac.digest("base64"),
    })
  ).toString("base64");

  return token;
}

/**
 * Decrypts a base64-encoded token using the provided user key.
 *
 * This function verifies the integrity and authenticity of the token
 * by checking its HMAC signature. It then decrypts the token's payload
 * using AES-256-CBC and returns the contained data if the token is valid
 * and not expired.
 *
 * @param token - The base64-encoded token to decrypt.
 * @param userKey - The user's key used to derive the decryption key.
 * @returns The decrypted data from the token.
 * @throws Will throw an error if the token's signature is invalid or if the token is expired.
 */
export function decrypt(token: string, userKey: string) {
  // Decode the token
  const decodedPayload = JSON.parse(
    Buffer.from(token, "base64").toString("utf8")
  );
  const { encryptedData, iv, salt, signature } = decodedPayload;

  const { derivedKey } = deriveKey(userKey, Buffer.from(salt, "base64"));

  const hmac = crypto.createHmac("sha256", derivedKey);
  hmac.update(Buffer.from(encryptedData, "base64"));
  if (hmac.digest("base64") !== signature) {
    throw new Error("Signature mismatch: Data integrity compromised");
  }

  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    derivedKey,
    Buffer.from(iv, "base64")
  );
  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(encryptedData, "base64")),
    decipher.final(),
  ]);

  const { data, metadata } = JSON.parse(decrypted.toString("utf8"));

  if (Date.now() > metadata.expiresAt) {
    throw new Error("Token expired");
  }

  return data;
}
