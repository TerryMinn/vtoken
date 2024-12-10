import { decrypt, encrypt } from "./index";

describe("encrypt", () => {
  it("should return a valid token", () => {
    const mockData = { message: "Hello, World!" };
    const mockUserKey = "secure-key";
    const mockExpiresIn = 60; // 1 minute

    const token = encrypt(mockData, mockUserKey, mockExpiresIn);

    expect(token).toBeDefined();
    expect(typeof token).toBe("string");

    // Decode the token
    const decoded = JSON.parse(Buffer.from(token, "base64").toString("utf8"));

    expect(decoded).toHaveProperty("encryptedData");
    expect(decoded).toHaveProperty("iv");
    expect(decoded).toHaveProperty("salt");
    expect(decoded).toHaveProperty("signature");

    const ivBuffer = Buffer.from(decoded.iv, "base64");
    expect(ivBuffer.length).toBe(16);
  });
});

describe("decrypt", () => {
  it("should successfully decrypt a valid token", () => {
    const mockData = { message: "Hello, World!" };
    const mockUserKey = "secure-key";
    const mockExpiresIn = 120; // 2 minutes

    // Encrypt the data to create a token
    const token = encrypt(mockData, mockUserKey, mockExpiresIn);

    // Decrypt the token
    const decryptedData = decrypt(token, mockUserKey);

    // Verify the decrypted data matches the original
    expect(decryptedData).toEqual(mockData);
  });

  it("should throw an error for expired tokens", () => {
    const mockData = { message: "Expired Test" };
    const mockUserKey = "test-key";
    const mockExpiresIn = 1; // 1 second

    // Encrypt the data to create a token
    const token = encrypt(mockData, mockUserKey, mockExpiresIn);

    // Wait for the token to expire
    return new Promise((resolve) => {
      setTimeout(() => {
        try {
          decrypt(token, mockUserKey);
        } catch (error) {
          expect(error).toBeInstanceOf(Error);
          expect((error as Error).message).toBe("Token expired");
          resolve(undefined);
        }
      }, 2000);
    });
  });

  it("should throw an error for signature mismatch", () => {
    const mockData = { message: "Tampered Data" };
    const mockUserKey = "secure-key";
    const mockExpiresIn = 120; // 2 minutes

    const token = encrypt(mockData, mockUserKey, mockExpiresIn);

    const decoded = JSON.parse(Buffer.from(token, "base64").toString("utf8"));
    decoded.signature = "tampered-signature"; // Modify the signature
    const tamperedToken = Buffer.from(JSON.stringify(decoded)).toString(
      "base64"
    );

    expect(() => decrypt(tamperedToken, mockUserKey)).toThrowError(
      "Signature mismatch: Data integrity compromised"
    );
  });
});
