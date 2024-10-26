const crypto = require('crypto');
const {
    encryptMessage,
    decryptMessage,
    encryptAESKeyWithRSA,
    decryptAESKeyWithRSA,
    signData,
    verifySignature,
} = require('../src/crypto-utils');

// Sample data for testing
const message = "This is a secret message!";
const aesKey = crypto.randomBytes(16); // AES-128 uses a 16-byte key
const iv = crypto.randomBytes(16);     // AES CBC mode requires a 16-byte IV

// Generate RSA key pair for testing
let rsaKeyPair;
beforeAll(() => {
    rsaKeyPair = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
    });
});

describe("Crypto Utils Integration Tests", () => {

    test("AES encryption and decryption should work correctly", () => {
        // Encrypt the message
        const encryptedMessage = encryptMessage(message, aesKey, iv);
        expect(encryptedMessage).toBeDefined();

        // Decrypt the message
        const decryptedMessage = decryptMessage(encryptedMessage, aesKey, iv);
        expect(decryptedMessage).toBe(message); // The decrypted message should match the original message
    });

    test("RSA encryption and decryption of AES key should work correctly", () => {
        // Encrypt the AES key using the RSA public key
        const encryptedAESKey = encryptAESKeyWithRSA(aesKey, rsaKeyPair.publicKey);
        expect(encryptedAESKey).toBeDefined();

        // Decrypt the AES key using the RSA private key
        const decryptedAESKey = decryptAESKeyWithRSA(encryptedAESKey, rsaKeyPair.privateKey);
        expect(decryptedAESKey).toEqual(aesKey); // The decrypted AES key should match the original AES key
    });

    test("Signing and verifying a message should work correctly", () => {
        // Sign the message using the RSA private key
        const signature = signData(message, rsaKeyPair.privateKey);
        expect(signature).toBeDefined();

        // Verify the signature using the RSA public key
        const isSignatureValid = verifySignature(message, signature, rsaKeyPair.publicKey);
        expect(isSignatureValid).toBe(true); // The signature should be valid
    });

    test("Verifying an invalid signature should fail", () => {
        // Sign a different message to create an invalid signature
        const invalidSignature = signData("Different message", rsaKeyPair.privateKey);

        // Verify the invalid signature
        const isSignatureValid = verifySignature(message, invalidSignature, rsaKeyPair.publicKey);
        expect(isSignatureValid).toBe(false); // The verification should fail for an invalid signature
    });
});
