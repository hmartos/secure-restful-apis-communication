const crypto = require('crypto');

// Function to encrypt a message using AES
function encryptMessage(message, aesKey, iv) {
    const cipher = crypto.createCipheriv('aes-128-cbc', aesKey, iv);
    let encrypted = cipher.update(message, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

// Function to decrypt a message using AES
function decryptMessage(encryptedMessage, aesKey, iv) {
    const decipher = crypto.createDecipheriv('aes-128-cbc', aesKey, Buffer.from(iv, 'hex'));
    let decrypted = decipher.update(encryptedMessage, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Function to encrypt the AES key with RSA
function encryptAESKeyWithRSA(aesKey, publicKey) {
    return crypto.publicEncrypt(publicKey, aesKey).toString('base64');
}

// Function to decrypt the AES key with RSA
function decryptAESKeyWithRSA(encryptedAESKey, privateKey) {
    return crypto.privateDecrypt(privateKey, Buffer.from(encryptedAESKey, 'base64'));
}

// Function to sign data with a private RSA key
function signData(data, privateKey) {
    const sign = crypto.createSign('SHA256');
    sign.update(data);
    sign.end();
    return sign.sign(privateKey, 'base64');
}

// Function to verify a digital signature
function verifySignature(data, signature, publicKey) {
    const verify = crypto.createVerify('SHA256');
    verify.update(data);
    verify.end();
    return verify.verify(publicKey, signature, 'base64');
}

module.exports = {
    encryptMessage,
    decryptMessage,
    encryptAESKeyWithRSA,
    decryptAESKeyWithRSA,
    signData,
    verifySignature,
};
