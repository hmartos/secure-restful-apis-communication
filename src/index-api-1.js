const express = require('express');
const crypto = require('crypto');
const axios = require('axios');
const {
    encryptMessage,
    decryptMessage,
    encryptAESKeyWithRSA,
    decryptAESKeyWithRSA,
    signData,
    verifySignature,
} = require('./crypto-utils');
const { readFileAsString } = require('./file-utils');
const {debug} = require('./debug-utils')

const app = express();
app.use(express.json());

// Load keys from environment or secure storage (for demonstration)
const api1PrivateKey = readFileAsString(process.env.API_1_PRIVATE_KEY_FILE);
const api2PublicKey = readFileAsString(process.env.API_2_PUBLIC_KEY_FILE);

// Load receiver API URL
const api2ReceiveMessageURL = process.env.API_2_RECEIVE_MESSAGE_URL

// Reusable function for sending secure messages
async function sendSecureMessage(url, message, headers) {
    try {
        return await axios.post(url, message, { headers });
    } catch (error) {
        throw new Error(`Failed to send message: ${error.message}`);
    }
}

// Send a message to API 2
app.post('/send-message', async (req, res) => {
    try {
        debug(`Sending new message to ${api2ReceiveMessageURL}`, req.body)
        const { message } = req.body;
        if (!message) {
            return res.status(400).json({ error: 'Message is required' });
        }

        // Generate AES key and IV for encryption
        const aesKey = crypto.randomBytes(16);
        const iv = crypto.randomBytes(16);
        debug(`Generated random AES encryption Key: ${aesKey.toString('hex')} and IV: ${iv.toString('hex')}`);

        // Encrypt the message using the AES key
        const encrypted = encryptMessage(message, aesKey, iv);
        debug(`Encrypted message: ${encrypted}`);

        // Encrypt the AES key with API 2's public RSA key
        const encryptedAESKey = encryptAESKeyWithRSA(aesKey, api2PublicKey);
        debug(`Encrypted AES encryption Key: ${encryptedAESKey}`);

        // Sign the encrypted message + IV with API 1's private RSA key for authenticity
        const signature = signData(encrypted + iv.toString('hex'), api1PrivateKey);
        debug(`Calculated signature for encrypted data + IV: ${signature}`)

        // Send the encrypted message to API 2
        debug(`Sending message to ${api2ReceiveMessageURL}...`)
        await sendSecureMessage(api2ReceiveMessageURL, {
            iv: iv.toString('hex'),
            encrypted,
        }, {
            'X-Encryption-Key': encryptedAESKey,
            'X-Signature': signature,
        });
        
        debug(`Message sent!`)
        res.json({ status: 'Message sent' });
        
    } catch (error) {
        console.error("Server side error while sending secure message.", error)
        res.status(500).send();
    }
});

// Receive a message from API 2
app.post('/receive-message', (req, res) => {
    try {
        // Get the secure message details
        debug(`Received new message`, req.body);
        const { iv, encrypted } = req.body;
        const encryptedAESKey = req.header('X-Encryption-Key');
        const signature = req.header('X-Signature');

        // Verify the signature of the encrypted message + IV with API 2's public key
        debug(`Verifying signature...`)
        const isSignatureValid = verifySignature(encrypted + iv, signature, api2PublicKey);
        debug(`Signature verification status: ${isSignatureValid ? "OK" : "KO"}`)

        if (!isSignatureValid) {
            debug(`Invalid signature!`)
            return res.status(403).json({ error: 'Invalid signature' });
        }

        // Decrypt the AES key with API 1's private RSA key
        debug(`Decrypting encrypted encryption key: ${encryptedAESKey}...`)
        const aesKey = decryptAESKeyWithRSA(encryptedAESKey, api1PrivateKey);
        debug(`Encryption key: ${aesKey.toString('hex')}`)

        // Decrypt the message using the decrypted AES key
        debug(`Decrypting encrypted message: ${encrypted} with IV: ${iv} and AES encryption key: ${aesKey.toString('hex')}`)
        const decryptedMessage = decryptMessage(encrypted, aesKey, iv);
        debug(`Decrypted message: ${decryptedMessage}`)

        res.json({ decryptedMessage });
    } catch (error) {
        console.error("Server side error while processing secure message.", error)
        res.status(500).send();
    }
});

app.listen(3000, () => {
    console.log('API 1 running on port 3000');
});
