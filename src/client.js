const net = require('net');
const crypto = require('crypto');

// Generate clientRandom
const clientRandom = crypto.randomBytes(16).toString('hex');

let serverRandom = null;
let serverPublicKey = null;

// Store premasterSecret and sessionKey
const premasterSecret = crypto.randomBytes(24).toString('hex');
let sessionKey = null;

const client = new net.Socket();

client.connect(4000, '127.0.0.1', () => {
  console.log('> Client: connected to server.');

  // 1. Send CLIENT_HELLO
  const clientHelloMsg = {
    type: 'CLIENT_HELLO',
    clientRandom: clientRandom,
  };
  client.write(JSON.stringify(clientHelloMsg));
});

// Handle server’s response
client.on('data', (data) => {
  try {
    const message = JSON.parse(data.toString());

    // If SERVER_HELLO
    if (message.type === 'SERVER_HELLO') {
      console.log('> Client received SERVER_HELLO:', message.serverRandom);
      serverRandom = message.serverRandom;
      serverPublicKey = message.publicKey; // PEM format of the public key

      // 2. Client encrypts premasterSecret with the server’s public key
      const encryptedPremaster = crypto.publicEncrypt(
        {
          key: serverPublicKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        },
        Buffer.from(premasterSecret, 'utf8')
      );

      // Send the encrypted premasterSecret
      const premasterMsg = {
        type: 'CLIENT_PREMASTER',
        clientRandom: clientRandom,
        encryptedPremaster: encryptedPremaster.toString('base64'),
      };
      client.write(JSON.stringify(premasterMsg));
    } else if (message.type === 'SERVER_READY') {
      // 3. Decrypt the message.
      sessionKey = crypto
        .createHash('sha256')
        .update(clientRandom + serverRandom + premasterSecret)
        .digest();

      // Check if “SERVER_READY” can indeed be decrypted with the sessionKey
      const decryptedReady = decryptWithAes(sessionKey, message.data);
      if (decryptedReady === 'SERVER_READY') {
        console.log('> Client received "SERVER_READY".');
        console.log('> Client generates sessionKey (SHA-256) and sends CLIENT_READY.');

        // 4. Send client’s “CLIENT_READY”
        const encryptedReady = encryptWithAes(sessionKey, 'CLIENT_READY');
        client.write(JSON.stringify({ type: 'CLIENT_READY', data: encryptedReady }));

        console.log('> Handshake completed! The channel is secure.');
        console.log('> You can now send messages encrypted with the sessionKey.');

        // Example: send a “SECURE_MESSAGE” — a chat message
        setTimeout(() => {
          sendSecureMessage('Hello from the client! This is a secure message.');
        }, 1000);
      }
    } else if (message.type === 'SECURE_MESSAGE') {
      const decrypted = decryptWithAes(sessionKey, message.data);
      console.log(`> [secure] Message from the server: "${decrypted}"`);
    } else {
      console.log('> Client received an unknown message type:', message.type);
    }
  } catch (err) {
    console.error('> Client: error processing data:', err.message);
  }
});

// Function to send encrypted messages to the server
function sendSecureMessage(text) {
  const encrypted = encryptWithAes(sessionKey, text);

  console.log('> Sending encrypted message to the server with text:', `"${text}"`);

  client.write(JSON.stringify({ type: 'SECURE_MESSAGE', data: encrypted }));
}

// Helper encryption/decryption functions
function encryptWithAes(key, text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(text, 'utf8', 'base64');
  encrypted += cipher.final('base64');
  return JSON.stringify({
    iv: iv.toString('base64'),
    data: encrypted,
  });
}

function decryptWithAes(key, encDataJSON) {
  const encData = JSON.parse(encDataJSON);
  const iv = Buffer.from(encData.iv, 'base64');
  const encryptedText = encData.data;
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
  let decrypted = decipher.update(encryptedText, 'base64', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}
