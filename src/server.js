const net = require('net');
const crypto = require('crypto');

// Generate an RSA key pair (pseudo SSL certificate)
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
});

let serverRandom = null;
let premasterSecret = null;
let sessionKey = null;

const server = net.createServer((socket) => {
  console.log('> Server: client connected.');

  // 1. Server receives “hello” from the client
  socket.on('data', (data) => {
    try {
      const message = JSON.parse(data.toString());

      if (message.type === 'CLIENT_HELLO') {
        console.log('> Server received CLIENT_HELLO:', message.clientRandom);

        // Generate and store serverRandom
        serverRandom = crypto.randomBytes(16).toString('hex');

        // 2. Send “server hello” + publicKey
        const serverHelloMsg = {
          type: 'SERVER_HELLO',
          serverRandom: serverRandom,
          publicKey: publicKey.export({ type: 'pkcs1', format: 'pem' }),
        };
        socket.write(JSON.stringify(serverHelloMsg));
      }
      // If the client has sent an encrypted premaster
      else if (message.type === 'CLIENT_PREMASTER') {
        console.log('> Server received encrypted premasterSecret');

        // 3. Server decrypts the premaster secret
        const decryptedPremaster = crypto.privateDecrypt(
          {
            key: privateKey,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          },
          Buffer.from(message.encryptedPremaster, 'base64')
        );

        premasterSecret = decryptedPremaster.toString();
        console.log('> Server decrypted premasterSecret:', premasterSecret);

        // 4. Generate sessionKey (sha256)
        sessionKey = crypto
          .createHash('sha256')
          .update(message.clientRandom + serverRandom + premasterSecret)
          .digest();

        console.log('> Server generated sessionKey (SHA-256)');

        // 5. Server sends “Server Ready” encrypted with the sessionKey
        const encryptedReady = encryptWithAes(sessionKey, 'SERVER_READY');
        socket.write(JSON.stringify({ type: 'SERVER_READY', data: encryptedReady }));
      } else if (message.type === 'CLIENT_READY') {
        console.log('> Server received CLIENT_READY');
        const decrypted = decryptWithAes(sessionKey, message.data);
        if (decrypted === 'CLIENT_READY') {
          console.log('> Handshake completed! The channel is secure.');
          console.log('> Server is awaiting further secure messages...');

          // From here on, the server can receive other encrypted messages
        }
      } else if (message.type === 'SECURE_MESSAGE') {
        const decryptedMsg = decryptWithAes(sessionKey, message.data);
        console.log(`> [secure] Message from client: "${decryptedMsg}"`);
      } else {
        console.log('> Server received an unknown message type:', message.type);
      }
    } catch (err) {
      console.error('> Server: error processing data:', err.message);
    }
  });

  // Handle client disconnection
  socket.on('close', () => {
    console.log('> Server: client disconnected.');
  });
});

// Start the server on port 4000
server.listen(4000, () => {
  console.log('> Server started on port 4000');
});

// Helper encryption/decryption functions (AES-256-CBC for simplicity)
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
