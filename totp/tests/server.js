const http = require('http');
const fs = require('fs');
const path = require('path');
// Path goes up one level from tests/ to totp/ and then into otpauth/
const otpauth = require('../otpauth/index.cjs');

const PORT = 3000;

// --- In-memory storage for user secrets (NOT FOR PRODUCTION!) ---
const userSecrets = {}; // { username: Secret }
// -------------------------------------------------------------

const server = http.createServer((req, res) => {
    console.log(`Request: ${req.method} ${req.url}`);

    // Helper to send JSON responses
    const sendJson = (statusCode, data) => {
        res.writeHead(statusCode, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify(data));
    };

    // Helper to read request body
    const readBody = (callback) => {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        req.on('end', () => {
            try {
                callback(null, JSON.parse(body || '{}'));
            } catch (e) {
                callback(e);
            }
        });
        req.on('error', (err) => {
             callback(err);
        })
    };


    // --- Routing ---
    if (req.method === 'GET' && req.url === '/') {
        // Serve index.html
        fs.readFile(path.join(__dirname, 'index.html'), (err, data) => {
            if (err) {
                res.writeHead(500, { 'Content-Type': 'text/plain' });
                res.end('Internal Server Error reading index.html');
                return;
            }
            res.writeHead(200, { 'Content-Type': 'text/html' });
            res.end(data);
        });
    } else if (req.method === 'GET' && req.url === '/client.js') {
        // Serve client.js
        fs.readFile(path.join(__dirname, 'client.js'), (err, data) => {
             if (err) {
                 res.writeHead(500, { 'Content-Type': 'text/plain' });
                 res.end('Internal Server Error reading client.js');
                 return;
             }
             res.writeHead(200, { 'Content-Type': 'application/javascript' });
             res.end(data);
         });
    } else if (req.method === 'GET' && req.url === '/totp/qrcode/index.js') {
         // Serve the QR code library
         fs.readFile(path.join(__dirname, '..', 'qrcode', 'index.js'), (err, data) => {
             if (err) {
                 console.error("Error reading QR code library:", err);
                 res.writeHead(500, { 'Content-Type': 'text/plain' });
                 res.end('Internal Server Error reading qrcode library');
                 return;
             }
             res.writeHead(200, { 'Content-Type': 'application/javascript' });
             res.end(data);
         });
    } else if (req.method === 'POST' && req.url === '/register') {
        // Start Registration - Generate secret and OTP URI
        const username = 'testuser'; // Hardcoded for simplicity
        const secret = new otpauth.Secret();
        userSecrets[username] = secret; // Store the secret object

        const totp = new otpauth.TOTP({
            issuer: 'MyAppTesting',
            label: username,
            algorithm: 'SHA1',
            digits: 6,
            period: 30,
            secret: secret // Use the newly generated secret
        });
        const otpUri = totp.toString();

        console.log(`Generated secret for ${username}: ${secret.base32}`);
        console.log(`Generated OTP URI for ${username}: ${otpUri}`);

        sendJson(200, { uri: otpUri, secret: secret.base32 /* For display only */ });

    } else if (req.method === 'POST' && req.url === '/verify') {
        // Verify the submitted TOTP code
        readBody((err, body) => {
            if (err) {
                 console.error("Error reading verify body:", err);
                 return sendJson(400, { verified: false, message: 'Invalid request body.' });
            }

            const { username = 'testuser', token } = body;

            if (!token) {
                 return sendJson(400, { verified: false, message: 'Token is required.' });
            }

            const secret = userSecrets[username];
            if (!secret) {
                console.warn(`Verification attempt for unknown user: ${username}`);
                return sendJson(400, { verified: false, message: 'User not registered or secret not found.' });
            }

            // Recreate TOTP instance with the stored secret to validate
            const totp = new otpauth.TOTP({
                 issuer: 'MyAppTesting', // Must match registration
                 label: username,       // Must match registration
                 algorithm: 'SHA1',     // Must match registration
                 digits: 6,             // Must match registration
                 period: 30,            // Must match registration
                 secret: secret         // Use the stored secret
             });

            const delta = totp.validate({ token: token, window: 1 }); // Allow 1 period tolerance

            if (delta !== null) {
                console.log(`Verification successful for ${username} (delta: ${delta})`);
                sendJson(200, { verified: true, message: 'Token verified successfully.' });
            } else {
                 console.log(`Verification failed for ${username}`);
                 sendJson(400, { verified: false, message: 'Invalid token.' });
            }
        });

    } else {
        // Not Found
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not Found');
    }
});

server.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}/`);
    console.log('Ready for registration and verification requests.');
});