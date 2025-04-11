const http = require('http');
const url = require('url');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// --- Our WebAuthn Library ---
const { 
    verifyRegistrationResponse,
    base64urlToBuffer,
    parseAndVerifyAuthenticatorData,
    verifyAttestationStatement,
    bufferEqual 
} = require('../../serverSideRegistration');

// --- Configuration (Should be securely configured in production) ---
const rpId = 'localhost'; // Relying Party ID - Must match the domain
const rpName = 'WebAuthn Demo';
const expectedOrigin = 'http://localhost:3000'; // Expected origin of the request

// --- Mock In-Memory Database ---
// Store user challenges temporarily and registered credentials
const challengeStore = new Map(); // In-memory store for challenges { userId: challengeBuffer }
const credentialStore = new Map(); // In-memory store for credentials { userId: [credentialInfo, ...] }
const userStore = new Map(); // Store basic user info { userId: { id: userId, name: userName, displayName: userDisplayName } }

// Simple function to generate user ID
function generateUserId() {
    return crypto.randomBytes(8).toString('hex');
}

// Simple function to generate challenge
function generateChallenge() {
    return crypto.randomBytes(32); // 32 bytes is recommended
}

// Helper to convert Buffer to base64url
function bufferToBase64url(buffer) {
    return buffer.toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}


// --- HTTP Server Logic ---
const server = http.createServer(async (req, res) => {
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;
    const method = req.method;

    console.log(`${method} ${pathname}`);

    try {
        // --- API Endpoints ---
        if (pathname === '/register/start' && method === 'POST') {
            // Simulate getting user info (e.g., from session or request body)
            // For demo, we'll just create a new user each time
            const userId = generateUserId();
            const userName = `user_${userId.substring(0, 4)}`;
            const userDisplayName = `Demo User ${userId.substring(0, 4)}`;

            const user = { id: userId, name: userName, displayName: userDisplayName };
            userStore.set(userId, user);

            const challengeBuffer = generateChallenge();
            challengeStore.set(userId, challengeBuffer); // Store challenge associated with user

            const publicKeyCredentialCreationOptions = {
                challenge: bufferToBase64url(challengeBuffer),
                rp: {
                    name: rpName,
                    id: rpId,
                },
                user: {
                    id: bufferToBase64url(Buffer.from(userId)), // User ID must be base64url encoded Buffer
                    name: userName,
                    displayName: userDisplayName,
                },
                pubKeyCredParams: [
                    { type: 'public-key', alg: -7 }, // ES256
                    { type: 'public-key', alg: -257 }, // RS256
                ],
                authenticatorSelection: {
                    // authenticatorAttachment: 'cross-platform', // or 'platform'
                    requireResidentKey: false,
                    userVerification: 'preferred', // 'required', 'preferred', 'discouraged'
                },
                timeout: 60000,
                attestation: 'direct' // 'none', 'indirect', 'direct'
            };

            // Send back options and the temporary userId for the client to use
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ options: publicKeyCredentialCreationOptions, userId: userId }));

        } else if (pathname === '/register/finish' && method === 'POST') {
            let body = '';
            req.on('data', chunk => { body += chunk.toString(); });
            req.on('end', async () => {
                try {
                    console.log('Received finish request body:', body);
                    const { userId, credential } = JSON.parse(body);

                    if (!userId || !credential) {
                        throw new Error('Missing userId or credential in request body.');
                    }

                    // 1. Get the challenge stored for this user
                    const expectedChallengeBuffer = challengeStore.get(userId);
                    if (!expectedChallengeBuffer) {
                        throw new Error('No challenge found for this user. Registration timed out or invalid.');
                    }
                    const expectedChallenge = bufferToBase64url(expectedChallengeBuffer);
                    challengeStore.delete(userId); // Challenge should be used only once

                    // 2. Perform verification
                    const requireUserVerification = false; // Policy decision
                    const credentialInfo = await verifyRegistrationResponse(
                        credential,
                        expectedChallenge,
                        expectedOrigin,
                        rpId,
                        requireUserVerification
                    );

                    // 3. Store the verified credential
                    if (!credentialStore.has(userId)) {
                        credentialStore.set(userId, []);
                    }
                    // Basic check for existing credential ID for this user (more robust needed in real app)
                    const existingUserCreds = credentialStore.get(userId);
                    const newCredIdB64 = bufferToBase64url(credentialInfo.credentialId);
                    if (existingUserCreds.some(c => bufferToBase64url(c.credentialId) === newCredIdB64)) {
                        console.warn(`Credential ID ${newCredIdB64} already registered for user ${userId}.`);
                        // Decide how to handle - error or just ignore?
                        // For demo, we'll allow it but log a warning.
                    }

                    existingUserCreds.push(credentialInfo);
                    console.log(`Credential stored successfully for user ${userId}:`, {
                        id: bufferToBase64url(credentialInfo.credentialId),
                        fmt: credentialInfo.attestationFormat,
                        count: credentialInfo.signCount
                    });

                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: true, message: 'Registration successful!' }));

                } catch (error) {
                    console.error('Registration verification failed:', error);
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: error.message || 'Registration verification failed.' }));
                }
            });
        } else {
            // --- Static File Serving ---
            let filePath = '.' + req.url;
            if (filePath === './') {
                filePath = './index.html';
            }

            const extname = String(path.extname(filePath)).toLowerCase();
            const contentTypeMap = {
                '.html': 'text/html',
                '.js': 'text/javascript',
                '.css': 'text/css',
            };
            const contentType = contentTypeMap[extname] || 'application/octet-stream';

            fs.readFile(filePath, (error, content) => {
                if (error) {
                    if (error.code == 'ENOENT') {
                        res.writeHead(404, { 'Content-Type': 'text/plain' });
                        res.end('404 Not Found');
                    } else {
                        res.writeHead(500);
                        res.end('Sorry, check with the site admin for error: ' + error.code + '..\n');
                    }
                } else {
                    res.writeHead(200, { 'Content-Type': contentType });
                    res.end(content, 'utf-8');
                }
            });
        }
    } catch (err) {
        console.error('Server error:', err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Internal Server Error' }));
    }
});

const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Server running at ${expectedOrigin}`);
    console.log(`Relying Party ID: ${rpId}`);
}); 