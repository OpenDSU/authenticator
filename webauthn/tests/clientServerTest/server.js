const http = require('http');
const url = require('url');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

// --- Our WebAuthn Library ---
const { 
    verifyRegistrationResponse,
    verifyAssertionResponse,
    base64urlToBuffer,
    bufferToBase64url,
    parseAssertionAuthenticatorData,
    bufferEqual 
} = require('../../index');

// --- Configuration (Should be securely configured in production) ---
const rpId = 'localhost'; // Relying Party ID - Must match the domain
const rpName = 'WebAuthn Demo';
const expectedOrigin = 'http://localhost:3000'; // Expected origin of the request

// --- Mock In-Memory Database ---
// Store user challenges temporarily and registered credentials
const challengeStore = new Map(); // In-memory store for challenges { userId_or_loginToken: challengeBuffer }
const credentialStore = new Map(); // In-memory store for credentials { userId: [credentialInfo, ...] }
const userStore = new Map(); // Store basic user info { userId: { id: userId, name: userName, displayName: userDisplayName } }
// Store usernames -> userId mapping for simple login lookup
const usernameToUserId = new Map(); 

// Simple function to generate user ID
function generateUserId() {
    return crypto.randomBytes(8).toString('hex');
}

// Simple function to generate challenge
function generateChallenge() {
    return crypto.randomBytes(32); // 32 bytes is recommended
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
            usernameToUserId.set(userName, userId); // Map username for login lookup

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
                    requireResidentKey: false,
                    userVerification: 'required',
                },
                timeout: 60000,
                attestation: 'direct' 
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
                    const requireUserVerification = true; // Policy decision
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
                    const existingUserCreds = credentialStore.get(userId);
                    const newCredIdB64 = bufferToBase64url(credentialInfo.credentialId);
                    if (existingUserCreds.some(c => bufferToBase64url(c.credentialId) === newCredIdB64)) {
                        console.warn(`Credential ID ${newCredIdB64} already registered for user ${userId}.`);
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
                    console.error("Registration verification failed:", error);
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: error.message || 'Registration verification failed.' }));
                }
            });

        } else if (pathname === '/login/start' && method === 'POST') {
            let body = '';
            req.on('data', chunk => { body += chunk.toString(); });
            req.on('end', async () => {
                try {
                    const { username } = JSON.parse(body); // Expect username to identify user
                    if (!username) {
                        throw new Error('Username missing in login start request.');
                    }

                    const userId = usernameToUserId.get(username);
                    if (!userId) {
                        throw new Error(`User '${username}' not found.`);
                    }

                    const userCredentials = credentialStore.get(userId) || [];

                    // We only need to send allowed credential IDs
                    const allowCredentials = userCredentials.map(cred => ({
                        type: 'public-key',
                        id: bufferToBase64url(cred.credentialId),
                    }));

                    const challengeBuffer = generateChallenge();
                    const loginChallengeKey = `login_${userId}_${Date.now()}`;
                    challengeStore.set(loginChallengeKey, challengeBuffer); // Store challenge

                    const publicKeyCredentialRequestOptions = {
                        challenge: bufferToBase64url(challengeBuffer),
                        allowCredentials: allowCredentials,
                        rpId: rpId,
                        userVerification: 'required',
                        timeout: 60000,
                    };

                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ options: publicKeyCredentialRequestOptions, challengeKey: loginChallengeKey }));

                } catch (error) {
                    console.error('Login start failed:', error);
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: error.message || 'Login start failed.' }));
                }
            });

        } else if (pathname === '/login/finish' && method === 'POST') {
            let body = '';
            req.on('data', chunk => { body += chunk.toString(); });
            req.on('end', async () => {
                let challengeKey, assertion;
                try {
                    console.log('Received login finish request body:', body);
                    let parsedBody = JSON.parse(body);
                    challengeKey = parsedBody.challengeKey;
                    assertion = parsedBody.assertion;
                } catch (error) {
                    console.error('Login finish request body parsing failed:', error);
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'Invalid request body.' }));
                    return;
                }
                try {
                    

                    if (!challengeKey || !assertion) {
                        throw new Error('Missing challengeKey or assertion in request body.');
                    }

                    // 1. Get the challenge stored for this login attempt
                    const expectedChallengeBuffer = challengeStore.get(challengeKey);
                    if (!expectedChallengeBuffer) {
                        throw new Error('No challenge found for this login attempt. Timed out or invalid.');
                    }
                    const expectedChallenge = bufferToBase64url(expectedChallengeBuffer);
                    challengeStore.delete(challengeKey); // Challenge should be used only once

                    // 2. Find the stored credential based on assertion.rawId
                    const credentialIdToLookup = base64urlToBuffer(assertion.rawId);
                    let userId = null;
                    let storedCredential = null;

                    for (const [uid, credentials] of credentialStore.entries()) {
                        const foundCred = credentials.find(c => bufferEqual(c.credentialId, credentialIdToLookup));
                        if (foundCred) {
                            storedCredential = foundCred;
                            userId = uid;
                            break;
                        }
                    }

                    if (!userId || !storedCredential) {
                        throw new Error("Credential ID not recognized or user not found.");
                    }
                    const user = userStore.get(userId);
                    if (!user) { throw new Error("User associated with credential not found."); }

                    // Add the properties expected by verifyAssertionResponse
                    storedCredential.publicKey = storedCredential.credentialPublicKey;
                    storedCredential.id = bufferToBase64url(storedCredential.credentialId);

                    // 3. Verify the assertion response
                    const requireUserVerification = true;
                    const verificationResult = await verifyAssertionResponse(
                        assertion,
                        storedCredential,
                        expectedChallenge,
                        expectedOrigin,
                        rpId,
                        requireUserVerification
                    );

                    // 4. Update the stored signature counter
                    storedCredential.signCount = verificationResult.newSignCount;
                    console.log(`Updated sign count for credential ${assertion.id} to ${verificationResult.newSignCount}`);
                    // In a real DB, you would SAVE the updated credentialStore entry here.

                    // 5. Login successful - Establish session, etc.
                    console.log(`User ${user.name} logged in successfully.`);

                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        success: true,
                        message: `Welcome ${user.name}!`,
                        username: user.name,
                        userVerified: verificationResult.userVerified
                    }));

                } catch (error) {
                    console.error('Login verification failed:', error);
                    challengeStore.delete(challengeKey); // Clean up challenge if verification fails
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: error.message || 'Login verification failed.' }));
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