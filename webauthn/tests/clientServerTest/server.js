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
    bufferEqual
} = require('../../index');

// --- Load AAGUID to Authenticator Name Mapping from JSON file ---
let authenticatorNameMap = {};
try {
    const mapFilePath = path.join(__dirname, 'authenticatorNameMap.json');
    const mapData = fs.readFileSync(mapFilePath, 'utf8');
    authenticatorNameMap = JSON.parse(mapData);
    console.log(`Loaded ${Object.keys(authenticatorNameMap).length} authenticator mappings`);
} catch (error) {
    console.error('Error loading authenticatorNameMap.json:', error);
    // Fallback to basic mapping if file can't be loaded
    authenticatorNameMap = {
        "00000000000000000000000000000000": "Software/Virtual Authenticator"
    };
}

// Helper function to get authenticator info from the attestation statement
function getAuthenticatorInfo(attestationObject) {
    try {
        // Decode the attestation object
        const attestationBuffer = base64urlToBuffer(attestationObject);
        const CBOR = require('../../cbor'); // You would need to add this dependency
        const arrayBuffer = attestationBuffer instanceof ArrayBuffer
            ? attestationBuffer
            : new Uint8Array(attestationBuffer).buffer;

        const attestation = CBOR.decode(arrayBuffer);
        const authData = attestation.authData;

        // Extract the AAGUID (starts at byte 37, 16 bytes long in the authenticator data)
        const aaguidBuffer = authData.slice(37, 37 + 16);

        // Format AAGUID as standard GUID with dashes (8-4-4-4-12 format)
        // Convert to hex and insert dashes
        const hex = Buffer.from(aaguidBuffer).toString('hex');
        const aaguid = [
            hex.slice(0, 8),
            hex.slice(8, 12),
            hex.slice(12, 16),
            hex.slice(16, 20),
            hex.slice(20, 32)
        ].join('-');

        // Get the name from our mapping
        const name = authenticatorNameMap[aaguid] || "Unknown Authenticator";

        return {
            aaguid: aaguid,
            name: name
        };
    } catch (error) {
        console.error("Error extracting authenticator info:", error);
        return {
            aaguid: "unknown",
            name: "Unknown Authenticator"
        };
    }
}

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

    // Enable CORS for all requests
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

    // Handle preflight requests
    if (method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
    }

    try {
        // --- API Endpoints ---
        if (pathname === '/register/start' && method === 'POST') {
            let body = '';
            req.on('data', chunk => { body += chunk.toString(); });
            req.on('end', async () => {
                try {
                    let username, userId, user;

                    // Parse the request body to get the username
                    try {
                        const parsed = JSON.parse(body);
                        username = parsed.username;
                    } catch (e) {
                        console.error("Error parsing request body:", e);
                        // If no JSON body provided, create a new user
                    }

                    // Check if this is an existing user
                    if (username && usernameToUserId.has(username)) {
                        userId = usernameToUserId.get(username);
                        user = userStore.get(userId);
                        console.log(`Using existing user: ${username} (${userId})`);
                    } else {
                        // Create a new user
                        userId = generateUserId();
                        username = username || `user_${userId.substring(0, 4)}`;
                        const userDisplayName = `Demo User ${username}`;

                        user = { id: userId, name: username, displayName: userDisplayName };
                        userStore.set(userId, user);
                        usernameToUserId.set(username, userId); // Map username for login lookup
                        console.log(`Created new user: ${username} (${userId})`);
                    }

                    const challengeBuffer = generateChallenge();
                    challengeStore.set(userId, challengeBuffer); // Store challenge associated with user

                    // Get existing credentials to exclude them
                    const existingCredentials = credentialStore.get(userId) || [];
                    const excludeCredentials = existingCredentials.map(cred => ({
                        type: 'public-key',
                        id: bufferToBase64url(cred.credentialId)
                    }));

                    const publicKeyCredentialCreationOptions = {
                        challenge: bufferToBase64url(challengeBuffer),
                        rp: {
                            name: rpName,
                            id: rpId,
                        },
                        user: {
                            id: bufferToBase64url(Buffer.from(userId)), // User ID must be base64url encoded Buffer
                            name: user.name,
                            displayName: user.displayName,
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
                        attestation: 'direct',
                        excludeCredentials: excludeCredentials.length > 0 ? excludeCredentials : undefined
                    };

                    // Send back options and the temporary userId for the client to use
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        options: publicKeyCredentialCreationOptions,
                        userId: userId
                    }));
                } catch (error) {
                    console.error("Registration start error:", error);
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: error.message || 'Registration start failed.' }));
                }
            });

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

                    // 4. Extract and store authenticator information
                    let authenticatorInfo = {};
                    try {
                        if (credential.response.attestationObject) {
                            // Try to get information from attestation
                            authenticatorInfo = getAuthenticatorInfo(credential.response.attestationObject);
                        }

                        // Add authenticator attachment information if available
                        if (credential.authenticatorAttachment) {
                            authenticatorInfo.authenticatorAttachment = credential.authenticatorAttachment;
                        }

                        // Default if not detected
                        if (!authenticatorInfo.authenticatorAttachment) {
                            authenticatorInfo.authenticatorAttachment = 'platform'; // or 'cross-platform'
                        }
                    } catch (error) {
                        console.error("Error extracting authenticator info:", error);
                        authenticatorInfo = {
                            authenticatorAttachment: credential.authenticatorAttachment || 'unknown',
                            aaguid: 'unknown',
                            name: 'Unknown Authenticator'
                        };
                    }

                    // Add authenticator info to credential
                    credentialInfo.authenticatorName = authenticatorInfo.name;
                    credentialInfo.authenticatorAttachment = authenticatorInfo.authenticatorAttachment;
                    credentialInfo.aaguid = authenticatorInfo.aaguid;
                    credentialInfo.createdAt = Date.now();

                    existingUserCreds.push(credentialInfo);
                    console.log(`Credential stored successfully for user ${userId}:`, {
                        id: bufferToBase64url(credentialInfo.credentialId),
                        fmt: credentialInfo.attestationFormat,
                        count: credentialInfo.signCount,
                        authenticator: authenticatorInfo
                    });

                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        success: true,
                        message: 'Registration successful!',
                        authenticatorInfo: authenticatorInfo
                    }));

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

        } else if (pathname === '/user/credentials' && method === 'POST') {
            let body = '';
            req.on('data', chunk => { body += chunk.toString(); });
            req.on('end', async () => {
                try {
                    const { username } = JSON.parse(body);
                    if (!username) {
                        throw new Error('Username missing in credentials request.');
                    }

                    const userId = usernameToUserId.get(username);
                    if (!userId) {
                        throw new Error(`User '${username}' not found.`);
                    }

                    const userCredentials = credentialStore.get(userId) || [];

                    // Map credentials to a more client-friendly format
                    const clientCredentials = userCredentials.map(cred => ({
                        id: bufferToBase64url(cred.credentialId),
                        authenticatorName: cred.authenticatorName || 'Unknown',
                        authenticatorAttachment: cred.authenticatorAttachment || 'Unknown',
                        aaguid: cred.aaguid || 'Unknown',
                        createdAt: cred.createdAt || Date.now()
                    }));

                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        success: true,
                        username: username,
                        credentials: clientCredentials
                    }));

                } catch (error) {
                    console.error('Error fetching user credentials:', error);
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        success: false,
                        error: error.message || 'Failed to fetch credentials.'
                    }));
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