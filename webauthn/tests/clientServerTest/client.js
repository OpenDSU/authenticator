// --- DOM Elements ---
const registerButton = document.getElementById('registerButton');
const loginButton = document.getElementById('loginButton');
const usernameInput = document.getElementById('username');
const messageDiv = document.getElementById('message');
const loggedInUserDiv = document.getElementById('loggedInUser');

// --- Helper Functions (from server, simplified for client) ---

// Converts buffer to base64url
function bufferToBase64url(buffer) {
    const base64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

// Converts base64url to Buffer
function base64urlToBuffer(base64urlString) {
    const base64 = base64urlString.replace(/-/g, '+').replace(/_/g, '/');
    const raw = atob(base64);
    const buffer = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) {
        buffer[i] = raw.charCodeAt(i);
    }
    return buffer.buffer; // Return ArrayBuffer
}

// --- Registration Logic ---
registerButton.addEventListener('click', async () => {
    messageDiv.textContent = 'Starting registration...';
    messageDiv.className = ''; // Clear previous styles

    try {
        // 1. Request registration options from the server
        const startResponse = await fetch('/register/start', { method: 'POST' });
        if (!startResponse.ok) {
            const errorData = await startResponse.json();
            throw new Error(`Failed to start registration: ${errorData.error || startResponse.statusText}`);
        }
        const { options: creationOptions, userId } = await startResponse.json();

        console.log('Received creation options:', creationOptions);
        console.log('Using temporary User ID:', userId);

        // 2. Prepare options for navigator.credentials.create()
        // Need to decode base64url fields back to ArrayBuffers
        creationOptions.challenge = base64urlToBuffer(creationOptions.challenge);
        creationOptions.user.id = base64urlToBuffer(creationOptions.user.id);
        if (creationOptions.excludeCredentials) {
            creationOptions.excludeCredentials = creationOptions.excludeCredentials.map(cred => ({
                ...cred,
                id: base64urlToBuffer(cred.id)
            }));
        }

        // 3. Call navigator.credentials.create()
        messageDiv.textContent = 'Waiting for authenticator interaction...';
        const credential = await navigator.credentials.create({ publicKey: creationOptions });

        console.log('Credential created:', credential);
        messageDiv.textContent = 'Sending credential to server for verification...';

        // 4. Prepare credential for sending to server
        // Need to encode ArrayBuffers to base64url
        const credentialForServer = {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
                attestationObject: bufferToBase64url(credential.response.attestationObject),
            },
        };
        // Include transports if available
        if (credential.response.getTransports) {
            credentialForServer.response.transports = credential.response.getTransports();
        }

        // 5. Send credential to server for verification and storage
        const finishResponse = await fetch('/register/finish', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ userId: userId, credential: credentialForServer })
        });

        const finishResult = await finishResponse.json();

        if (!finishResponse.ok || !finishResult.success) {
            throw new Error(`Registration failed on server: ${finishResult.error || 'Unknown error'}`);
        }

        console.log('Server verification successful:', finishResult);
        messageDiv.textContent = 'Registration successful!';
        messageDiv.className = 'success';

    } catch (err) {
        console.error('Registration error:', err);
        messageDiv.textContent = `Error: ${err.message}`;
        messageDiv.className = 'error';
    }
}); 

// --- Login Logic ---
loginButton.addEventListener('click', async () => {
    const username = usernameInput.value;
    if (!username) {
        messageDiv.textContent = 'Please enter a username to log in.';
        messageDiv.className = 'error';
        return;
    }

    messageDiv.textContent = `Starting login for ${username}...`;
    messageDiv.className = '';
    loggedInUserDiv.textContent = '';

    try {
        // 1. Request login options from the server
        const startResponse = await fetch('/login/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: username })
        });
        if (!startResponse.ok) {
            const errorData = await startResponse.json();
            throw new Error(`Failed to start login: ${errorData.error || startResponse.statusText}`);
        }
        const { options: requestOptions, challengeKey } = await startResponse.json();

        console.log('Received request options:', requestOptions);

        // 2. Prepare options for navigator.credentials.get()
        requestOptions.challenge = base64urlToBuffer(requestOptions.challenge);
        if (requestOptions.allowCredentials) {
            requestOptions.allowCredentials = requestOptions.allowCredentials.map(cred => ({
                ...cred,
                id: base64urlToBuffer(cred.id)
            }));
        }

        // 3. Call navigator.credentials.get()
        messageDiv.textContent = 'Waiting for authenticator interaction...';
        const assertion = await navigator.credentials.get({ publicKey: requestOptions });

        console.log('Assertion created:', assertion);
        messageDiv.textContent = 'Sending assertion to server for verification...';

        // 4. Prepare assertion for sending to server
        const assertionForServer = {
            id: assertion.id,
            rawId: bufferToBase64url(assertion.rawId),
            type: assertion.type,
            response: {
                authenticatorData: bufferToBase64url(assertion.response.authenticatorData),
                clientDataJSON: bufferToBase64url(assertion.response.clientDataJSON),
                signature: bufferToBase64url(assertion.response.signature),
                userHandle: assertion.response.userHandle ? bufferToBase64url(assertion.response.userHandle) : null,
            },
        };

        // 5. Send assertion to server for verification
        const finishResponse = await fetch('/login/finish', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ challengeKey: challengeKey, assertion: assertionForServer })
        });

        const finishResult = await finishResponse.json();

        if (!finishResponse.ok || !finishResult.success) {
            throw new Error(`Login failed on server: ${finishResult.error || 'Unknown error'}`);
        }

        console.log('Server verification successful:', finishResult);
        messageDiv.textContent = 'Login successful!';
        messageDiv.className = 'success';
        loggedInUserDiv.textContent = `Logged in as: ${finishResult.username} (User Verified: ${finishResult.userVerified})`;

    } catch (err) {
        console.error('Login error:', err);
        // Handle specific errors like "NotAllowedError" if the user cancels
        if (err.name === 'NotAllowedError') {
             messageDiv.textContent = 'Login cancelled or no matching credentials found.';
        } else {
            messageDiv.textContent = `Error: ${err.message}`;
        }
        messageDiv.className = 'error';
    }
}); 