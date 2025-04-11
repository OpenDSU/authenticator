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

// --- DOM Elements ---
const registerButton = document.getElementById('registerButton');
const messageDiv = document.getElementById('message');

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