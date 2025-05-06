// --- DOM Elements ---
const registerButton = document.getElementById('registerButton');
const loginButton = document.getElementById('loginButton');
const usernameInput = document.getElementById('username');
const registerUsernameInput = document.getElementById('registerUsername');
const messageDiv = document.getElementById('message');
const loggedInUserDiv = document.getElementById('loggedInUser');
const authenticatorInfoDiv = document.getElementById('authenticatorInfo');
const credentialListDiv = document.getElementById('credentialList');

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

// Function to display user's registered authenticators
async function displayUserCredentials() {
    const username = registerUsernameInput.value;
    if (!username) {
        messageDiv.textContent = 'Please enter a username';
        messageDiv.className = 'error';
        return;
    }

    try {
        messageDiv.textContent = `Fetching credentials for ${username}...`;

        const response = await fetch('/user/credentials', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.error || response.statusText);
        }

        const { credentials } = await response.json();

        if (!credentials || credentials.length === 0) {
            credentialListDiv.innerHTML = '<p>No credentials registered for this user.</p>';
            messageDiv.textContent = `No credentials found for ${username}`;
            return;
        }

        let html = '<h3>Registered Authenticators</h3><ul class="credential-list">';
        credentials.forEach(cred => {
            // Determine authenticator type label
            let typeLabel = 'Unknown';
            if (cred.authenticatorAttachment === 'platform') {
                typeLabel = 'Built-in Authenticator';
            } else if (cred.authenticatorAttachment === 'cross-platform') {
                typeLabel = 'External Authenticator';
            }

            html += `
            <li class="credential-item">
                <div class="credential-name">${cred.authenticatorName || 'Unknown Authenticator'}</div>
                <div class="credential-details">
                    <span class="credential-type">${typeLabel}</span>
                    <span class="credential-date">Created: ${new Date(cred.createdAt).toLocaleString()}</span>
                </div>
                <div class="credential-aaguid">AAGUID: ${cred.aaguid}</div>
            </li>`;
        });
        html += '</ul>';

        credentialListDiv.innerHTML = html;
        messageDiv.textContent = `Found ${credentials.length} credential(s) for ${username}`;
        messageDiv.className = 'success';
    } catch (err) {
        console.error('Error fetching credentials:', err);
        credentialListDiv.innerHTML = `<p class="error">Error: ${err.message}</p>`;
        messageDiv.textContent = `Error: ${err.message}`;
        messageDiv.className = 'error';
    }
}

// --- Registration Logic ---
registerButton.addEventListener('click', async () => {
    const username = registerUsernameInput.value;
    if (!username) {
        messageDiv.textContent = 'Please enter a username for registration';
        messageDiv.className = 'error';
        return;
    }

    messageDiv.textContent = 'Starting registration...';
    messageDiv.className = ''; // Clear previous styles
    authenticatorInfoDiv.textContent = '';
    authenticatorInfoDiv.style.display = 'none';

    try {
        // 1. Request registration options from the server
        const startResponse = await fetch('/register/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username })
        });

        if (!startResponse.ok) {
            const errorData = await startResponse.json();
            throw new Error(`Failed to start registration: ${errorData.error || startResponse.statusText}`);
        }
        const { options: creationOptions, userId } = await startResponse.json();

        console.log('Received creation options:', creationOptions);
        console.log('Using User ID:', userId);

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

        // Include authenticator attachment if available
        if (credential.authenticatorAttachment) {
            credentialForServer.authenticatorAttachment = credential.authenticatorAttachment;
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

        // Display authenticator information
        if (finishResult.authenticatorInfo) {
            const info = finishResult.authenticatorInfo;
            authenticatorInfoDiv.style.display = 'block';
            authenticatorInfoDiv.innerHTML = `
                <h3>Authenticator Information</h3>
                <p><strong>Type:</strong> ${info.authenticatorAttachment || 'Unknown'}</p>
                <p><strong>AAGUID:</strong> ${info.aaguid || 'Unknown'}</p>
                <p><strong>Name:</strong> ${info.name || 'Unknown'}</p>
            `;
        }

        // Update the credentials list
        await displayUserCredentials();

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

// Event listener for the credential list button
document.getElementById('showCredentialsButton').addEventListener('click', displayUserCredentials); 