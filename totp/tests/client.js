document.addEventListener('DOMContentLoaded', () => {
    const qrCodeContainer = document.getElementById('qrcode');
    const registerBtn = document.getElementById('register-btn');
    const verifyForm = document.getElementById('verify-form');
    const totpCodeInput = document.getElementById('totp-code');
    const statusDiv = document.getElementById('status');
    const secretDisplay = document.getElementById('secret-display');

    // --- Helper Function to Update Status ---
    function updateStatus(message, isError = false) {
        statusDiv.textContent = message;
        statusDiv.className = isError ? 'error' : 'success';
        if (!message) {
            statusDiv.textContent = 'Status messages will appear here.'; // Default text
             statusDiv.className = ''; // Default class
        }
    }

    // --- Check if QRCode library is loaded ---
    if (!qrCodeContainer || !registerBtn || !verifyForm || !totpCodeInput || !statusDiv || !secretDisplay) {
        console.error("One or more required HTML elements not found!");
        updateStatus('Initialization Error: Missing HTML elements. Check console.', true);
        return;
    }
    if (typeof QRCode === 'undefined') {
        updateStatus('Error: QRCode library not loaded. Check script tag in index.html', true);
        console.error('QRCode library not loaded. Check script tag in index.html');
        return;
    }

    // --- Registration Logic ---
    registerBtn.addEventListener('click', () => {
        updateStatus('Registering...');
        qrCodeContainer.innerHTML = 'Generating QR Code...'; // Clear previous QR
        secretDisplay.textContent = 'Requesting...';

        fetch('/register', { method: 'POST' })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(errData => {
                        throw new Error(errData.message || `HTTP error! status: ${response.status}`);
                    });
                }
                return response.json();
            })
            .then(data => {
                if (data && data.uri && data.secret) {
                    console.log('Registration successful, received URI:', data.uri);
                    qrCodeContainer.innerHTML = ''; // Clear loading message
                    secretDisplay.textContent = data.secret; // Display secret for debugging

                    try {
                        new QRCode(qrCodeContainer, {
                            text: data.uri,
                            width: 256,
                            height: 256,
                            colorDark: "#000000",
                            colorLight: "#ffffff",
                            correctLevel: QRCode.CorrectLevel.H
                        });
                        updateStatus('Registration initiated. Scan the QR code with your authenticator app.');
                    } catch (e) {
                        console.error("Error generating QR Code:", e);
                        updateStatus('Error generating QR Code. See console.', true);
                        qrCodeContainer.innerHTML = 'Error.';
                    }
                } else {
                    throw new Error('Invalid registration data received from server');
                }
            })
            .catch(error => {
                console.error('Error during registration:', error);
                updateStatus(`Registration failed: ${error.message}`, true);
                qrCodeContainer.innerHTML = 'Failed to load QR Code.';
                secretDisplay.textContent = 'Error';
            });
    });

    // --- Verification Logic ---
    verifyForm.addEventListener('submit', (event) => {
        event.preventDefault(); // Prevent page reload
        const token = totpCodeInput.value.trim();

        if (!token || !/^[0-9]{6}$/.test(token)) {
            updateStatus('Please enter a valid 6-digit code.', true);
            return;
        }

        updateStatus('Verifying code...');

        fetch('/verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ token: token, username: 'testuser' }) // Sending username too
        })
        .then(response => {
            // We need to check status code *and* the verified flag in the JSON
            return response.json().then(data => ({
                 ok: response.ok,
                 verified: data.verified,
                 message: data.message
             }));
        })
        .then(result => {
             if (result.ok && result.verified) {
                 console.log('Verification successful:', result.message);
                 updateStatus(`Verification successful! ${result.message || ''}`);
                 totpCodeInput.value = ''; // Clear input on success
             } else {
                 console.log('Verification failed:', result.message);
                 throw new Error(result.message || 'Verification failed. Invalid code?');
             }
         })
        .catch(error => {
            console.error('Error during verification:', error);
            updateStatus(`Verification failed: ${error.message}`, true);
        });
    });

    // Initial status
    updateStatus('Ready. Click Register to start.');
});