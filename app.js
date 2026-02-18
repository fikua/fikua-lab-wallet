(() => {
    // Theme toggle
    const html = document.documentElement;
    const saved = localStorage.getItem('fikua-theme');
    if (saved) {
        html.setAttribute('data-theme', saved);
    } else if (window.matchMedia('(prefers-color-scheme: dark)').matches) {
        html.setAttribute('data-theme', 'dark');
    }
    document.querySelectorAll('.theme-toggle').forEach(btn => {
        btn.addEventListener('click', () => {
            const next = html.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
            html.setAttribute('data-theme', next);
            localStorage.setItem('fikua-theme', next);
        });
    });

    const PASSKEY_KEY = 'fikua_passkey';
    const SESSION_KEY = 'fikua_session';
    const USER_KEY = 'fikua_user';

    // --- Screens ---
    const screenLogin = document.getElementById('screen-login');
    const screenWallet = document.getElementById('screen-wallet');

    // --- Login phases ---
    const loginPhaseStart = document.getElementById('login-phase-start');
    const loginPhaseCreate = document.getElementById('login-phase-create');
    const loginPhaseLoading = document.getElementById('login-phase-loading');

    function showScreen(name) {
        screenLogin.classList.toggle('hidden', name !== 'login');
        screenWallet.classList.toggle('hidden', name !== 'wallet');
    }

    function showLoginPhase(name) {
        loginPhaseStart.classList.toggle('hidden', name !== 'start');
        loginPhaseCreate.classList.toggle('hidden', name !== 'create');
        loginPhaseLoading.classList.toggle('hidden', name !== 'loading');
    }

    // --- Passkey ---
    function hasPasskey() {
        return !!localStorage.getItem(PASSKEY_KEY);
    }

    function hasSession() {
        return !!sessionStorage.getItem(SESSION_KEY);
    }

    async function createPasskey() {
        showLoginPhase('loading');
        document.querySelector('.login-status').textContent = 'Setting up passkey...';

        try {
            if (window.PublicKeyCredential) {
                const challenge = crypto.getRandomValues(new Uint8Array(32));
                const credential = await navigator.credentials.create({
                    publicKey: {
                        challenge,
                        rp: { name: 'Fikua Lab Wallet', id: window.location.hostname },
                        user: {
                            id: crypto.getRandomValues(new Uint8Array(16)),
                            name: 'wallet@fikua.com',
                            displayName: 'Fikua Wallet User'
                        },
                        pubKeyCredParams: [
                            { alg: -7, type: 'public-key' },
                            { alg: -257, type: 'public-key' }
                        ],
                        authenticatorSelection: {
                            authenticatorAttachment: 'platform',
                            userVerification: 'required',
                            residentKey: 'preferred'
                        },
                        timeout: 60000
                    }
                });

                localStorage.setItem(PASSKEY_KEY, JSON.stringify({
                    created: Date.now(),
                    credentialId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                    type: 'webauthn'
                }));
            } else {
                // Fallback for non-WebAuthn browsers
                localStorage.setItem(PASSKEY_KEY, JSON.stringify({
                    created: Date.now(),
                    type: 'simulated'
                }));
            }

            startSession();
            showWallet();
        } catch (err) {
            console.error('Passkey creation failed:', err);
            showLoginPhase('create');
        }
    }

    async function authenticatePasskey() {
        showLoginPhase('loading');
        document.querySelector('.login-status').textContent = 'Authenticating...';

        try {
            if (window.PublicKeyCredential) {
                const challenge = crypto.getRandomValues(new Uint8Array(32));
                const credential = await navigator.credentials.get({
                    publicKey: {
                        challenge,
                        rpId: window.location.hostname,
                        userVerification: 'required',
                        timeout: 60000
                    }
                });

                // Restore local reference if it was cleared
                if (!hasPasskey()) {
                    localStorage.setItem(PASSKEY_KEY, JSON.stringify({
                        created: Date.now(),
                        credentialId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                        type: 'webauthn'
                    }));
                }
            }

            startSession();
            showWallet();
        } catch (err) {
            console.error('Authentication failed:', err);
            showLoginPhase('create');
        }
    }

    function startSession() {
        sessionStorage.setItem(SESSION_KEY, Date.now().toString());
        localStorage.setItem(USER_KEY, JSON.stringify({ name: 'Wallet User' }));
    }

    function endSession() {
        sessionStorage.removeItem(SESSION_KEY);
    }

    // --- Login events ---
    document.getElementById('btn-login').addEventListener('click', () => {
        authenticatePasskey();
    });

    document.getElementById('btn-create-passkey').addEventListener('click', createPasskey);

    document.getElementById('btn-logout').addEventListener('click', () => {
        endSession();
        showScreen('login');
        showLoginPhase(hasPasskey() ? 'start' : 'create');
    });

    // --- Wallet ---
    function showWallet() {
        const user = JSON.parse(localStorage.getItem(USER_KEY) || '{}');
        document.getElementById('greeting').textContent = `Hello, ${user.name || 'User'}`;
        showScreen('wallet');
    }

    // --- Tabs ---
    document.querySelectorAll('.tab').forEach(tab => {
        tab.addEventListener('click', () => {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
            tab.classList.add('active');
            document.getElementById(`tab-${tab.dataset.tab}`).classList.remove('hidden');
        });
    });

    // --- QR Scanner ---
    const qrModal = document.getElementById('qr-modal');
    const qrVideo = document.getElementById('qr-video');
    let mediaStream = null;

    document.getElementById('btn-scan').addEventListener('click', () => {
        qrModal.showModal();
        startCamera();
    });

    document.getElementById('btn-close-qr').addEventListener('click', closeQrModal);

    qrModal.addEventListener('close', stopCamera);

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && qrModal.open) closeQrModal();
    });

    async function startCamera() {
        try {
            mediaStream = await navigator.mediaDevices.getUserMedia({
                video: { facingMode: 'environment' }
            });
            qrVideo.srcObject = mediaStream;
            document.querySelector('.qr-fallback').classList.add('hidden');
        } catch {
            document.querySelector('.qr-fallback').classList.remove('hidden');
        }
    }

    function stopCamera() {
        if (mediaStream) {
            mediaStream.getTracks().forEach(track => track.stop());
            mediaStream = null;
        }
        qrVideo.srcObject = null;
    }

    function closeQrModal() {
        stopCamera();
        qrModal.close();
    }

    // Simulate scan
    document.getElementById('btn-simulate-scan').addEventListener('click', () => {
        closeQrModal();
        addDemoCredential();
    });

    function addDemoCredential() {
        const list = document.getElementById('credentials-list');
        const emptyState = list.querySelector('.empty-state');
        if (emptyState) emptyState.remove();

        const card = document.createElement('div');
        card.className = 'credential-card';
        card.innerHTML = `
            <div class="credential-header">
                <div class="credential-icon">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                </div>
                <div class="credential-title">
                    <strong>University Diploma</strong>
                    <span>Issued by Fikua Lab Issuer</span>
                </div>
                <span class="credential-status status--valid">VALID</span>
            </div>
            <div class="credential-details">
                <span>sd_jwt_vc</span>
                <span>ES256</span>
                <span>Issued: ${new Date().toISOString().slice(0, 10)}</span>
            </div>
        `;
        list.prepend(card);

        // Add activity entry
        addActivityEntry('Credential received', 'University Diploma', 'issued');
    }

    function addActivityEntry(action, credential, type) {
        const list = document.getElementById('activity-list');
        const emptyState = list.querySelector('.empty-state');
        if (emptyState) emptyState.remove();

        const item = document.createElement('div');
        item.className = 'activity-item';
        item.innerHTML = `
            <span class="activity-dot activity-dot--${type}"></span>
            <div class="activity-info">
                <strong>${esc(action)}</strong>
                <span>${esc(credential)}</span>
            </div>
            <span class="activity-time">${new Date().toLocaleTimeString()}</span>
        `;
        list.prepend(item);
    }

    function esc(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    // --- Init ---
    const params = new URLSearchParams(window.location.search);
    if (params.get('reset') === 'passkey') {
        localStorage.removeItem(PASSKEY_KEY);
        localStorage.removeItem(USER_KEY);
        sessionStorage.removeItem(SESSION_KEY);
        window.history.replaceState({}, '', window.location.pathname);
    }

    if (hasSession()) {
        showWallet();
    } else {
        showScreen('login');
        showLoginPhase(hasPasskey() ? 'start' : 'create');
    }
})();
