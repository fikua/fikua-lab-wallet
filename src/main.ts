import './style.css';

import {
    ISSUER_BASE, WALLET_BASE, PASSKEY_KEY, SESSION_KEY, USER_KEY,
    PRIVACY_KEY, AUTH_FLOW_KEY, PENDING_OFFER_KEY, PRE_AUTH_GRANT,
} from './constants';
import { esc, formatTime, formatDate, generateRandomString } from './utils';
import {
    generateHolderKeyPair, generateExtractableKeyPair, generatePkce,
    exportKeyPair, importKeyPair,
} from './crypto';
import { openDb, saveCredential, getCredential, getAllCredentials, deleteCredentialById, logActivity, getAllActivity } from './storage';
import { parseSdJwt } from './sdjwt';
import { parseMdoc } from './mdoc';
import { startScanning } from './qr-scanner';
import {
    parseCredentialOfferFromUrl, fetchCredentialOffer,
    fetchIssuerMetadata, fetchAuthServerMetadata,
    analyzeGrant, requestToken, requestNonce,
    buildProofJwt, requestCredential, sendNotification,
    buildDpopProof, generateWia, generateWiaPop,
    pushAuthorizationRequest, getPreAuthCode, getPreAuthTxCode,
    fetchRequestObject, buildVpToken, submitPresentation,
} from './protocol';
import type {
    CredentialOffer, CredentialIssuerMetadata, AuthServerMetadata,
    CredentialResponse, GrantInfo, OfferData, StoredCredential,
    AuthFlowState, AuthCodeGrant,
} from './types';

// =========================================================================
// DOM References
// =========================================================================

const $ = (id: string) => document.getElementById(id)!;

const screenLogin = $('screen-login');
const screenWallet = $('screen-wallet');
const screenFlow = $('screen-flow');
const screenDetail = $('screen-detail');

// =========================================================================
// Screen Navigation
// =========================================================================

function showScreen(name: 'login' | 'wallet' | 'flow' | 'detail'): void {
    screenLogin.classList.toggle('hidden', name !== 'login');
    screenWallet.classList.toggle('hidden', name !== 'wallet');
    screenFlow.classList.toggle('hidden', name !== 'flow');
    screenDetail.classList.toggle('hidden', name !== 'detail');
}

function showLoginPhase(name: 'start' | 'create' | 'install' | 'loading'): void {
    $('login-phase-start').classList.toggle('hidden', name !== 'start');
    $('login-phase-create').classList.toggle('hidden', name !== 'create');
    $('login-phase-install').classList.toggle('hidden', name !== 'install');
    $('login-phase-loading').classList.toggle('hidden', name !== 'loading');
}

function showFlowPhase(phase: 'processing' | 'consent' | 'error'): void {
    $('flow-processing').classList.toggle('hidden', phase !== 'processing');
    $('flow-consent').classList.toggle('hidden', phase !== 'consent');
    $('flow-error').classList.toggle('hidden', phase !== 'error');
}

function updateFlowStatus(msg: string): void {
    $('flow-status').textContent = msg;
    plog('step', msg);
}

function showFlowError(msg: string): void {
    showFlowPhase('error');
    $('flow-error-msg').textContent = msg;
    plog('error', msg);
}

// =========================================================================
// Protocol Log
// =========================================================================

interface LogEntry {
    time: string;
    level: 'info' | 'step' | 'error' | 'ok';
    message: string;
}

const protocolLogs: LogEntry[] = [];
const MAX_LOGS = 200;

function plog(level: LogEntry['level'], message: string): void {
    const now = new Date();
    const time = now.toLocaleTimeString('en-GB', { hour12: false }) + '.' + String(now.getMilliseconds()).padStart(3, '0');
    protocolLogs.push({ time, level, message });
    if (protocolLogs.length > MAX_LOGS) protocolLogs.shift();
    renderLogs();
}

function renderLogs(): void {
    const container = document.getElementById('logs-list');
    if (!container) return;
    const empty = container.querySelector('.empty-state');
    if (empty && protocolLogs.length > 0) empty.remove();

    // Only append the last entry for performance
    const entry = protocolLogs[protocolLogs.length - 1];
    const div = document.createElement('div');
    div.className = 'log-entry log-' + entry.level;
    div.innerHTML = '<span class="log-time">' + esc(entry.time) + '</span>'
        + '<span class="log-level">' + esc(entry.level.toUpperCase()) + '</span>'
        + '<span class="log-msg">' + esc(entry.message) + '</span>';
    container.appendChild(div);
    container.scrollTop = container.scrollHeight;
}

// =========================================================================
// Theme
// =========================================================================

const html = document.documentElement;
const savedTheme = localStorage.getItem('fikua-theme');
if (savedTheme) {
    html.setAttribute('data-theme', savedTheme);
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

// =========================================================================
// Privacy Mode
// =========================================================================

let privacyMode = localStorage.getItem(PRIVACY_KEY) === 'true';

function applyPrivacy(): void {
    document.body.classList.toggle('privacy-blur', privacyMode);
    document.querySelectorAll('.icon-eye').forEach(el => el.classList.toggle('hidden', privacyMode));
    document.querySelectorAll('.icon-eye-off').forEach(el => el.classList.toggle('hidden', !privacyMode));
}

function togglePrivacy(): void {
    privacyMode = !privacyMode;
    localStorage.setItem(PRIVACY_KEY, privacyMode.toString());
    applyPrivacy();
}

$('btn-privacy').addEventListener('click', togglePrivacy);
$('btn-privacy-detail').addEventListener('click', togglePrivacy);

// =========================================================================
// Passkey Auth
// =========================================================================

function hasPasskey(): boolean { return !!localStorage.getItem(PASSKEY_KEY); }
function hasSession(): boolean { return !!sessionStorage.getItem(SESSION_KEY); }

function startSession(): void {
    sessionStorage.setItem(SESSION_KEY, Date.now().toString());
    localStorage.setItem(USER_KEY, JSON.stringify({ name: 'Wallet User' }));
}

function endSession(): void { sessionStorage.removeItem(SESSION_KEY); }

async function createPasskey(): Promise<void> {
    showLoginPhase('loading');
    (document.querySelector('.login-status') as HTMLElement).textContent = 'Setting up passkey...';
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
                        displayName: 'Fikua Wallet User',
                    },
                    pubKeyCredParams: [
                        { alg: -7, type: 'public-key' },
                        { alg: -257, type: 'public-key' },
                    ],
                    authenticatorSelection: {
                        authenticatorAttachment: 'platform',
                        userVerification: 'required',
                        residentKey: 'preferred',
                    },
                    timeout: 60000,
                },
            }) as PublicKeyCredential;
            localStorage.setItem(PASSKEY_KEY, JSON.stringify({
                created: Date.now(),
                credentialId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                type: 'webauthn',
            }));
        } else {
            localStorage.setItem(PASSKEY_KEY, JSON.stringify({ created: Date.now(), type: 'simulated' }));
        }
        startSession();
        await onSessionStart();
    } catch (err) {
        console.error('Passkey creation failed:', err);
        showLoginPhase('create');
    }
}

async function authenticatePasskey(): Promise<void> {
    showLoginPhase('loading');
    (document.querySelector('.login-status') as HTMLElement).textContent = 'Authenticating...';
    try {
        if (window.PublicKeyCredential) {
            const challenge = crypto.getRandomValues(new Uint8Array(32));
            const credential = await navigator.credentials.get({
                publicKey: {
                    challenge,
                    rpId: window.location.hostname,
                    userVerification: 'required',
                    timeout: 60000,
                },
            }) as PublicKeyCredential;
            if (!hasPasskey()) {
                localStorage.setItem(PASSKEY_KEY, JSON.stringify({
                    created: Date.now(),
                    credentialId: btoa(String.fromCharCode(...new Uint8Array(credential.rawId))),
                    type: 'webauthn',
                }));
            }
        }
        startSession();
        await onSessionStart();
    } catch (err) {
        console.error('Authentication failed:', err);
        showLoginPhase('create');
    }
}

$('btn-login').addEventListener('click', () => authenticatePasskey());
$('btn-create-passkey').addEventListener('click', createPasskey);
$('btn-logout').addEventListener('click', () => {
    endSession();
    showScreen('login');
    showLoginPhase(hasPasskey() ? 'start' : 'create');
});

// =========================================================================
// Credential Display Helpers
// =========================================================================

const CLAIM_LABELS: Record<string, string> = {
    given_name: 'Given Name',
    family_name: 'Family Name',
    birth_date: 'Date of Birth',
    issuing_authority: 'Issuing Authority',
    issuing_country: 'Issuing Country',
    vct: 'Credential Type',
    iss: 'Issuer',
    sub: 'Subject',
    iat: 'Issued At',
    exp: 'Expires At',
};

function getCredentialDisplayName(cred: StoredCredential): string {
    if (cred.credentialConfigId) {
        if (cred.credentialConfigId.includes('student-id')) return 'Student ID';
        if (cred.credentialConfigId.includes('mDL')) return 'mDL';
        if (cred.credentialConfigId.includes('pid.mdoc')) return 'PID mdoc';
        if (cred.credentialConfigId.includes('pid')) return 'PID';
        const parts = cred.credentialConfigId.split('.');
        const last = parts[parts.length - 1];
        if (last === '1' && parts.length > 1) return parts[parts.length - 2].toUpperCase();
        return last;
    }
    return cred.vct || 'Credential';
}

function getClaimLabel(key: string): string {
    return CLAIM_LABELS[key] || key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

function formatClaimValue(key: string, value: unknown): string {
    if ((key === 'iat' || key === 'exp') && typeof value === 'number') {
        return formatDate(value * 1000);
    }
    if (typeof value === 'object') return JSON.stringify(value);
    return String(value);
}

// =========================================================================
// Rendering — Credentials
// =========================================================================

async function renderCredentials(): Promise<void> {
    const credentials = await getAllCredentials();
    const list = $('credentials-list');

    if (credentials.length === 0) {
        list.innerHTML = `<div class="empty-state">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="5" width="20" height="14" rx="2"/><line x1="2" y1="10" x2="22" y2="10"/></svg>
            <p>No credentials yet</p>
            <span>Tap "Add Credential" to receive your first credential</span>
        </div>`;
        return;
    }

    list.innerHTML = '';
    credentials.sort((a, b) => b.issuedAt - a.issuedAt);
    for (const cred of credentials) {
        const card = document.createElement('div');
        card.className = 'credential-card';
        card.dataset.id = cred.id;

        const name = getCredentialDisplayName(cred);
        const issuedDate = cred.metadata?.issuedAt ? formatDate(new Date(cred.metadata.issuedAt).getTime()) : '';
        const previewClaims = ['given_name', 'family_name', 'birth_date']
            .filter(k => cred.claims[k])
            .map(k => `<span class="claim-value">${esc(String(cred.claims[k]))}</span>`)
            .join(' ');

        card.innerHTML = `
            <div class="credential-header">
                <div class="credential-icon">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                </div>
                <div class="credential-title">
                    <strong>${esc(name)}</strong>
                    <span>${esc(cred.issuerName || cred.issuer)}</span>
                </div>
                <span class="credential-status status--valid">VALID</span>
            </div>
            <div class="credential-details">
                <span>${esc(cred.format || 'dc+sd-jwt')}</span>
                <span>${esc(cred.metadata?.alg || 'ES256')}</span>
                ${issuedDate ? '<span>Issued: ' + esc(issuedDate) + '</span>' : ''}
            </div>
            ${previewClaims ? '<div class="credential-claims-preview">' + previewClaims + '</div>' : ''}`;
        card.addEventListener('click', () => showCredentialDetail(cred.id));
        list.appendChild(card);
    }
}

// =========================================================================
// Rendering — Activity
// =========================================================================

async function renderActivity(): Promise<void> {
    const activities = await getAllActivity();
    const list = $('activity-list');

    if (activities.length === 0) {
        list.innerHTML = `<div class="empty-state">
            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
            <p>No activity yet</p>
            <span>Your credential activity will appear here</span>
        </div>`;
        return;
    }

    list.innerHTML = '';
    activities.sort((a, b) => b.timestamp - a.timestamp);
    for (const act of activities) {
        const item = document.createElement('div');
        item.className = 'activity-item';
        item.innerHTML = `
            <span class="activity-dot activity-dot--${esc(act.type)}"></span>
            <div class="activity-info">
                <strong>${esc(act.action)}</strong>
                <span>${esc(act.credentialName)}${act.issuerOrVerifier ? ' — ' + esc(act.issuerOrVerifier) : ''}</span>
            </div>
            <span class="activity-time">${esc(formatTime(act.timestamp))}</span>`;
        list.appendChild(item);
    }
}

// =========================================================================
// Credential Detail
// =========================================================================

let currentDetailId: string | null = null;

async function showCredentialDetail(credId: string): Promise<void> {
    const cred = await getCredential(credId);
    if (!cred) return;
    currentDetailId = credId;

    const name = getCredentialDisplayName(cred);
    const issuedDate = cred.metadata?.issuedAt ? formatDate(new Date(cred.metadata.issuedAt).getTime()) : 'Unknown';

    $('detail-header').innerHTML = `
        <div class="detail-card">
            <div class="credential-icon credential-icon--lg">
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
            </div>
            <h2>${esc(name)}</h2>
            <p class="detail-issuer">${esc(cred.issuerName || cred.issuer)}</p>
            <span class="credential-status status--valid">VALID</span>
        </div>`;

    const skipKeys = new Set(['iss', 'sub', 'iat', 'exp', 'vct']);
    let claimsHtml = '<h3>Claims</h3><div class="claims-list">';
    for (const [key, value] of Object.entries(cred.claims)) {
        if (skipKeys.has(key)) continue;
        claimsHtml += `<div class="claim-row">
            <span class="claim-label">${esc(getClaimLabel(key))}</span>
            <span class="claim-value">${esc(formatClaimValue(key, value))}</span>
        </div>`;
    }
    claimsHtml += '</div>';
    $('detail-claims').innerHTML = claimsHtml;

    let metaHtml = '<h3>Metadata</h3><div class="claims-list">';
    const metaItems: [string, string][] = [
        ['Format', cred.format || 'dc+sd-jwt'],
        ['Algorithm', cred.metadata?.alg || 'ES256'],
        ['Credential Type', cred.vct || cred.credentialConfigId || ''],
        ['Issuer URL', cred.issuer || ''],
        ['Issued', issuedDate],
        ['Expires', cred.metadata?.expiresAt ? formatDate(new Date(cred.metadata.expiresAt).getTime()) : 'No expiry'],
    ];
    for (const [label, value] of metaItems) {
        if (!value) continue;
        metaHtml += `<div class="claim-row">
            <span class="claim-label">${esc(label)}</span>
            <span class="claim-value">${esc(value)}</span>
        </div>`;
    }
    metaHtml += '</div>';
    $('detail-metadata').innerHTML = metaHtml;

    showScreen('detail');
}

async function deleteCredential(credId: string): Promise<void> {
    const cred = await getCredential(credId);
    if (!cred) return;

    if (cred.metadata?.notificationId && cred.metadata?.notificationEndpoint) {
        await sendNotification(
            cred.metadata.notificationEndpoint, cred.accessToken, cred.tokenType,
            cred.metadata.notificationId, 'credential_deleted', 'User deleted the credential from wallet',
        );
    }

    await deleteCredentialById(credId);
    await logActivity('Credential deleted', getCredentialDisplayName(cred), cred.issuerName || cred.issuer, 'deleted');
    await renderCredentials();
    await renderActivity();
    showScreen('wallet');
}

$('btn-back-detail').addEventListener('click', () => showScreen('wallet'));
$('btn-delete-credential').addEventListener('click', () => {
    if (currentDetailId && confirm('Delete this credential? This cannot be undone.')) {
        deleteCredential(currentDetailId);
    }
});

// =========================================================================
// Tabs
// =========================================================================

document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(c => c.classList.add('hidden'));
        (tab as HTMLElement).classList.add('active');
        $('tab-' + (tab as HTMLElement).dataset.tab!).classList.remove('hidden');
    });
});

// =========================================================================
// Consent
// =========================================================================

let consentResolve: ((accepted: boolean) => void) | null = null;

function showCredentialConsent(
    claims: Record<string, unknown>, issuerUrl: string, issuerMeta: CredentialIssuerMetadata,
): Promise<boolean> {
    return new Promise((resolve) => {
        consentResolve = resolve;
        showFlowPhase('consent');

        const issuerDisplay = issuerMeta.display?.[0]?.name ?? issuerUrl;
        $('consent-issuer').innerHTML = `
            <div class="consent-issuer-info">
                <strong>${esc(issuerDisplay)}</strong>
                <span>${esc(issuerUrl)}</span>
            </div>`;

        const skipKeys = new Set(['iss', 'sub', 'iat', 'exp', 'vct', '_sd', '_sd_alg']);
        let html = '';
        for (const [key, value] of Object.entries(claims)) {
            if (skipKeys.has(key)) continue;
            html += `<div class="consent-claim">
                <span class="consent-claim-label">${esc(getClaimLabel(key))}</span>
                <span class="consent-claim-value">${esc(formatClaimValue(key, value))}</span>
            </div>`;
        }
        $('consent-claims').innerHTML = html;
    });
}

$('btn-consent-accept').addEventListener('click', () => { if (consentResolve) { consentResolve(true); consentResolve = null; } });
$('btn-consent-reject').addEventListener('click', () => { if (consentResolve) { consentResolve(false); consentResolve = null; } });
$('btn-flow-back').addEventListener('click', () => showScreen('wallet'));

// =========================================================================
// Tx Code Prompt
// =========================================================================

function promptTxCode(): Promise<string | null> {
    return new Promise((resolve) => {
        const modal = $('txcode-modal') as HTMLDialogElement;
        const input = $('txcode-input') as HTMLInputElement;
        input.value = '';
        modal.showModal();

        const submit = () => { modal.close(); resolve(input.value.trim()); };
        const cancel = () => { modal.close(); resolve(null); };

        $('btn-txcode-submit').onclick = submit;
        $('btn-txcode-cancel').onclick = cancel;
        input.addEventListener('keydown', (e: KeyboardEvent) => { if (e.key === 'Enter') submit(); }, { once: true });
    });
}

// =========================================================================
// Flow Orchestrators
// =========================================================================

async function executeIssuanceFlow(offer: CredentialOffer): Promise<void> {
    showScreen('flow');
    showFlowPhase('processing');
    try {
        const issuerUrl = offer.credential_issuer;
        const configId = offer.credential_configuration_ids[0];
        const grant = analyzeGrant(offer);
        plog('info', 'Issuer: ' + issuerUrl + ' | Config: ' + configId + ' | Grant: ' + grant.type);

        updateFlowStatus('Fetching issuer metadata...');
        const issuerMeta = await fetchIssuerMetadata(issuerUrl);
        plog('ok', 'Issuer metadata OK — credential_endpoint: ' + issuerMeta.credential_endpoint);
        const authMeta = await fetchAuthServerMetadata(issuerUrl);
        plog('ok', 'Auth metadata OK — token_endpoint: ' + authMeta.token_endpoint);

        if (grant.type === 'pre-authorized_code') {
            await executePreAuthFlow(offer, grant, issuerMeta, authMeta, configId);
        } else {
            await executeAuthCodeFlow(offer, grant, issuerMeta, authMeta, configId);
        }
    } catch (err) {
        showFlowError((err as Error).message);
        await logActivity('Issuance failed', '', '', 'failed', (err as Error).message);
    }
}

async function executePreAuthFlow(
    offer: CredentialOffer, grant: GrantInfo,
    issuerMeta: CredentialIssuerMetadata, authMeta: AuthServerMetadata,
    configId: string,
): Promise<void> {
    const issuerUrl = offer.credential_issuer;

    updateFlowStatus('Requesting access token...');
    const tokenParams: Record<string, string> = {
        grant_type: PRE_AUTH_GRANT,
        'pre-authorized_code': getPreAuthCode(grant),
    };
    if (getPreAuthTxCode(grant)) {
        const txCode = await promptTxCode();
        if (!txCode) { showScreen('wallet'); return; }
        tokenParams.tx_code = txCode;
    }
    const tokenResponse = await requestToken(authMeta.token_endpoint, tokenParams);
    plog('ok', 'Token OK — type: ' + tokenResponse.token_type);

    updateFlowStatus('Requesting nonce...');
    const nonceResponse = await requestNonce(issuerMeta.nonce_endpoint!);
    plog('ok', 'Nonce: ' + nonceResponse.c_nonce.substring(0, 16) + '...');

    updateFlowStatus('Generating cryptographic proof...');
    const holderKeyPair = await generateHolderKeyPair();
    const proofJwt = await buildProofJwt(holderKeyPair, WALLET_BASE, issuerUrl, nonceResponse.c_nonce);
    plog('ok', 'Proof JWT built');

    updateFlowStatus('Requesting credential...');
    const credResponse = await requestCredential(
        issuerMeta.credential_endpoint, tokenResponse.access_token,
        tokenResponse.token_type, configId, proofJwt,
    );
    plog('ok', 'Credential response received');

    await processCredentialResponse(credResponse, issuerMeta, issuerUrl, configId, tokenResponse, holderKeyPair);
}

async function executeAuthCodeFlow(
    offer: CredentialOffer | null, grant: GrantInfo,
    issuerMeta: CredentialIssuerMetadata, authMeta: AuthServerMetadata,
    configId: string,
): Promise<void> {
    const issuerUrl = offer?.credential_issuer ?? ISSUER_BASE;
    const clientId = WALLET_BASE;
    const redirectUri = WALLET_BASE + '/';
    const state = generateRandomString(16);
    const isHaip = !!(authMeta.dpop_signing_alg_values_supported?.length);

    updateFlowStatus('Generating PKCE challenge...');
    const pkce = await generatePkce();

    let dpopKeyPair: CryptoKeyPair | null = null;
    let wiaKeyPair: CryptoKeyPair | null = null;
    if (isHaip) {
        updateFlowStatus('Generating cryptographic keys...');
        dpopKeyPair = await generateExtractableKeyPair();
        wiaKeyPair = await generateExtractableKeyPair();
    }

    const parEndpoint = authMeta.pushed_authorization_request_endpoint;
    let requestUri: string | null = null;

    if (parEndpoint) {
        updateFlowStatus('Sending authorization request...');
        const parParams: Record<string, string> = {
            client_id: clientId,
            redirect_uri: redirectUri,
            response_type: 'code',
            scope: configId,
            state,
            code_challenge: pkce.code_challenge,
            code_challenge_method: 'S256',
        };
        const issuerState = (grant.data as AuthCodeGrant).issuer_state;
        if (issuerState) parParams.issuer_state = issuerState;

        let dpopProofPar: string | undefined;
        let wiaJwt: string | undefined;
        let popJwt: string | undefined;
        if (isHaip && dpopKeyPair && wiaKeyPair) {
            dpopProofPar = await buildDpopProof(dpopKeyPair, 'POST', parEndpoint);
            wiaJwt = await generateWia(wiaKeyPair, clientId);
            popJwt = await generateWiaPop(wiaKeyPair, clientId, issuerUrl);
        }
        const parResponse = await pushAuthorizationRequest(parEndpoint, parParams, dpopProofPar, wiaJwt, popJwt);
        requestUri = parResponse.request_uri;
    }

    // Save flow state for callback
    const flowState: AuthFlowState = {
        offer, issuerMeta, authMeta, configId, state,
        codeVerifier: pkce.code_verifier,
        isHaip, clientId, redirectUri, issuerUrl,
    };
    if (dpopKeyPair) flowState.dpopKeyPair = await exportKeyPair(dpopKeyPair);
    if (wiaKeyPair) flowState.wiaKeyPair = await exportKeyPair(wiaKeyPair);
    sessionStorage.setItem(AUTH_FLOW_KEY, JSON.stringify(flowState));

    // Redirect to authorize
    let authorizeUrl = authMeta.authorization_endpoint ?? (issuerUrl + '/oid4vci/v1/authorize');
    if (requestUri) {
        authorizeUrl += '?request_uri=' + encodeURIComponent(requestUri) + '&client_id=' + encodeURIComponent(clientId);
    } else {
        authorizeUrl += '?response_type=code&client_id=' + encodeURIComponent(clientId)
            + '&redirect_uri=' + encodeURIComponent(redirectUri)
            + '&scope=' + encodeURIComponent(configId)
            + '&state=' + state
            + '&code_challenge=' + pkce.code_challenge
            + '&code_challenge_method=S256';
    }
    window.location.href = authorizeUrl;
}

async function handleAuthCallback(params: URLSearchParams): Promise<boolean> {
    const code = params.get('code');
    const state = params.get('state');
    if (!code) return false;

    window.history.replaceState({}, '', window.location.pathname);

    const flowStateJson = sessionStorage.getItem(AUTH_FLOW_KEY);
    sessionStorage.removeItem(AUTH_FLOW_KEY);
    if (!flowStateJson) { showFlowError('No flow state found for authorization callback'); return true; }

    const flowState: AuthFlowState = JSON.parse(flowStateJson);
    if (flowState.state !== state) { showFlowError('Authorization state mismatch'); return true; }

    showScreen('flow');
    showFlowPhase('processing');

    try {
        const dpopKeyPair = flowState.dpopKeyPair ? await importKeyPair(flowState.dpopKeyPair) : null;
        const wiaKeyPair = flowState.wiaKeyPair ? await importKeyPair(flowState.wiaKeyPair) : null;

        updateFlowStatus('Exchanging authorization code...');
        const tokenParams: Record<string, string> = {
            grant_type: 'authorization_code',
            code,
            redirect_uri: flowState.redirectUri,
            code_verifier: flowState.codeVerifier,
        };
        const tokenOptions: { dpopProof?: string; wiaJwt?: string; popJwt?: string } = {};
        if (flowState.isHaip && dpopKeyPair && wiaKeyPair) {
            tokenOptions.dpopProof = await buildDpopProof(dpopKeyPair, 'POST', flowState.authMeta.token_endpoint);
            tokenOptions.wiaJwt = await generateWia(wiaKeyPair, flowState.clientId);
            tokenOptions.popJwt = await generateWiaPop(wiaKeyPair, flowState.clientId, flowState.issuerUrl);
        }
        const tokenResponse = await requestToken(flowState.authMeta.token_endpoint, tokenParams, tokenOptions);

        updateFlowStatus('Requesting nonce...');
        const nonceOpts: { dpopProof?: string } = {};
        if (flowState.isHaip && dpopKeyPair) {
            nonceOpts.dpopProof = await buildDpopProof(dpopKeyPair, 'POST', flowState.issuerMeta.nonce_endpoint!);
        }
        const nonceResponse = await requestNonce(flowState.issuerMeta.nonce_endpoint!, nonceOpts);

        updateFlowStatus('Generating proof...');
        const holderKeyPair = await generateHolderKeyPair();
        const proofJwt = await buildProofJwt(holderKeyPair, flowState.clientId, flowState.issuerUrl, nonceResponse.c_nonce);

        updateFlowStatus('Requesting credential...');
        const credOpts: { dpopProof?: string } = {};
        if (flowState.isHaip && dpopKeyPair) {
            credOpts.dpopProof = await buildDpopProof(
                dpopKeyPair, 'POST', flowState.issuerMeta.credential_endpoint,
                tokenResponse.access_token,
            );
        }
        const credResponse = await requestCredential(
            flowState.issuerMeta.credential_endpoint, tokenResponse.access_token,
            tokenResponse.token_type, flowState.configId, proofJwt, credOpts,
        );

        await processCredentialResponse(credResponse, flowState.issuerMeta, flowState.issuerUrl, flowState.configId, tokenResponse, holderKeyPair);
    } catch (err) {
        showFlowError((err as Error).message);
        await logActivity('Issuance failed', flowState.configId, flowState.issuerUrl, 'failed', (err as Error).message);
    }
    return true;
}

async function processCredentialResponse(
    credResponse: CredentialResponse, issuerMeta: CredentialIssuerMetadata,
    issuerUrl: string, configId: string,
    tokenResponse: { access_token: string; token_type: string },
    holderKeyPair: CryptoKeyPair,
): Promise<void> {
    updateFlowStatus('Processing credential...');
    const rawCredential = credResponse.credentials[0].credential;
    const credConfig = issuerMeta.credential_configurations_supported?.[configId];
    const format = credConfig?.format ?? 'dc+sd-jwt';
    const issuerDisplay = issuerMeta.display?.[0]?.name ?? issuerUrl;
    const credName = credConfig?.credential_metadata?.display?.[0]?.name ?? getClaimLabel(configId);

    // Parse according to format
    let claims: Record<string, unknown>;
    let storedFormat: string;
    let vct: string;
    let alg: string;
    let issuedAt: string | null;
    let expiresAt: string | null;

    if (format === 'mso_mdoc') {
        const mdoc = parseMdoc(rawCredential);
        claims = mdoc.claims;
        storedFormat = 'mso_mdoc';
        vct = mdoc.docType;
        alg = 'ES256';
        issuedAt = mdoc.validFrom;
        expiresAt = mdoc.validUntil;
    } else {
        const parsed = parseSdJwt(rawCredential);
        claims = parsed.allClaims;
        storedFormat = (parsed.header.typ as string) || 'dc+sd-jwt';
        vct = parsed.vct ?? '';
        alg = (parsed.header.alg as string) || 'ES256';
        issuedAt = parsed.issuedAt ? new Date(parsed.issuedAt * 1000).toISOString() : null;
        expiresAt = parsed.expiresAt ? new Date(parsed.expiresAt * 1000).toISOString() : null;
    }

    const accepted = await showCredentialConsent(claims, issuerUrl, issuerMeta);

    if (accepted) {
        const credId = crypto.randomUUID();
        await saveCredential({
            id: credId,
            rawSdJwt: rawCredential,
            format: storedFormat,
            issuer: issuerUrl,
            issuerName: issuerDisplay,
            credentialConfigId: configId,
            vct,
            claims,
            metadata: {
                alg,
                issuedAt,
                expiresAt,
                notificationId: credResponse.notification_id ?? null,
                notificationEndpoint: issuerMeta.notification_endpoint ?? null,
            },
            accessToken: tokenResponse.access_token,
            tokenType: tokenResponse.token_type,
            holderKey: holderKeyPair,
            issuedAt: Date.now(),
        });

        if (credResponse.notification_id && issuerMeta.notification_endpoint) {
            await sendNotification(
                issuerMeta.notification_endpoint, tokenResponse.access_token,
                tokenResponse.token_type, credResponse.notification_id, 'credential_accepted',
            );
        }

        await logActivity('Credential received', credName, issuerDisplay, 'issued');
        await renderCredentials();
        await renderActivity();
        showScreen('wallet');
    } else {
        if (credResponse.notification_id && issuerMeta.notification_endpoint) {
            await sendNotification(
                issuerMeta.notification_endpoint, tokenResponse.access_token,
                tokenResponse.token_type, credResponse.notification_id,
                'credential_failure', 'User declined the credential',
            );
        }
        showScreen('wallet');
    }
}

// =========================================================================
// Add Credential (Wallet-Initiated)
// =========================================================================

async function showAddCredentialModal(): Promise<void> {
    const modal = $('add-credential-modal') as HTMLDialogElement;
    const loading = $('add-credential-loading');
    const listEl = $('add-credential-list');
    const errorEl = $('add-credential-error');

    loading.classList.remove('hidden');
    listEl.classList.add('hidden');
    errorEl.classList.add('hidden');
    modal.showModal();

    try {
        const meta = await fetchIssuerMetadata(ISSUER_BASE);
        const configs = meta.credential_configurations_supported ?? {};
        const keys = Object.keys(configs);
        if (keys.length === 0) throw new Error('No credential configurations available');

        listEl.innerHTML = '';
        for (const configId of keys) {
            const config = configs[configId];
            const display = config.credential_metadata?.display?.[0];
            const name = display?.name ?? configId;
            const desc = display?.description ?? config.format ?? '';

            const item = document.createElement('button');
            item.className = 'add-credential-item';
            item.innerHTML = `
                <div class="add-credential-info">
                    <strong>${esc(name)}</strong>
                    <span>${esc(desc)}</span>
                </div>
                <span class="add-credential-format">${esc(config.format || '')}</span>`;
            item.addEventListener('click', () => {
                modal.close();
                startWalletInitiatedFlow(configId, meta);
            });
            listEl.appendChild(item);
        }

        loading.classList.add('hidden');
        listEl.classList.remove('hidden');
    } catch (err) {
        loading.classList.add('hidden');
        errorEl.classList.remove('hidden');
        $('add-credential-error-msg').textContent = (err as Error).message;
    }
}

async function startWalletInitiatedFlow(configId: string, issuerMeta: CredentialIssuerMetadata): Promise<void> {
    showScreen('flow');
    showFlowPhase('processing');
    updateFlowStatus('Starting wallet-initiated issuance...');

    try {
        const authMeta = await fetchAuthServerMetadata(ISSUER_BASE);
        const grant: GrantInfo = { type: 'authorization_code', data: {} };
        await executeAuthCodeFlow(null, grant, issuerMeta, authMeta, configId);
    } catch (err) {
        showFlowError((err as Error).message);
        await logActivity('Issuance failed', configId, ISSUER_BASE, 'failed', (err as Error).message);
    }
}

$('btn-add-credential').addEventListener('click', () => showAddCredentialModal());
$('btn-close-add').addEventListener('click', () => ($('add-credential-modal') as HTMLDialogElement).close());

// =========================================================================
// QR Scanner
// =========================================================================

const qrModal = $('qr-modal') as HTMLDialogElement;
const qrVideo = $('qr-video') as HTMLVideoElement;
let scanController: AbortController | null = null;

$('btn-scan').addEventListener('click', () => { qrModal.showModal(); startCamera(); });
$('btn-close-qr').addEventListener('click', closeQrModal);
qrModal.addEventListener('close', stopScanner);

$('btn-qr-submit').addEventListener('click', () => {
    const input = ($('qr-url-input') as HTMLInputElement).value.trim();
    if (!input) return;
    closeQrModal();
    handleOfferUri(input);
});

function startCamera(): void {
    const fallback = document.querySelector('.qr-fallback') as HTMLElement;
    const status = document.querySelector('.qr-scan-status') as HTMLElement;

    if (fallback) fallback.classList.add('hidden');
    if (status) { status.textContent = 'Scanning...'; status.classList.remove('hidden'); }

    scanController = startScanning(qrVideo, {
        onResult: (result) => {
            if (status) status.classList.add('hidden');
            closeQrModal();
            handleOfferUri(result.data);
        },
        onStatus: (msg) => {
            if (msg === 'Camera not available') {
                if (fallback) fallback.classList.remove('hidden');
                if (status) status.classList.add('hidden');
            } else if (status) {
                status.textContent = msg;
            }
        },
    });
}

function stopScanner(): void {
    if (scanController) { scanController.abort(); scanController = null; }
    const status = document.querySelector('.qr-scan-status') as HTMLElement;
    if (status) status.classList.add('hidden');
}

function closeQrModal(): void { stopScanner(); qrModal.close(); }

// =========================================================================
// OID4VP — Presentation Flow
// =========================================================================

async function handlePresentationRequest(uri: string): Promise<void> {
    plog('info', 'OID4VP presentation request detected');
    showScreen('flow');
    showFlowPhase('processing');

    try {
        // 1. Parse URI params
        const search = uri.includes('?') ? uri.substring(uri.indexOf('?')) : '';
        const params = new URLSearchParams(search);
        const requestUri = params.get('request_uri');
        const clientId = params.get('client_id') || '';

        if (!requestUri) {
            showFlowError('Missing request_uri in OID4VP request');
            return;
        }

        // 2. Fetch Authorization Request (Request Object)
        updateFlowStatus('Fetching verification request...');
        const authReq = await fetchRequestObject(decodeURIComponent(requestUri));
        plog('ok', 'Authorization Request received');
        plog('info', 'Verifier: ' + (authReq.client_id || clientId));

        // 3. Parse DCQL query
        const credQuery = authReq.dcql_query?.credentials?.[0];
        if (!credQuery) {
            showFlowError('No credential query in authorization request');
            return;
        }
        const vctValues = credQuery.meta?.vct_values ?? [];
        const requestedClaims = (credQuery.claims ?? []).map(c => c.path[0]);
        plog('info', 'Requested VCT: ' + vctValues.join(', '));
        plog('info', 'Requested claims: ' + requestedClaims.join(', '));

        // 4. Find matching credential
        updateFlowStatus('Searching for matching credential...');
        const allCreds = await getAllCredentials();
        const matching = allCreds.find(c =>
            vctValues.length === 0 || vctValues.includes(c.vct),
        );

        if (!matching) {
            showFlowError('No matching credential found for type: ' + vctValues.join(', '));
            return;
        }
        plog('ok', 'Found matching credential: ' + getCredentialDisplayName(matching));

        // 5. Show presentation consent
        const accepted = await showPresentationConsent(
            matching, requestedClaims, authReq.client_id || clientId,
        );

        if (!accepted) {
            plog('info', 'User declined presentation');
            showScreen('wallet');
            return;
        }

        // 6. Build VP Token
        showFlowPhase('processing');
        updateFlowStatus('Building VP Token...');
        const vpToken = await buildVpToken(
            matching, requestedClaims, authReq.nonce, authReq.client_id || clientId,
        );
        plog('ok', 'VP Token built (' + vpToken.length + ' bytes)');

        // 7. Submit to verifier
        updateFlowStatus('Sending presentation to verifier...');
        const res = await submitPresentation(authReq.response_uri, vpToken, authReq.state);
        if (!res.ok) {
            const err = await res.json().catch(() => ({} as Record<string, string>));
            throw new Error('Presentation submission failed: ' + ((err as Record<string, string>).error_description || (err as Record<string, string>).error || res.status));
        }
        plog('ok', 'Presentation submitted successfully');

        // 8. Log activity + show success
        await logActivity('Credential presented', getCredentialDisplayName(matching), authReq.client_id || clientId, 'presented');
        await renderActivity();
        updateFlowStatus('Presentation complete!');

        // Return to wallet after brief delay
        setTimeout(() => showScreen('wallet'), 1500);

    } catch (err) {
        showFlowError(err instanceof Error ? err.message : 'Presentation failed');
    }
}

function showPresentationConsent(
    credential: StoredCredential,
    requestedClaims: string[],
    verifierClientId: string,
): Promise<boolean> {
    return new Promise((resolve) => {
        consentResolve = resolve;
        showFlowPhase('consent');

        // Update consent title for presentation context
        const consentTitle = document.querySelector('#flow-consent h2');
        if (consentTitle) consentTitle.textContent = 'Share Credential';
        const consentSub = document.querySelector('#flow-consent .flow-sub');
        if (consentSub) consentSub.textContent = 'A verifier is requesting the following claims from your credential.';

        // Show verifier info
        $('consent-issuer').innerHTML = `
            <div class="consent-issuer-info">
                <strong>${esc(getCredentialDisplayName(credential))}</strong>
                <span>${esc(verifierClientId)}</span>
            </div>`;

        // Show requested claims with current values
        const requested = new Set(requestedClaims);
        let html = '';
        for (const [key, value] of Object.entries(credential.claims)) {
            if (!requested.has(key)) continue;
            html += `<div class="consent-claim">
                <span class="consent-claim-label">${esc(getClaimLabel(key))}</span>
                <span class="consent-claim-value">${esc(formatClaimValue(key, value))}</span>
            </div>`;
        }
        $('consent-claims').innerHTML = html;

        // Update button text
        $('btn-consent-accept').textContent = 'Share';
        $('btn-consent-reject').textContent = 'Decline';
    });
}

function handleOfferUri(uri: string): void {
    plog('info', 'QR/URI received: ' + uri.substring(0, 120) + (uri.length > 120 ? '...' : ''));

    // OID4VP presentation request
    if (uri.startsWith('openid4vp://')) {
        handlePresentationRequest(uri);
        return;
    }

    const search = uri.includes('?') ? uri.substring(uri.indexOf('?')) : '';
    const params = new URLSearchParams(search);
    const offerData = parseCredentialOfferFromUrl(params);
    if (offerData) {
        plog('ok', 'Credential offer parsed (' + offerData.source + ')');
        processOffer(offerData);
    } else if (uri.startsWith('http://') || uri.startsWith('https://')) {
        // Fallback: treat bare HTTP URL as a credential_offer_uri (by_reference)
        plog('info', 'Treating as direct credential_offer_uri');
        processOffer({ offerUri: uri, source: 'by_reference' });
    } else {
        plog('error', 'No credential_offer or credential_offer_uri found in URI');
    }
}

async function processOffer(offerData: OfferData): Promise<void> {
    let offer: CredentialOffer;
    if (offerData.source === 'by_reference' && offerData.offerUri) {
        offer = await fetchCredentialOffer(offerData.offerUri);
    } else {
        offer = offerData.offer!;
    }
    await executeIssuanceFlow(offer);
}

// =========================================================================
// PWA Install
// =========================================================================

const INSTALL_DISMISSED_KEY = 'fikua-install-dismissed';

let deferredInstallPrompt: BeforeInstallPromptEvent | null = null;

interface BeforeInstallPromptEvent extends Event {
    prompt(): Promise<void>;
    userChoice: Promise<{ outcome: string }>;
}

function isIosSafari(): boolean {
    const ua = navigator.userAgent;
    return /iPad|iPhone|iPod/.test(ua) && !('MSStream' in window);
}

function isStandalone(): boolean {
    return window.matchMedia('(display-mode: standalone)').matches
        || ('standalone' in navigator && (navigator as unknown as { standalone: boolean }).standalone);
}

function showInstallBanner(): void {
    if (isStandalone() || sessionStorage.getItem(INSTALL_DISMISSED_KEY)) return;
    const banner = $('install-banner');
    banner.classList.remove('hidden');
}

// Chromium browsers: capture beforeinstallprompt
window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredInstallPrompt = e as BeforeInstallPromptEvent;
    showInstallBanner();
});

// iOS Safari: show instructions instead of install button (both in banner and login phase)
if (isIosSafari() && !isStandalone()) {
    $('install-banner-text').textContent = 'Tap the Share button, then "Add to Home Screen"';
    $('btn-install').classList.add('hidden');
    showInstallBanner();
    // Login install phase: show iOS instructions, hide install button
    $('btn-login-install').classList.add('hidden');
    $('login-install-ios').classList.remove('hidden');
}

// Wallet screen install banner
$('btn-install').addEventListener('click', async () => {
    if (!deferredInstallPrompt) return;
    deferredInstallPrompt.prompt();
    const { outcome } = await deferredInstallPrompt.userChoice;
    deferredInstallPrompt = null;
    if (outcome === 'accepted') {
        $('install-banner').classList.add('hidden');
    }
});

$('btn-install-dismiss').addEventListener('click', () => {
    $('install-banner').classList.add('hidden');
    sessionStorage.setItem(INSTALL_DISMISSED_KEY, '1');
});

// Login screen install phase
$('btn-login-install').addEventListener('click', async () => {
    if (!deferredInstallPrompt) return;
    deferredInstallPrompt.prompt();
    const { outcome } = await deferredInstallPrompt.userChoice;
    deferredInstallPrompt = null;
    if (outcome === 'accepted') {
        showLoginPhase('create');
    }
});

$('btn-skip-install').addEventListener('click', () => {
    showLoginPhase('create');
});

// =========================================================================
// Session Start
// =========================================================================

async function onSessionStart(): Promise<void> {
    $('greeting').textContent = 'Hello,';
    await renderCredentials();
    await renderActivity();

    const pendingOffer = sessionStorage.getItem(PENDING_OFFER_KEY);
    if (pendingOffer) {
        sessionStorage.removeItem(PENDING_OFFER_KEY);
        await executeIssuanceFlow(JSON.parse(pendingOffer));
        return;
    }

    showScreen('wallet');
}

// =========================================================================
// Initialization
// =========================================================================

async function init(): Promise<void> {
    await openDb();
    applyPrivacy();

    const params = new URLSearchParams(window.location.search);

    // Handle passkey reset
    if (params.get('reset') === 'passkey') {
        localStorage.removeItem(PASSKEY_KEY);
        localStorage.removeItem(USER_KEY);
        sessionStorage.removeItem(SESSION_KEY);
        window.history.replaceState({}, '', window.location.pathname);
    }

    // Handle auth code callback
    if (params.get('code') && hasSession()) {
        const handled = await handleAuthCallback(params);
        if (handled) return;
    }

    // Handle credential offer in URL
    const offerData = parseCredentialOfferFromUrl(params);
    if (offerData) {
        window.history.replaceState({}, '', window.location.pathname);
        if (hasSession()) {
            await onSessionStart();
            await processOffer(offerData);
            return;
        } else {
            if (offerData.source === 'by_value' && offerData.offer) {
                sessionStorage.setItem(PENDING_OFFER_KEY, JSON.stringify(offerData.offer));
            } else if (offerData.offerUri) {
                const offer = await fetchCredentialOffer(offerData.offerUri);
                sessionStorage.setItem(PENDING_OFFER_KEY, JSON.stringify(offer));
            }
        }
    }

    if (hasSession()) {
        await onSessionStart();
    } else {
        showScreen('login');
        if (hasPasskey()) {
            showLoginPhase('start');
        } else if (!isStandalone()) {
            showLoginPhase('install');
        } else {
            showLoginPhase('create');
        }
    }
}

init().catch(err => console.error('Wallet init error:', err));
