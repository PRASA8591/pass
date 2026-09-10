import { initializeApp } from 'https://www.gstatic.com/firebasejs/11.0.2/firebase-app.js';
import {
  getFirestore,
  collection,
  getDocs,
  getDoc,
  addDoc,
  setDoc,
  updateDoc,
  deleteDoc,
  doc,
  query,
  where,
} from 'https://www.gstatic.com/firebasejs/11.0.2/firebase-firestore.js';

const firebaseConfig = {
  apiKey: 'AIzaSyCB2SHj9ffusZoP2PI_wGlbXG3xZahk_dI',
  authDomain: 'mypassword-5e734.firebaseapp.com',
  projectId: 'mypassword-5e734',
  storageBucket: 'mypassword-5e734.firebasestorage.app',
  messagingSenderId: '13145555075',
  appId: '1:13145555075:web:de5740f087981b86c69bb6',
  measurementId: 'G-4D8VN1E901',
};

const firebaseApp = initializeApp(firebaseConfig);
const db = getFirestore(firebaseApp);
const usersRef = collection(db, 'users');

const $ = (selector) => document.querySelector(selector);
const authView = $('#auth-view');
const appView = $('#app-view');
const authContent = $('#auth-content');
const themeKey = 'pass-theme';

const state = {
  user: null,
  authTimer: null,
  pendingLogin: null,
  pendingSetup: null,
};

let authMode = 'login';
const entries = [];
let editingId = null;

const normalizeUsername = (value) => String(value || '').trim().toLowerCase();
const safeText = (value) => String(value ?? '');

function formatDisplayDate(value) {
  if (!value) return 'Never';
  const date = value?.toDate ? value.toDate() : new Date(value);
  if (Number.isNaN(date.getTime())) return 'Never';
  return new Intl.DateTimeFormat('en-US', {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(date);
}

function normalizeEntry(record) {
  return {
    ...record,
    label: safeText(record.label),
    username: safeText(record.username),
    password: safeText(record.password),
    remark: safeText(record.remark),
    lastViewedAt: record.lastViewedAt || null,
    updatedAt: record.updatedAt || record.createdAt || null,
  };
}

function hexToBytes(hex) {
  const clean = hex.replace(/\s+/g, '');
  const buffer = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    buffer[i / 2] = Number.parseInt(clean.slice(i, i + 2), 16);
  }
  return buffer;
}

async function derivePasswordHash(password, saltBytes) {
  const textEncoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', textEncoder.encode(password), 'PBKDF2', false, ['deriveBits']);
  const derivedBits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: saltBytes, iterations: 200000, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return Array.from(new Uint8Array(derivedBits)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function base32Encode(bytes) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  let output = '';

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      output += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 31];
  }

  return output;
}

function base32Decode(secret) {
  const compact = String(secret || '').toUpperCase().replace(/=+$/g, '').replace(/[^A-Z2-7]/g, '');
  if (!compact) return new Uint8Array();

  let bits = 0;
  let value = 0;
  const bytes = [];

  for (const char of compact) {
    const index = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'.indexOf(char);
    if (index < 0) continue;
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 255);
    }
  }

  return new Uint8Array(bytes);
}

function getTotpSecret() {
  const secretBytes = crypto.getRandomValues(new Uint8Array(20));
  return base32Encode(secretBytes);
}

async function getTotpCode(secret, timestampMs = Date.now()) {
  const keyBytes = base32Decode(secret);
  if (!keyBytes.length) return '000000';

  const counter = BigInt(Math.floor(timestampMs / 30000));
  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  let value = counter;
  for (let i = 7; i >= 0; i -= 1) {
    view.setUint8(i, Number(value & 0xFFn));
    value >>= 8n;
  }

  const cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const hash = new Uint8Array(await crypto.subtle.sign('HMAC', cryptoKey, buffer));
  const offset = hash[hash.length - 1] & 0x0f;
  const binary = ((hash[offset] & 0x7f) << 24) | ((hash[offset + 1] & 0xff) << 16) | ((hash[offset + 2] & 0xff) << 8) | (hash[offset + 3] & 0xff);
  const code = (binary % 1000000).toString().padStart(6, '0');
  return code;
}

async function verifyTotp(secret, code, drift = 2) {
  if (!secret || !code) return false;
  const cleanCode = String(code).replace(/\D/g, '').slice(0, 6);
  if (!cleanCode) return false;

  for (let offset = -drift; offset <= drift; offset += 1) {
    const candidate = await getTotpCode(secret, Date.now() + offset * 30000);
    if (candidate === cleanCode.padStart(6, '0')) {
      return true;
    }
  }

  return false;
}

function makeTotpUri(username, secret) {
  if (!secret) return '';
  return `otpauth://totp/PassVault:${encodeURIComponent(username)}?secret=${encodeURIComponent(secret)}&issuer=${encodeURIComponent('PassVault')}`;
}

function applyTheme(theme) {
  const nextTheme = theme === 'dark' ? 'dark' : 'light';
  document.body.dataset.theme = nextTheme;
  const toggle = $('#theme-toggle');
  if (!toggle) return;

  const isDark = nextTheme === 'dark';
  toggle.setAttribute('aria-pressed', String(isDark));
  const icon = toggle.querySelector('.theme-toggle-icon');
  const text = toggle.querySelector('.theme-toggle-text');
  if (icon) icon.textContent = isDark ? '🌙' : '☀️';
  if (text) text.textContent = isDark ? 'Dark' : 'Light';

  try {
    localStorage.setItem(themeKey, nextTheme);
  } catch (_error) {
    // ignore restricted storage
  }
}

function initializeTheme() {
  try {
    const saved = localStorage.getItem(themeKey);
    applyTheme(saved === 'dark' ? 'dark' : 'light');
  } catch (_error) {
    applyTheme('light');
  }

  const toggle = $('#theme-toggle');
  if (!toggle) return;

  toggle.addEventListener('click', () => {
    const nextTheme = document.body.dataset.theme === 'dark' ? 'light' : 'dark';
    applyTheme(nextTheme);
  });
}

async function findUserByUsername(username) {
  const normalized = normalizeUsername(username);
  const userDoc = await getDoc(doc(db, 'users', normalized));
  if (!userDoc.exists()) return null;
  return { id: userDoc.id, ...userDoc.data() };
}

async function ensureUserExists(username) {
  const existing = await findUserByUsername(username);
  return existing;
}

function clearUserSession() {
  state.user = null;
  state.pendingLogin = null;
  state.pendingSetup = null;
  if (state.authTimer) {
    clearTimeout(state.authTimer);
    state.authTimer = null;
  }
  entries.length = 0;
  editingId = null;
  appView.classList.add('hidden');
  authView.classList.remove('hidden');
}

function startAutoLogout() {
  if (state.authTimer) clearTimeout(state.authTimer);
  state.authTimer = setTimeout(() => {
    clearUserSession();
    showAuth('login');
    const errorBox = $('#auth-error');
    if (errorBox) {
      errorBox.textContent = 'Session expired after 3 minutes. Please sign in again.';
    }
  }, 180000);
}

function registerSessionActivity() {
  if (state.user) startAutoLogout();
}

window.addEventListener('click', registerSessionActivity);
window.addEventListener('keydown', registerSessionActivity);
window.addEventListener('mousemove', registerSessionActivity);

function showAuth(mode = 'login') {
  authMode = mode;
  authView.classList.remove('hidden');
  appView.classList.add('hidden');
  authContent.innerHTML = '';

  if (mode === 'login') {
    renderLoginView();
  } else if (mode === 'create') {
    renderCreateView();
  } else if (mode === 'otp-setup') {
    renderOtpSetupView(state.pendingSetup || {});
  } else if (mode === 'otp-login') {
    renderOtpLoginView(state.pendingLogin || {});
  }
}

async function loadEntries() {
  if (!state.user) return;

  const entriesRef = collection(db, 'users', state.user.id, 'entries');
  const snapshot = await getDocs(entriesRef);
  const loaded = snapshot.docs.map((docSnap) => normalizeEntry({ id: docSnap.id, ...docSnap.data() }));

  entries.splice(0, entries.length, ...loaded);
  renderEntries();
  const total = $('#total-count');
  const lastUpdated = $('#last-updated');
  if (total) total.textContent = String(entries.length);

  if (entries.length) {
    const newest = entries
      .map((entry) => entry.updatedAt || entry.createdAt)
      .sort((left, right) => Number(new Date(right)) - Number(new Date(left)))[0];
    if (lastUpdated) lastUpdated.textContent = formatDisplayDate(newest);
  } else if (lastUpdated) {
    lastUpdated.textContent = '—';
  }
}

function renderLoginView() {
  const wrapper = document.createElement('div');
  wrapper.className = 'auth-box';

  const heading = document.createElement('h2');
  heading.textContent = 'Sign in to your vault';

  const form = document.createElement('form');
  form.id = 'login-form';

  const usernameField = document.createElement('label');
  usernameField.textContent = 'Username';
  const usernameInput = document.createElement('input');
  usernameInput.name = 'username';
  usernameInput.required = true;
  usernameInput.placeholder = 'username';
  usernameField.appendChild(usernameInput);

  const passwordField = document.createElement('label');
  passwordField.textContent = 'Password';
  const passwordInput = document.createElement('input');
  passwordInput.name = 'password';
  passwordInput.type = 'password';
  passwordInput.required = true;
  passwordInput.placeholder = 'Your password';
  passwordField.appendChild(passwordInput);

  const errorText = document.createElement('p');
  errorText.id = 'auth-error';
  errorText.className = 'form-error';

  const submit = document.createElement('button');
  submit.type = 'submit';
  submit.className = 'primary-button full-button';
  submit.innerHTML = 'Login <span>→</span>';

  form.append(usernameField, passwordField, errorText, submit);
  form.addEventListener('submit', handleLoginSubmit);

  const switchButton = document.createElement('button');
  switchButton.type = 'button';
  switchButton.className = 'switch-button';
  switchButton.textContent = 'Create account';
  switchButton.addEventListener('click', () => showAuth('create'));

  wrapper.append(heading, form, switchButton);
  authContent.appendChild(wrapper);
}

function renderCreateView() {
  const wrapper = document.createElement('div');
  wrapper.className = 'auth-box';

  const heading = document.createElement('h2');
  heading.textContent = 'Create a secure account';

  const form = document.createElement('form');
  form.id = 'create-form';

  const usernameField = document.createElement('label');
  usernameField.textContent = 'Username';
  const usernameInput = document.createElement('input');
  usernameInput.name = 'username';
  usernameInput.required = true;
  usernameInput.placeholder = 'choose a username';
  usernameField.appendChild(usernameInput);

  const passwordField = document.createElement('label');
  passwordField.textContent = 'Password';
  const passwordInput = document.createElement('input');
  passwordInput.name = 'password';
  passwordInput.type = 'password';
  passwordInput.required = true;
  passwordInput.minLength = 8;
  passwordInput.placeholder = 'minimum 8 characters';
  passwordField.appendChild(passwordInput);

  const errorText = document.createElement('p');
  errorText.id = 'auth-error';
  errorText.className = 'form-error';

  const submit = document.createElement('button');
  submit.type = 'submit';
  submit.className = 'primary-button full-button';
  submit.innerHTML = 'Create account <span>→</span>';

  form.append(usernameField, passwordField, errorText, submit);
  form.addEventListener('submit', handleCreateSubmit);

  const switchButton = document.createElement('button');
  switchButton.type = 'button';
  switchButton.className = 'switch-button';
  switchButton.textContent = 'Back to login';
  switchButton.addEventListener('click', () => showAuth('login'));

  wrapper.append(heading, form, switchButton);
  authContent.appendChild(wrapper);
}

function renderOtpSetupView(data) {
  const wrapper = document.createElement('div');
  wrapper.className = 'auth-box';

  const title = document.createElement('h2');
  title.textContent = 'Set up Google Authenticator';

  const description = document.createElement('p');
  description.className = 'muted';
  description.textContent = 'Scan the QR code, then enter the 6-digit code shown in the app.';

  const qrContainer = document.createElement('div');
  qrContainer.className = 'qr-wrap';

  const qrImage = document.createElement('img');
  qrImage.id = 'otp-qr';
  qrImage.alt = 'Google Authenticator QR code';
  qrImage.className = 'qr-image';

  const form = document.createElement('form');
  form.id = 'otp-setup-form';

  const codeInput = document.createElement('input');
  codeInput.name = 'otp';
  codeInput.type = 'text';
  codeInput.inputMode = 'numeric';
  codeInput.placeholder = 'Enter 6-digit code';
  codeInput.required = true;
  codeInput.maxLength = 6;

  const errorText = document.createElement('p');
  errorText.id = 'auth-error';
  errorText.className = 'form-error';

  const button = document.createElement('button');
  button.type = 'submit';
  button.className = 'primary-button full-button';
  button.textContent = 'Verify and finish';

  form.append(codeInput, errorText, button);
  form.addEventListener('submit', handleOtpSetupSubmit);

  qrContainer.appendChild(qrImage);
  wrapper.append(title, description, qrContainer, form);
  authContent.appendChild(wrapper);

  const uri = makeTotpUri(data.username, data.secret);
  if (uri) {
    const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(uri)}&size=220x220`;
    qrImage.src = qrUrl;
  }
}

function renderOtpLoginView(data) {
  const wrapper = document.createElement('div');
  wrapper.className = 'auth-box';

  const title = document.createElement('h2');
  title.textContent = 'Authenticator verification';

  const description = document.createElement('p');
  description.className = 'muted';
  description.textContent = `Enter the 6-digit code for ${data.username}.`;

  const form = document.createElement('form');
  form.id = 'otp-login-form';

  const input = document.createElement('input');
  input.name = 'otp';
  input.type = 'text';
  input.inputMode = 'numeric';
  input.placeholder = 'Enter 6-digit code';
  input.required = true;
  input.maxLength = 6;

  const errorText = document.createElement('p');
  errorText.id = 'auth-error';
  errorText.className = 'form-error';

  const submit = document.createElement('button');
  submit.type = 'submit';
  submit.className = 'primary-button full-button';
  submit.textContent = 'Verify code';

  form.append(input, errorText, submit);
  form.addEventListener('submit', handleOtpLoginSubmit);

  wrapper.append(title, description, form);
  authContent.appendChild(wrapper);
}

function renderDashboard() {
  appView.classList.remove('hidden');
  authView.classList.add('hidden');
  $('#welcome-user').textContent = `Signed in as ${state.user.username}`;
  loadEntries();
}

async function handleCreateSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const formData = new FormData(form);
  const username = normalizeUsername(formData.get('username'));
  const password = safeText(formData.get('password'));

  if (!username || username.length < 3) {
    $('#auth-error').textContent = 'Username must be at least 3 characters.';
    return;
  }

  if (password.length < 8) {
    $('#auth-error').textContent = 'Password must be at least 8 characters.';
    return;
  }

  const existing = await ensureUserExists(username);
  if (existing) {
    $('#auth-error').textContent = 'That username already exists.';
    return;
  }

  const saltBytes = crypto.getRandomValues(new Uint8Array(16));
  const passwordHash = await derivePasswordHash(password, saltBytes);
  const secret = getTotpSecret();

  if (!secret) {
    $('#auth-error').textContent = 'Unable to generate authenticator secret.';
    return;
  }

  try {
    const userDocRef = doc(db, 'users', username);
    const now = new Date();
    await setDoc(userDocRef, {
      username,
      passwordHash,
      passwordSalt: Array.from(saltBytes).map((value) => value.toString(16).padStart(2, '0')).join(''),
      otpSecret: secret,
      otpEnabled: false,
      createdAt: now,
      updatedAt: now,
    });

    state.pendingSetup = { id: username, username, secret };
    showAuth('otp-setup');
  } catch (_error) {
    $('#auth-error').textContent = 'Could not create account. Please try again.';
  }
}

async function handleOtpSetupSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const formData = new FormData(form);
  const code = String(formData.get('otp') || '').trim();

  if (!state.pendingSetup) {
    $('#auth-error').textContent = 'No pending setup found.';
    return;
  }

  const valid = await verifyTotp(state.pendingSetup.secret, code);
  if (!valid) {
    $('#auth-error').textContent = 'The authenticator code is invalid.';
    return;
  }

  try {
    const recordRef = doc(db, 'users', state.pendingSetup.id);
    await updateDoc(recordRef, {
      otpEnabled: true,
      updatedAt: new Date(),
    });

    state.user = { id: state.pendingSetup.id, username: state.pendingSetup.username };
    state.pendingSetup = null;
    startAutoLogout();
    renderDashboard();
  } catch (_error) {
    $('#auth-error').textContent = 'Could not confirm setup. Please try again.';
  }
}

async function handleLoginSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const formData = new FormData(form);
  const username = normalizeUsername(formData.get('username'));
  const password = safeText(formData.get('password'));

  const errorBox = $('#auth-error');
  if (!username || !password) {
    errorBox.textContent = 'Username and password are required.';
    return;
  }

  const userRecord = await ensureUserExists(username);
  if (!userRecord) {
    errorBox.textContent = 'Invalid username or password.';
    return;
  }

  const computedHash = await derivePasswordHash(password, hexToBytes(userRecord.passwordSalt || ''));
  if (computedHash !== (userRecord.passwordHash || '')) {
    errorBox.textContent = 'Invalid username or password.';
    return;
  }

  if (!userRecord.otpEnabled) {
    errorBox.textContent = 'This account has not finished Google Authenticator setup.';
    return;
  }

  state.pendingLogin = { id: userRecord.id, username, secret: userRecord.otpSecret };
  showAuth('otp-login');
}

async function handleOtpLoginSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const formData = new FormData(form);
  const code = String(formData.get('otp') || '').trim();

  if (!state.pendingLogin) {
    $('#auth-error').textContent = 'No login in progress.';
    return;
  }

  const valid = await verifyTotp(state.pendingLogin.secret, code);
  if (!valid) {
    $('#auth-error').textContent = 'The authenticator code is invalid.';
    return;
  }

  state.user = { id: state.pendingLogin.id, username: state.pendingLogin.username };
  state.pendingLogin = null;
  startAutoLogout();
  renderDashboard();
}

function compareEntries(a, b) {
  const av = a.lastViewedAt || a.updatedAt || 0;
  const bv = b.lastViewedAt || b.updatedAt || 0;
  return Number(bv) - Number(av);
}

function renderEntries() {
  const grid = $('#entries-grid');
  if (!grid) return;
  grid.innerHTML = '';

  if (!entries.length) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';
    empty.innerHTML = '<div class="empty-icon">+</div><h3>Your vault is empty</h3><p>Add your first password to get started.</p>';
    grid.appendChild(empty);
    return;
  }

  entries.sort(compareEntries);
  for (const entry of entries) {
    const card = document.createElement('article');
    card.className = 'entry-card';

    const icon = document.createElement('div');
    icon.className = 'entry-icon';
    icon.textContent = (entry.label || 'V').substr(0, 1).toUpperCase();

    const main = document.createElement('div');
    main.className = 'entry-main';

    const heading = document.createElement('h4');
    heading.textContent = entry.label || 'Untitled';

    const subtitle = document.createElement('p');
    subtitle.textContent = entry.username || 'No username';

    const meta = document.createElement('span');
    meta.className = 'entry-meta';
    meta.textContent = `Last viewed: ${formatDisplayDate(entry.lastViewedAt)}`;

    main.append(heading, subtitle, meta);

    const openBtn = document.createElement('button');
    openBtn.type = 'button';
    openBtn.className = 'open-button';
    openBtn.textContent = 'Open ';
    const arrow = document.createElement('span');
    arrow.textContent = '→';
    openBtn.appendChild(arrow);
    openBtn.addEventListener('click', () => openEntry(entry.id));

    card.append(icon, main, openBtn);
    grid.appendChild(card);
  }
}

async function markEntryViewed(entryId) {
  if (!state.user || !entryId) return;
  const entryRef = doc(db, 'users', state.user.id, 'entries', entryId);
  const now = new Date();
  await updateDoc(entryRef, { lastViewedAt: now, updatedAt: now });

  const target = entries.find((item) => item.id === entryId);
  if (target) {
    target.lastViewedAt = now;
    target.updatedAt = now;
  }
  renderEntries();
}

function resetEntryForm() {
  const form = $('#entry-form');
  if (!form) return;
  form.reset();
  const passwordInput = form.querySelector('input[name="password"]');
  if (passwordInput) passwordInput.type = 'password';
  const revealButton = form.querySelector('.reveal-button');
  if (revealButton) revealButton.textContent = 'Show';
  $('#form-error').textContent = '';
  $('#delete-btn').classList.add('hidden');
  $('#edit-btn').classList.add('hidden');
  $('#cancel-edit-btn').classList.add('hidden');
  $('#modal').classList.add('hidden');
}

async function handleEntrySubmit(event) {
  event.preventDefault();
  if (!state.user) return;

  const form = event.currentTarget;
  const formData = new FormData(form);
  const label = safeText(formData.get('label')).trim();
  const username = safeText(formData.get('username')).trim();
  const password = safeText(formData.get('password')).trim();
  const remark = safeText(formData.get('remark')).trim();
  const errorBox = $('#form-error');

  if (!label || !username || !password) {
    errorBox.textContent = 'Label, username, and password are required.';
    return;
  }

  try {
    const now = new Date();
    if (editingId) {
      const recordRef = doc(db, 'users', state.user.id, 'entries', editingId);
      await updateDoc(recordRef, {
        label,
        username,
        password,
        remark,
        updatedAt: now,
      });
      const target = entries.find((entry) => entry.id === editingId);
      if (target) {
        Object.assign(target, { label, username, password, remark, updatedAt: now });
      }
    } else {
      await addDoc(collection(db, 'users', state.user.id, 'entries'), {
        userId: state.user.id,
        label,
        username,
        password,
        remark,
        createdAt: now,
        updatedAt: now,
        lastViewedAt: null,
        version: 1,
      });
    }

    await loadEntries();
    resetEntryForm();
  } catch (_error) {
    errorBox.textContent = 'Could not save this entry. Please try again.';
  }
}

async function openEntry(id) {
  const entry = entries.find((item) => item.id === id);
  if (!entry) return;
  editingId = id;

  const form = $('#entry-form');
  form.elements.label.value = entry.label || '';
  form.elements.username.value = entry.username || '';
  form.elements.password.value = entry.password || '';
  form.elements.remark.value = entry.remark || '';

  $('#modal-kicker').textContent = 'EDIT ENTRY';
  $('#modal-title').textContent = 'Open password';
  $('#delete-btn').classList.remove('hidden');
  $('#edit-btn').classList.remove('hidden');
  $('#cancel-edit-btn').classList.remove('hidden');
  $('#modal').classList.remove('hidden');

  await markEntryViewed(id);
}

async function deleteEntry() {
  if (!state.user || !editingId) return;
  try {
    const recordRef = doc(db, 'users', state.user.id, 'entries', editingId);
    await deleteDoc(recordRef);
    const index = entries.findIndex((entry) => entry.id === editingId);
    if (index >= 0) entries.splice(index, 1);
    await loadEntries();
    resetEntryForm();
  } catch (_error) {
    $('#form-error').textContent = 'Could not delete this entry.';
  }
}

$('#add-btn').addEventListener('click', () => {
  editingId = null;
  $('#modal-kicker').textContent = 'NEW ENTRY';
  $('#modal-title').textContent = 'Add a password';
  $('#form-error').textContent = '';
  $('#delete-btn').classList.add('hidden');
  $('#edit-btn').classList.add('hidden');
  $('#cancel-edit-btn').classList.add('hidden');
  $('#entry-form').reset();
  $('#modal').classList.remove('hidden');
});
$('#close-modal').addEventListener('click', () => resetEntryForm());
$('#logout-btn').addEventListener('click', () => {
  clearUserSession();
  showAuth('login');
});
$('#delete-btn').addEventListener('click', deleteEntry);
$('#edit-btn').addEventListener('click', () => {
  $('#entry-form').requestSubmit();
});
$('#cancel-edit-btn').addEventListener('click', () => resetEntryForm());
$('#entry-form').addEventListener('submit', handleEntrySubmit);
$('#entry-form .reveal-button')?.addEventListener('click', () => {
  const input = $('#entry-form input[name="password"]');
  const pressed = input.type === 'password';
  input.type = pressed ? 'text' : 'password';
  $('#entry-form .reveal-button').textContent = pressed ? 'Hide' : 'Show';
});

const infoContent = {
  privacy: ['Privacy policy', '<p>Access is protected by username, password, and Google Authenticator verification.</p>'],
  terms: ['Terms of service', '<p>This vault is for personal credential management only.</p>'],
  contact: ['Contact us', '<p>Contact PrasaTek System Solutions for support.</p>'],
};

document.querySelectorAll('[data-info]').forEach((link) => {
  link.addEventListener('click', (event) => {
    event.preventDefault();
    const [title, content] = infoContent[link.dataset.info];
    $('#info-title').textContent = title;
    $('#info-content').innerHTML = content;
    $('#info-modal').classList.remove('hidden');
  });
});
$('#close-info').addEventListener('click', () => $('#info-modal').classList.add('hidden'));

document.querySelector('#info-modal .modal-backdrop').addEventListener('click', () => $('#info-modal').classList.add('hidden'));

initializeTheme();
showAuth('login');
