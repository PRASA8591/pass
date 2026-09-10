import { initializeApp } from 'https://www.gstatic.com/firebasejs/11.0.2/firebase-app.js';
import { getAnalytics } from 'https://www.gstatic.com/firebasejs/11.0.2/firebase-analytics.js';
import { getAuth, onAuthStateChanged, signInWithEmailAndPassword, createUserWithEmailAndPassword, signOut, setPersistence, browserLocalPersistence } from 'https://www.gstatic.com/firebasejs/11.0.2/firebase-auth.js';
import { getFirestore, collection, addDoc, getDocs, getDoc, doc, updateDoc, deleteDoc, serverTimestamp } from 'https://www.gstatic.com/firebasejs/11.0.2/firebase-firestore.js';

const firebaseConfig = { apiKey: 'AIzaSyCB2SHj9ffusZoP2PI_wGlbXG3xZahk_dI', authDomain: 'mypassword-5e734.firebaseapp.com', projectId: 'mypassword-5e734', storageBucket: 'mypassword-5e734.firebasestorage.app', messagingSenderId: '13145555075', appId: '1:13145555075:web:de5740f087981b86c69bb6', measurementId: 'G-4D8VN1E901' };
const firebaseApp = initializeApp(firebaseConfig); try { getAnalytics(firebaseApp); } catch { /* Analytics may be unavailable on local hosts. */ }
const auth = getAuth(firebaseApp); const db = getFirestore(firebaseApp);
const $ = (selector) => document.querySelector(selector); const authView = $('#auth-view'); const appView = $('#app-view'); const authContent = $('#auth-content'); const THEME_KEY = 'pass-theme'; let entries = []; let editingId = null; let authMode = 'login'; let isEntryEditMode = false;

async function initializeAuthPersistence() {
  try {
    await setPersistence(auth, browserLocalPersistence);
  } catch (error) {
    console.warn('Auth persistence could not be enabled:', error);
  }

  onAuthStateChanged(auth, (user) => {
    if (user) {
      showApp();
    } else {
      appView.classList.add('hidden');
      authView.classList.remove('hidden');
      showAuth();
    }
  });
}

function applyTheme(theme) {
  const nextTheme = theme === 'dark' ? 'dark' : 'light';
  document.body.dataset.theme = nextTheme;
  const toggle = $('#theme-toggle');
  if (toggle) {
    const isDark = nextTheme === 'dark';
    toggle.setAttribute('aria-pressed', String(isDark));
    const icon = toggle.querySelector('.theme-toggle-icon');
    const text = toggle.querySelector('.theme-toggle-text');
    if (icon) icon.textContent = isDark ? '🌙' : '☀️';
    if (text) text.textContent = isDark ? 'Dark' : 'Light';
  }
  try { localStorage.setItem(THEME_KEY, nextTheme); } catch (error) { /* Ignore unavailable storage. */ }
}

function initializeTheme() {
  try {
    const savedTheme = localStorage.getItem(THEME_KEY);
    applyTheme(savedTheme === 'dark' ? 'dark' : 'light');
  } catch (error) {
    applyTheme('light');
  }

  const toggle = $('#theme-toggle');
  if (toggle) {
    toggle.addEventListener('click', () => {
      const nextTheme = document.body.dataset.theme === 'dark' ? 'light' : 'dark';
      applyTheme(nextTheme);
    });
  }
}

const usernameEmail = (username) => `${username.trim().toLowerCase().replace(/[^a-z0-9._-]/g, '-')}@mypassword-5e734.firebaseapp.com`;
const entriesRef = () => collection(db, 'users', auth.currentUser.uid, 'entries');
const readableAuthError = (error) => ({ 'auth/invalid-credential': 'Username or password is incorrect.', 'auth/email-already-in-use': 'That username is already in use.', 'auth/weak-password': 'Use a password of at least 10 characters.' }[error.code] || 'Could not complete that request.');

function bytesToBase64(bytes) {
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function base64ToBytes(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function getSessionKeyName() {
  return `passvault-key-${auth.currentUser?.uid || 'anonymous'}`;
}

function getEncryptedKey() {
  try {
    return sessionStorage.getItem(getSessionKeyName());
  } catch (error) {
    return null;
  }
}

function setEncryptedKey(value) {
  try {
    sessionStorage.setItem(getSessionKeyName(), value);
  } catch (error) {
    // Ignore storage access issues so the app can still run in a restricted browser session.
  }
}

async function getCryptoKey() {
  const existing = getEncryptedKey();
  if (existing) {
    return crypto.subtle.importKey('raw', base64ToBytes(existing), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }
  const secret = crypto.getRandomValues(new Uint8Array(32));
  const rawKey = bytesToBase64(secret);
  setEncryptedKey(rawKey);
  return crypto.subtle.importKey('raw', secret, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

async function encryptText(value) {
  const text = String(value ?? '');
  if (!text) return '';
  const cryptoKey = await getCryptoKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(text);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, cryptoKey, encoded);
  return `enc:${bytesToBase64(iv)}:${bytesToBase64(new Uint8Array(encrypted))}`;
}

async function decryptText(value) {
  if (typeof value !== 'string' || !value.startsWith('enc:')) return value;
  try {
    const [, ivBase64, payloadBase64] = value.split(':');
    if (!ivBase64 || !payloadBase64) return value;
    const cryptoKey = await getCryptoKey();
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: base64ToBytes(ivBase64) }, cryptoKey, base64ToBytes(payloadBase64));
    return new TextDecoder().decode(decrypted);
  } catch (error) {
    return value;
  }
}

async function decryptEntry(entry) {
  const decrypted = { ...entry };
  for (const field of ['label', 'username', 'password', 'remark']) {
    decrypted[field] = typeof entry[field] === 'string' ? await decryptText(entry[field]) : '';
  }
  return decrypted;
}

function setFormEditable(enabled) {
  const form = $('#entry-form');
  if (!form) return;
  const fields = form.querySelectorAll('input, textarea');
  fields.forEach((field) => {
    field.readOnly = !enabled;
    field.disabled = !enabled && editingId !== null;
  });
  const entryExists = Boolean(editingId);
  $('#delete-btn').classList.toggle('hidden', !entryExists);
  $('#edit-btn').classList.toggle('hidden', !entryExists || enabled);
  $('#cancel-edit-btn').classList.toggle('hidden', !entryExists || !enabled);
  $('#save-btn').classList.toggle('hidden', !enabled);
  if (enabled && entryExists) {
    $('#save-btn').textContent = 'Save changes';
  } else if (entryExists) {
    $('#save-btn').textContent = 'Save entry';
  } else {
    $('#save-btn').textContent = 'Save entry';
  }
}

function showAuth(mode = 'login') { authMode = mode; const setup = mode === 'setup'; authContent.innerHTML = setup ? `<p class="eyebrow">FIRST-TIME SETUP</p><h2>Create your vault</h2><p class="muted">Set the admin account that will protect every password in this vault.</p>` : `<p class="eyebrow">WELCOME BACK</p><h2>Unlock your vault</h2><p class="muted">Your passwords are waiting for you.</p>`; authContent.innerHTML += `<form id="auth-form"><label>Username<input name="username" required autocomplete="username" placeholder="admin" /></label><label>${setup ? 'Master password' : 'Password'}<input name="password" required minlength="10" type="password" autocomplete="${setup ? 'new-password' : 'current-password'}" placeholder="At least 10 characters" /></label><p id="auth-error" class="form-error"></p><button class="primary-button full-button">${setup ? 'Create secure vault' : 'Unlock vault'} <span>→</span></button></form><button id="auth-switch" class="switch-button">${setup ? 'Already have a vault? Sign in' : 'First time here? Create a vault'}</button><p class="security-note"><span>✦</span> Your vault is protected by Firebase Authentication and private Firestore rules.</p>`; $('#auth-form').addEventListener('submit', handleAuth); $('#auth-switch').addEventListener('click', () => showAuth(setup ? 'login' : 'setup')); }
async function handleAuth(event) { event.preventDefault(); const form = new FormData(event.target); const username = String(form.get('username') || '').trim(); const password = String(form.get('password') || ''); try { const email = usernameEmail(username); if (authMode === 'setup') await createUserWithEmailAndPassword(auth, email, password); else await signInWithEmailAndPassword(auth, email, password); } catch (error) { $('#auth-error').textContent = readableAuthError(error); } }
function formatLastView(value) {
  if (!value) return 'Never opened';
  const date = value?.seconds ? new Date(value.seconds * 1000) : new Date(value);
  if (Number.isNaN(date.getTime())) return 'Never opened';
  return new Intl.DateTimeFormat(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' }).format(date);
}

function sortEntries() {
  entries.sort((a, b) => (b.updatedAt?.seconds || b.lastViewedAt?.seconds || 0) - (a.updatedAt?.seconds || a.lastViewedAt?.seconds || 0));
}

function updateEntryLastView(entryId) {
  const index = entries.findIndex((entry) => entry.id === entryId);
  if (index === -1) return;
  const now = { seconds: Math.floor(Date.now() / 1000), nanoseconds: 0 };
  entries[index] = { ...entries[index], lastViewedAt: now };
  sortEntries();
  renderEntries();
}

function showApp() { authView.classList.add('hidden'); appView.classList.remove('hidden'); $('#welcome-user').textContent = `Signed in as ${auth.currentUser.email.split('@')[0]}`; loadEntries(); }
async function loadEntries() { const snapshot = await getDocs(entriesRef()); entries = await Promise.all(snapshot.docs.map(async (item) => decryptEntry({ id: item.id, ...item.data() }))); sortEntries(); renderEntries(); $('#total-count').textContent = entries.length; $('#last-updated').textContent = entries[0]?.updatedAt ? new Date(entries[0].updatedAt.seconds * 1000).toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : '—'; }
function renderEntries() { const term = $('#search-input').value.trim().toLowerCase(); const visible = entries.filter((entry) => `${entry.label || ''} ${entry.username || ''} ${entry.remark || ''}`.toLowerCase().includes(term)); $('#entries-grid').innerHTML = visible.length ? visible.map((entry) => `<article class="entry-card"><div class="entry-icon">${escapeHtml((entry.label || 'V').charAt(0).toUpperCase())}</div><div class="entry-main"><h4>${escapeHtml(entry.label || 'Untitled')}</h4><p>${escapeHtml(entry.username || 'No username')}</p><span class="entry-meta">Last viewed: ${escapeHtml(formatLastView(entry.lastViewedAt))}</span></div><button class="open-button" data-id="${entry.id}">Open <span>→</span></button></article>`).join('') : `<div class="empty-state"><div class="empty-icon">+</div><h3>${term ? 'No matches found' : 'Your vault is empty'}</h3><p>${term ? 'Try a different search.' : 'Add your first password to get started.'}</p></div>`; document.querySelectorAll('.open-button').forEach((button) => button.addEventListener('click', () => openEntry(button.dataset.id))); }
function escapeHtml(value) { return String(value).replace(/[&<>"']/g, (char) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[char])); }
function openModal(entry) { const form = $('#entry-form'); editingId = entry?.id || null; isEntryEditMode = !entry; $('#modal-kicker').textContent = entry ? 'EDIT ENTRY' : 'NEW ENTRY'; $('#modal-title').textContent = entry ? 'Edit password' : 'Add a password'; form.reset(); if (entry) { Object.entries(entry).forEach(([key, value]) => { if (form.elements[key] && typeof value === 'string') form.elements[key].value = value; }); setFormEditable(false); } else { setFormEditable(true); } $('#form-error').textContent = ''; $('#modal').classList.remove('hidden'); form.elements.label.focus(); }
async function openEntry(id) {
  const cachedEntry = entries.find((entry) => entry.id === id);
  if (cachedEntry) {
    openModal({ ...cachedEntry });
    updateEntryLastView(id);
    const ref = doc(db, 'users', auth.currentUser.uid, 'entries', id);
    void updateDoc(ref, { lastViewedAt: serverTimestamp() }).catch(() => {});
    return;
  }

  try {
    const ref = doc(db, 'users', auth.currentUser.uid, 'entries', id);
    const snapshot = await getDoc(ref);
    if (!snapshot.exists()) throw new Error('Entry not found.');
    const entry = await decryptEntry({ id: snapshot.id, ...snapshot.data() });
    openModal(entry);
    updateEntryLastView(id);
    void updateDoc(ref, { lastViewedAt: serverTimestamp() }).catch(() => {});
  } catch (error) {
    alert(error.message);
  }
}
$('#add-btn').addEventListener('click', () => { editingId = null; isEntryEditMode = true; openModal(); }); $('#close-modal').addEventListener('click', () => $('#modal').classList.add('hidden')); $('.modal-backdrop').addEventListener('click', () => $('#modal').classList.add('hidden')); $('#search-input').addEventListener('input', renderEntries);
$('#edit-btn').addEventListener('click', () => { isEntryEditMode = true; setFormEditable(true); const form = $('#entry-form'); form.elements.label.focus(); });
$('#cancel-edit-btn').addEventListener('click', async () => { if (!editingId) return; const snapshot = await getDoc(doc(db, 'users', auth.currentUser.uid, 'entries', editingId)); if (snapshot.exists()) { const entry = await decryptEntry({ id: snapshot.id, ...snapshot.data() }); openModal(entry); } });
$('.reveal-button').addEventListener('click', (event) => { const input = event.target.previousElementSibling; input.type = input.type === 'password' ? 'text' : 'password'; event.target.textContent = input.type === 'password' ? 'Show' : 'Hide'; });
$('#entry-form').addEventListener('submit', async (event) => { event.preventDefault(); const formData = new FormData(event.target); const payload = {
  label: String(formData.get('label') || '').trim(),
  username: String(formData.get('username') || '').trim(),
  password: String(formData.get('password') || '').trim(),
  remark: String(formData.get('remark') || '').trim(),
};

if (!payload.label || !payload.username || !payload.password) {
  $('#form-error').textContent = 'URL, username, and password are required.';
  return;
}

try {
  const encryptedPayload = {
    label: await encryptText(payload.label),
    username: await encryptText(payload.username),
    password: await encryptText(payload.password),
    remark: await encryptText(payload.remark),
  };

  if (editingId) {
    await updateDoc(doc(db, 'users', auth.currentUser.uid, 'entries', editingId), { ...encryptedPayload, updatedAt: serverTimestamp() });
  } else {
    await addDoc(entriesRef(), { ...encryptedPayload, createdAt: serverTimestamp(), updatedAt: serverTimestamp() });
  }

  $('#modal').classList.add('hidden');
  await loadEntries();
} catch (error) {
  $('#form-error').textContent = 'Could not save this entry. Check your browser security settings and Firebase configuration.';
}
});
$('#delete-btn').addEventListener('click', async () => { if (!editingId || !confirm('Delete this password permanently?')) return; await deleteDoc(doc(db, 'users', auth.currentUser.uid, 'entries', editingId)); $('#modal').classList.add('hidden'); await loadEntries(); }); $('#logout-btn').addEventListener('click', () => signOut(auth));
const infoContent = { privacy: ['Privacy policy', '<p>PassVault stores your account and password entries in Firebase services connected to this project. Your entries are protected by Firebase Authentication and owner-only Firestore rules.</p><p>We do not sell or share your vault data. Keep your master password private and sign out on shared devices.</p>'], terms: ['Terms of service', '<p>PassVault is provided for personal credential management. You are responsible for the accuracy of entries and for protecting your account credentials.</p><p>Use the service lawfully and do not share access to your private vault.</p>'], contact: ['Contact us', '<p>For support about this PassVault installation, contact PrasaTek System Solutions.</p><p><a class="contact-link" href="mailto:info@prasatek.lk">info@prasatek.lk</a></p><p><a class="contact-link" href="https://time.prasatek.lk/" target="_blank" rel="noreferrer">time.prasatek.lk</a></p>'] };
document.querySelectorAll('[data-info]').forEach((link) => link.addEventListener('click', (event) => { event.preventDefault(); const [title, content] = infoContent[link.dataset.info]; $('#info-title').textContent = title; $('#info-content').innerHTML = content; $('#info-modal').classList.remove('hidden'); })); $('#close-info').addEventListener('click', () => $('#info-modal').classList.add('hidden')); document.querySelector('#info-modal .modal-backdrop').addEventListener('click', () => $('#info-modal').classList.add('hidden'));
initializeTheme();
initializeAuthPersistence();