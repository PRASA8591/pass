import { initializeApp } from 'https://www.gstatic.com/firebasejs/11.0.2/firebase-app.js';
import { getAnalytics } from 'https://www.gstatic.com/firebasejs/11.0.2/firebase-analytics.js';
import {
  getAuth,
  onAuthStateChanged,
  signInWithEmailAndPassword,
  createUserWithEmailAndPassword,
  signOut,
  setPersistence,
  browserLocalPersistence,
} from 'https://www.gstatic.com/firebasejs/11.0.2/firebase-auth.js';
import {
  getFirestore,
  collection,
  addDoc,
  getDocs,
  getDoc,
  doc,
  updateDoc,
  deleteDoc,
  serverTimestamp,
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
try {
  getAnalytics(firebaseApp);
} catch (_error) {
  // analytics is not required for the vault to work locally
}

const auth = getAuth(firebaseApp);
const db = getFirestore(firebaseApp);
const dexieDb = new Dexie('passvault-local');
dexieDb.version(1).stores({
  entries: '++id, userId, label, username, password, remark, createdAt, updatedAt, lastViewedAt',
});

const $ = (selector) => document.querySelector(selector);
const authView = $('#auth-view');
const appView = $('#app-view');
const authContent = $('#auth-content');
const themeKey = 'pass-theme';

const state = {
  masterPassword: '',
  user: null,
};

let entries = [];
let editingId = null;
let authMode = 'login';

const usernameEmail = (username) =>
  `${username.trim().toLowerCase().replace(/[^a-z0-9._-]/g, '-')}@mypassword-5e734.firebaseapp.com`;

const readableAuthError = (error) => ({
  'auth/invalid-credential': 'Username or password is incorrect.',
  'auth/email-already-in-use': 'That username is already in use.',
  'auth/weak-password': 'Use a password of at least 10 characters.',
}[error.code] || 'Could not complete that request.');

const entriesRef = () => collection(db, 'users', auth.currentUser.uid, 'entries');

function toBase64(bytes) {
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

async function deriveKey(masterPassword, saltBytes) {
  const imported = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(masterPassword),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltBytes,
      iterations: 200000,
      hash: 'SHA-256',
    },
    imported,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptSecret(value, masterPassword) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(masterPassword, salt);
  const cipher = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    new TextEncoder().encode(value)
  );

  return {
    salt: toBase64(salt),
    iv: toBase64(iv),
    ct: toBase64(new Uint8Array(cipher)),
  };
}

async function decryptSecret(payload, masterPassword) {
  if (!payload || typeof payload !== 'object') return '';

  const salt = fromBase64(payload.salt || '');
  const iv = fromBase64(payload.iv || '');
  const ct = fromBase64(payload.ct || '');

  if (!salt.length || !iv.length || !ct.length) return '';

  try {
    const key = await deriveKey(masterPassword, salt);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
    return new TextDecoder().decode(decrypted);
  } catch (_error) {
    return '';
  }
}

async function encryptEntryRecord(entry, masterPassword) {
  const encrypted = { ...entry };
  for (const field of ['label', 'username', 'password', 'remark']) {
    const value = typeof entry[field] === 'string' ? entry[field] : '';
    if (value) {
      encrypted[field] = await encryptSecret(value, masterPassword);
    } else {
      encrypted[field] = { salt: '', iv: '', ct: '' };
    }
  }
  return encrypted;
}

async function decryptEntryRecord(entry, masterPassword) {
  const decrypted = { ...entry };
  for (const field of ['label', 'username', 'password', 'remark']) {
    if (entry[field] && typeof entry[field] === 'object' && entry[field].ct) {
      decrypted[field] = await decryptSecret(entry[field], masterPassword);
    } else {
      decrypted[field] = typeof entry[field] === 'string' ? entry[field] : '';
    }
  }
  return decrypted;
}

function clearMemorySession() {
  state.masterPassword = '';
  state.user = null;
  entries = [];
  editingId = null;
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

function renderAuthForm() {
  authContent.replaceChildren();

  const intro = document.createElement('div');
  intro.className = 'auth-intro';

  const eyebrow = document.createElement('p');
  eyebrow.className = 'eyebrow';
  eyebrow.textContent = authMode === 'setup' ? 'FIRST-TIME SETUP' : 'WELCOME BACK';

  const title = document.createElement('h2');
  title.textContent = authMode === 'setup' ? 'Create your vault' : 'Unlock your vault';

  const muted = document.createElement('p');
  muted.className = 'muted';
  muted.textContent = authMode === 'setup'
    ? 'Create your secure vault and protect every saved password.'
    : 'Use your Firebase account and master password to unlock the vault.';

  intro.append(eyebrow, title, muted);

  const form = document.createElement('form');
  form.id = 'auth-form';

  const usernameLabel = document.createElement('label');
  usernameLabel.textContent = 'Username';
  const usernameInput = document.createElement('input');
  usernameInput.name = 'username';
  usernameInput.required = true;
  usernameInput.autocomplete = 'username';
  usernameInput.placeholder = 'admin';
  usernameLabel.appendChild(usernameInput);

  const firebasePasswordLabel = document.createElement('label');
  firebasePasswordLabel.textContent = 'Firebase password';
  const firebasePasswordInput = document.createElement('input');
  firebasePasswordInput.name = 'firebasePassword';
  firebasePasswordInput.type = 'password';
  firebasePasswordInput.required = true;
  firebasePasswordInput.minLength = 10;
  firebasePasswordInput.autocomplete = authMode === 'setup' ? 'new-password' : 'current-password';
  firebasePasswordInput.placeholder = 'At least 10 characters';
  firebasePasswordLabel.appendChild(firebasePasswordInput);

  const masterPasswordLabel = document.createElement('label');
  masterPasswordLabel.textContent = 'Master password';
  const masterPasswordInput = document.createElement('input');
  masterPasswordInput.name = 'masterPassword';
  masterPasswordInput.type = 'password';
  masterPasswordInput.required = true;
  masterPasswordInput.minLength = 10;
  masterPasswordInput.autocomplete = 'off';
  masterPasswordInput.placeholder = 'Stored only in memory';
  masterPasswordLabel.appendChild(masterPasswordInput);

  const errorText = document.createElement('p');
  errorText.id = 'auth-error';
  errorText.className = 'form-error';

  const submit = document.createElement('button');
  submit.type = 'submit';
  submit.className = 'primary-button full-button';
  submit.innerHTML = `${authMode === 'setup' ? 'Create secure vault' : 'Unlock vault'} <span>→</span>`;

  form.append(usernameLabel, firebasePasswordLabel, masterPasswordLabel, errorText, submit);
  form.addEventListener('submit', handleAuth);

  const switchButton = document.createElement('button');
  switchButton.type = 'button';
  switchButton.className = 'switch-button';
  switchButton.textContent = authMode === 'setup' ? 'Already have a vault? Sign in' : 'First time here? Create a vault';
  switchButton.addEventListener('click', () => {
    authMode = authMode === 'setup' ? 'login' : 'setup';
    renderAuthForm();
  });

  const securityNote = document.createElement('p');
  securityNote.className = 'security-note';
  securityNote.innerHTML = '<span>✦</span> Encryption runs in your browser using a PBKDF2-derived key that stays in memory only.';

  authContent.append(intro, form, switchButton, securityNote);
}

function showAuth(mode = 'login') {
  authMode = mode;
  renderAuthForm();
}

async function handleAuth(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const formData = new FormData(form);
  const username = String(formData.get('username') || '').trim();
  const firebasePassword = String(formData.get('firebasePassword') || '').trim();
  const masterPassword = String(formData.get('masterPassword') || '').trim();

  if (!username || !firebasePassword || !masterPassword) {
    const errorBox = $('#auth-error');
    if (errorBox) {
      errorBox.textContent = 'Username, Firebase password, and master password are required.';
    }
    return;
  }

  try {
    const email = usernameEmail(username);
    if (authMode === 'setup') {
      await createUserWithEmailAndPassword(auth, email, firebasePassword);
    } else {
      await signInWithEmailAndPassword(auth, email, firebasePassword);
    }

    state.masterPassword = masterPassword;
    showApp();
  } catch (error) {
    const errorBox = $('#auth-error');
    if (errorBox) {
      errorBox.textContent = readableAuthError(error);
    }
  }
}

async function initializeAuthPersistence() {
  try {
    await setPersistence(auth, browserLocalPersistence);
  } catch (_error) {
    // some browsers restrict persistence
  }

  onAuthStateChanged(auth, (user) => {
    if (user) {
      state.user = user;
      appView.classList.remove('hidden');
      authView.classList.add('hidden');
      $('#welcome-user').textContent = `Signed in as ${user.email.split('@')[0]}`;
      loadEntries();
    } else {
      clearMemorySession();
      appView.classList.add('hidden');
      authView.classList.remove('hidden');
      showAuth();
    }
  });
}

function formatLastView(value) {
  if (!value) return 'Never opened';
  const date = value?.seconds ? new Date(value.seconds * 1000) : new Date(value);
  if (Number.isNaN(date.getTime())) return 'Never opened';
  return new Intl.DateTimeFormat(undefined, {
    month: 'short',
    day: 'numeric',
    year: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  }).format(date);
}

function sortEntries() {
  entries.sort((a, b) => {
    const aStamp = b.updatedAt?.seconds ?? b.lastViewedAt?.seconds ?? 0;
    const bStamp = a.updatedAt?.seconds ?? a.lastViewedAt?.seconds ?? 0;
    return aStamp - bStamp;
  });
}

function setFormEditable(enabled) {
  const form = $('#entry-form');
  if (!form) return;

  const fields = form.querySelectorAll('input, textarea');
  fields.forEach((field) => {
    field.readOnly = !enabled;
    field.disabled = !enabled && editingId !== null;
  });

  const hasEntry = Boolean(editingId);
  $('#delete-btn').classList.toggle('hidden', !hasEntry);
  $('#edit-btn').classList.toggle('hidden', !hasEntry || enabled);
  $('#cancel-edit-btn').classList.toggle('hidden', !hasEntry || !enabled);
  $('#save-btn').classList.toggle('hidden', !enabled);
}

async function loadLocalEntries() {
  if (!auth.currentUser || !state.masterPassword) return [];

  const rows = await dexieDb.entries.where('userId').equals(auth.currentUser.uid).toArray();
  const decrypted = [];

  for (const row of rows) {
    const plain = await decryptEntryRecord(row, state.masterPassword);
    decrypted.push({
      id: row.id,
      userId: row.userId,
      label: plain.label,
      username: plain.username,
      password: plain.password,
      remark: plain.remark,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt,
      lastViewedAt: row.lastViewedAt,
    });
  }

  return decrypted;
}

async function loadEntries() {
  if (!auth.currentUser || !state.masterPassword) return;

  try {
    const snapshot = await getDocs(entriesRef());
    const cloudEntries = [];

    for (const document of snapshot.docs) {
      const data = document.data();
      if (data.userId !== auth.currentUser.uid) continue;
      const plain = await decryptEntryRecord(data, state.masterPassword);
      cloudEntries.push({
        id: document.id,
        userId: data.userId,
        label: plain.label,
        username: plain.username,
        password: plain.password,
        remark: plain.remark,
        createdAt: data.createdAt,
        updatedAt: data.updatedAt,
        lastViewedAt: data.lastViewedAt,
      });
    }

    entries = cloudEntries.length ? cloudEntries : await loadLocalEntries();
  } catch (_error) {
    entries = await loadLocalEntries();
  }

  sortEntries();
  renderEntries();
  $('#total-count').textContent = String(entries.length);
  const newest = entries[0]?.updatedAt?.seconds ? new Date(entries[0].updatedAt.seconds * 1000) : null;
  $('#last-updated').textContent = newest ? newest.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : '—';
}

function renderEntries() {
  const term = $('#search-input').value.trim().toLowerCase();
  const visible = entries.filter(({ label, username, remark }) => `${label || ''} ${username || ''} ${remark || ''}`.toLowerCase().includes(term));
  const grid = $('#entries-grid');
  grid.replaceChildren();

  if (!visible.length) {
    const empty = document.createElement('div');
    empty.className = 'empty-state';

    const icon = document.createElement('div');
    icon.className = 'empty-icon';
    icon.textContent = '+';

    const title = document.createElement('h3');
    title.textContent = term ? 'No matches found' : 'Your vault is empty';

    const desc = document.createElement('p');
    desc.textContent = term ? 'Try a different search.' : 'Add your first password to get started.';

    empty.append(icon, title, desc);
    grid.appendChild(empty);
    return;
  }

  for (const entry of visible) {
    const card = document.createElement('article');
    card.className = 'entry-card';

    const icon = document.createElement('div');
    icon.className = 'entry-icon';
    icon.textContent = (entry.label || 'V').charAt(0).toUpperCase();

    const main = document.createElement('div');
    main.className = 'entry-main';

    const heading = document.createElement('h4');
    heading.textContent = entry.label || 'Untitled';

    const username = document.createElement('p');
    username.textContent = entry.username || 'No username';

    const meta = document.createElement('span');
    meta.className = 'entry-meta';
    meta.textContent = `Last viewed: ${formatLastView(entry.lastViewedAt)}`;

    main.append(heading, username, meta);

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'open-button';
    button.dataset.id = String(entry.id);
    button.textContent = 'Open ';

    const arrow = document.createElement('span');
    arrow.textContent = '→';
    button.appendChild(arrow);
    button.addEventListener('click', () => openEntry(entry.id));

    card.append(icon, main, button);
    grid.appendChild(card);
  }
}

function openModal(entry) {
  const form = $('#entry-form');
  editingId = entry?.id || null;
  $('#modal-kicker').textContent = entry ? 'EDIT ENTRY' : 'NEW ENTRY';
  $('#modal-title').textContent = entry ? 'Edit password' : 'Add a password';
  form.reset();

  if (entry) {
    for (const [key, value] of Object.entries(entry)) {
      const field = form.elements[key];
      if (field && typeof value === 'string') field.value = value;
    }
    setFormEditable(false);
  } else {
    setFormEditable(true);
  }

  $('#form-error').textContent = '';
  $('#modal').classList.remove('hidden');
  form.elements.label.focus();
}

async function openEntry(id) {
  const model = entries.find((item) => item.id === id);
  if (!model) return;

  openModal({ ...model });

  const now = { seconds: Math.floor(Date.now() / 1000), nanoseconds: 0 };
  entries = entries.map((item) => (item.id === id ? { ...item, lastViewedAt: now } : item));
  renderEntries();

  try {
    await updateDoc(doc(db, 'users', auth.currentUser.uid, 'entries', id), {
      lastViewedAt: serverTimestamp(),
    });
  } catch (_error) {
    // use the local view timestamp even if the cloud update fails
  }
}

function showApp() {
  if (!auth.currentUser) return;
  appView.classList.remove('hidden');
  authView.classList.add('hidden');
  $('#welcome-user').textContent = `Signed in as ${auth.currentUser.email.split('@')[0]}`;
  loadEntries();
}

$('#add-btn').addEventListener('click', () => {
  editingId = null;
  openModal();
});
$('#close-modal').addEventListener('click', () => $('#modal').classList.add('hidden'));
$('.modal-backdrop').addEventListener('click', () => $('#modal').classList.add('hidden'));
$('#search-input').addEventListener('input', renderEntries);

$('#edit-btn').addEventListener('click', () => {
  setFormEditable(true);
  const entry = entries.find((item) => item.id === editingId);
  if (entry) openModal(entry);
});

$('#cancel-edit-btn').addEventListener('click', () => {
  const entry = entries.find((item) => item.id === editingId);
  if (entry) openModal(entry);
});

$('#logout-btn').addEventListener('click', async () => {
  await signOut(auth);
  clearMemorySession();
});

$('#delete-btn').addEventListener('click', async () => {
  if (!editingId || !confirm('Delete this password permanently?')) return;
  await deleteDoc(doc(db, 'users', auth.currentUser.uid, 'entries', editingId));
  $('#modal').classList.add('hidden');
  await loadEntries();
});

$('.reveal-button').addEventListener('click', (event) => {
  const button = event.currentTarget;
  const input = button.previousElementSibling;
  input.type = input.type === 'password' ? 'text' : 'password';
  button.textContent = input.type === 'password' ? 'Show' : 'Hide';
});

$('#entry-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const formData = new FormData(event.currentTarget);
  const payload = {
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
    const encrypted = await encryptEntryRecord(payload, state.masterPassword);
    const record = {
      userId: auth.currentUser.uid,
      label: encrypted.label,
      username: encrypted.username,
      password: encrypted.password,
      remark: encrypted.remark,
      version: 1,
      updatedAt: serverTimestamp(),
    };

    if (editingId) {
      await updateDoc(doc(db, 'users', auth.currentUser.uid, 'entries', editingId), record);
    } else {
      const created = await addDoc(entriesRef(), {
        ...record,
        createdAt: serverTimestamp(),
      });

      await dexieDb.entries.add({
        userId: auth.currentUser.uid,
        label: encrypted.label,
        username: encrypted.username,
        password: encrypted.password,
        remark: encrypted.remark,
        createdAt: new Date(),
        updatedAt: new Date(),
        lastViewedAt: null,
        firestoreId: created.id,
      });
    }

    $('#modal').classList.add('hidden');
    await loadEntries();
  } catch (_error) {
    $('#form-error').textContent = 'Could not save this entry. Check your browser security settings and Firebase configuration.';
  }
});

const infoContent = {
  privacy: ['Privacy policy', '<p>PassVault stores only encrypted data and never stores raw passwords in plain text.</p><p>All secrets are protected by a PBKDF2-derived key in memory for the current session only.</p>'],
  terms: ['Terms of service', '<p>PassVault is provided for personal credential storage and management. You remain responsible for keeping your master password private.</p>'],
  contact: ['Contact us', '<p>For support, contact PrasaTek System Solutions.</p><p><a class="contact-link" href="mailto:info@prasatek.lk">info@prasatek.lk</a></p>'],
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
initializeAuthPersistence();
