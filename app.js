/**
 * Pakka — Local-first, voice-friendly agreement tracker with SHA-256 tamper-evident event chain.
 * Zero external dependencies, pure vanilla JavaScript.
 */

// ==========================================
// 1. CRYPTO ENGINE & DETERMINISTIC SERIALIZER
// ==========================================

/**
 * Deterministic JSON serialization: recursively sorts object keys to guarantee
 * identical string output across different JavaScript runtimes.
 */
function canonicalStringify(obj) {
  if (obj === null || typeof obj !== 'object') {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return '[' + obj.map(item => canonicalStringify(item)).join(',') + ']';
  }
  const sortedKeys = Object.keys(obj).sort();
  const keyVals = sortedKeys.map(k => `"${k}":${canonicalStringify(obj[k])}`);
  return '{' + keyVals.join(',') + '}';
}

/**
 * SHA-256 implementation using Web Crypto API with a standalone JS fallback.
 */
async function computeSha256(text) {
  if (window.crypto && window.crypto.subtle && window.crypto.subtle.digest) {
    try {
      const msgBuffer = new TextEncoder().encode(text);
      const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgBuffer);
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } catch (e) {
      console.warn('Web Crypto digest failed, using JS fallback:', e);
    }
  }
  return jsSha256Fallback(text);
}

// Lightweight standard SHA-256 fallback (RFC 6234 compliant) for environments where SubtleCrypto is disabled
function jsSha256Fallback(ascii) {
  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }
  const mathPow = Math.pow;
  const maxWord = mathPow(2, 32);
  let lengthProperty = 'length';
  let i, j;
  let result = '';

  const words = [];
  const asciiBitLength = ascii[lengthProperty] * 8;
  
  let hash = jsSha256Fallback.h = jsSha256Fallback.h || [];
  const k = jsSha256Fallback.k = jsSha256Fallback.k || [];
  let primeCounter = k[lengthProperty];

  const isComposite = {};
  for (let candidate = 2; primeCounter < 64; candidate++) {
    if (!isComposite[candidate]) {
      for (i = 0; i < 300; i += candidate) {
        isComposite[i] = candidate;
      }
      hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
      k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
    }
  }

  ascii += '\x80';
  while ((ascii[lengthProperty] % 64) - 56) ascii += '\x00';
  for (i = 0; i < ascii[lengthProperty]; i++) {
    j = ascii.charCodeAt(i);
    if (j >> 8) return;
    words[i >> 2] |= j << (((3 - i) % 4) * 8);
  }
  words[words[lengthProperty]] = (asciiBitLength / maxWord) | 0;
  words[words[lengthProperty]] = asciiBitLength;

  for (j = 0; j < words[lengthProperty];) {
    const w = words.slice(j, j += 16);
    const oldHash = hash;
    hash = hash.slice(0, 8);

    for (i = 0; i < 64; i++) {
      const i2 = i + j;
      const w15 = w[i - 15], w2 = w[i - 2];
      const s0 = rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3);
      const s1 = rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10);
      const ch = (hash[4] & hash[5]) ^ (~hash[4] & hash[6]);
      const maj = (hash[0] & hash[1]) ^ (hash[0] & hash[2]) ^ (hash[1] & hash[2]);
      const temp1 = (hash[7] + (rightRotate(hash[4], 6) ^ rightRotate(hash[4], 11) ^ rightRotate(hash[4], 25)) + ch + k[i] + (w[i] = (i < 16) ? w[i] : (w[i - 16] + s0 + w[i - 7] + s1) | 0)) | 0;
      const temp2 = ((rightRotate(hash[0], 2) ^ rightRotate(hash[0], 13) ^ rightRotate(hash[0], 22)) + maj) | 0;

      hash = [(temp1 + temp2) | 0].concat(hash);
      hash[4] = (hash[4] + temp1) | 0;
    }
    for (i = 0; i < 8; i++) {
      hash[i] = (hash[i] + oldHash[i]) | 0;
    }
  }
  for (i = 0; i < 8; i++) {
    for (let b = 3; b >= 0; b--) {
      const chunk = (hash[i] >> (8 * b)) & 255;
      result += (chunk < 16 ? '0' : '') + chunk.toString(16);
    }
  }
  return result;
}

/**
 * Calculates the deterministic genesis hash for an agreement.
 */
async function computeGenesisHash(agreementId, createdAt) {
  const seedString = `pakka:genesis:${agreementId}:${createdAt}`;
  return await computeSha256(seedString);
}

/**
 * Calculates the hash of an individual event over its canonicalized fields.
 */
async function computeEventHash(event) {
  const hashPayload = {
    id: event.id,
    agreementId: event.agreementId,
    type: event.type,
    actor: event.actor,
    timestamp: event.timestamp,
    payload: event.payload,
    prevHash: event.prevHash
  };
  return await computeSha256(canonicalStringify(hashPayload));
}

/**
 * Full chain verification engine.
 * Replays every event from genesis and confirms every previous link and digest.
 */
async function verifyAgreementIntegrity(agreement) {
  if (!agreement || !Array.isArray(agreement.events) || agreement.events.length === 0) {
    return { isValid: false, reason: 'Agreement contains no event history.' };
  }

  const expectedGenesis = await computeGenesisHash(agreement.id, agreement.createdAt);
  let expectedPrevHash = expectedGenesis;

  for (let i = 0; i < agreement.events.length; i++) {
    const ev = agreement.events[i];

    // Check link integrity
    if (ev.prevHash !== expectedPrevHash) {
      return {
        isValid: false,
        errorEventIndex: i,
        eventId: ev.id,
        reason: `Broken chain link at event #${i + 1} (${ev.type}). Expected prevHash "${expectedPrevHash.slice(0, 10)}..." but found "${ev.prevHash ? ev.prevHash.slice(0, 10) : 'null'}...".`
      };
    }

    // Check digest integrity
    const computed = await computeEventHash(ev);
    if (computed !== ev.hash) {
      return {
        isValid: false,
        errorEventIndex: i,
        eventId: ev.id,
        reason: `Cryptographic digest mismatch at event #${i + 1} (${ev.type}). Payload has been altered without a matching hash.`
      };
    }

    expectedPrevHash = ev.hash;
  }

  return { isValid: true, eventCount: agreement.events.length };
}


// ==========================================
// 2. PRELOADED SAMPLE SCENARIOS
// ==========================================

const SAMPLE_AGREEMENTS_DATA = [
  {
    id: 'ag_rahul_posters',
    clientName: 'Rahul Sharma',
    workerName: 'Aman Verma',
    deliverables: '20 print-ready promotional posters for Goa Tech Festival 2026. High-res PDF and PNG exports in 300 DPI.',
    amount: 4000,
    currency: 'INR',
    dueDate: '2026-10-30',
    acceptanceCriteria: 'Colors match fest palette; 1 revision round included; files approved in write-up via email.',
    paymentTerms: '50% advance before layout printing, 50% upon final acceptance.',
    status: 'active',
    amountPaid: 2000,
    createdAt: '2026-10-24T10:00:00.000Z',
    updatedAt: '2026-10-25T14:30:00.000Z',
    clientConfirmed: true,
    clientConfirmedAt: '2026-10-24T10:15:00.000Z',
    workerConfirmed: true,
    workerConfirmedAt: '2026-10-24T10:20:00.000Z',
    events: [] // Populated during seed
  },
  {
    id: 'ag_priya_shopify',
    clientName: 'Priya Patel',
    workerName: 'Neha Kapoor',
    deliverables: 'Shopify storefront setup with custom theme styling, 15 product uploads, and Razorpay test payment integration.',
    amount: 18000,
    currency: 'INR',
    dueDate: '2026-11-08',
    acceptanceCriteria: 'End-to-end checkout demo on staging; mobile responsive; speed score above 75.',
    paymentTerms: '30% upfront, 40% on test site demo, 30% after domain handover.',
    status: 'awaiting_confirmation',
    amountPaid: 0,
    createdAt: '2026-10-25T16:00:00.000Z',
    updatedAt: '2026-10-25T16:00:00.000Z',
    clientConfirmed: true,
    clientConfirmedAt: '2026-10-25T16:05:00.000Z',
    workerConfirmed: false,
    workerConfirmedAt: null,
    events: []
  },
  {
    id: 'ag_carlos_branding',
    clientName: 'Carlos Fernandes',
    workerName: 'Devika Roy',
    deliverables: 'Branding identity and 5 social media launch graphics for Cafe Goa.',
    amount: 7500,
    currency: 'INR',
    dueDate: '2026-11-04',
    acceptanceCriteria: '', // Intentionally blank to demonstrate missing-terms check
    paymentTerms: 'Full payment on delivery',
    status: 'draft',
    amountPaid: 0,
    createdAt: '2026-10-26T09:00:00.000Z',
    updatedAt: '2026-10-26T09:00:00.000Z',
    clientConfirmed: false,
    clientConfirmedAt: null,
    workerConfirmed: false,
    workerConfirmedAt: null,
    events: []
  }
];

// Seed sample events with genuine SHA-256 chains
async function buildSampleChains() {
  // Scenario 1: Rahul Posters
  const s1 = SAMPLE_AGREEMENTS_DATA[0];
  const g1 = await computeGenesisHash(s1.id, s1.createdAt);
  
  const e1_0 = {
    id: 'ev_1_created',
    agreementId: s1.id,
    type: 'agreement_created',
    actor: 'Aman Verma (Worker)',
    timestamp: '2026-10-24T10:00:00.000Z',
    payload: { amount: 4000, deliverables: s1.deliverables, dueDate: s1.dueDate },
    prevHash: g1
  };
  e1_0.hash = await computeEventHash(e1_0);

  const e1_1 = {
    id: 'ev_1_client_confirm',
    agreementId: s1.id,
    type: 'party_confirmed',
    actor: 'Rahul Sharma (Client)',
    timestamp: '2026-10-24T10:15:00.000Z',
    payload: { role: 'Client', confirmedTerms: true },
    prevHash: e1_0.hash
  };
  e1_1.hash = await computeEventHash(e1_1);

  const e1_2 = {
    id: 'ev_1_worker_confirm',
    agreementId: s1.id,
    type: 'party_confirmed',
    actor: 'Aman Verma (Worker)',
    timestamp: '2026-10-24T10:20:00.000Z',
    payload: { role: 'Worker', confirmedTerms: true, statusAdvancedTo: 'active' },
    prevHash: e1_1.hash
  };
  e1_2.hash = await computeEventHash(e1_2);

  const e1_3 = {
    id: 'ev_1_adv_payment',
    agreementId: s1.id,
    type: 'payment_update',
    actor: 'Rahul Sharma (Client)',
    timestamp: '2026-10-24T12:00:00.000Z',
    payload: { amountPaidNow: 2000, totalPaid: 2000, balanceRemaining: 2000, note: '50% advance via UPI' },
    prevHash: e1_2.hash
  };
  e1_3.hash = await computeEventHash(e1_3);

  const e1_4 = {
    id: 'ev_1_work_checkin',
    agreementId: s1.id,
    type: 'work_checkin',
    actor: 'Aman Verma (Worker)',
    timestamp: '2026-10-25T14:30:00.000Z',
    payload: { progressNote: 'Sent 10 draft layouts for client review over WhatsApp.' },
    prevHash: e1_3.hash
  };
  e1_4.hash = await computeEventHash(e1_4);

  s1.events = [e1_0, e1_1, e1_2, e1_3, e1_4];

  // Scenario 2: Priya Shopify
  const s2 = SAMPLE_AGREEMENTS_DATA[1];
  const g2 = await computeGenesisHash(s2.id, s2.createdAt);
  
  const e2_0 = {
    id: 'ev_2_created',
    agreementId: s2.id,
    type: 'agreement_created',
    actor: 'Priya Patel (Client)',
    timestamp: '2026-10-25T16:00:00.000Z',
    payload: { amount: 18000, deliverables: s2.deliverables, dueDate: s2.dueDate },
    prevHash: g2
  };
  e2_0.hash = await computeEventHash(e2_0);

  const e2_1 = {
    id: 'ev_2_client_confirm',
    agreementId: s2.id,
    type: 'party_confirmed',
    actor: 'Priya Patel (Client)',
    timestamp: '2026-10-25T16:05:00.000Z',
    payload: { role: 'Client', confirmedTerms: true },
    prevHash: e2_0.hash
  };
  e2_1.hash = await computeEventHash(e2_1);

  s2.events = [e2_0, e2_1];

  // Scenario 3: Carlos Branding
  const s3 = SAMPLE_AGREEMENTS_DATA[2];
  const g3 = await computeGenesisHash(s3.id, s3.createdAt);

  const e3_0 = {
    id: 'ev_3_created',
    agreementId: s3.id,
    type: 'agreement_created',
    actor: 'Devika Roy (Worker)',
    timestamp: '2026-10-26T09:00:00.000Z',
    payload: { amount: 7500, deliverables: s3.deliverables, dueDate: s3.dueDate },
    prevHash: g3
  };
  e3_0.hash = await computeEventHash(e3_0);

  s3.events = [e3_0];
}


// ==========================================
// 3. APPLICATION STATE & PERSISTENCE
// ==========================================

const STORAGE_KEY = 'pakka_agreements_v1';

const AppState = {
  agreements: [],
  selectedAgreementId: null,
  activeSimulatedRole: 'client', // 'client' or 'worker'
  speechRecognition: null,
  isRecordingSpeech: false,
  tamperedStateNotice: null
};

function saveState() {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(AppState.agreements));
  } catch (err) {
    console.error('Failed to save to localStorage:', err);
  }
}

async function loadState() {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored) {
    try {
      AppState.agreements = JSON.parse(stored);
    } catch (e) {
      console.warn('Failed parsing stored agreements, reseeding defaults.', e);
      await seedDefaults();
    }
  } else {
    await seedDefaults();
  }

  if (AppState.agreements.length > 0) {
    AppState.selectedAgreementId = AppState.agreements[0].id;
  }
}

async function seedDefaults() {
  await buildSampleChains();
  AppState.agreements = JSON.parse(JSON.stringify(SAMPLE_AGREEMENTS_DATA));
  saveState();
}

function getSelectedAgreement() {
  return AppState.agreements.find(a => a.id === AppState.selectedAgreementId) || null;
}


// ==========================================
// 4. MISSING TERMS VALIDATOR
// ==========================================

/**
 * Checks an agreement or form payload for missing/vague terms.
 * Returns an array of human-readable warnings.
 */
function inspectMissingTerms(data) {
  const missing = [];
  if (!data.clientName || !data.clientName.trim()) {
    missing.push('Client Name is required');
  }
  if (!data.workerName || !data.workerName.trim()) {
    missing.push('Worker Name is required');
  }
  if (!data.deliverables || data.deliverables.trim().length < 5) {
    missing.push('Deliverables description is too brief or missing');
  }
  const amt = Number(data.amount);
  if (isNaN(amt) || amt <= 0) {
    missing.push('Agreed amount in INR must be greater than zero');
  }
  if (!data.dueDate) {
    missing.push('Target Due Date is required');
  }
  if (!data.acceptanceCriteria || data.acceptanceCriteria.trim().length < 5) {
    missing.push('Clear Acceptance Criteria must be defined before activation');
  }
  if (!data.paymentTerms || data.paymentTerms.trim().length < 3) {
    missing.push('Payment terms / schedule must be specified');
  }
  return missing;
}


// ==========================================
// 5. NATURAL LANGUAGE BRIEF EXTRACTOR (NLP)
// ==========================================

/**
 * Parses informal text for rupees, deadlines, and candidate names.
 * Never silently finalizes terms; returns suggestions for review.
 */
function extractBriefSuggestions(text) {
  if (!text || !text.trim()) return [];
  const suggestions = [];

  // 1. Amount Extraction (₹, Rs, INR, k)
  const amtMatch = text.match(/(?:₹|rs\.?|inr)\s*([\d,]+)|([\d,]+)\s*(?:rupees|inr)|(\d+)\s*k\b/i);
  if (amtMatch) {
    let raw = amtMatch[1] || amtMatch[2];
    let val = 0;
    if (raw) {
      val = parseInt(raw.replace(/,/g, ''), 10);
    } else if (amtMatch[3]) {
      val = parseInt(amtMatch[3], 10) * 1000;
    }
    if (val > 0) {
      suggestions.push({
        field: 'amount',
        label: `Amount: ₹${val.toLocaleString('en-IN')}`,
        value: val
      });
    }
  }

  // 2. Day of week / Deadline Extraction
  const days = ['sunday', 'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday'];
  const dayMatch = text.match(/\b(friday|monday|tuesday|wednesday|thursday|saturday|sunday|tomorrow|next week)\b/i);
  if (dayMatch) {
    const word = dayMatch[1].toLowerCase();
    const targetDate = new Date();
    if (word === 'tomorrow') {
      targetDate.setDate(targetDate.getDate() + 1);
    } else if (word === 'next week') {
      targetDate.setDate(targetDate.getDate() + 7);
    } else {
      const targetDayIndex = days.indexOf(word);
      const currentDayIndex = targetDate.getDay();
      let diff = targetDayIndex - currentDayIndex;
      if (diff <= 0) diff += 7;
      targetDate.setDate(targetDate.getDate() + diff);
    }
    const isoDate = targetDate.toISOString().split('T')[0];
    suggestions.push({
      field: 'dueDate',
      label: `Deadline: ${isoDate} (${dayMatch[1]})`,
      value: isoDate
    });
  }

  // 3. Candidate Client Name: "for [Name]" or "with [Name]"
  const nameMatch = text.match(/(?:for|with)\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)/);
  if (nameMatch) {
    suggestions.push({
      field: 'clientName',
      label: `Client: ${nameMatch[1]}`,
      value: nameMatch[1]
    });
  }

  // 4. Candidate Deliverables hint
  if (text.length > 15) {
    suggestions.push({
      field: 'deliverables',
      label: `Use brief as Deliverables`,
      value: text.trim()
    });
  }

  return suggestions;
}


// ==========================================
// 6. UI RENDERING & DOM UPDATES
// ==========================================

function renderAgreementsList() {
  const container = document.getElementById('agreementsList');
  const emptyState = document.getElementById('agreementsEmptyState');
  const countBadge = document.getElementById('agreementsCount');

  countBadge.textContent = AppState.agreements.length;

  if (AppState.agreements.length === 0) {
    container.innerHTML = '';
    emptyState.style.display = 'block';
    return;
  }
  emptyState.style.display = 'none';

  container.innerHTML = AppState.agreements.map(ag => {
    const isSelected = ag.id === AppState.selectedAgreementId;
    const badgeClass = {
      draft: 'badge-draft',
      awaiting_confirmation: 'badge-awaiting',
      active: 'badge-active',
      completed: 'badge-completed',
      disputed: 'badge-disputed'
    }[ag.status] || 'badge-draft';

    const statusLabel = ag.status.replace('_', ' ');

    return `
      <div class="agreement-item ${isSelected ? 'active-item' : ''}" data-id="${ag.id}">
        <div class="agreement-item-header">
          <span class="agreement-item-parties">${escapeHtml(ag.clientName)} &bull; ${escapeHtml(ag.workerName)}</span>
          <span class="badge ${badgeClass}">${statusLabel}</span>
        </div>
        <div class="agreement-item-deliverables">${escapeHtml(ag.deliverables || 'No description')}</div>
        <div class="agreement-item-footer">
          <span class="agreement-item-amount">₹${(ag.amount || 0).toLocaleString('en-IN')}</span>
          <span class="agreement-item-date">Due: ${ag.dueDate || 'Unset'}</span>
        </div>
      </div>
    `;
  }).join('');

  // Add click handlers
  container.querySelectorAll('.agreement-item').forEach(el => {
    el.addEventListener('click', () => {
      AppState.selectedAgreementId = el.getAttribute('data-id');
      AppState.tamperedStateNotice = null; // Clear any transient tamper display
      renderAll();
    });
  });
}

async function renderSelectedAgreementWorkspace() {
  const ag = getSelectedAgreement();
  const workspace = document.getElementById('detailWorkspace');

  if (!ag) {
    workspace.style.display = 'none';
    return;
  }
  workspace.style.display = 'flex';

  // Header and terms
  document.getElementById('viewAgreementTitle').textContent = `${ag.deliverables ? ag.deliverables.slice(0, 32) + (ag.deliverables.length > 32 ? '...' : '') : 'Agreement'}`;
  document.getElementById('viewAgreementId').textContent = ag.id;
  document.getElementById('viewCreatedAt').textContent = new Date(ag.createdAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  
  const statusBadge = document.getElementById('viewStatusBadge');
  statusBadge.className = `badge badge-${ag.status === 'awaiting_confirmation' ? 'awaiting' : ag.status}`;
  statusBadge.textContent = ag.status.replace('_', ' ');

  document.getElementById('viewClientName').textContent = ag.clientName;
  document.getElementById('viewWorkerName').textContent = ag.workerName;
  document.getElementById('viewAmount').textContent = `₹${(ag.amount || 0).toLocaleString('en-IN')}`;
  document.getElementById('viewDueDate').textContent = ag.dueDate || 'Pending';
  document.getElementById('viewDeliverables').textContent = ag.deliverables;
  document.getElementById('viewAcceptanceCriteria').textContent = ag.acceptanceCriteria || '(Not yet specified)';
  document.getElementById('viewPaymentTerms').textContent = ag.paymentTerms || '(Not yet specified)';

  // Missing terms check in workspace
  const missing = inspectMissingTerms(ag);
  const missingBox = document.getElementById('missingTermsWarningBox');
  const missingList = document.getElementById('missingTermsList');
  if (missing.length > 0 && ag.status === 'draft') {
    missingBox.style.display = 'block';
    missingList.innerHTML = missing.map(m => `<span class="missing-term-pill">⚠️ ${escapeHtml(m)}</span>`).join('');
  } else {
    missingBox.style.display = 'none';
  }

  // Persona labels
  document.getElementById('roleLabelClient').textContent = ag.clientName ? ag.clientName.split(' ')[0] : 'Client';
  document.getElementById('roleLabelWorker').textContent = ag.workerName ? ag.workerName.split(' ')[0] : 'Worker';

  // Role button styles
  const isClientActive = AppState.activeSimulatedRole === 'client';
  document.getElementById('roleBtnClient').classList.toggle('active', isClientActive);
  document.getElementById('roleBtnWorker').classList.toggle('active', !isClientActive);

  // Dual confirmation cards
  const clientCardState = document.getElementById('confirmCardClientState');
  const clientCardTime = document.getElementById('confirmCardClientTime');
  const btnConfirmClient = document.getElementById('btnActionConfirmClient');

  if (ag.clientConfirmed) {
    clientCardState.textContent = 'Confirmed ✓';
    clientCardState.style.color = 'var(--success-text)';
    clientCardTime.textContent = `Confirmed at ${new Date(ag.clientConfirmedAt).toLocaleTimeString()}`;
    btnConfirmClient.style.display = 'none';
  } else {
    clientCardState.textContent = 'Pending Confirmation';
    clientCardState.style.color = 'var(--warning-text)';
    clientCardTime.textContent = 'Awaiting simulated review';
    btnConfirmClient.style.display = 'inline-flex';
    btnConfirmClient.disabled = !isClientActive || missing.length > 0;
    btnConfirmClient.title = !isClientActive ? 'Switch to Client role to confirm' : (missing.length > 0 ? 'Resolve missing terms first' : '');
  }

  const workerCardState = document.getElementById('confirmCardWorkerState');
  const workerCardTime = document.getElementById('confirmCardWorkerTime');
  const btnConfirmWorker = document.getElementById('btnActionConfirmWorker');

  if (ag.workerConfirmed) {
    workerCardState.textContent = 'Confirmed ✓';
    workerCardState.style.color = 'var(--success-text)';
    workerCardTime.textContent = `Confirmed at ${new Date(ag.workerConfirmedAt).toLocaleTimeString()}`;
    btnConfirmWorker.style.display = 'none';
  } else {
    workerCardState.textContent = 'Pending Confirmation';
    workerCardState.style.color = 'var(--warning-text)';
    workerCardTime.textContent = 'Awaiting simulated review';
    btnConfirmWorker.style.display = 'inline-flex';
    btnConfirmWorker.disabled = isClientActive || missing.length > 0;
    btnConfirmWorker.title = isClientActive ? 'Switch to Worker role to confirm' : (missing.length > 0 ? 'Resolve missing terms first' : '');
  }

  // Activate button
  const activationBox = document.getElementById('activationPromptBox');
  if (ag.status === 'draft' || ag.status === 'awaiting_confirmation') {
    if (ag.clientConfirmed && ag.workerConfirmed && missing.length === 0) {
      activationBox.style.display = 'block';
    } else {
      activationBox.style.display = 'none';
    }
  } else {
    activationBox.style.display = 'none';
  }

  // Financial Stats
  const paid = ag.amountPaid || 0;
  const total = ag.amount || 0;
  const remaining = Math.max(0, total - paid);
  const percent = total > 0 ? Math.min(100, Math.round((paid / total) * 100)) : 0;

  document.getElementById('statAmountPaid').textContent = `₹${paid.toLocaleString('en-IN')}`;
  document.getElementById('statAmountRemaining').textContent = `₹${remaining.toLocaleString('en-IN')}`;
  document.getElementById('financialProgressFill').style.width = `${percent}%`;

  // Dispute Toggle Button Text
  const btnDispute = document.getElementById('btnDisputeToggle');
  if (ag.status === 'disputed') {
    btnDispute.textContent = 'Resolve Dispute';
    btnDispute.className = 'btn btn-success btn-sm';
  } else {
    btnDispute.textContent = 'Flag Dispute';
    btnDispute.className = 'btn btn-danger btn-sm';
  }

  // SHA-256 Chain & Integrity Verification
  await renderIntegritySection(ag);
}

async function renderIntegritySection(ag) {
  const countLabel = document.getElementById('eventCountLabel');
  const badge = document.getElementById('integrityStatusBadge');
  const text = document.getElementById('integrityStatusText');
  const timeline = document.getElementById('eventTimeline');

  const events = ag.events || [];
  countLabel.textContent = events.length;

  // Run integrity verification
  const verification = await verifyAgreementIntegrity(ag);

  if (AppState.tamperedStateNotice) {
    badge.className = 'integrity-badge tampered';
    text.textContent = 'Tampering Detected ⚠️';
  } else if (verification.isValid) {
    badge.className = 'integrity-badge verified';
    text.textContent = 'Verified (SHA-256 Chain Intact)';
  } else {
    badge.className = 'integrity-badge tampered';
    text.textContent = 'Tampering Detected ⚠️';
  }

  // Render events in chronological order
  timeline.innerHTML = events.map((ev, idx) => {
    const isErrorEvent = !verification.isValid && verification.errorEventIndex === idx;
    const typeLabel = ev.type.replace(/_/g, ' ').toUpperCase();
    const timeFormatted = new Date(ev.timestamp).toLocaleString();

    let payloadSummary = '';
    if (ev.type === 'payment_update') {
      payloadSummary = `Payment recorded: +₹${ev.payload.amountPaidNow.toLocaleString('en-IN')} (Balance: ₹${ev.payload.balanceRemaining.toLocaleString('en-IN')}) &bull; ${escapeHtml(ev.payload.note || '')}`;
    } else if (ev.type === 'work_checkin') {
      payloadSummary = `Progress update: "${escapeHtml(ev.payload.progressNote)}"`;
    } else if (ev.type === 'party_confirmed') {
      payloadSummary = `${escapeHtml(ev.payload.role)} confirmed the terms of the agreement.`;
    } else if (ev.type === 'agreement_created') {
      payloadSummary = `Initial terms recorded: ₹${(ev.payload.amount || 0).toLocaleString('en-IN')} &bull; Deliverables: ${escapeHtml(ev.payload.deliverables)}`;
    } else {
      payloadSummary = JSON.stringify(ev.payload);
    }

    return `
      <div class="timeline-item" style="${isErrorEvent ? 'border-color: #ef4444; background: rgba(239, 68, 68, 0.1);' : ''}">
        <div class="timeline-item-header">
          <div style="display: flex; align-items: center; gap: 8px;">
            <strong style="font-size: 0.85rem; color: #fff;">#${idx + 1} ${typeLabel}</strong>
            <span class="timeline-actor-pill">${escapeHtml(ev.actor)}</span>
          </div>
          <span style="font-size: 0.725rem; color: var(--text-dim);">${timeFormatted}</span>
        </div>
        <div style="color: var(--text-muted); font-size: 0.8rem; margin: 4px 0;">
          ${payloadSummary}
        </div>
        ${isErrorEvent ? `<div style="color: #f87171; font-weight: 600; font-size: 0.75rem; margin: 4px 0;">🚨 ${verification.reason}</div>` : ''}
        <div class="timeline-hashes">
          <div>Prev: <span class="hash-val" title="Click to copy">${ev.prevHash ? ev.prevHash : 'Genesis'}</span></div>
          <div>Hash: <span class="hash-val" style="color: #38bdf8;" title="Click to copy">${ev.hash}</span></div>
        </div>
      </div>
    `;
  }).join('');
}

async function renderAll() {
  renderAgreementsList();
  await renderSelectedAgreementWorkspace();
}


// ==========================================
// 7. EVENT EMISSION & WORKFLOW ACTIONS
// ==========================================

async function appendEventToAgreement(ag, eventType, actorLabel, payload) {
  const genesisHash = await computeGenesisHash(ag.id, ag.createdAt);
  const lastEvent = ag.events && ag.events.length > 0 ? ag.events[ag.events.length - 1] : null;
  const prevHash = lastEvent ? lastEvent.hash : genesisHash;

  const newEvent = {
    id: `ev_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`,
    agreementId: ag.id,
    type: eventType,
    actor: actorLabel,
    timestamp: new Date().toISOString(),
    payload: payload,
    prevHash: prevHash
  };

  newEvent.hash = await computeEventHash(newEvent);
  
  if (!ag.events) ag.events = [];
  ag.events.push(newEvent);
  ag.updatedAt = newEvent.timestamp;

  saveState();
  await renderAll();
}

// Confirm as Client or Worker
async function handlePartyConfirm(role) {
  const ag = getSelectedAgreement();
  if (!ag) return;

  const now = new Date().toISOString();
  if (role === 'client') {
    ag.clientConfirmed = true;
    ag.clientConfirmedAt = now;
    await appendEventToAgreement(ag, 'party_confirmed', `${ag.clientName} (Client)`, {
      role: 'Client',
      confirmedTerms: true
    });
  } else {
    ag.workerConfirmed = true;
    ag.workerConfirmedAt = now;
    await appendEventToAgreement(ag, 'party_confirmed', `${ag.workerName} (Worker)`, {
      role: 'Worker',
      confirmedTerms: true
    });
  }

  // If both confirmed, transition to active
  if (ag.clientConfirmed && ag.workerConfirmed && ag.status === 'draft') {
    ag.status = 'awaiting_confirmation';
  }
  saveState();
  await renderAll();
}

// Final Activation Action
async function handleActivateAgreement() {
  const ag = getSelectedAgreement();
  if (!ag) return;

  const missing = inspectMissingTerms(ag);
  if (missing.length > 0) {
    alert('Cannot activate agreement: missing required terms.\n\n' + missing.join('\n'));
    return;
  }

  ag.status = 'active';
  await appendEventToAgreement(ag, 'status_update', 'Pakka Protocol Simulation', {
    previousStatus: 'awaiting_confirmation',
    newStatus: 'active',
    note: 'Both parties confirmed all terms. Agreement activated into formal monitoring state.'
  });
}

// Work Check-in Action
async function handleRecordWorkCheckin() {
  const ag = getSelectedAgreement();
  if (!ag) return;

  const noteInput = document.getElementById('inputWorkNote');
  const note = noteInput.value.trim();
  if (!note) {
    alert('Please enter a progress note or milestone update.');
    return;
  }

  const actor = AppState.activeSimulatedRole === 'client' 
    ? `${ag.clientName} (Client)` 
    : `${ag.workerName} (Worker)`;

  await appendEventToAgreement(ag, 'work_checkin', actor, {
    progressNote: note,
    recordedByRole: AppState.activeSimulatedRole
  });

  noteInput.value = '';
}

// Payment Recording Action
async function handleRecordPayment() {
  const ag = getSelectedAgreement();
  if (!ag) return;

  const amtInput = document.getElementById('inputPaymentAmount');
  const noteInput = document.getElementById('inputPaymentNote');

  const amt = parseFloat(amtInput.value);
  if (isNaN(amt) || amt <= 0) {
    alert('Please enter a valid positive payment amount.');
    return;
  }

  const currentPaid = ag.amountPaid || 0;
  const newPaid = currentPaid + amt;
  const balanceRemaining = Math.max(0, ag.amount - newPaid);

  ag.amountPaid = newPaid;
  if (balanceRemaining === 0 && ag.status === 'active') {
    ag.status = 'completed';
  }

  const actor = AppState.activeSimulatedRole === 'client' 
    ? `${ag.clientName} (Client)` 
    : `${ag.workerName} (Worker)`;

  await appendEventToAgreement(ag, 'payment_update', actor, {
    amountPaidNow: amt,
    totalPaid: newPaid,
    balanceRemaining: balanceRemaining,
    note: noteInput.value.trim() || 'Payment installment'
  });

  amtInput.value = '';
  noteInput.value = '';
}

// Dispute Toggle
async function handleToggleDispute() {
  const ag = getSelectedAgreement();
  if (!ag) return;

  const newStatus = ag.status === 'disputed' ? 'active' : 'disputed';
  ag.status = newStatus;

  const actor = AppState.activeSimulatedRole === 'client' 
    ? `${ag.clientName} (Client)` 
    : `${ag.workerName} (Worker)`;

  await appendEventToAgreement(ag, 'status_update', actor, {
    status: newStatus,
    reason: newStatus === 'disputed' ? 'Dispute raised regarding deliverables or payment.' : 'Dispute resolved by mutual review.'
  });
}

// Tamper Demo Action
async function handleTamperDemo() {
  const ag = getSelectedAgreement();
  if (!ag || !ag.events || ag.events.length === 0) {
    alert('No events in this agreement to tamper with.');
    return;
  }

  // Find an event to tamper with (preferably a payment or the creation event)
  const targetEvent = ag.events[ag.events.length > 1 ? 1 : 0];

  // Tamper payload silently without updating hash
  if (targetEvent.type === 'payment_update') {
    targetEvent.payload.amountPaidNow = targetEvent.payload.amountPaidNow + 99999;
    targetEvent.payload.note = '[TAMPERED] Fraudulent amount injected';
  } else if (targetEvent.type === 'party_confirmed') {
    targetEvent.payload.confirmedTerms = false;
    targetEvent.payload.tamperedNote = 'Altered confirmation state';
  } else {
    targetEvent.payload.amount = 999999;
    targetEvent.payload.deliverables = '[TAMPERED] Maliciously modified deliverables text';
  }

  AppState.tamperedStateNotice = true;
  saveState();
  await renderAll();

  alert('⚠️ TAMPER DEMO EXECUTED:\n\nAn event payload in this agreement was silently modified in local storage without updating its SHA-256 hash.\n\nNotice that verification now immediately fails with "Tampering Detected"!');
}


// ==========================================
// 8. PROOF FILE VIEW & EXPORT ENGINE
// ==========================================

async function openProofFileModal() {
  const ag = getSelectedAgreement();
  if (!ag) return;

  const modal = document.getElementById('modalProofFile');
  modal.classList.add('active');

  document.getElementById('proofAgreementId').textContent = ag.id;
  document.getElementById('proofStatus').textContent = ag.status.toUpperCase();
  document.getElementById('proofClient').textContent = ag.clientName;
  document.getElementById('proofWorker').textContent = ag.workerName;
  document.getElementById('proofDeliverables').textContent = ag.deliverables;
  document.getElementById('proofAmount').textContent = `₹${(ag.amount || 0).toLocaleString('en-IN')}`;
  document.getElementById('proofDueDate').textContent = ag.dueDate || 'Unspecified';
  document.getElementById('proofAcceptance').textContent = ag.acceptanceCriteria || 'Unspecified';
  document.getElementById('proofPaymentTerms').textContent = ag.paymentTerms || 'Unspecified';

  const paid = ag.amountPaid || 0;
  const remaining = Math.max(0, (ag.amount || 0) - paid);
  document.getElementById('proofStatTotal').textContent = `₹${(ag.amount || 0).toLocaleString('en-IN')}`;
  document.getElementById('proofStatPaid').textContent = `₹${paid.toLocaleString('en-IN')}`;
  document.getElementById('proofStatRemaining').textContent = `₹${remaining.toLocaleString('en-IN')}`;

  document.getElementById('proofGeneratedDate').textContent = new Date().toLocaleString();

  // Verification status inside proof file
  const verification = await verifyAgreementIntegrity(ag);
  const badge = document.getElementById('proofIntegrityBadge');
  const badgeText = document.getElementById('proofBadgeText');

  if (verification.isValid) {
    badge.className = 'integrity-badge verified';
    badgeText.textContent = 'Verified SHA-256 Chain Intact';
  } else {
    badge.className = 'integrity-badge tampered';
    badgeText.textContent = 'Tampering Detected (Broken Chain)';
  }

  // Populate events table
  const tbody = document.getElementById('proofEventsTableBody');
  tbody.innerHTML = (ag.events || []).map((ev, i) => `
    <tr>
      <td>${i + 1}</td>
      <td><strong>${ev.type}</strong></td>
      <td>${escapeHtml(ev.actor)}</td>
      <td style="white-space: nowrap;">${new Date(ev.timestamp).toLocaleString()}</td>
      <td class="proof-hash-cell">
        <div><strong>Prev:</strong> ${ev.prevHash ? ev.prevHash : 'Genesis'}</div>
        <div><strong>Hash:</strong> ${ev.hash}</div>
      </td>
    </tr>
  `).join('');
}

function exportAgreementJson() {
  const ag = getSelectedAgreement();
  if (!ag) return;

  const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(ag, null, 2));
  const downloadAnchor = document.createElement('a');
  downloadAnchor.setAttribute('href', dataStr);
  downloadAnchor.setAttribute('download', `pakka_agreement_${ag.id}.json`);
  document.body.appendChild(downloadAnchor);
  downloadAnchor.click();
  downloadAnchor.remove();
}


// ==========================================
// 9. AGREEMENT CREATION MODAL & VOICE INPUT
// ==========================================

function openCreateAgreementModal() {
  const modal = document.getElementById('modalCreateAgreement');
  modal.classList.add('active');
  resetCreateForm();
  validateCreateForm();
}

function closeCreateAgreementModal() {
  const modal = document.getElementById('modalCreateAgreement');
  modal.classList.remove('active');
  stopSpeechRecognition();
}

function resetCreateForm() {
  document.getElementById('inputSpokenBrief').value = '';
  document.getElementById('formClientName').value = '';
  document.getElementById('formWorkerName').value = '';
  document.getElementById('formDeliverables').value = '';
  document.getElementById('formAmount').value = '';
  document.getElementById('formDueDate').value = '';
  document.getElementById('formAcceptanceCriteria').value = '';
  document.getElementById('formPaymentTerms').value = '';
  document.getElementById('hintsPillContainer').style.display = 'none';
  document.getElementById('hintsPillContainer').innerHTML = '';
}

function validateCreateForm() {
  const formData = {
    clientName: document.getElementById('formClientName').value,
    workerName: document.getElementById('formWorkerName').value,
    deliverables: document.getElementById('formDeliverables').value,
    amount: document.getElementById('formAmount').value,
    dueDate: document.getElementById('formDueDate').value,
    acceptanceCriteria: document.getElementById('formAcceptanceCriteria').value,
    paymentTerms: document.getElementById('formPaymentTerms').value
  };

  const missing = inspectMissingTerms(formData);
  const alertBox = document.getElementById('modalMissingTermsBox');
  const alertList = document.getElementById('modalMissingTermsList');
  const submitBtn = document.getElementById('btnSubmitAgreement');

  if (missing.length > 0) {
    alertBox.style.display = 'block';
    alertList.innerHTML = missing.map(m => `<span class="missing-term-pill">⚠️ ${escapeHtml(m)}</span>`).join('');
    submitBtn.disabled = true;
  } else {
    alertBox.style.display = 'none';
    submitBtn.disabled = false;
  }
}

// Transparent Hint Chip handler
function handleBriefInput() {
  const briefText = document.getElementById('inputSpokenBrief').value;
  const suggestions = extractBriefSuggestions(briefText);
  const container = document.getElementById('hintsPillContainer');

  if (suggestions.length === 0) {
    container.style.display = 'none';
    container.innerHTML = '';
    return;
  }

  container.style.display = 'flex';
  container.innerHTML = suggestions.map((s, idx) => `
    <button type="button" class="hint-pill" data-hint-idx="${idx}">
      + ${escapeHtml(s.label)}
    </button>
  `).join('');

  // Pill click applies to structured form
  container.querySelectorAll('.hint-pill').forEach((pill, idx) => {
    pill.addEventListener('click', () => {
      const s = suggestions[idx];
      if (s.field === 'amount') document.getElementById('formAmount').value = s.value;
      if (s.field === 'dueDate') document.getElementById('formDueDate').value = s.value;
      if (s.field === 'clientName') document.getElementById('formClientName').value = s.value;
      if (s.field === 'deliverables') document.getElementById('formDeliverables').value = s.value;
      validateCreateForm();
    });
  });
}

// Web Speech API Integration
function initSpeechRecognition() {
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  const feedback = document.getElementById('speechFeedbackText');
  const micBtn = document.getElementById('btnToggleSpeech');

  if (!SpeechRecognition) {
    feedback.textContent = 'Voice input not supported in this browser. Use typing fallback.';
    micBtn.disabled = true;
    return;
  }

  AppState.speechRecognition = new SpeechRecognition();
  AppState.speechRecognition.continuous = false;
  AppState.speechRecognition.interimResults = true;

  AppState.speechRecognition.onstart = () => {
    AppState.isRecordingSpeech = true;
    micBtn.classList.add('recording');
    document.getElementById('speechBtnText').textContent = 'Listening...';
    feedback.textContent = 'Speak clearly into your microphone...';
  };

  AppState.speechRecognition.onresult = (event) => {
    let transcript = '';
    for (let i = event.resultIndex; i < event.results.length; i++) {
      transcript += event.results[i][0].transcript;
    }
    const briefArea = document.getElementById('inputSpokenBrief');
    briefArea.value = transcript;
    handleBriefInput();
    validateCreateForm();
  };

  AppState.speechRecognition.onerror = (event) => {
    console.warn('Speech recognition error:', event.error);
    feedback.textContent = `Speech note: ${event.error}. You can type directly below.`;
    stopSpeechRecognition();
  };

  AppState.speechRecognition.onend = () => {
    stopSpeechRecognition();
  };
}

function toggleSpeechRecognition() {
  if (!AppState.speechRecognition) return;
  if (AppState.isRecordingSpeech) {
    stopSpeechRecognition();
  } else {
    const langSelect = document.getElementById('selectSpeechLang');
    AppState.speechRecognition.lang = langSelect.value || 'en-IN';
    try {
      AppState.speechRecognition.start();
    } catch (e) {
      console.warn('Recognition start exception:', e);
    }
  }
}

function stopSpeechRecognition() {
  if (AppState.speechRecognition && AppState.isRecordingSpeech) {
    try {
      AppState.speechRecognition.stop();
    } catch (e) {}
  }
  AppState.isRecordingSpeech = false;
  const micBtn = document.getElementById('btnToggleSpeech');
  if (micBtn) {
    micBtn.classList.remove('recording');
    document.getElementById('speechBtnText').textContent = 'Dictate Brief';
  }
}

// Create new Agreement Submission
async function handleCreateAgreementSubmit() {
  const clientName = document.getElementById('formClientName').value.trim();
  const workerName = document.getElementById('formWorkerName').value.trim();
  const deliverables = document.getElementById('formDeliverables').value.trim();
  const amount = parseFloat(document.getElementById('formAmount').value);
  const dueDate = document.getElementById('formDueDate').value;
  const acceptanceCriteria = document.getElementById('formAcceptanceCriteria').value.trim();
  const paymentTerms = document.getElementById('formPaymentTerms').value.trim();

  const id = `ag_${Date.now()}_${Math.random().toString(36).substr(2, 4)}`;
  const now = new Date().toISOString();

  const newAgreement = {
    id: id,
    clientName: clientName,
    workerName: workerName,
    deliverables: deliverables,
    amount: amount,
    currency: 'INR',
    dueDate: dueDate,
    acceptanceCriteria: acceptanceCriteria,
    paymentTerms: paymentTerms,
    status: 'draft',
    amountPaid: 0,
    createdAt: now,
    updatedAt: now,
    clientConfirmed: false,
    clientConfirmedAt: null,
    workerConfirmed: false,
    workerConfirmedAt: null,
    events: []
  };

  // Compute genesis hash and first event
  const genesisHash = await computeGenesisHash(newAgreement.id, newAgreement.createdAt);
  const creatorActor = `${workerName} (Worker)`;

  const genesisEvent = {
    id: `ev_genesis_${id}`,
    agreementId: id,
    type: 'agreement_created',
    actor: creatorActor,
    timestamp: now,
    payload: {
      clientName: clientName,
      workerName: workerName,
      amount: amount,
      currency: 'INR',
      dueDate: dueDate,
      deliverables: deliverables,
      acceptanceCriteria: acceptanceCriteria,
      paymentTerms: paymentTerms
    },
    prevHash: genesisHash
  };
  genesisEvent.hash = await computeEventHash(genesisEvent);
  newAgreement.events.push(genesisEvent);

  AppState.agreements.unshift(newAgreement);
  AppState.selectedAgreementId = newAgreement.id;
  AppState.tamperedStateNotice = null;

  saveState();
  closeCreateAgreementModal();
  await renderAll();
}


// ==========================================
// 10. HELPER UTILITIES & EVENT LISTENERS
// ==========================================

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function setupEventListeners() {
  // Navigation actions
  document.getElementById('btnNewAgreement').addEventListener('click', openCreateAgreementModal);
  document.getElementById('btnCreateFirst').addEventListener('click', openCreateAgreementModal);
  
  document.getElementById('btnLoadSamples').addEventListener('click', async () => {
    if (confirm('Reload the 3 sample agreements? Any unsaved edits will be refreshed.')) {
      await seedDefaults();
      AppState.tamperedStateNotice = null;
      await renderAll();
    }
  });

  document.getElementById('btnResetDemo').addEventListener('click', async () => {
    if (confirm('Reset all demo data and restore initial clean hash chains?')) {
      localStorage.removeItem(STORAGE_KEY);
      await seedDefaults();
      AppState.tamperedStateNotice = null;
      await renderAll();
    }
  });

  // Role Switcher
  document.getElementById('roleBtnClient').addEventListener('click', () => {
    AppState.activeSimulatedRole = 'client';
    renderSelectedAgreementWorkspace();
  });
  document.getElementById('roleBtnWorker').addEventListener('click', () => {
    AppState.activeSimulatedRole = 'worker';
    renderSelectedAgreementWorkspace();
  });

  // Confirmation actions
  document.getElementById('btnActionConfirmClient').addEventListener('click', () => handlePartyConfirm('client'));
  document.getElementById('btnActionConfirmWorker').addEventListener('click', () => handlePartyConfirm('worker'));
  document.getElementById('btnFinalizeActivation').addEventListener('click', handleActivateAgreement);

  // Check-in and Payment actions
  document.getElementById('btnRecordWorkCheckin').addEventListener('click', handleRecordWorkCheckin);
  document.getElementById('btnRecordPayment').addEventListener('click', handleRecordPayment);
  document.getElementById('btnDisputeToggle').addEventListener('click', handleToggleDispute);

  // Integrity actions
  document.getElementById('btnVerifyChain').addEventListener('click', async () => {
    AppState.tamperedStateNotice = null;
    const ag = getSelectedAgreement();
    if (ag) {
      const res = await verifyAgreementIntegrity(ag);
      if (res.isValid) {
        alert('🟢 INTEGRITY VERIFICATION SUCCEEDED\n\nAll SHA-256 event digests and previous-hash links were recomputed and match the stored chain perfectly.');
      } else {
        alert(`🔴 INTEGRITY VERIFICATION FAILED\n\n${res.reason}`);
      }
      await renderAll();
    }
  });

  document.getElementById('btnTamperDemo').addEventListener('click', handleTamperDemo);

  // Proof File & Print actions
  document.getElementById('btnOpenProofFile').addEventListener('click', openProofFileModal);
  document.getElementById('btnCloseProof').addEventListener('click', () => {
    document.getElementById('modalProofFile').classList.remove('active');
  });
  document.getElementById('btnPrintProof').addEventListener('click', () => window.print());
  document.getElementById('btnExportJson').addEventListener('click', exportAgreementJson);

  // Modal creation actions
  document.getElementById('btnCloseCreateModal').addEventListener('click', closeCreateAgreementModal);
  document.getElementById('btnCancelCreate').addEventListener('click', closeCreateAgreementModal);
  document.getElementById('btnSubmitAgreement').addEventListener('click', handleCreateAgreementSubmit);

  // Input listeners for form validation
  document.getElementById('inputSpokenBrief').addEventListener('input', handleBriefInput);
  ['formClientName', 'formWorkerName', 'formDeliverables', 'formAmount', 'formDueDate', 'formAcceptanceCriteria', 'formPaymentTerms'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.addEventListener('input', validateCreateForm);
  });

  // Speech Recognition
  document.getElementById('btnToggleSpeech').addEventListener('click', toggleSpeechRecognition);
}

// Initial Boot
document.addEventListener('DOMContentLoaded', async () => {
  setupEventListeners();
  initSpeechRecognition();
  await loadState();
  await renderAll();
});
