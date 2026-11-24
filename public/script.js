/**
 * codaaa - Secure Ephemeral Peer File Transfer & Chat
 * Client Engine with E2EE (AES-GCM 256-bit + ECDH P-256),
 * Real-time Read Receipts (only on last message),
 * Message Replies (Quotes), and Emoji Reactions ("amojy reply")
 */

(function () {
  'use strict';

  // --- Constants & Config ---
  const CHUNK_SIZE = 128 * 1024; // 128 KB per binary chunk
  const MAX_FILE_SIZE = 100 * 1024 * 1024; // 100 MB max recommended
  const QUICK_EMOJIS = ['👍', '❤️', '😂', '😮', '😢', '🙏', '🔥', '🎉'];

  const EMOJI_CATEGORIES = [
    {
      name: 'Smileys & Emotions',
      emojis: [
        '😀', '😃', '😄', '😁', '😆', '😅', '😂', '🤣', '🥲', '☺️',
        '😊', '😇', '🙂', '🙃', '😉', '😌', '😍', '🥰', '😘', '😗',
        '😙', '😚', '😋', '😛', '😜', '🤪', '😝', '🤑', '🤗', '🤭',
        '🤫', '🤔', '🤐', '🤨', '😐', '😑', '😶', '😏', '😒', '🙄',
        '😬', '🤥', '😔', '😪', '🤤', '😴', '😷', '🤒', '🤕', '🤢',
        '🤮', '🤧', '🥵', '🥶', '🥴', '😵', '🤯', '🤠', '🥳', '🥸',
        '😎', '🤓', '🧐', '😕', '😟', '🙁', '😮', '😯', '😲', '😳',
        '🥺', '😦', '😧', '😨', '😰', '😥', '😢', '😭', '😱', '😖',
        '😣', '😞', '😓', '😩', '😫', '🥱', '😤', '😡', '😠', '🤬',
        '😈', '👿', '💀', '☠️', '💩', '🤡', '👻', '👽', '🤖'
      ]
    },
    {
      name: 'Gestures & Hands',
      emojis: [
        '👍', '👎', '👊', '✊', '🤛', '🤜', '🤞', '✌️', '🤟', '🤘',
        '👌', '🤌', '🤏', '👈', '👉', '👆', '👇', '☝️', '✋', '🤚',
        '🖐️', '🖖', '👋', '🤙', '💪', '🦾', '🙏', '🤝', '👏', '🙌',
        '👐', '🤲', '✍️', '💅', '🤳', '👀', '👁️', '🧠', '🫀', '🫁'
      ]
    },
    {
      name: 'Hearts & Love',
      emojis: [
        '❤️', '🧡', '💛', '💚', '💙', '💜', '🖤', '🤍', '🤎', '💔',
        '❣️', '💕', '💞', '💓', '💗', '💖', '💘', '💝', '💟', '💌',
        '💋', '💍', '💐', '🌹', '🥀'
      ]
    },
    {
      name: 'Party, Vibes & Fun',
      emojis: [
        '🔥', '✨', '💥', '💯', '💢', '💨', '💫', '💬', '💭', '💤',
        '🎉', '🎊', '🎈', '🎁', '🏆', '🥇', '🥈', '🥉', '🎯', '🎲',
        '🎮', '🚀', '⚡', '🌟', '⭐', '🌈', '☀️', '🌙', '🍻', '🥂',
        '🍾', '🍕', '🍔', '🍟', '🍦', '🎂', '☕', '🥤', '🍿', '🍩',
        '👑', '💎', '🔑', '💡', '🔔', '📣', '📢', '🎵', '🎶', '🎸'
      ]
    }
  ];

  // --- State ---
  let socket = null;
  let currentPin = null;
  let isHost = false;
  let activeTransfers = new Map(); // fileId -> transferState
  let sendQueue = [];
  let isSendingFile = false;
  let typingTimeout = null;

  // E2EE State (AES-GCM 256-bit + ECDH P-256)
  let e2eeKeyPair = null;
  let myPublicJwk = null;
  let sharedAesKey = null;
  let safetyCode = '•••• •••• •••• ••••';
  let e2eeReady = false;

  // Read Receipts: ONLY on the latest sent message
  let latestSentReceiptContainer = null;
  let latestSentMessageId = null;
  const pendingUnreadMessageIds = new Set();

  // Reply State
  let activeReply = null; // { id, text, sender }

  // Emoji Reactions Store: msgId -> Map<emoji, Set<senderId>>
  const reactionsStore = new Map();

  // --- DOM Elements ---
  const views = {
    lobby: document.getElementById('lobby-view'),
    pin: document.getElementById('pin-view'),
    chat: document.getElementById('chat-view'),
  };

  const serverStatus = document.getElementById('server-status');
  const serverStatusDot = serverStatus ? serverStatus.querySelector('.status-dot') : null;
  const serverStatusLabel = serverStatus ? serverStatus.querySelector('.status-label') : null;

  // Lobby Elements
  const tabBtnSend = document.getElementById('tab-btn-send');
  const tabBtnReceive = document.getElementById('tab-btn-receive');
  const panelSend = document.getElementById('panel-send');
  const panelReceive = document.getElementById('panel-receive');
  const btnSwitchToReceive = document.getElementById('btn-switch-to-receive');
  const btnSwitchToSend = document.getElementById('btn-switch-to-send');
  const btnCreateRoom = document.getElementById('btn-create-room');
  const joinForm = document.getElementById('join-form');
  const pinDigitBoxes = Array.from(document.querySelectorAll('.pin-digit-box'));
  const joinErrorMsg = document.getElementById('join-error-msg');
  const btnPastePin = document.getElementById('btn-paste-pin');

  // PIN View Elements
  const displayPin = document.getElementById('display-pin');
  const btnCopyPin = document.getElementById('btn-copy-pin');
  const shareLinkInput = document.getElementById('share-link-input');
  const btnCopyLink = document.getElementById('btn-copy-link');
  const btnCancelRoom = document.getElementById('btn-cancel-room');

  // Chat Elements
  const activePinBadge = document.getElementById('active-pin-badge');
  const peerStatusText = document.getElementById('peer-status-text');
  const btnLeaveRoom = document.getElementById('btn-leave-room');
  const messagesContainer = document.getElementById('messages-container');
  const chatTextarea = document.getElementById('chat-textarea');
  const btnSendMessage = document.getElementById('btn-send-message');
  const fileInput = document.getElementById('file-input');
  const imageInput = document.getElementById('image-input');
  const btnAttachFile = document.getElementById('btn-attach-file');
  const btnAttachImage = document.getElementById('btn-attach-image');
  const dropOverlay = document.getElementById('drop-overlay');
  const typingBar = document.getElementById('typing-bar');
  const toastContainer = document.getElementById('toast-container');
  const brandLogo = document.getElementById('brand-logo');
  const btnThemeToggle = document.getElementById('btn-theme-toggle');
  const btnChatThemeToggle = document.getElementById('btn-chat-theme-toggle');
  const themeBtnText = document.getElementById('theme-btn-text');
  const chatThemeBtnText = document.getElementById('chat-theme-btn-text');

  // Theme Management State (Normal / White vs Night / Dark)
  const THEME_STORAGE_KEY = 'codaaa_theme';
  let currentTheme = 'light';
  try {
    const saved = localStorage.getItem(THEME_STORAGE_KEY);
    if (saved === 'dark' || saved === 'light') {
      currentTheme = saved;
    }
  } catch (_) {}

  function applyTheme(theme) {
    currentTheme = theme === 'dark' ? 'dark' : 'light';
    try {
      localStorage.setItem(THEME_STORAGE_KEY, currentTheme);
    } catch (_) {}

    const isDark = currentTheme === 'dark';
    if (isDark) {
      document.documentElement.setAttribute('data-theme', 'dark');
      document.body.classList.add('theme-dark');
    } else {
      document.documentElement.removeAttribute('data-theme');
      document.body.classList.remove('theme-dark');
    }

    if (themeBtnText) {
      themeBtnText.textContent = isDark ? 'Normal' : 'Night';
    }
    if (chatThemeBtnText) {
      chatThemeBtnText.textContent = isDark ? 'Normal' : 'Night';
    }

    if (btnThemeToggle) {
      btnThemeToggle.setAttribute(
        'title',
        isDark ? 'Switch to Normal (White Background)' : 'Switch to Night (Dark Theme)'
      );
    }
    if (btnChatThemeToggle) {
      btnChatThemeToggle.setAttribute(
        'title',
        isDark ? 'Switch to Normal (White Background)' : 'Switch to Night (Dark Theme)'
      );
    }
  }

  function toggleTheme() {
    const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
    applyTheme(nextTheme);
  }

  // Pre-apply theme immediately before DOM render completes
  applyTheme(currentTheme);

  // Reply Bar Elements
  const replyBar = document.getElementById('reply-bar');
  const replyBarSender = document.getElementById('reply-bar-sender');
  const replyBarText = document.getElementById('reply-bar-text');
  const btnCancelReply = document.getElementById('btn-cancel-reply');

  // Call & Video Calling Elements
  const btnAudioCall = document.getElementById('btn-audio-call');
  const btnVideoCall = document.getElementById('btn-video-call');
  const callRingingModal = document.getElementById('call-ringing-modal');
  const callRingingTitle = document.getElementById('call-ringing-title');
  const callRingingStatus = document.getElementById('call-ringing-status');
  const callDeclineLabel = document.getElementById('call-decline-label');
  const btnCallDecline = document.getElementById('btn-call-decline');
  const btnCallAccept = document.getElementById('btn-call-accept');

  // Active Call Modal Elements
  const activeCallModal = document.getElementById('active-call-modal');
  const activeCallTypeBadge = document.getElementById('active-call-type-badge');
  const activeCallTimer = document.getElementById('active-call-timer');
  const btnCallMinimize = document.getElementById('btn-call-minimize');
  const remoteVideoElem = document.getElementById('remote-video-elem');
  const localVideoElem = document.getElementById('local-video-elem');
  const remoteAvatarFallback = document.getElementById('remote-avatar-fallback');
  const localAvatarFallback = document.getElementById('local-avatar-fallback');
  const remoteStatusBadge = document.getElementById('remote-status-badge');
  const btnToggleMic = document.getElementById('btn-toggle-mic');
  const iconMicOn = document.getElementById('icon-mic-on');
  const iconMicOff = document.getElementById('icon-mic-off');
  const btnToggleVideo = document.getElementById('btn-toggle-video');
  const iconCamOn = document.getElementById('icon-cam-on');
  const iconCamOff = document.getElementById('icon-cam-off');
  const btnSwitchCamera = document.getElementById('btn-switch-camera');
  const btnEndCall = document.getElementById('btn-end-call');

  // WebRTC Call State
  let peerConnection = null;
  let localMediaStream = null;
  let isCallActive = false;
  let isCaller = false;
  let currentCallType = 'video'; // 'video' or 'voice'
  let callTimerInterval = null;
  let callStartTime = 0;
  let ringtoneInterval = null;
  let isAudioMuted = false;
  let isVideoMuted = false;
  let isCallMinimized = false;

  // STUN Configuration for WebRTC P2P Direct Connection
  const RTC_CONFIG = {
    iceServers: [
      { urls: 'stun:stun.l.google.com:19302' },
      { urls: 'stun:stun1.l.google.com:19302' },
      { urls: 'stun:stun2.l.google.com:19302' }
    ]
  };

  // E2EE Badges & Modal
  const safetyFingerprintTag = document.getElementById('safety-fingerprint-tag');
  const btnShowE2eeModal = document.getElementById('btn-show-e2ee-modal');
  const e2eeModal = document.getElementById('e2ee-modal');
  const e2eeBackdrop = document.getElementById('e2ee-backdrop');
  const e2eeModalClose = document.getElementById('e2ee-modal-close');
  const btnCloseE2eeModal = document.getElementById('btn-close-e2ee-modal');
  const modalSafetyCode = document.getElementById('modal-safety-code');
  const btnCopySafetyCode = document.getElementById('btn-copy-safety-code');

  // Lightbox
  const lightboxModal = document.getElementById('lightbox-modal');
  const lightboxImg = document.getElementById('lightbox-img');
  const lightboxFilename = document.getElementById('lightbox-filename');
  const lightboxDownload = document.getElementById('lightbox-download');
  const lightboxClose = document.getElementById('lightbox-close');

  // Multi-Member Group Chat & Members Modal Elements
  const btnOpenGroupModal = document.getElementById('btn-open-group-modal');
  const groupChatModal = document.getElementById('group-chat-modal');
  const groupModalCloseBtn = document.getElementById('group-modal-close-btn');
  const groupModalBackdrop = document.getElementById('group-modal-backdrop');
  const tabGroupCreate = document.getElementById('tab-group-create');
  const tabGroupReserve = document.getElementById('tab-group-reserve');
  const panelGroupCreate = document.getElementById('panel-group-create');
  const panelGroupReserve = document.getElementById('panel-group-reserve');
  const inputCreatorName = document.getElementById('input-creator-name');
  const inputGroupTitle = document.getElementById('input-group-title');
  const btnSubmitCreateGroup = document.getElementById('btn-submit-create-group');
  const groupCreateError = document.getElementById('group-create-error');
  const inputJoinerName = document.getElementById('input-joiner-name');
  const inputGroupCode = document.getElementById('input-group-code');
  const btnSubmitJoinGroup = document.getElementById('btn-submit-join-group');
  const groupReserveError = document.getElementById('group-reserve-error');
  const groupTitleBadge = document.getElementById('group-title-badge');
  const btnShowMembers = document.getElementById('btn-show-members');
  const membersCountBadge = document.getElementById('members-count-badge');
  const groupMembersModal = document.getElementById('group-members-modal');
  const membersModalClose = document.getElementById('members-modal-close');
  const membersModalBackdrop = document.getElementById('members-modal-backdrop');
  const btnCloseMembersModal = document.getElementById('btn-close-members-modal');
  const membersRoomPin = document.getElementById('members-room-pin');
  const btnCopyGroupPin = document.getElementById('btn-copy-group-pin');
  const membersListCount = document.getElementById('members-list-count');
  const groupMembersList = document.getElementById('group-members-list');
  const membersModalGroupName = document.getElementById('members-modal-group-name');

  // Multi-Member Group & Display Name State
  let isGroupSession = false;
  let groupRoomTitle = 'codaaa Group';
  let myDisplayName = '';
  try {
    myDisplayName = localStorage.getItem('codaaa_user_name') || '';
  } catch (_) {}
  let currentMembers = [];

  // --- Sound Effects (Web Audio API Synthesizer) ---
  const audioCtx = (typeof AudioContext !== 'undefined' || typeof webkitAudioContext !== 'undefined')
    ? new (window.AudioContext || window.webkitAudioContext)()
    : null;

  function playTone(type) {
    if (!audioCtx) return;
    try {
      if (audioCtx.state === 'suspended') {
        audioCtx.resume();
      }
      const osc = audioCtx.createOscillator();
      const gain = audioCtx.createGain();
      osc.connect(gain);
      gain.connect(audioCtx.destination);

      const now = audioCtx.currentTime;

      if (type === 'message') {
        osc.frequency.setValueAtTime(540, now);
        osc.frequency.exponentialRampToValueAtTime(780, now + 0.08);
        gain.gain.setValueAtTime(0.08, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.08);
        osc.start(now);
        osc.stop(now + 0.08);
      } else if (type === 'connected') {
        osc.frequency.setValueAtTime(440, now);
        osc.frequency.setValueAtTime(660, now + 0.1);
        osc.frequency.setValueAtTime(880, now + 0.2);
        gain.gain.setValueAtTime(0.1, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.35);
        osc.start(now);
        osc.stop(now + 0.35);
      } else if (type === 'seen') {
        osc.frequency.setValueAtTime(700, now);
        osc.frequency.setValueAtTime(950, now + 0.06);
        gain.gain.setValueAtTime(0.04, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.1);
        osc.start(now);
        osc.stop(now + 0.1);
      } else if (type === 'reaction') {
        osc.frequency.setValueAtTime(600, now);
        osc.frequency.exponentialRampToValueAtTime(900, now + 0.06);
        gain.gain.setValueAtTime(0.05, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.07);
        osc.start(now);
        osc.stop(now + 0.07);
      } else if (type === 'complete') {
        osc.frequency.setValueAtTime(587.33, now);
        osc.frequency.setValueAtTime(880, now + 0.12);
        gain.gain.setValueAtTime(0.12, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.3);
        osc.start(now);
        osc.stop(now + 0.3);
      } else if (type === 'ringtone') {
        osc.frequency.setValueAtTime(440, now);
        osc.frequency.setValueAtTime(480, now + 0.4);
        gain.gain.setValueAtTime(0.08, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.8);
        osc.start(now);
        osc.stop(now + 0.8);
      } else if (type === 'call_end') {
        osc.frequency.setValueAtTime(400, now);
        osc.frequency.setValueAtTime(300, now + 0.15);
        gain.gain.setValueAtTime(0.1, now);
        gain.gain.exponentialRampToValueAtTime(0.001, now + 0.3);
        osc.start(now);
        osc.stop(now + 0.3);
      }
    } catch (e) {
      // Audio playback fails silently if user hasn't interacted
    }
  }

  // --- Toast Notification Helper ---
  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(100%)';
      setTimeout(() => toast.remove(), 250);
    }, 3200);
  }

  // --- View Switching ---
  function switchView(target) {
    Object.keys(views).forEach((key) => {
      if (key === target) {
        views[key].classList.add('active');
      } else {
        views[key].classList.remove('active');
      }
    });
  }

  // --- Format Utilities ---
  function formatBytes(bytes, decimals = 1) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  }

  function formatTime(timestamp) {
    const d = new Date(timestamp);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  }

  // Cyber Defense: Strict HTML sanitization
  function escapeHTML(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // Base64 & Buffer conversions
  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  function base64ToArrayBuffer(base64) {
    const binary_string = window.atob(base64);
    const len = binary_string.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binary_string.charCodeAt(i);
    }
    return bytes.buffer;
  }

  // ==========================================
  // --- END-TO-END ENCRYPTION (E2EE) ENGINE ---
  // ==========================================

  async function generateE2EEKeys() {
    if (!window.crypto || !window.crypto.subtle) {
      console.warn('Web Crypto API not available');
      return null;
    }
    try {
      e2eeKeyPair = await window.crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' },
        true,
        ['deriveKey', 'deriveBits']
      );
      myPublicJwk = await window.crypto.subtle.exportKey('jwk', e2eeKeyPair.publicKey);
      return myPublicJwk;
    } catch (err) {
      console.error('Error generating ECDH keypair:', err);
      return null;
    }
  }

  async function deriveE2EESharedKey(peerJwk, pin) {
    if (!e2eeKeyPair || !peerJwk) return;
    try {
      const peerPublicKey = await window.crypto.subtle.importKey(
        'jwk',
        peerJwk,
        { name: 'ECDH', namedCurve: 'P-256' },
        false,
        []
      );

      const sharedBits = await window.crypto.subtle.deriveBits(
        { name: 'ECDH', public: peerPublicKey },
        e2eeKeyPair.privateKey,
        256
      );

      // Salt with room PIN via SHA-256
      const enc = new TextEncoder();
      const pinBytes = enc.encode(pin || 'codaaa');
      const combined = new Uint8Array(sharedBits.byteLength + pinBytes.byteLength);
      combined.set(new Uint8Array(sharedBits), 0);
      combined.set(pinBytes, sharedBits.byteLength);

      const keyDigest = await window.crypto.subtle.digest('SHA-256', combined);

      // Derive AES-GCM 256-bit encryption key
      sharedAesKey = await window.crypto.subtle.importKey(
        'raw',
        keyDigest,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
      );

      // Cryptographic Safety Code (First 8 bytes formatted as 4 groups)
      const digestBytes = new Uint8Array(keyDigest);
      const hex = Array.from(digestBytes.slice(0, 8))
        .map((b) => b.toString(16).padStart(2, '0').toUpperCase())
        .join('');
      safetyCode = `${hex.slice(0, 4)} ${hex.slice(4, 8)} ${hex.slice(8, 12)} ${hex.slice(12, 16)}`;

      e2eeReady = true;

      if (safetyFingerprintTag) {
        safetyFingerprintTag.textContent = `${hex.slice(0, 4)} ${hex.slice(4, 8)}`;
      }
      if (modalSafetyCode) {
        modalSafetyCode.textContent = safetyCode;
      }

      console.log('[codaaa E2EE] AES-256-GCM established. Safety code:', safetyCode);
      showToast('End-to-End Encryption verified (AES-256-GCM)', 'success');
    } catch (err) {
      console.error('Failed to derive E2EE key:', err);
    }
  }

  async function encryptMessage(plaintext) {
    if (!sharedAesKey || !e2eeReady) {
      return { text: plaintext, iv: null, isEncrypted: false };
    }
    try {
      const iv = window.crypto.getRandomValues(new Uint8Array(12));
      const encoded = new TextEncoder().encode(plaintext);
      const ciphertextBuf = await window.crypto.subtle.encrypt(
        { name: 'AES-GCM', iv },
        sharedAesKey,
        encoded
      );
      return {
        text: arrayBufferToBase64(ciphertextBuf),
        iv: arrayBufferToBase64(iv),
        isEncrypted: true,
      };
    } catch (err) {
      console.warn('Encryption failed, sending plain:', err);
      return { text: plaintext, iv: null, isEncrypted: false };
    }
  }

  async function decryptMessage(encryptedPayload) {
    if (!encryptedPayload.isEncrypted || !encryptedPayload.iv || !sharedAesKey) {
      return encryptedPayload.text;
    }
    try {
      const iv = new Uint8Array(base64ToArrayBuffer(encryptedPayload.iv));
      const cipherBuf = base64ToArrayBuffer(encryptedPayload.text);
      const decryptedBuf = await window.crypto.subtle.decrypt(
        { name: 'AES-GCM', iv },
        sharedAesKey,
        cipherBuf
      );
      return new TextDecoder().decode(decryptedBuf);
    } catch (err) {
      console.warn('Decryption failed, showing raw:', err);
      return encryptedPayload.text;
    }
  }

  // ==========================================
  // --- REAL-TIME READ RECEIPTS LOGIC ---
  // (Rendered strictly on the LATEST sent message)
  // ==========================================

  const SVG_CHECK_SINGLE = `<svg class="receipt-check-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
  const SVG_CHECK_DOUBLE = `<svg class="receipt-check-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 6L7 17l-5-5"></path><path d="m22 10-7.5 7.5L13 16"></path></svg>`;

  function createReceiptElement(status = 'sent') {
    const span = document.createElement('span');
    span.className = `receipt-status ${status}`;
    span.innerHTML = status === 'sent' ? SVG_CHECK_SINGLE : SVG_CHECK_DOUBLE;
    span.title = status === 'seen' ? 'Seen' : (status === 'delivered' ? 'Delivered' : 'Sent');
    return span;
  }

  function updateLatestReceipt(newStatus, timestamp) {
    if (!latestSentReceiptContainer) return;

    if (newStatus === 'delivered') {
      latestSentReceiptContainer.className = 'receipt-status delivered';
      latestSentReceiptContainer.innerHTML = SVG_CHECK_DOUBLE;
      latestSentReceiptContainer.title = 'Delivered';
    } else if (newStatus === 'seen') {
      latestSentReceiptContainer.className = 'receipt-status seen';
      latestSentReceiptContainer.innerHTML = SVG_CHECK_DOUBLE;
      latestSentReceiptContainer.title = timestamp ? `Seen at ${formatTime(timestamp)}` : 'Seen';
      playTone('seen');
    }
  }

  function markPendingAsRead() {
    if (!socket || !socket.connected || !currentPin) return;
    if (pendingUnreadMessageIds.size === 0) return;

    const ids = Array.from(pendingUnreadMessageIds);
    pendingUnreadMessageIds.clear();

    socket.emit('read', {
      messageIds: ids,
      messageId: ids[ids.length - 1],
      pin: currentPin,
      timestamp: Date.now(),
    });
  }

  // ==========================================
  // --- EMOJI REACTIONS ENGINE ("amojy reply") ---
  // ==========================================

  function addReaction(msgId, emoji, senderId) {
    let msgReactions = reactionsStore.get(msgId);
    if (!msgReactions) {
      msgReactions = new Map();
      reactionsStore.set(msgId, msgReactions);
    }

    // Check if this sender already reacted with any emoji on this message
    let previousEmoji = null;
    msgReactions.forEach((usersSet, emo) => {
      if (usersSet.has(senderId)) {
        previousEmoji = emo;
      }
    });

    if (previousEmoji === emoji) {
      // Tapping same emoji: toggle OFF (remove reaction)
      const usersSet = msgReactions.get(emoji);
      if (usersSet) {
        usersSet.delete(senderId);
        if (usersSet.size === 0) {
          msgReactions.delete(emoji);
        }
      }
    } else {
      // Remove previous reaction if any (WhatsApp single reaction per user rule)
      if (previousEmoji) {
        const prevSet = msgReactions.get(previousEmoji);
        if (prevSet) {
          prevSet.delete(senderId);
          if (prevSet.size === 0) {
            msgReactions.delete(previousEmoji);
          }
        }
      }
      // Add new reaction
      let usersSet = msgReactions.get(emoji);
      if (!usersSet) {
        usersSet = new Set();
        msgReactions.set(emoji, usersSet);
      }
      usersSet.add(senderId);
    }

    renderReactions(msgId);
    playTone('reaction');
  }

  function renderReactions(msgId) {
    const container = document.getElementById(`reactions_${msgId}`);
    if (!container) return;

    container.innerHTML = '';
    const msgReactions = reactionsStore.get(msgId);
    if (!msgReactions || msgReactions.size === 0) return;

    msgReactions.forEach((usersSet, emoji) => {
      if (usersSet.size === 0) return;
      const pill = document.createElement('span');
      const isMyReaction = socket && usersSet.has(socket.id);
      pill.className = `reaction-pill ${isMyReaction ? 'user-reacted' : ''}`;
      pill.textContent = usersSet.size > 1 ? `${emoji} ${usersSet.size}` : emoji;
      pill.title = isMyReaction ? 'Tap to remove reaction' : 'Tap to react';

      const handlePillClick = (e) => {
        e.stopPropagation();
        e.preventDefault();
        if (!socket || !currentPin) return;
        addReaction(msgId, emoji, socket.id);
        socket.emit('message_reaction', { messageId: msgId, emoji, pin: currentPin });
      };

      pill.addEventListener('click', handlePillClick);
      pill.addEventListener('touchend', handlePillClick);

      container.appendChild(pill);
    });
  }

  // ==========================================
  // --- WHATSAPP-STYLE MESSAGE MENU & EMOJI TRAY ---
  // (Triggers on 1-second long press / hold on ANY message, sent or received)
  // ==========================================

  let activeMenuRow = null;

  function closeActiveMenu() {
    document.querySelectorAll('.whatsapp-msg-menu').forEach((el) => el.remove());
    document.querySelectorAll('.emoji-full-tray-overlay').forEach((el) => el.remove());
    if (activeMenuRow) {
      activeMenuRow.classList.remove('message-active-target');
      activeMenuRow = null;
    }
  }

  function attachLongPressListener(targetElement, onTrigger, onDoubleTap = null) {
    let pressTimer = null;
    let startX = 0;
    let startY = 0;
    let triggered = false;
    let lastTapTime = 0;
    const LONG_PRESS_DURATION = 500; // 500ms: instant, natural mobile long-press

    const cancel = () => {
      if (pressTimer) {
        clearTimeout(pressTimer);
        pressTimer = null;
      }
    };

    // Mobile Touch Events
    targetElement.addEventListener('touchstart', (e) => {
      const touch = e.touches[0];
      if (!touch) return;
      startX = touch.clientX;
      startY = touch.clientY;
      triggered = false;
      cancel();

      // Check double-tap
      const now = Date.now();
      if (onDoubleTap && now - lastTapTime < 320) {
        lastTapTime = 0;
        cancel();
        if (navigator.vibrate) {
          try { navigator.vibrate(30); } catch (_) {}
        }
        onDoubleTap(e);
        return;
      }
      lastTapTime = now;

      pressTimer = setTimeout(() => {
        triggered = true;
        if (navigator.vibrate) {
          try { navigator.vibrate(40); } catch (_) {}
        }
        onTrigger(e);
      }, LONG_PRESS_DURATION);
    }, { passive: true });

    targetElement.addEventListener('touchmove', (e) => {
      const touch = e.touches[0];
      if (!touch) return;
      if (Math.abs(touch.clientX - startX) > 25 || Math.abs(touch.clientY - startY) > 25) {
        cancel();
      }
    }, { passive: true });

    targetElement.addEventListener('touchend', (e) => {
      if (triggered) {
        e.preventDefault();
      }
      cancel();
    });

    targetElement.addEventListener('touchcancel', cancel);

    // Desktop Mouse Events
    targetElement.addEventListener('mousedown', (e) => {
      if (e.button !== 0) return; // Left click only
      triggered = false;
      startX = e.clientX;
      startY = e.clientY;
      cancel();

      const now = Date.now();
      if (onDoubleTap && now - lastTapTime < 320) {
        lastTapTime = 0;
        cancel();
        onDoubleTap(e);
        return;
      }
      lastTapTime = now;

      pressTimer = setTimeout(() => {
        triggered = true;
        onTrigger(e);
      }, LONG_PRESS_DURATION);
    });

    targetElement.addEventListener('mousemove', (e) => {
      if (Math.abs(e.clientX - startX) > 25 || Math.abs(e.clientY - startY) > 25) {
        cancel();
      }
    });

    targetElement.addEventListener('mouseup', cancel);
    targetElement.addEventListener('mouseleave', cancel);

    // Desktop Contextmenu (Right click)
    targetElement.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      cancel();
      onTrigger(e);
    });
  }

  function openMessageActionMenu(msg, row, bubbleWrapper, direction) {
    closeActiveMenu();

    activeMenuRow = row;
    row.classList.add('message-active-target');

    const menu = document.createElement('div');
    menu.className = `whatsapp-msg-menu ${direction}`;

    // 1. Top Quick Emoji Reactions Bar
    const reactionsBar = document.createElement('div');
    reactionsBar.className = 'whatsapp-reactions-bar';

    QUICK_EMOJIS.forEach((emoji) => {
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'whatsapp-emoji-quick-btn';
      btn.textContent = emoji;
      btn.title = `React ${emoji}`;

      const handleReact = (e) => {
        e.stopPropagation();
        e.preventDefault();
        if (!socket || !currentPin) return;
        addReaction(msg.id, emoji, socket.id);
        socket.emit('message_reaction', { messageId: msg.id, emoji, pin: currentPin });
        closeActiveMenu(); // Closes immediately after reacting!
      };

      btn.addEventListener('click', handleReact);
      btn.addEventListener('touchend', handleReact);

      reactionsBar.appendChild(btn);
    });

    // "+" Button: Open all emojis tray (WhatsApp style)
    const moreBtn = document.createElement('button');
    moreBtn.type = 'button';
    moreBtn.className = 'whatsapp-emoji-more-btn';
    moreBtn.title = 'More Emojis';
    moreBtn.innerHTML = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><line x1="12" y1="5" x2="12" y2="19"></line><line x1="5" y1="12" x2="19" y2="12"></line></svg>`;

    const handleMore = (e) => {
      e.stopPropagation();
      e.preventDefault();
      openFullEmojiTray(msg.id);
    };
    moreBtn.addEventListener('click', handleMore);
    moreBtn.addEventListener('touchend', handleMore);

    reactionsBar.appendChild(moreBtn);
    menu.appendChild(reactionsBar);

    // 2. Action Buttons (Reply, Copy)
    const actionsList = document.createElement('div');
    actionsList.className = 'whatsapp-actions-list';

    // Reply button
    const replyItem = document.createElement('button');
    replyItem.type = 'button';
    replyItem.className = 'whatsapp-action-item';
    replyItem.innerHTML = `
      <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="9 17 4 12 9 7"></polyline><path d="M20 18v-2a4 4 0 0 0-4-4H4"></path></svg>
      <span>Reply</span>
    `;
    const handleReply = (e) => {
      e.stopPropagation();
      e.preventDefault();
      startReply(msg.id, msg.text || 'File attachment', direction === 'sent' ? 'You' : (msg.senderName || 'Peer'));
      closeActiveMenu(); // Closes immediately after clicking reply!
    };
    replyItem.addEventListener('click', handleReply);
    replyItem.addEventListener('touchend', handleReply);
    actionsList.appendChild(replyItem);

    // Copy button (if text message)
    if (msg.text) {
      const copyItem = document.createElement('button');
      copyItem.type = 'button';
      copyItem.className = 'whatsapp-action-item';
      copyItem.innerHTML = `
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>
        <span>Copy Text</span>
      `;
      const handleCopy = (e) => {
        e.stopPropagation();
        e.preventDefault();
        navigator.clipboard.writeText(msg.text);
        showToast('Copied to clipboard', 'info');
        closeActiveMenu(); // Closes immediately after copying!
      };
      copyItem.addEventListener('click', handleCopy);
      copyItem.addEventListener('touchend', handleCopy);
      actionsList.appendChild(copyItem);
    }

    menu.appendChild(actionsList);
    bubbleWrapper.appendChild(menu);

    // Safe horizontal and vertical viewport clamping
    requestAnimationFrame(() => {
      const rect = menu.getBoundingClientRect();
      const viewportWidth = window.innerWidth;

      // Vertical clamping: if near top edge, place below bubble
      if (rect.top < 75) {
        menu.classList.add('position-below');
      }

      // Horizontal clamping: ensure menu stays fully within screen edges
      if (direction === 'received') {
        if (rect.right > viewportWidth - 12) {
          const shift = rect.right - (viewportWidth - 12);
          menu.style.left = `-${shift}px`;
        }
        if (rect.left < 10) {
          menu.style.left = `${Math.abs(rect.left) + 10}px`;
        }
      } else {
        if (rect.left < 12) {
          const shift = 12 - rect.left;
          menu.style.right = `-${shift}px`;
        }
      }
    });

    // Auto-dismiss on click outside
    const dismissHandler = (e) => {
      if (!menu.contains(e.target)) {
        closeActiveMenu();
        document.removeEventListener('click', dismissHandler);
        document.removeEventListener('touchstart', dismissHandler);
      }
    };
    setTimeout(() => {
      document.addEventListener('click', dismissHandler);
      document.addEventListener('touchstart', dismissHandler, { passive: true });
    }, 40);
  }

  function openFullEmojiTray(msgId) {
    closeActiveMenu();

    const overlay = document.createElement('div');
    overlay.className = 'emoji-full-tray-overlay';

    const tray = document.createElement('div');
    tray.className = 'emoji-full-tray';

    // Tray Header
    const header = document.createElement('div');
    header.className = 'emoji-tray-header';
    header.innerHTML = `
      <span>Choose Emoji Reaction</span>
      <button type="button" class="btn-close-tray" title="Close">&times;</button>
    `;
    tray.appendChild(header);

    // Category Tabs Bar
    const tabsBar = document.createElement('div');
    tabsBar.className = 'emoji-category-tabs';

    // Content container
    const content = document.createElement('div');
    content.className = 'emoji-tray-content';

    EMOJI_CATEGORIES.forEach((cat, idx) => {
      const tabBtn = document.createElement('button');
      tabBtn.type = 'button';
      tabBtn.className = `emoji-tab-btn ${idx === 0 ? 'active' : ''}`;
      tabBtn.textContent = cat.name.split(' ')[0];
      tabBtn.onclick = () => {
        tray.querySelectorAll('.emoji-tab-btn').forEach((b) => b.classList.remove('active'));
        tabBtn.classList.add('active');
        const sectionEl = document.getElementById(`cat_section_${idx}`);
        if (sectionEl) sectionEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
      };
      tabsBar.appendChild(tabBtn);

      const section = document.createElement('div');
      section.className = 'emoji-category-section';
      section.id = `cat_section_${idx}`;

      const secTitle = document.createElement('div');
      secTitle.className = 'emoji-category-title';
      secTitle.textContent = cat.name;
      section.appendChild(secTitle);

      const grid = document.createElement('div');
      grid.className = 'emoji-grid';

      cat.emojis.forEach((emoji) => {
        const eBtn = document.createElement('button');
        eBtn.type = 'button';
        eBtn.className = 'emoji-grid-btn';
        eBtn.textContent = emoji;

        const handleTrayReact = (e) => {
          e.stopPropagation();
          e.preventDefault();
          if (!socket || !currentPin) return;
          addReaction(msgId, emoji, socket.id);
          socket.emit('message_reaction', { messageId: msgId, emoji, pin: currentPin });
          closeActiveMenu(); // Closes tray immediately after reacting!
        };

        eBtn.addEventListener('click', handleTrayReact);
        eBtn.addEventListener('touchend', handleTrayReact);

        grid.appendChild(eBtn);
      });

      section.appendChild(grid);
      content.appendChild(section);
    });

    tray.appendChild(tabsBar);
    tray.appendChild(content);
    overlay.appendChild(tray);
    document.body.appendChild(overlay);

    const closeBtn = header.querySelector('.btn-close-tray');
    if (closeBtn) closeBtn.onclick = closeActiveMenu;

    overlay.onclick = (e) => {
      if (e.target === overlay) closeActiveMenu();
    };
  }

  // ==========================================
  // --- MESSAGE REPLY / QUOTE ENGINE ---
  // ==========================================

  function startReply(msgId, text, sender) {
    activeReply = {
      id: msgId,
      text: text.slice(0, 100),
      sender: sender || 'Peer',
    };
    if (replyBarSender) replyBarSender.textContent = `Replying to ${activeReply.sender}`;
    if (replyBarText) replyBarText.textContent = activeReply.text;
    if (replyBar) replyBar.classList.remove('hidden');
    chatTextarea.focus();
  }

  function clearReply() {
    activeReply = null;
    if (replyBar) replyBar.classList.add('hidden');
  }

  function scrollToMessage(msgId) {
    const target = document.getElementById(`msg_row_${msgId}`);
    if (target) {
      target.scrollIntoView({ behavior: 'smooth', block: 'center' });
      target.style.transition = 'box-shadow 0.3s ease';
      target.style.boxShadow = '0 0 15px rgba(16, 185, 129, 0.5)';
      setTimeout(() => {
        target.style.boxShadow = 'none';
      }, 1200);
    }
  }

  // ==========================================
  // --- SOCKET.IO INITIALIZATION & EVENTS ---
  // ==========================================

  function initSocket() {
    if (typeof io === 'undefined') {
      console.error('Socket.io library not loaded');
      if (serverStatusLabel) serverStatusLabel.textContent = 'Offline';
      if (serverStatusDot) serverStatusDot.className = 'status-dot disconnected';
      return;
    }

    socket = io();

    socket.on('connect', () => {
      if (serverStatusLabel) serverStatusLabel.textContent = 'Ready';
      if (serverStatusDot) serverStatusDot.className = 'status-dot';
      console.log('[codaaa] Connected to relay server:', socket.id);

      const urlParams = new URLSearchParams(window.location.search);
      const queryPin = urlParams.get('pin');
      if (queryPin && queryPin.length === 4 && /^\d+$/.test(queryPin)) {
        setLobbyTab('receive');
        fillPinBoxes(queryPin);
      }
    });

    socket.on('disconnect', () => {
      if (serverStatusLabel) serverStatusLabel.textContent = 'Offline';
      if (serverStatusDot) serverStatusDot.className = 'status-dot disconnected';
    });

    socket.on('connect_error', () => {
      if (serverStatusLabel) serverStatusLabel.textContent = 'Connecting...';
      if (serverStatusDot) serverStatusDot.className = 'status-dot connecting';
    });

    // 1. Room Created (Sender)
    socket.on('room_created', async (data) => {
      currentPin = data.pin;
      isHost = true;
      displayPin.textContent = data.pin;
      const shareUrl = `${window.location.origin}/?pin=${data.pin}`;
      shareLinkInput.value = shareUrl;

      await generateE2EEKeys();

      switchView('pin');
      showToast(`Room #${data.pin} created. Share PIN with receiver!`, 'success');
    });

    // 2. Room Matched (Both Host & Peer Connected!)
    socket.on('room_matched', async (data) => {
      currentPin = data.pin;
      if (activePinBadge) activePinBadge.textContent = data.pin;
      if (peerStatusText) peerStatusText.textContent = 'Connected';
      switchView('chat');
      playTone('connected');

      if (!myPublicJwk) {
        await generateE2EEKeys();
      }
      if (myPublicJwk) {
        socket.emit('e2ee:key_exchange', { publicKey: myPublicJwk });
      }

      showToast(`Connected with peer in room #${data.pin}!`, 'success');
      chatTextarea.focus();
    });

    // 2B. Group Room Created (Multi-Member)
    socket.on('group_room_created', async (data) => {
      currentPin = data.pin;
      isHost = true;
      isGroupSession = true;
      groupRoomTitle = data.groupName || 'codaaa Group';
      currentMembers = data.members || [];

      if (activePinBadge) activePinBadge.textContent = data.pin;
      if (groupTitleBadge) {
        groupTitleBadge.textContent = groupRoomTitle;
        groupTitleBadge.classList.remove('hidden');
      }
      if (membersCountBadge) {
        membersCountBadge.textContent = currentMembers.length;
      }

      await generateE2EEKeys();
      closeGroupModal();
      switchView('chat');
      playTone('connected');

      showToast(`Group room #${data.pin} created! Share 4-digit code with members.`, 'success');
      appendSystemNotice(`Group "${groupRoomTitle}" created with Code #${data.pin}`);
      renderGroupMembersList();
    });

    // 2C. Group Room Joined (Reserve / Join with Name & Code)
    socket.on('group_room_joined', async (data) => {
      currentPin = data.pin;
      isHost = data.isHost || false;
      isGroupSession = true;
      groupRoomTitle = data.groupName || 'codaaa Group';
      currentMembers = data.members || [];

      if (activePinBadge) activePinBadge.textContent = data.pin;
      if (groupTitleBadge) {
        groupTitleBadge.textContent = groupRoomTitle;
        groupTitleBadge.classList.remove('hidden');
      }
      if (membersCountBadge) {
        membersCountBadge.textContent = currentMembers.length;
      }

      await generateE2EEKeys();
      closeGroupModal();
      switchView('chat');
      playTone('connected');

      showToast(`Joined group "${groupRoomTitle}" #${data.pin}!`, 'success');
      appendSystemNotice(`You joined the group as ${data.myName || myDisplayName}`);
      renderGroupMembersList();
    });

    // 2D. Group Member Joined Live Notice
    socket.on('group_member_joined', (data) => {
      if (data.members) {
        currentMembers = data.members;
        if (membersCountBadge) membersCountBadge.textContent = currentMembers.length;
        renderGroupMembersList();
      }
      showToast(data.message || 'A new member joined the group', 'info');
      appendSystemNotice(data.message || `${data.member?.name || 'A member'} joined the group chat`);
      playTone('message');
    });

    // 2E. Group Member Left Notice
    socket.on('group_member_left', (data) => {
      if (data.members) {
        currentMembers = data.members;
        if (membersCountBadge) membersCountBadge.textContent = currentMembers.length;
        renderGroupMembersList();
      }
      showToast(data.message || 'A member left the group', 'info');
      appendSystemNotice(data.message || `${data.memberName || 'A member'} left the group`);
    });

    // 2F. Room Members List
    socket.on('room_members', (data) => {
      if (data && data.members) {
        currentMembers = data.members;
        if (data.groupName) groupRoomTitle = data.groupName;
        renderGroupMembersList();
      }
    });

    // 3. E2EE Public Key Exchange
    socket.on('e2ee:key_exchange', async (data) => {
      if (!myPublicJwk) {
        await generateE2EEKeys();
        if (myPublicJwk) {
          socket.emit('e2ee:key_exchange', { publicKey: myPublicJwk });
        }
      }
      if (data && data.publicKey) {
        await deriveE2EESharedKey(data.publicKey, currentPin);
      }
    });

    // 4. Join Error
    socket.on('join_error', (data) => {
      const msg = data.message || 'Failed to join room.';
      showJoinError(msg);
      if (groupReserveError) {
        groupReserveError.textContent = msg;
        groupReserveError.classList.remove('hidden');
      }
      if (groupCreateError) {
        groupCreateError.textContent = msg;
        groupCreateError.classList.remove('hidden');
      }
      showToast(msg, 'error');
    });

    // 5. Peer Disconnected
    socket.on('peer_disconnected', (data) => {
      showToast(data.message || 'Peer disconnected. Session terminated.', 'error');
      resetToLobby();
    });

    // 6. Incoming Chat Message
    socket.on('chat_message', async (msg) => {
      const plainText = await decryptMessage(msg);
      msg.text = plainText;

      appendChatMessage(msg, 'received');
      playTone('message');

      // Send 'delivered' receipt to peer
      socket.emit('delivered', {
        messageId: msg.id,
        pin: currentPin,
      });

      // Mark read if active
      if (!document.hidden && document.hasFocus()) {
        socket.emit('read', {
          messageId: msg.id,
          messageIds: [msg.id],
          pin: currentPin,
          timestamp: Date.now(),
        });
      } else {
        pendingUnreadMessageIds.add(msg.id);
      }
    });

    // 7. Message Delivered Receipt
    socket.on('delivered', (data) => {
      updateLatestReceipt('delivered', data ? data.timestamp : Date.now());
    });

    // 8. Real-Time Read Receipt ('seen' status)
    socket.on('read', (data) => {
      updateLatestReceipt('seen', data ? data.timestamp : Date.now());
    });

    // 9. Emoji Reaction Received ("amojy reply")
    socket.on('message_reaction', (data) => {
      if (!data || !data.messageId || !data.emoji) return;
      addReaction(data.messageId, data.emoji, data.senderId);
    });

    // 10. Typing Indicator
    socket.on('typing_indicator', (data) => {
      if (data.isTyping) {
        typingBar.classList.remove('hidden');
      } else {
        typingBar.classList.add('hidden');
      }
    });

    // --- File Transfer Binary Protocol Events ---
    socket.on('file:start', (meta) => {
      handleIncomingFileStart(meta);
    });

    socket.on('file:chunk', (data) => {
      handleIncomingFileChunk(data);
    });

    socket.on('file:ack', (data) => {
      handleOutgoingFileAck(data);
    });

    socket.on('file:cancel', (data) => {
      handleFileCancelled(data);
    });

    // ==========================================
    // --- WebRTC Video & Audio Call Signaling ---
    // ==========================================
    // Incoming call notice from peer
    socket.on('call:incoming', (data) => {
      handleIncomingCall(data);
    });

    // Peer accepted call
    socket.on('call:accepted', async (data) => {
      handleCallAccepted(data);
    });

    // Peer rejected call
    socket.on('call:rejected', (data) => {
      handleCallRejected(data);
    });

    // Call ended by peer
    socket.on('call:ended', () => {
      handleCallEndedByPeer();
    });

    // WebRTC SDP Offer / Answer
    socket.on('webrtc:signal', async (data) => {
      handleWebRtcSignal(data);
    });

    // WebRTC ICE Candidate
    socket.on('webrtc:ice-candidate', async (data) => {
      handleRemoteIceCandidate(data);
    });

    // Peer toggled camera or mic
    socket.on('call:media-state', (data) => {
      handlePeerMediaState(data);
    });
  }

  // --- Reset to Lobby State ---
  function resetToLobby() {
    currentPin = null;
    isHost = false;
    isGroupSession = false;
    groupRoomTitle = 'codaaa Group';
    currentMembers = [];
    if (groupTitleBadge) groupTitleBadge.classList.add('hidden');
    if (membersCountBadge) membersCountBadge.textContent = '1';
    closeGroupModal();
    closeMembersModal();

    activeTransfers.clear();
    sendQueue = [];
    isSendingFile = false;
    latestSentReceiptContainer = null;
    latestSentMessageId = null;
    pendingUnreadMessageIds.clear();
    reactionsStore.clear();
    clearReply();

    e2eeKeyPair = null;
    myPublicJwk = null;
    sharedAesKey = null;
    safetyCode = '•••• •••• •••• ••••';
    e2eeReady = false;

    if (safetyFingerprintTag) {
      safetyFingerprintTag.textContent = 'E2EE';
    }

    // Terminate any ongoing or pending WebRTC call
    cleanupCall(false);

    if (window.location.search) {
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    pinDigitBoxes.forEach((box) => (box.value = ''));
    hideJoinError();
    setLobbyTab('send');

    const welcome = messagesContainer.querySelector('.system-message');
    messagesContainer.innerHTML = '';
    if (welcome) messagesContainer.appendChild(welcome);

    switchView('lobby');
  }

  // --- PIN Digit Box Auto-Navigation ---
  function setupPinDigitBoxes() {
    pinDigitBoxes.forEach((box, index) => {
      box.addEventListener('input', (e) => {
        const val = e.target.value.replace(/\D/g, '');
        e.target.value = val ? val[0] : '';

        if (e.target.value && index < pinDigitBoxes.length - 1) {
          pinDigitBoxes[index + 1].focus();
        }
        hideJoinError();
      });

      box.addEventListener('keydown', (e) => {
        if (e.key === 'Backspace' && !box.value && index > 0) {
          pinDigitBoxes[index - 1].focus();
        }
      });

      box.addEventListener('paste', (e) => {
        e.preventDefault();
        const pasted = (e.clipboardData || window.clipboardData).getData('text');
        fillPinBoxes(pasted);
      });
    });
  }

  function fillPinBoxes(text) {
    if (!text) return;
    const digits = text.replace(/\D/g, '').slice(0, 4);
    for (let i = 0; i < 4; i++) {
      pinDigitBoxes[i].value = digits[i] || '';
    }
    if (digits.length === 4) {
      pinDigitBoxes[3].focus();
      submitJoin();
    } else {
      const nextIdx = Math.min(digits.length, 3);
      pinDigitBoxes[nextIdx].focus();
    }
  }

  function getEnteredPin() {
    return pinDigitBoxes.map((b) => b.value.trim()).join('');
  }

  function showJoinError(msg) {
    joinErrorMsg.textContent = msg;
    joinErrorMsg.classList.remove('hidden');
  }

  function hideJoinError() {
    joinErrorMsg.classList.add('hidden');
    joinErrorMsg.textContent = '';
  }

  async function submitJoin() {
    const pin = getEnteredPin();
    if (pin.length !== 4) {
      showJoinError('Please enter all 4 digits of the PIN.');
      return;
    }
    if (!socket || !socket.connected) {
      showJoinError('Connecting to server relay... please wait.');
      return;
    }
    hideJoinError();

    await generateE2EEKeys();
    socket.emit('join_room', { pin, name: myDisplayName || 'Member' });
  }

  function setLobbyTab(tab) {
    if (tab === 'receive') {
      if (tabBtnReceive) {
        tabBtnReceive.classList.add('active');
        tabBtnReceive.setAttribute('aria-selected', 'true');
      }
      if (tabBtnSend) {
        tabBtnSend.classList.remove('active');
        tabBtnSend.setAttribute('aria-selected', 'false');
      }
      if (panelReceive) panelReceive.classList.add('active');
      if (panelSend) panelSend.classList.remove('active');
      setTimeout(() => {
        const firstEmpty = pinDigitBoxes.find((b) => !b.value) || pinDigitBoxes[0];
        if (firstEmpty) firstEmpty.focus();
      }, 50);
    } else {
      if (tabBtnSend) {
        tabBtnSend.classList.add('active');
        tabBtnSend.setAttribute('aria-selected', 'true');
      }
      if (tabBtnReceive) {
        tabBtnReceive.classList.remove('active');
        tabBtnReceive.setAttribute('aria-selected', 'false');
      }
      if (panelSend) panelSend.classList.add('active');
      if (panelReceive) panelReceive.classList.remove('active');
    }
  }

  // --- Group Chat Launcher & Modal Engine ---
  function openGroupModal() {
    if (inputCreatorName) inputCreatorName.value = myDisplayName || '';
    if (inputJoinerName) inputJoinerName.value = myDisplayName || '';
    if (groupCreateError) groupCreateError.classList.add('hidden');
    if (groupReserveError) groupReserveError.classList.add('hidden');
    setGroupTab('create');
    if (groupChatModal) groupChatModal.classList.remove('hidden');
    setTimeout(() => {
      if (inputCreatorName && !inputCreatorName.value) inputCreatorName.focus();
    }, 60);
  }

  function closeGroupModal() {
    if (groupChatModal) groupChatModal.classList.add('hidden');
  }

  function setGroupTab(tab) {
    if (tab === 'reserve') {
      if (tabGroupReserve) {
        tabGroupReserve.classList.add('active');
        tabGroupReserve.setAttribute('aria-selected', 'true');
      }
      if (tabGroupCreate) {
        tabGroupCreate.classList.remove('active');
        tabGroupCreate.setAttribute('aria-selected', 'false');
      }
      if (panelGroupReserve) panelGroupReserve.classList.add('active');
      if (panelGroupCreate) panelGroupCreate.classList.remove('active');
      setTimeout(() => {
        if (inputJoinerName && !inputJoinerName.value) {
          inputJoinerName.focus();
        } else if (inputGroupCode) {
          inputGroupCode.focus();
        }
      }, 50);
    } else {
      if (tabGroupCreate) {
        tabGroupCreate.classList.add('active');
        tabGroupCreate.setAttribute('aria-selected', 'true');
      }
      if (tabGroupReserve) {
        tabGroupReserve.classList.remove('active');
        tabGroupReserve.setAttribute('aria-selected', 'false');
      }
      if (panelGroupCreate) panelGroupCreate.classList.add('active');
      if (panelGroupReserve) panelGroupReserve.classList.remove('active');
      setTimeout(() => {
        if (inputCreatorName) inputCreatorName.focus();
      }, 50);
    }
  }

  function submitCreateGroup() {
    const name = (inputCreatorName ? inputCreatorName.value : '').trim();
    const groupTitle = (inputGroupTitle ? inputGroupTitle.value : '').trim() || 'codaaa Squad';

    if (!name) {
      if (groupCreateError) {
        groupCreateError.textContent = 'Please enter your name to create the group.';
        groupCreateError.classList.remove('hidden');
      }
      if (inputCreatorName) inputCreatorName.focus();
      return;
    }

    myDisplayName = name;
    try {
      localStorage.setItem('codaaa_user_name', myDisplayName);
    } catch (_) {}

    if (!socket || !socket.connected) {
      if (groupCreateError) {
        groupCreateError.textContent = 'Connecting to server relay... please wait.';
        groupCreateError.classList.remove('hidden');
      }
      return;
    }

    if (groupCreateError) groupCreateError.classList.add('hidden');
    socket.emit('create_group_room', { name, groupName: groupTitle });
  }

  function submitJoinGroup() {
    const name = (inputJoinerName ? inputJoinerName.value : '').trim();
    const code = (inputGroupCode ? inputGroupCode.value : '').replace(/\D/g, '').slice(0, 4);

    if (!name) {
      if (groupReserveError) {
        groupReserveError.textContent = 'Please enter your name.';
        groupReserveError.classList.remove('hidden');
      }
      if (inputJoinerName) inputJoinerName.focus();
      return;
    }

    if (code.length !== 4) {
      if (groupReserveError) {
        groupReserveError.textContent = 'Please enter all 4 digits of the Group PIN code.';
        groupReserveError.classList.remove('hidden');
      }
      if (inputGroupCode) inputGroupCode.focus();
      return;
    }

    myDisplayName = name;
    try {
      localStorage.setItem('codaaa_user_name', myDisplayName);
    } catch (_) {}

    if (!socket || !socket.connected) {
      if (groupReserveError) {
        groupReserveError.textContent = 'Connecting to server relay... please wait.';
        groupReserveError.classList.remove('hidden');
      }
      return;
    }

    if (groupReserveError) groupReserveError.classList.add('hidden');
    socket.emit('join_group_room', { name, pin: code });
  }

  // --- Show Members Modal Engine ---
  function renderGroupMembersList() {
    if (!groupMembersList) return;
    groupMembersList.innerHTML = '';

    if (!currentMembers || currentMembers.length === 0) {
      const emptyRow = document.createElement('div');
      emptyRow.className = 'member-item-row';
      emptyRow.innerHTML = '<span class="member-name-text">No active members online</span>';
      groupMembersList.appendChild(emptyRow);
      return;
    }

    currentMembers.forEach((member) => {
      const row = document.createElement('div');
      row.className = 'member-item-row';

      const isMe =
        (socket && member.id === socket.id) ||
        (member.name === myDisplayName && member.isHost === isHost);
      const initial = (member.name || 'M').charAt(0).toUpperCase();

      row.innerHTML = `
        <div class="member-item-left">
          <div class="member-avatar-circle">${escapeHTML(initial)}</div>
          <div>
            <div class="member-name-text">${escapeHTML(member.name || 'Member')}</div>
          </div>
        </div>
        <div class="member-badges">
          ${member.isHost ? '<span class="badge-member-host">Host</span>' : ''}
          ${isMe ? '<span class="badge-member-you">You</span>' : ''}
        </div>
      `;
      groupMembersList.appendChild(row);
    });

    if (membersListCount) {
      membersListCount.textContent = currentMembers.length;
    }
    if (membersCountBadge) {
      membersCountBadge.textContent = currentMembers.length;
    }
    if (membersRoomPin) {
      membersRoomPin.textContent = currentPin || '----';
    }
    if (membersModalGroupName) {
      membersModalGroupName.textContent = groupRoomTitle || 'Group Members';
    }
  }

  function openMembersModal() {
    renderGroupMembersList();
    if (socket && currentPin) {
      socket.emit('get_room_members');
    }
    if (groupMembersModal) {
      groupMembersModal.classList.remove('hidden');
    }
  }

  function closeMembersModal() {
    if (groupMembersModal) {
      groupMembersModal.classList.add('hidden');
    }
  }

  function appendSystemNotice(text) {
    const noticeRow = document.createElement('div');
    noticeRow.className = 'system-message';
    noticeRow.innerHTML = `<span>${escapeHTML(text)}</span>`;
    messagesContainer.appendChild(noticeRow);
    scrollToBottom();
  }

  // --- Event Listeners Setup ---
  function setupEventListeners() {
    if (tabBtnSend) tabBtnSend.addEventListener('click', () => setLobbyTab('send'));
    if (tabBtnReceive) tabBtnReceive.addEventListener('click', () => setLobbyTab('receive'));
    if (btnSwitchToReceive) btnSwitchToReceive.addEventListener('click', () => setLobbyTab('receive'));
    if (btnSwitchToSend) btnSwitchToSend.addEventListener('click', () => setLobbyTab('send'));

    brandLogo.addEventListener('click', () => {
      if (currentPin) {
        if (confirm('Leave current session and return to lobby?')) {
          if (socket) socket.emit('leave_room');
          resetToLobby();
        }
      } else {
        resetToLobby();
      }
    });

    btnCreateRoom.addEventListener('click', () => {
      if (!socket || !socket.connected) {
        showToast('Connecting to server... Please wait a moment.', 'error');
        return;
      }
      socket.emit('create_room');
    });

    joinForm.addEventListener('submit', (e) => {
      e.preventDefault();
      submitJoin();
    });

    btnPastePin.addEventListener('click', async () => {
      try {
        const text = await navigator.clipboard.readText();
        fillPinBoxes(text);
      } catch (err) {
        showToast('Clipboard access denied. Please type PIN manually.', 'error');
      }
    });

    btnCopyPin.addEventListener('click', () => {
      if (!currentPin) return;
      navigator.clipboard.writeText(currentPin);
      showToast(`PIN ${currentPin} copied to clipboard!`, 'success');
    });

    btnCopyLink.addEventListener('click', () => {
      if (!shareLinkInput.value) return;
      navigator.clipboard.writeText(shareLinkInput.value);
      showToast('Share link copied to clipboard!', 'success');
    });

    btnCancelRoom.addEventListener('click', () => {
      if (socket) socket.emit('leave_room');
      resetToLobby();
    });

    btnLeaveRoom.addEventListener('click', () => {
      if (confirm('Disconnect and wipe this ephemeral session?')) {
        if (socket) socket.emit('leave_room');
        resetToLobby();
      }
    });

    btnSendMessage.addEventListener('click', sendTextMessage);
    chatTextarea.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault();
        sendTextMessage();
      }
    });

    // Cancel Reply Button
    if (btnCancelReply) {
      btnCancelReply.addEventListener('click', clearReply);
    }

    // Focus & Visibility triggers for Read Receipts
    window.addEventListener('focus', markPendingAsRead);
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) markPendingAsRead();
    });
    messagesContainer.addEventListener('click', markPendingAsRead);
    chatTextarea.addEventListener('focus', markPendingAsRead);

    chatTextarea.addEventListener('input', () => {
      autoResizeTextarea();
      if (!socket || !currentPin) return;

      socket.emit('typing_indicator', { isTyping: true });
      clearTimeout(typingTimeout);
      typingTimeout = setTimeout(() => {
        if (socket) socket.emit('typing_indicator', { isTyping: false });
      }, 1200);
    });

    btnAttachFile.addEventListener('click', () => fileInput.click());
    btnAttachImage.addEventListener('click', () => imageInput.click());

    // Voice & Video Call Event Handlers
    if (btnAudioCall) {
      btnAudioCall.addEventListener('click', () => initiateCall('voice'));
    }
    if (btnVideoCall) {
      btnVideoCall.addEventListener('click', () => initiateCall('video'));
    }
    if (btnCallAccept) {
      btnCallAccept.addEventListener('click', acceptIncomingCall);
    }
    if (btnCallDecline) {
      btnCallDecline.addEventListener('click', declineOrCancelCall);
    }
    if (btnEndCall) {
      btnEndCall.addEventListener('click', endCall);
    }
    if (btnToggleMic) {
      btnToggleMic.addEventListener('click', toggleMicrophone);
    }
    if (btnToggleVideo) {
      btnToggleVideo.addEventListener('click', toggleCamera);
    }
    if (btnCallMinimize) {
      btnCallMinimize.addEventListener('click', toggleMinimizeCall);
    }
    if (btnThemeToggle) {
      btnThemeToggle.addEventListener('click', toggleTheme);
    }
    if (btnChatThemeToggle) {
      btnChatThemeToggle.addEventListener('click', toggleTheme);
    }

    fileInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files.length) {
        queueFilesForTransfer(Array.from(e.target.files));
        fileInput.value = '';
      }
    });

    imageInput.addEventListener('change', (e) => {
      if (e.target.files && e.target.files.length) {
        queueFilesForTransfer(Array.from(e.target.files));
        imageInput.value = '';
      }
    });

    setupDragAndDrop();

    lightboxClose.addEventListener('click', closeLightbox);
    lightboxModal.addEventListener('click', (e) => {
      if (e.target === lightboxModal || e.target.classList.contains('lightbox-backdrop')) {
        closeLightbox();
      }
    });

    if (btnShowE2eeModal) {
      btnShowE2eeModal.addEventListener('click', openE2eeModal);
    }
    if (e2eeModalClose) {
      e2eeModalClose.addEventListener('click', closeE2eeModal);
    }
    if (btnCloseE2eeModal) {
      btnCloseE2eeModal.addEventListener('click', closeE2eeModal);
    }
    if (e2eeBackdrop) {
      e2eeBackdrop.addEventListener('click', closeE2eeModal);
    }
    if (btnCopySafetyCode) {
      btnCopySafetyCode.addEventListener('click', () => {
        navigator.clipboard.writeText(safetyCode);
        showToast('Safety Code copied to clipboard', 'success');
      });
    }

    // Multi-Member Group Chat Modal Event Listeners
    if (btnOpenGroupModal) btnOpenGroupModal.addEventListener('click', openGroupModal);
    if (groupModalCloseBtn) groupModalCloseBtn.addEventListener('click', closeGroupModal);
    if (groupModalBackdrop) groupModalBackdrop.addEventListener('click', closeGroupModal);
    if (tabGroupCreate) tabGroupCreate.addEventListener('click', () => setGroupTab('create'));
    if (tabGroupReserve) tabGroupReserve.addEventListener('click', () => setGroupTab('reserve'));
    if (btnSubmitCreateGroup) btnSubmitCreateGroup.addEventListener('click', submitCreateGroup);
    if (btnSubmitJoinGroup) btnSubmitJoinGroup.addEventListener('click', submitJoinGroup);

    if (inputCreatorName) {
      inputCreatorName.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') submitCreateGroup();
      });
    }
    if (inputJoinerName) {
      inputJoinerName.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
          if (inputGroupCode) inputGroupCode.focus();
        }
      });
    }
    if (inputGroupCode) {
      inputGroupCode.addEventListener('input', (e) => {
        e.target.value = e.target.value.replace(/\D/g, '').slice(0, 4);
        if (groupReserveError) groupReserveError.classList.add('hidden');
        if (e.target.value.length === 4) submitJoinGroup();
      });
      inputGroupCode.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') submitJoinGroup();
      });
    }

    // Show Members Modal Event Listeners
    if (btnShowMembers) btnShowMembers.addEventListener('click', openMembersModal);
    if (membersModalClose) membersModalClose.addEventListener('click', closeMembersModal);
    if (membersModalBackdrop) membersModalBackdrop.addEventListener('click', closeMembersModal);
    if (btnCloseMembersModal) btnCloseMembersModal.addEventListener('click', closeMembersModal);
    if (btnCopyGroupPin) {
      btnCopyGroupPin.addEventListener('click', () => {
        if (!currentPin) return;
        navigator.clipboard.writeText(currentPin);
        showToast(`Group PIN #${currentPin} copied to clipboard!`, 'success');
      });
    }
  }

  function autoResizeTextarea() {
    chatTextarea.style.height = 'auto';
    chatTextarea.style.height = Math.min(chatTextarea.scrollHeight, 100) + 'px';
  }

  function openE2eeModal() {
    if (modalSafetyCode) {
      modalSafetyCode.textContent = safetyCode;
    }
    if (e2eeModal) {
      e2eeModal.classList.remove('hidden');
    }
  }

  function closeE2eeModal() {
    if (e2eeModal) {
      e2eeModal.classList.add('hidden');
    }
  }

  // --- Chat Messaging with E2EE, Reply & Single Read Receipt on Latest Message ---
  async function sendTextMessage() {
    const text = chatTextarea.value.trim();
    if (!text || !socket || !currentPin) return;

    let senderName = myDisplayName || '';
    if (!senderName) {
      try {
        senderName = localStorage.getItem('codaaa_user_name') || '';
      } catch (_) {}
    }
    if (!senderName) senderName = isGroupSession ? 'Member' : 'You';

    const msgId = `msg_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const timestamp = Date.now();

    // Encrypt client-side via AES-GCM (256-bit)
    const encrypted = await encryptMessage(text);

    // Attach active reply metadata if present
    const replyMeta = activeReply ? { ...activeReply } : null;

    // Relay encrypted ciphertext over socket
    socket.emit('chat_message', {
      id: msgId,
      text: encrypted.text,
      iv: encrypted.iv,
      isEncrypted: encrypted.isEncrypted,
      replyTo: replyMeta,
      senderName,
      timestamp,
    });

    // Append to local sender chat (showing unencrypted text locally)
    appendChatMessage({ id: msgId, text, replyTo: replyMeta, senderName: 'You', timestamp }, 'sent');

    clearReply();
    chatTextarea.value = '';
    chatTextarea.style.height = 'auto';
    chatTextarea.focus();
    playTone('message');
  }

  function appendChatMessage(msg, direction) {
    const row = document.createElement('div');
    row.className = `message-row ${direction}`;
    row.id = `msg_row_${msg.id}`;

    const bubbleWrapper = document.createElement('div');
    bubbleWrapper.className = 'message-bubble-wrapper';

    const bubble = document.createElement('div');
    bubble.className = 'message-bubble';

    // 0. Sender Name Header (WhatsApp / Group Chat Style: "jishse pta chale ke kon massage kar raha")
    if (direction === 'received' && (msg.senderName || isGroupSession)) {
      const senderTag = document.createElement('div');
      senderTag.className = 'msg-sender-name';
      senderTag.textContent = msg.senderName || 'Member';
      bubble.appendChild(senderTag);
    }

    // 1. Quoted Message Preview (if reply)
    if (msg.replyTo) {
      const quoteBox = document.createElement('div');
      quoteBox.className = 'quoted-message';
      quoteBox.innerHTML = `
        <div class="quoted-sender">${escapeHTML(msg.replyTo.sender || 'Peer')}</div>
        <div class="quoted-text">${escapeHTML(msg.replyTo.text || '')}</div>
      `;
      quoteBox.onclick = () => scrollToMessage(msg.replyTo.id);
      bubble.appendChild(quoteBox);
    }

    // Message Text
    const textNode = document.createElement('div');
    textNode.className = 'message-text-content';
    textNode.innerHTML = escapeHTML(msg.text).replace(/\n/g, '<br>');
    bubble.appendChild(textNode);

    // Compact WhatsApp-style Inline Meta (Time + Status)
    const metaBox = document.createElement('div');
    metaBox.className = 'bubble-meta';

    const timeSpan = document.createElement('span');
    timeSpan.className = 'bubble-time';
    timeSpan.textContent = formatTime(msg.timestamp);
    metaBox.appendChild(timeSpan);

    // Read Receipt Rule: ONLY ON THE LATEST SENT MESSAGE!
    if (direction === 'sent') {
      if (latestSentReceiptContainer && latestSentReceiptContainer.parentElement) {
        latestSentReceiptContainer.remove();
      }
      latestSentReceiptContainer = createReceiptElement('sent');
      metaBox.appendChild(latestSentReceiptContainer);
      latestSentMessageId = msg.id;
    }

    bubble.appendChild(metaBox);

    // 2. Reactions Container under Bubble (only appears when reactions exist)
    const reactionsContainer = document.createElement('div');
    reactionsContainer.className = 'reactions-container';
    reactionsContainer.id = `reactions_${msg.id}`;

    bubbleWrapper.appendChild(bubble);
    bubbleWrapper.appendChild(reactionsContainer);
    row.appendChild(bubbleWrapper);

    // Attach long-press & double-tap listeners (WhatsApp style)
    const triggerMenu = () => openMessageActionMenu(msg, row, bubbleWrapper, direction);
    const triggerQuickHeart = () => {
      if (!socket || !currentPin) return;
      addReaction(msg.id, '❤️', socket.id);
      socket.emit('message_reaction', { messageId: msg.id, emoji: '❤️', pin: currentPin });
    };

    attachLongPressListener(bubble, triggerMenu, triggerQuickHeart);
    attachLongPressListener(bubbleWrapper, triggerMenu, triggerQuickHeart);

    messagesContainer.appendChild(row);
    scrollToBottom();
  }

  function scrollToBottom() {
    messagesContainer.scrollTop = messagesContainer.scrollHeight;
  }

  // --- Drag and Drop Setup ---
  function setupDragAndDrop() {
    let dragCounter = 0;

    window.addEventListener('dragenter', (e) => {
      e.preventDefault();
      if (!views.chat.classList.contains('active')) return;
      dragCounter++;
      dropOverlay.classList.add('active');
    });

    window.addEventListener('dragleave', (e) => {
      e.preventDefault();
      if (!views.chat.classList.contains('active')) return;
      dragCounter--;
      if (dragCounter <= 0) {
        dropOverlay.classList.remove('active');
        dragCounter = 0;
      }
    });

    window.addEventListener('dragover', (e) => {
      e.preventDefault();
    });

    window.addEventListener('drop', (e) => {
      e.preventDefault();
      dropOverlay.classList.remove('active');
      dragCounter = 0;
      if (!views.chat.classList.contains('active')) return;

      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
        queueFilesForTransfer(Array.from(e.dataTransfer.files));
      }
    });
  }

  // --- File Transfer Queue ---
  function queueFilesForTransfer(files) {
    if (!currentPin || !socket) {
      showToast('Connect with a peer before sending files.', 'error');
      return;
    }

    files.forEach((file) => {
      if (file.size > MAX_FILE_SIZE) {
        showToast(`File "${file.name}" exceeds 100MB limit. Skipping.`, 'error');
        return;
      }
      sendQueue.push(file);
    });

    processSendQueue();
  }

  function processSendQueue() {
    if (isSendingFile || sendQueue.length === 0) return;
    const file = sendQueue.shift();
    startSendingFile(file);
  }

  // --- SENDER ENGINE (Chunked Binary Streaming with Backpressure) ---
  function startSendingFile(file) {
    isSendingFile = true;
    const fileId = `file_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`;
    const totalChunks = Math.ceil(file.size / CHUNK_SIZE);

    const cardElements = createTransferCard(file.name, file.size, 'sent', fileId);
    messagesContainer.appendChild(cardElements.row);
    scrollToBottom();

    const transferState = {
      fileId,
      file,
      totalChunks,
      currentChunk: 0,
      startTime: Date.now(),
      cardElements,
      isImage: file.type.startsWith('image/'),
    };
    activeTransfers.set(fileId, transferState);

    socket.emit('file:start', {
      fileId,
      name: file.name,
      size: file.size,
      type: file.type || 'application/octet-stream',
      totalChunks,
      chunkSize: CHUNK_SIZE,
    });

    sendNextChunk(fileId);
  }

  function sendNextChunk(fileId) {
    const state = activeTransfers.get(fileId);
    if (!state) return;

    const { file, currentChunk, totalChunks, cardElements, startTime } = state;

    if (currentChunk >= totalChunks) {
      onSenderTransferComplete(state);
      return;
    }

    const start = currentChunk * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, file.size);
    const slice = file.slice(start, end);

    const reader = new FileReader();
    reader.onload = (e) => {
      const arrayBuffer = e.target.result;

      const percent = Math.round(((currentChunk + 1) / totalChunks) * 100);
      const elapsedSec = (Date.now() - startTime) / 1000 || 0.1;
      const speed = formatBytes(end / elapsedSec) + '/s';

      cardElements.progressFill.style.width = `${percent}%`;
      cardElements.percentLabel.textContent = `${percent}%`;
      cardElements.speedLabel.textContent = speed;
      cardElements.statusLabel.textContent = `Uploading chunk ${currentChunk + 1}/${totalChunks}...`;

      socket.emit('file:chunk', {
        fileId,
        chunkIndex: currentChunk,
        totalChunks,
        chunk: arrayBuffer,
      });
    };

    reader.readAsArrayBuffer(slice);
  }

  function handleOutgoingFileAck(data) {
    const state = activeTransfers.get(data.fileId);
    if (!state) return;

    if (data.chunkIndex === state.currentChunk) {
      state.currentChunk++;
      sendNextChunk(data.fileId);
    }
  }

  function onSenderTransferComplete(state) {
    const { cardElements, file, isImage } = state;
    cardElements.progressFill.style.width = '100%';
    cardElements.percentLabel.textContent = '100%';
    cardElements.statusLabel.textContent = 'Sent successfully!';
    cardElements.statusLabel.style.color = '#10b981';
    cardElements.speedLabel.textContent = 'Done';

    if (isImage) {
      const url = URL.createObjectURL(file);
      appendImagePreviewToCard(cardElements, url, file.name);
    }

    playTone('complete');
    activeTransfers.delete(state.fileId);
    isSendingFile = false;

    processSendQueue();
  }

  // --- RECEIVER ENGINE (Chunk Reassembly & Direct Download) ---
  function handleIncomingFileStart(meta) {
    const cardElements = createTransferCard(meta.name, meta.size, 'received', meta.fileId);
    messagesContainer.appendChild(cardElements.row);
    scrollToBottom();

    const transferState = {
      fileId: meta.fileId,
      name: meta.name,
      size: meta.size,
      type: meta.type,
      totalChunks: meta.totalChunks,
      receivedChunks: new Array(meta.totalChunks),
      receivedBytes: 0,
      startTime: Date.now(),
      cardElements,
      isImage: meta.type && meta.type.startsWith('image/'),
    };

    activeTransfers.set(meta.fileId, transferState);
  }

  function handleIncomingFileChunk(data) {
    const state = activeTransfers.get(data.fileId);
    if (!state) return;

    const { receivedChunks, totalChunks, cardElements, startTime } = state;
    const chunkIndex = data.chunkIndex;

    receivedChunks[chunkIndex] = data.chunk;
    state.receivedBytes += data.chunk.byteLength || data.chunk.length || 0;

    socket.emit('file:ack', {
      fileId: data.fileId,
      chunkIndex,
    });

    const chunksReceived = chunkIndex + 1;
    const percent = Math.min(100, Math.round((chunksReceived / totalChunks) * 100));
    const elapsedSec = (Date.now() - startTime) / 1000 || 0.1;
    const speed = formatBytes(state.receivedBytes / elapsedSec) + '/s';

    cardElements.progressFill.style.width = `${percent}%`;
    cardElements.percentLabel.textContent = `${percent}%`;
    cardElements.speedLabel.textContent = speed;
    cardElements.statusLabel.textContent = `Receiving chunk ${chunksReceived}/${totalChunks}...`;

    if (chunksReceived >= totalChunks) {
      onReceiverTransferComplete(state);
    }
  }

  function onReceiverTransferComplete(state) {
    const { receivedChunks, type, name, cardElements, isImage } = state;

    const blob = new Blob(receivedChunks, { type: type || 'application/octet-stream' });
    const downloadUrl = URL.createObjectURL(blob);

    cardElements.progressFill.style.width = '100%';
    cardElements.percentLabel.textContent = '100%';
    cardElements.statusLabel.textContent = 'Ready to download!';
    cardElements.statusLabel.style.color = '#10b981';
    cardElements.speedLabel.textContent = 'Ready';

    const downloadBtn = document.createElement('a');
    downloadBtn.className = 'btn btn-emerald btn-sm';
    downloadBtn.href = downloadUrl;
    downloadBtn.download = name;
    downloadBtn.innerHTML = `
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg>
      <span>Download</span>
    `;

    cardElements.actionsContainer.innerHTML = '';
    cardElements.actionsContainer.appendChild(downloadBtn);

    if (isImage) {
      appendImagePreviewToCard(cardElements, downloadUrl, name);
    }

    playTone('complete');
    showToast(`File "${name}" ready to download!`, 'success');
    activeTransfers.delete(state.fileId);
  }

  function appendImagePreviewToCard(cardElements, url, name) {
    const previewContainer = document.createElement('div');
    previewContainer.className = 'image-attachment-card';
    previewContainer.style.marginTop = '0.5rem';

    const img = document.createElement('img');
    img.className = 'image-attachment-preview';
    img.src = url;
    img.alt = name;
    img.title = 'Click to enlarge';
    img.onclick = () => openLightbox(url, name);

    previewContainer.appendChild(img);
    cardElements.fileCard.appendChild(previewContainer);
    scrollToBottom();
  }

  function handleFileCancelled(data) {
    const state = activeTransfers.get(data.fileId);
    if (!state) return;
    state.cardElements.statusLabel.textContent = `Cancelled: ${data.reason}`;
    state.cardElements.statusLabel.style.color = '#f43f5e';
    activeTransfers.delete(data.fileId);
  }

  // --- Transfer UI Card Generator ---
  function createTransferCard(fileName, fileSize, direction, fileId) {
    const row = document.createElement('div');
    row.className = `message-row ${direction}`;

    const fileCard = document.createElement('div');
    fileCard.className = 'file-card';
    fileCard.id = `card_${fileId}`;

    const ext = fileName.split('.').pop().toUpperCase().slice(0, 4) || 'FILE';

    const fileHeader = document.createElement('div');
    fileHeader.className = 'file-header';

    const fileIcon = document.createElement('div');
    fileIcon.className = 'file-type-icon';
    fileIcon.textContent = ext;

    const fileInfo = document.createElement('div');
    fileInfo.className = 'file-info';

    const nameEl = document.createElement('div');
    nameEl.className = 'file-name';
    nameEl.textContent = fileName;
    nameEl.title = fileName;

    const sizeEl = document.createElement('div');
    sizeEl.className = 'file-size-status';
    sizeEl.textContent = `${formatBytes(fileSize)} • ${direction === 'sent' ? 'Sending' : 'Receiving'}`;

    fileInfo.appendChild(nameEl);
    fileInfo.appendChild(sizeEl);

    fileHeader.appendChild(fileIcon);
    fileHeader.appendChild(fileInfo);

    const progressContainer = document.createElement('div');
    progressContainer.className = 'progress-container';

    const track = document.createElement('div');
    track.className = 'progress-track';

    const fill = document.createElement('div');
    fill.className = 'progress-fill';
    track.appendChild(fill);

    const details = document.createElement('div');
    details.className = 'progress-details';

    const percentLabel = document.createElement('span');
    percentLabel.textContent = '0%';

    const speedLabel = document.createElement('span');
    speedLabel.textContent = 'Calculating...';

    details.appendChild(percentLabel);
    details.appendChild(speedLabel);

    const statusLabel = document.createElement('div');
    statusLabel.className = 'file-size-status';
    statusLabel.style.fontSize = '0.72rem';
    statusLabel.textContent = 'Initializing transfer...';

    progressContainer.appendChild(track);
    progressContainer.appendChild(details);
    progressContainer.appendChild(statusLabel);

    const actionsContainer = document.createElement('div');
    actionsContainer.className = 'file-actions';

    fileCard.appendChild(fileHeader);
    fileCard.appendChild(progressContainer);
    fileCard.appendChild(actionsContainer);

    const timeSpan = document.createElement('span');
    timeSpan.className = 'file-card-time';
    timeSpan.textContent = formatTime(Date.now());
    fileHeader.appendChild(timeSpan);

    const fileWrapper = document.createElement('div');
    fileWrapper.className = 'message-bubble-wrapper';
    fileWrapper.appendChild(fileCard);

    const reactionsContainer = document.createElement('div');
    reactionsContainer.className = 'reactions-container';
    reactionsContainer.id = `reactions_${fileId}`;
    fileWrapper.appendChild(reactionsContainer);

    row.appendChild(fileWrapper);

    // Attach long-press & double-tap listeners
    const triggerMenu = () => openMessageActionMenu({ id: fileId, text: fileName }, row, fileWrapper, direction);
    const triggerQuickHeart = () => {
      if (!socket || !currentPin) return;
      addReaction(fileId, '❤️', socket.id);
      socket.emit('message_reaction', { messageId: fileId, emoji: '❤️', pin: currentPin });
    };

    attachLongPressListener(fileCard, triggerMenu, triggerQuickHeart);
    attachLongPressListener(fileWrapper, triggerMenu, triggerQuickHeart);

    return {
      row,
      fileCard,
      progressFill: fill,
      percentLabel,
      speedLabel,
      statusLabel,
      actionsContainer,
    };
  }

  // --- Lightbox Modal ---
  function openLightbox(url, filename) {
    lightboxImg.src = url;
    lightboxFilename.textContent = filename;
    lightboxDownload.href = url;
    lightboxDownload.download = filename;
    lightboxModal.classList.remove('hidden');
  }

  function closeLightbox() {
    lightboxModal.classList.add('hidden');
    lightboxImg.src = '';
  }

  // ========================================================
  // --- REAL-TIME WEBRTC VIDEO & AUDIO CALLING ENGINE ---
  // ========================================================

  function startRingtone() {
    stopRingtone();
    playTone('ringtone');
    ringtoneInterval = setInterval(() => {
      playTone('ringtone');
    }, 2800);
  }

  function stopRingtone() {
    if (ringtoneInterval) {
      clearInterval(ringtoneInterval);
      ringtoneInterval = null;
    }
  }

  function startCallTimer() {
    stopCallTimer();
    callStartTime = Date.now();
    activeCallTimer.textContent = '00:00';
    callTimerInterval = setInterval(() => {
      const elapsed = Math.floor((Date.now() - callStartTime) / 1000);
      const m = Math.floor(elapsed / 60).toString().padStart(2, '0');
      const s = (elapsed % 60).toString().padStart(2, '0');
      activeCallTimer.textContent = `${m}:${s}`;
    }, 1000);
  }

  function stopCallTimer() {
    if (callTimerInterval) {
      clearInterval(callTimerInterval);
      callTimerInterval = null;
    }
  }

  // Request user camera/mic with safe fallback for voice vs video
  async function acquireUserMedia(type) {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      throw new Error('Camera/Microphone is not supported in this browser.');
    }

    const constraints = {
      audio: {
        echoCancellation: true,
        noiseSuppression: true,
        autoGainControl: true
      },
      video: type === 'video' ? {
        width: { ideal: 1280 },
        height: { ideal: 720 },
        facingMode: 'user'
      } : false
    };

    try {
      const stream = await navigator.mediaDevices.getUserMedia(constraints);
      return stream;
    } catch (err) {
      // If video failed (e.g., no webcam), try audio only as graceful degradation
      if (type === 'video') {
        try {
          showToast('No camera found or access denied. Switching to voice...', 'info');
          const audioOnlyStream = await navigator.mediaDevices.getUserMedia({ audio: true });
          currentCallType = 'voice';
          return audioOnlyStream;
        } catch (audioErr) {
          throw err;
        }
      }
      throw err;
    }
  }

  // Create WebRTC PeerConnection
  function createPeerConnectionInstance() {
    if (peerConnection) {
      peerConnection.close();
      peerConnection = null;
    }

    peerConnection = new RTCPeerConnection(RTC_CONFIG);

    // Relay local ICE candidates to peer
    peerConnection.onicecandidate = (event) => {
      if (event.candidate && socket && currentPin) {
        socket.emit('webrtc:ice-candidate', {
          candidate: event.candidate,
          pin: currentPin
        });
      }
    };

    // Attach remote stream when received
    peerConnection.ontrack = (event) => {
      if (event.streams && event.streams[0]) {
        remoteVideoElem.srcObject = event.streams[0];
        remoteStatusBadge.textContent = 'Peer Connected';
        updateMediaFallbackUI();
      }
    };

    peerConnection.onconnectionstatechange = () => {
      if (!peerConnection) return;
      const state = peerConnection.connectionState;
      if (state === 'connected') {
        remoteStatusBadge.textContent = 'Connected';
        showToast('Call connected!', 'success');
      } else if (state === 'disconnected' || state === 'failed') {
        remoteStatusBadge.textContent = 'Reconnecting...';
      } else if (state === 'closed') {
        remoteStatusBadge.textContent = 'Call Ended';
      }
    };

    // Add local media tracks to peer connection
    if (localMediaStream) {
      localMediaStream.getTracks().forEach((track) => {
        peerConnection.addTrack(track, localMediaStream);
      });
    }

    return peerConnection;
  }

  // Action: Initiate an outgoing call
  async function initiateCall(type = 'video') {
    if (!socket || !currentPin) {
      showToast('You must join a room first to make a call.', 'error');
      return;
    }
    if (isCallActive) {
      showToast('A call is already in progress.', 'info');
      return;
    }

    currentCallType = type;
    isCaller = true;

    // Caller Display Name Prompt ("call karte time call krne waale kaa naam")
    let callerName = myDisplayName || '';
    if (!callerName) {
      try {
        callerName = localStorage.getItem('codaaa_user_name') || '';
      } catch (_) {}
    }
    if (!callerName) {
      const prompted = window.prompt('Enter your name for the call:', '')?.trim();
      callerName = prompted || 'Caller';
      myDisplayName = callerName;
      try {
        localStorage.setItem('codaaa_user_name', myDisplayName);
      } catch (_) {}
    }

    try {
      localMediaStream = await acquireUserMedia(type);
      localVideoElem.srcObject = localMediaStream;
      isAudioMuted = false;
      isVideoMuted = type !== 'video';
      updateMediaControlsUI();
      updateMediaFallbackUI();
    } catch (err) {
      showToast('Cannot access microphone/camera: ' + (err.message || 'Permission denied'), 'error');
      return;
    }

    // Show outgoing calling modal
    callRingingTitle.textContent = type === 'video' ? 'Outgoing Video Call...' : 'Outgoing Voice Call...';
    callRingingStatus.textContent = `Calling peer as "${callerName}" in room #${currentPin}`;
    callDeclineLabel.textContent = 'Cancel';
    btnCallAccept.classList.add('hidden');
    callRingingModal.classList.remove('hidden');

    startRingtone();

    // Signal call initiation to peer
    socket.emit('call:initiate', {
      type,
      callerName,
      pin: currentPin
    });
  }

  // Handle incoming call notification from peer
  function handleIncomingCall(data) {
    if (isCallActive) {
      socket.emit('call:reject', { reason: 'busy', pin: currentPin });
      return;
    }

    currentCallType = data.type === 'video' ? 'video' : 'voice';
    isCaller = false;

    const callerName = (data && data.callerName) ? data.callerName : 'Peer';
    callRingingTitle.textContent = currentCallType === 'video' ? `Incoming Video Call` : `Incoming Voice Call`;
    callRingingStatus.textContent = `${callerName} is calling you in room #${currentPin}`;
    callDeclineLabel.textContent = 'Decline';
    btnCallAccept.classList.remove('hidden');
    callRingingModal.classList.remove('hidden');

    startRingtone();
  }

  // Action: Accept an incoming call
  async function acceptIncomingCall() {
    stopRingtone();
    callRingingModal.classList.add('hidden');

    try {
      localMediaStream = await acquireUserMedia(currentCallType);
      localVideoElem.srcObject = localMediaStream;
      isAudioMuted = false;
      isVideoMuted = currentCallType !== 'video';
      updateMediaControlsUI();
      updateMediaFallbackUI();
    } catch (err) {
      showToast('Permission denied for microphone/camera: ' + err.message, 'error');
      socket.emit('call:reject', { reason: 'permission_denied', pin: currentPin });
      return;
    }

    createPeerConnectionInstance();

    // Tell caller we accepted
    socket.emit('call:accept', {
      type: currentCallType,
      pin: currentPin
    });

    openActiveCallModal();
  }

  // Action: Decline or cancel call
  function declineOrCancelCall() {
    stopRingtone();
    callRingingModal.classList.add('hidden');

    if (isCaller) {
      socket.emit('call:end', { pin: currentPin });
      showToast('Call cancelled', 'info');
    } else {
      socket.emit('call:reject', { reason: 'declined', pin: currentPin });
      showToast('Call declined', 'info');
    }

    cleanupCall(false);
  }

  // Handler: Peer accepted our outgoing call
  async function handleCallAccepted(data) {
    stopRingtone();
    callRingingModal.classList.add('hidden');

    createPeerConnectionInstance();
    openActiveCallModal();

    // Caller creates SDP Offer
    try {
      const offer = await peerConnection.createOffer({
        offerToReceiveAudio: true,
        offerToReceiveVideo: currentCallType === 'video'
      });
      await peerConnection.setLocalDescription(offer);

      socket.emit('webrtc:signal', {
        signal: offer,
        pin: currentPin
      });
    } catch (err) {
      console.error('Failed to create offer:', err);
      showToast('Call setup error', 'error');
    }
  }

  // Handler: Peer rejected our call
  function handleCallRejected(data) {
    stopRingtone();
    callRingingModal.classList.add('hidden');
    const msg = data.reason === 'busy' ? 'Peer is currently busy on another call.' : 'Peer declined the call.';
    showToast(msg, 'info');
    cleanupCall(false);
  }

  // Handler: Handle SDP signal (Offer or Answer)
  async function handleWebRtcSignal(data) {
    if (!peerConnection || !data || !data.signal) return;

    try {
      const signal = data.signal;
      if (signal.type === 'offer') {
        await peerConnection.setRemoteDescription(new RTCSessionDescription(signal));
        const answer = await peerConnection.createAnswer();
        await peerConnection.setLocalDescription(answer);

        socket.emit('webrtc:signal', {
          signal: answer,
          pin: currentPin
        });
      } else if (signal.type === 'answer') {
        await peerConnection.setRemoteDescription(new RTCSessionDescription(signal));
      }
    } catch (err) {
      console.error('Signal handling error:', err);
    }
  }

  // Handler: Handle remote ICE candidate
  async function handleRemoteIceCandidate(data) {
    if (!peerConnection || !data || !data.candidate) return;
    try {
      await peerConnection.addIceCandidate(new RTCIceCandidate(data.candidate));
    } catch (err) {
      console.warn('ICE candidate error:', err);
    }
  }

  // Handler: Peer ended call
  function handleCallEndedByPeer() {
    showToast('Peer ended the call', 'info');
    playTone('call_end');
    cleanupCall(false);
  }

  // Handler: Peer toggled camera or mic
  function handlePeerMediaState(data) {
    if (data.videoMuted) {
      remoteAvatarFallback.classList.remove('hidden');
    } else {
      remoteAvatarFallback.classList.add('hidden');
    }
  }

  // Open the Active Call Fullscreen Stage
  function openActiveCallModal() {
    isCallActive = true;
    isCallMinimized = false;
    activeCallTypeBadge.textContent = currentCallType === 'video' ? 'VIDEO CALL' : 'VOICE CALL';
    activeCallModal.classList.remove('hidden');
    activeCallModal.style.transform = 'none';
    startCallTimer();
  }

  // Action: End active call
  function endCall() {
    if (socket && currentPin) {
      socket.emit('call:end', { pin: currentPin });
    }
    playTone('call_end');
    cleanupCall(false);
    showToast('Call ended', 'info');
  }

  // Cleanup WebRTC call resources
  function cleanupCall(notifyPeer = true) {
    stopRingtone();
    stopCallTimer();

    if (notifyPeer && socket && currentPin && isCallActive) {
      socket.emit('call:end', { pin: currentPin });
    }

    if (localMediaStream) {
      localMediaStream.getTracks().forEach((track) => track.stop());
      localMediaStream = null;
    }

    if (peerConnection) {
      peerConnection.close();
      peerConnection = null;
    }

    localVideoElem.srcObject = null;
    remoteVideoElem.srcObject = null;

    isCallActive = false;
    isCaller = false;
    isCallMinimized = false;

    callRingingModal.classList.add('hidden');
    activeCallModal.classList.add('hidden');
  }

  // Action: Toggle microphone
  function toggleMicrophone() {
    if (!localMediaStream) return;
    const audioTrack = localMediaStream.getAudioTracks()[0];
    if (audioTrack) {
      audioTrack.enabled = !audioTrack.enabled;
      isAudioMuted = !audioTrack.enabled;
      updateMediaControlsUI();

      if (socket && currentPin) {
        socket.emit('call:media-state', {
          audioMuted: isAudioMuted,
          videoMuted: isVideoMuted,
          pin: currentPin
        });
      }
    }
  }

  // Action: Toggle camera
  function toggleCamera() {
    if (!localMediaStream) return;
    const videoTrack = localMediaStream.getVideoTracks()[0];
    if (videoTrack) {
      videoTrack.enabled = !videoTrack.enabled;
      isVideoMuted = !videoTrack.enabled;
      updateMediaControlsUI();
      updateMediaFallbackUI();

      if (socket && currentPin) {
        socket.emit('call:media-state', {
          audioMuted: isAudioMuted,
          videoMuted: isVideoMuted,
          pin: currentPin
        });
      }
    } else if (currentCallType === 'voice') {
      showToast('Voice call: Camera is inactive', 'info');
    }
  }

  // Action: Minimize / Expand active call overlay
  function toggleMinimizeCall() {
    isCallMinimized = !isCallMinimized;
    if (isCallMinimized) {
      activeCallModal.style.maxHeight = '80px';
      activeCallModal.style.top = '10px';
      activeCallModal.style.bottom = 'auto';
      btnCallMinimize.title = 'Expand call';
    } else {
      activeCallModal.style.maxHeight = '';
      activeCallModal.style.top = '0';
      activeCallModal.style.bottom = '0';
      btnCallMinimize.title = 'Minimize call';
    }
  }

  // Update button icons for mute/cam
  function updateMediaControlsUI() {
    if (isAudioMuted) {
      iconMicOn.classList.add('hidden');
      iconMicOff.classList.remove('hidden');
      btnToggleMic.classList.add('ctrl-disabled');
    } else {
      iconMicOn.classList.remove('hidden');
      iconMicOff.classList.add('hidden');
      btnToggleMic.classList.remove('ctrl-disabled');
    }

    if (isVideoMuted || currentCallType === 'voice') {
      iconCamOn.classList.add('hidden');
      iconCamOff.classList.remove('hidden');
      btnToggleVideo.classList.add('ctrl-disabled');
    } else {
      iconCamOn.classList.remove('hidden');
      iconCamOff.classList.add('hidden');
      btnToggleVideo.classList.remove('ctrl-disabled');
    }
  }

  // Update avatars fallback when camera is off
  function updateMediaFallbackUI() {
    if (isVideoMuted || currentCallType === 'voice') {
      localAvatarFallback.classList.remove('hidden');
    } else {
      localAvatarFallback.classList.add('hidden');
    }
  }

  // --- Bootstrap ---
  window.addEventListener('DOMContentLoaded', () => {
    applyTheme(currentTheme);
    setupPinDigitBoxes();
    setupEventListeners();
    initSocket();
  });
})();

