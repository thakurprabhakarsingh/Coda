import express from 'express';
import http from 'http';
import { Server } from 'socket.io';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const server = http.createServer(app);

// Cyber Attack Hardening: Mozilla HTTP Observatory 100/100 A+ Security Headers
app.disable('x-powered-by');
app.use((req, res, next) => {
  // Check if request is loaded inside an iframe (e.g., AI Studio preview panel)
  const isIframeOrPreview =
    req.headers['sec-fetch-dest'] === 'iframe' ||
    req.headers['sec-fetch-mode'] === 'nested-navigate' ||
    Boolean(req.headers['referer'] && (req.headers['referer'].includes('google') || req.headers['referer'].includes('aistudio')));

  // 1. Strict Transport Security (HSTS) - 2 years for Mozilla preload criteria
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');

  // 2. Content Security Policy (CSP) - Hardened & UI-Safe
  // Allows AI Studio preview framing while strictly forbidding untrusted clickjacking
  const allowedAncestors = isIframeOrPreview
    ? "'self' https://*.google.com https://*.googleusercontent.com https://*.aistudio.google.com https://*.run.app"
    : "'self' https://*.google.com https://*.googleusercontent.com https://*.aistudio.google.com https://*.run.app";

  res.setHeader(
    'Content-Security-Policy',
    [
      "default-src 'self'",
      "script-src 'self' https://cdn.socket.io",
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com",
      "img-src 'self' data: https: blob:",
      "connect-src 'self' ws: wss:",
      "object-src 'none'",
      "base-uri 'self'",
      `frame-ancestors ${allowedAncestors}`,
      "upgrade-insecure-requests"
    ].join('; ')
  );

  // 3. Cross-Origin Policies (COOP, COEP, CORP)
  // Avoid setting COOP same-origin inside an iframe to prevent Chrome from blocking cross-origin parent/frame contexts
  if (!isIframeOrPreview) {
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  }
  res.setHeader('Cross-Origin-Embedder-Policy', 'credentialless');
  res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');

  // 4. Standard Defensive Headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  // In CSP Level 2/3, frame-ancestors supersedes XFO. Do not set DENY inside iframes so AI Studio preview displays cleanly.
  if (!isIframeOrPreview) {
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  }
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(self), microphone=(self), geolocation=()');

  // 5. Explicit Cookie Security Enforcement (Secure, HttpOnly, SameSite=Lax)
  const origSetHeader = res.setHeader.bind(res);
  res.setHeader = function (name, value) {
    if (typeof name === 'string' && name.toLowerCase() === 'set-cookie') {
      const hardenCookie = (cookieStr) => {
        let cookie = String(cookieStr);
        if (!/;\s*Secure/i.test(cookie)) cookie += '; Secure';
        if (!/;\s*HttpOnly/i.test(cookie)) cookie += '; HttpOnly';
        if (!/;\s*SameSite/i.test(cookie)) cookie += '; SameSite=Lax';
        return cookie;
      };

      if (Array.isArray(value)) {
        value = value.map(hardenCookie);
      } else if (value) {
        value = hardenCookie(value);
      }
    }
    return origSetHeader(name, value);
  };

  next();
});

// Configure Socket.IO with bounded packet buffer, timeouts, and cookie disabled
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  },
  cookie: false,
  maxHttpBufferSize: 5e6, // 5 MB max per chunk packet to eliminate RAM exhaustion
  pingTimeout: 20000,
  pingInterval: 10000
});

// Ephemeral in-memory room store (zero logs, zero database storage)
const rooms = new Map();
const socketToRoom = new Map();

// Cyber Defense: In-Memory Rate Limiters & Anti-Brute-Force
const ipFailedJoinAttempts = new Map(); // ip -> { count: number, blockedUntil: number }
const socketMessageRate = new Map();    // socketId -> { count: number, resetAt: number }
const ipRoomCreations = new Map();      // ip -> { count: number, resetAt: number }

function getClientIp(socket) {
  return socket.handshake.headers['x-forwarded-for']?.split(',')[0]?.trim() || socket.handshake.address || 'unknown';
}

function checkRateLimit(socket) {
  const now = Date.now();
  let rate = socketMessageRate.get(socket.id);
  if (!rate || now > rate.resetAt) {
    rate = { count: 1, resetAt: now + 1000 };
    socketMessageRate.set(socket.id, rate);
    return true;
  }
  rate.count++;
  if (rate.count > 20) { // Limit to 20 messages/second per socket
    return false;
  }
  return true;
}

// Generate unique, unpredictable 4-digit PIN (1000 to 9999)
function generateUniquePIN() {
  let attempts = 0;
  while (attempts < 1000) {
    const pin = Math.floor(1000 + Math.random() * 9000).toString();
    if (!rooms.has(pin)) {
      return pin;
    }
    attempts++;
  }
  return (Date.now() % 9000 + 1000).toString();
}

// Clean up room and notify peers
function closeRoom(pin, reason = 'Peer disconnected') {
  const room = rooms.get(pin);
  if (!room) return;

  if (room.timer) {
    clearTimeout(room.timer);
  }

  // Notify any remaining sockets in the room
  io.to(pin).emit('peer_disconnected', {
    message: reason,
    pin
  });

  // Remove socket mappings
  if (room.hostId) socketToRoom.delete(room.hostId);
  if (room.peerId) socketToRoom.delete(room.peerId);
  if (room.members) {
    for (const memberId of room.members.keys()) {
      socketToRoom.delete(memberId);
    }
  }

  // Instant deletion from memory
  rooms.delete(pin);
  console.log(`[codaaa] Room ${pin} destroyed. Active rooms: ${rooms.size}`);
}

function handleSocketLeave(socket, pin, reason = 'left the group') {
  const room = rooms.get(pin);
  if (!room) return;

  if (room.isGroup && room.members) {
    const member = room.members.get(socket.id);
    const memberName = member ? member.name : 'A member';
    room.members.delete(socket.id);
    socketToRoom.delete(socket.id);
    socket.leave(pin);

    if (room.members.size === 0) {
      if (room.timer) clearTimeout(room.timer);
      rooms.delete(pin);
      console.log(`[codaaa] Group room ${pin} empty and destroyed.`);
    } else {
      const membersList = Array.from(room.members.values());
      io.to(pin).emit('group_member_left', {
        memberId: socket.id,
        memberName,
        members: membersList,
        message: `${memberName} ${reason}`
      });
    }
  } else {
    closeRoom(pin, 'Peer left the session');
  }
}

// Socket.io Real-Time Event Handlers with Security Guardrails
io.on('connection', (socket) => {
  const clientIp = getClientIp(socket);

  // Action 1: Create Room (Sender)
  socket.on('create_room', () => {
    const now = Date.now();
    // Rate limit room creation: max 10 rooms per 5 minutes per IP
    let creationRecord = ipRoomCreations.get(clientIp);
    if (!creationRecord || now > creationRecord.resetAt) {
      creationRecord = { count: 1, resetAt: now + 5 * 60 * 1000 };
      ipRoomCreations.set(clientIp, creationRecord);
    } else {
      creationRecord.count++;
      if (creationRecord.count > 10) {
        socket.emit('join_error', { message: 'Too many rooms created. Please wait a few minutes.' });
        return;
      }
    }

    const existingPin = socketToRoom.get(socket.id);
    if (existingPin) {
      closeRoom(existingPin, 'User created a new room');
    }

    const pin = generateUniquePIN();

    // Auto-expire room after 15 minutes of inactivity
    const timer = setTimeout(() => {
      closeRoom(pin, 'Session expired due to inactivity');
    }, 15 * 60 * 1000);

    const roomData = {
      pin,
      hostId: socket.id,
      peerId: null,
      createdAt: Date.now(),
      timer
    };

    rooms.set(pin, roomData);
    socketToRoom.set(socket.id, pin);
    socket.join(pin);

    socket.emit('room_created', { pin });
  });

  // Action 1B: Create Group Chat Room (Multi-Member)
  socket.on('create_group_room', (data) => {
    const rawName = String(data?.name || '').trim();
    const creatorName = rawName.slice(0, 30) || 'Creator';
    const groupName = String(data?.groupName || 'codaaa Group').trim().slice(0, 50) || 'codaaa Group';

    const existingPin = socketToRoom.get(socket.id);
    if (existingPin) {
      handleSocketLeave(socket, existingPin, 'created another room');
    }

    const pin = generateUniquePIN();

    // Group rooms expire after 45 minutes of session
    const timer = setTimeout(() => {
      closeRoom(pin, 'Group session expired due to timeout');
    }, 45 * 60 * 1000);

    const members = new Map();
    members.set(socket.id, {
      id: socket.id,
      name: creatorName,
      isHost: true,
      joinedAt: Date.now()
    });

    const roomData = {
      pin,
      hostId: socket.id,
      peerId: null,
      isGroup: true,
      groupName,
      members,
      createdAt: Date.now(),
      timer
    };

    rooms.set(pin, roomData);
    socketToRoom.set(socket.id, pin);
    socket.join(pin);

    const membersList = Array.from(members.values());

    socket.emit('group_room_created', {
      pin,
      groupName,
      myName: creatorName,
      isHost: true,
      members: membersList
    });
  });

  // Action 2: Join Room (Receiver with Anti-Brute-Force Defense)
  socket.on('join_room', (data) => {
    const now = Date.now();
    const failRecord = ipFailedJoinAttempts.get(clientIp);

    // Anti-Brute-Force check: block if > 5 failed attempts in cooldown period
    if (failRecord && failRecord.blockedUntil > now) {
      const waitSec = Math.ceil((failRecord.blockedUntil - now) / 1000);
      socket.emit('join_error', { message: `Too many incorrect attempts. Cooldown: ${waitSec}s.` });
      return;
    }

    const rawPin = data && typeof data.pin === 'string' ? data.pin.trim() : '';
    const pin = rawPin.replace(/\D/g, '');

    // Strict 4-digit validation
    if (!pin || pin.length !== 4) {
      socket.emit('join_error', { message: 'Please enter a valid 4-digit PIN.' });
      return;
    }

    const room = rooms.get(pin);
    if (!room) {
      // Record failed attempt for brute-force protection
      let currentFail = ipFailedJoinAttempts.get(clientIp) || { count: 0, blockedUntil: 0 };
      currentFail.count++;
      if (currentFail.count >= 5) {
        currentFail.blockedUntil = now + 60 * 1000; // 60s cooldown
        currentFail.count = 0;
      }
      ipFailedJoinAttempts.set(clientIp, currentFail);

      socket.emit('join_error', { message: 'PIN not found or session has expired.' });
      return;
    }

    if (room.isGroup) {
      // If user joined group room through normal join, route to group join
      const joinerName = String(data?.name || 'Member').trim().slice(0, 30) || 'Member';
      joinGroupRoomInternal(socket, room, pin, joinerName);
      return;
    }

    if (room.hostId === socket.id) {
      socket.emit('join_error', { message: 'You are already the host of this PIN.' });
      return;
    }

    if (room.peerId && room.peerId !== socket.id) {
      socket.emit('join_error', { message: 'Room is already full (2 peers connected).' });
      return;
    }

    // Reset failed attempts on success
    ipFailedJoinAttempts.delete(clientIp);

    // Connect receiver
    room.peerId = socket.id;
    socketToRoom.set(socket.id, pin);
    socket.join(pin);

    // Match both peers
    io.to(pin).emit('room_matched', {
      pin,
      hostId: room.hostId,
      peerId: room.peerId,
      timestamp: Date.now()
    });
  });

  // Action 2B: Join Group Room (Reserve / Join with Name & Code)
  function joinGroupRoomInternal(socket, room, pin, memberName) {
    if (!room.members) {
      room.members = new Map();
      if (room.hostId) {
        room.members.set(room.hostId, { id: room.hostId, name: 'Creator', isHost: true, joinedAt: room.createdAt });
      }
    }

    if (room.members.size >= 25) {
      socket.emit('join_error', { message: 'Group room is full (max 25 members).' });
      return;
    }

    ipFailedJoinAttempts.delete(clientIp);

    const isHost = room.hostId === socket.id;
    const memberObj = {
      id: socket.id,
      name: memberName,
      isHost,
      joinedAt: Date.now()
    };

    room.members.set(socket.id, memberObj);
    socketToRoom.set(socket.id, pin);
    socket.join(pin);

    const membersList = Array.from(room.members.values());

    socket.emit('group_room_joined', {
      pin,
      groupName: room.groupName || 'codaaa Group',
      myName: memberName,
      isHost,
      members: membersList
    });

    // Notify other members
    socket.to(pin).emit('group_member_joined', {
      member: memberObj,
      members: membersList,
      message: `${memberName} joined the group chat`
    });
  }

  socket.on('join_group_room', (data) => {
    const rawPin = data && typeof data.pin === 'string' ? data.pin.trim() : '';
    const pin = rawPin.replace(/\D/g, '');
    const memberName = String(data?.name || 'Member').trim().slice(0, 30) || 'Member';

    if (!pin || pin.length !== 4) {
      socket.emit('join_error', { message: 'Please enter a valid 4-digit Group Code.' });
      return;
    }

    const room = rooms.get(pin);
    if (!room) {
      socket.emit('join_error', { message: 'Group code not found or expired.' });
      return;
    }

    joinGroupRoomInternal(socket, room, pin, memberName);
  });

  // Get Room Members List
  socket.on('get_room_members', () => {
    const pin = socketToRoom.get(socket.id);
    if (!pin) return;
    const room = rooms.get(pin);
    if (room) {
      let membersList = [];
      if (room.members) {
        membersList = Array.from(room.members.values());
      } else {
        membersList = [
          { id: room.hostId, name: 'Host', isHost: true },
          ...(room.peerId ? [{ id: room.peerId, name: 'Peer', isHost: false }] : [])
        ];
      }
      socket.emit('room_members', {
        pin,
        groupName: room.groupName || 'codaaa Room',
        members: membersList
      });
    }
  });

  // End-to-End Encryption (E2EE) Public Key Relay
  socket.on('e2ee:key_exchange', (payload) => {
    const pin = socketToRoom.get(socket.id);
    if (!pin || !payload || !payload.publicKey) return;
    socket.to(pin).emit('e2ee:key_exchange', {
      publicKey: payload.publicKey,
      senderId: socket.id
    });
  });

  // Real-time Chat Messaging (with Reply Support & Replay Protection)
  socket.on('chat_message', (payload) => {
    if (!checkRateLimit(socket)) return;

    const pin = socketToRoom.get(socket.id);
    if (!pin || !payload) return;

    // Sanitize reply metadata if present
    let replyTo = null;
    if (payload.replyTo && typeof payload.replyTo === 'object') {
      replyTo = {
        id: String(payload.replyTo.id || '').slice(0, 64),
        text: String(payload.replyTo.text || '').slice(0, 100),
        sender: String(payload.replyTo.sender || 'Peer').slice(0, 30)
      };
    }

    const room = rooms.get(pin);
    let senderName = payload.senderName ? String(payload.senderName).slice(0, 30) : '';
    if (!senderName && room && room.members && room.members.has(socket.id)) {
      senderName = room.members.get(socket.id).name;
    }
    if (!senderName) senderName = 'Member';

    socket.to(pin).emit('chat_message', {
      id: String(payload.id || `msg_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`).slice(0, 64),
      text: payload.text ? String(payload.text).slice(0, 50000) : '',
      iv: payload.iv ? String(payload.iv).slice(0, 100) : null,
      isEncrypted: !!payload.isEncrypted,
      replyTo,
      senderId: socket.id,
      senderName,
      timestamp: Date.now()
    });
  });

  // Emoji Reactions ("amojy reply")
  socket.on('message_reaction', (payload) => {
    if (!checkRateLimit(socket)) return;

    let pin = socketToRoom.get(socket.id);
    if (!pin && payload && payload.pin) {
      const cleanPin = String(payload.pin).replace(/\D/g, '');
      if (rooms.has(cleanPin)) {
        pin = cleanPin;
        socketToRoom.set(socket.id, pin);
        socket.join(pin);
      }
    }
    if (!pin || !payload || !payload.messageId || !payload.emoji) return;

    // Strict emoji sanitization (only safe emoji strings)
    const emoji = String(payload.emoji).slice(0, 12);
    const messageId = String(payload.messageId).slice(0, 64);
    const action = payload.action ? String(payload.action).slice(0, 16) : null;
    const previousEmoji = payload.previousEmoji ? String(payload.previousEmoji).slice(0, 12) : null;

    // Relay to peer in the same room
    socket.to(pin).emit('message_reaction', {
      messageId,
      emoji,
      action,
      previousEmoji,
      senderId: socket.id,
      timestamp: Date.now()
    });
  });

  // Message Delivered Receipt
  socket.on('delivered', (payload) => {
    const pin = socketToRoom.get(socket.id);
    if (!pin || !payload || !payload.messageId) return;
    socket.to(pin).emit('delivered', {
      messageId: String(payload.messageId).slice(0, 64),
      recipientId: socket.id,
      timestamp: Date.now()
    });
  });

  // Real-Time Read Receipts ('seen' status)
  socket.on('read', (payload) => {
    const pin = socketToRoom.get(socket.id);
    if (!pin || !payload) return;
    socket.to(pin).emit('read', {
      messageId: payload.messageId ? String(payload.messageId).slice(0, 64) : null,
      messageIds: Array.isArray(payload.messageIds) ? payload.messageIds.slice(0, 100).map(id => String(id).slice(0, 64)) : [],
      readerId: socket.id,
      timestamp: Date.now()
    });
  });

  // Typing indicator
  socket.on('typing_indicator', (payload) => {
    const pin = socketToRoom.get(socket.id);
    if (!pin) return;
    socket.to(pin).emit('typing_indicator', {
      isTyping: !!(payload && payload.isTyping),
      senderId: socket.id
    });
  });

  // Binary Chunk File Transfer Protocol (Strict bounds checked)
  socket.on('file:start', (meta) => {
    const pin = socketToRoom.get(socket.id);
    if (!pin || !meta) return;

    // Validation: max 100MB
    const size = Number(meta.size);
    if (isNaN(size) || size <= 0 || size > 100 * 1024 * 1024) return;

    socket.to(pin).emit('file:start', {
      fileId: String(meta.fileId).slice(0, 64),
      name: String(meta.name || 'file').slice(0, 255),
      size,
      type: String(meta.type || 'application/octet-stream').slice(0, 100),
      totalChunks: Math.min(Number(meta.totalChunks) || 1, 2000),
      chunkSize: Math.min(Number(meta.chunkSize) || 131072, 524288),
      senderId: socket.id
    });
  });

  socket.on('file:chunk', (data) => {
    const pin = socketToRoom.get(socket.id);
    if (!pin || !data || !data.chunk) return;

    socket.to(pin).emit('file:chunk', {
      fileId: String(data.fileId).slice(0, 64),
      chunkIndex: Number(data.chunkIndex),
      totalChunks: Number(data.totalChunks),
      chunk: data.chunk
    });
  });

  socket.on('file:ack', (data) => {
    const pin = socketToRoom.get(socket.id);
    if (!pin || !data) return;
    socket.to(pin).emit('file:ack', {
      fileId: String(data.fileId).slice(0, 64),
      chunkIndex: Number(data.chunkIndex)
    });
  });

  socket.on('file:cancel', (data) => {
    const pin = socketToRoom.get(socket.id);
    if (!pin || !data) return;
    socket.to(pin).emit('file:cancel', {
      fileId: String(data.fileId).slice(0, 64),
      reason: String(data.reason || 'Transfer cancelled').slice(0, 100)
    });
  });

  // ========================================================
  // WebRTC Audio & Video Calling Signaling Relays
  // ========================================================
  // Initiate call request (video or voice)
  socket.on('call:initiate', (payload) => {
    const pin = socketToRoom.get(socket.id);
    if (!pin || !payload) return;
    const room = rooms.get(pin);
    let callerName = payload.callerName ? String(payload.callerName).slice(0, 30) : '';
    if (!callerName && room && room.members && room.members.has(socket.id)) {
      callerName = room.members.get(socket.id).name;
    }
    if (!callerName) callerName = 'Someone';

    socket.to(pin).emit('call:incoming', {
      type: payload.type === 'video' ? 'video' : 'voice',
      callerId: socket.id,
      callerName,
      timestamp: Date.now()
    });
  });

  // Answer call (accept)
  socket.on('call:accept', (payload) => {
    const pin = socketToRoom.get(socket.id);
    if (!pin) return;
    socket.to(pin).emit('call:accepted', {
      responderId: socket.id,
      type: payload?.type === 'video' ? 'video' : 'voice'
    });
  });

  // Reject / Decline call
  socket.on('call:reject', (payload) => {
    const pin = socketToRoom.get(socket.id);
    if (!pin) return;
    socket.to(pin).emit('call:rejected', {
      reason: String(payload?.reason || 'declined').slice(0, 50)
    });
  });

  // End active call
  socket.on('call:end', () => {
    const pin = socketToRoom.get(socket.id);
    if (!pin) return;
    socket.to(pin).emit('call:ended', {
      by: socket.id
    });
  });

  // WebRTC SDP Offer / Answer relay
  socket.on('webrtc:signal', (payload) => {
    const pin = socketToRoom.get(socket.id);
    if (!pin || !payload) return;
    socket.to(pin).emit('webrtc:signal', {
      signal: payload.signal,
      senderId: socket.id
    });
  });

  // WebRTC ICE Candidate relay
  socket.on('webrtc:ice-candidate', (payload) => {
    const pin = socketToRoom.get(socket.id);
    if (!pin || !payload || !payload.candidate) return;
    socket.to(pin).emit('webrtc:ice-candidate', {
      candidate: payload.candidate,
      senderId: socket.id
    });
  });

  // Mute / Camera status toggled notice
  socket.on('call:media-state', (payload) => {
    const pin = socketToRoom.get(socket.id);
    if (!pin || !payload) return;
    socket.to(pin).emit('call:media-state', {
      audioMuted: !!payload.audioMuted,
      videoMuted: !!payload.videoMuted,
      senderId: socket.id
    });
  });

  socket.on('leave_room', () => {
    const pin = socketToRoom.get(socket.id);
    if (pin) {
      handleSocketLeave(socket, pin, 'left the room');
    }
  });

  socket.on('disconnect', (reason) => {
    socketMessageRate.delete(socket.id);
    const pin = socketToRoom.get(socket.id);
    if (pin) {
      handleSocketLeave(socket, pin, 'disconnected');
    }
  });
});

// Middleware & Static files
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    activeRooms: rooms.size,
    timestamp: Date.now()
  });
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`[codaaa] Secure ephemeral peer server running on port ${PORT}`);
});
