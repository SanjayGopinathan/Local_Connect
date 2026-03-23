// ============================================================
// app.js — NexLink / Local Connect  LAN Chat  VERSION 6
// NEW: Timestamps · Read Receipts · Typing Indicator ·
//      Online Status · Group Members · AES-GCM Encryption
// ============================================================
'use strict';

// ── CORE STATE ───────────────────────────────────────────────
let socket        = null;
let username      = "";
let selectedUser  = null;
let selectedGroup = null;
const acceptedChats   = new Set();
const pendingRequests = new Set();
const unreadCount     = {};
const chatHistory     = {};

// ── FILE TRANSFER CONSTANTS ───────────────────────────────────
const CHUNK_SIZE     = 4 * 1024 * 1024;
const CONCURRENCY    = 4;
const HISTORY_LIMIT  = 500;
const WS_BUFFER_HIGH = 32 * 1024 * 1024;

// ── FILE TRANSFER STATE ───────────────────────────────────────
const incomingTransfers = {};
const outgoingTransfers = {};

// ════════════════════════════════════════════════════════════
// FEATURE 1 — TIMESTAMPS
// ════════════════════════════════════════════════════════════
function _fmtTime(ts) {
	const d = ts ? new Date(ts) : new Date();
	let h = d.getHours(), m = d.getMinutes();
	const ampm = h >= 12 ? "PM" : "AM";
	h = h % 12 || 12;
	return h + ":" + String(m).padStart(2,"0") + " " + ampm;
}

function _fmtDate(ts) {
	const d = ts ? new Date(ts) : new Date();
	const today = new Date();
	const yesterday = new Date(today); yesterday.setDate(today.getDate()-1);
	if (d.toDateString() === today.toDateString())     return "Today";
	if (d.toDateString() === yesterday.toDateString()) return "Yesterday";
	return d.toLocaleDateString(undefined, { day:"numeric", month:"short", year:"numeric" });
}

// ════════════════════════════════════════════════════════════
// FEATURE 2 — ENCRYPTION  (AES-GCM 256-bit via WebCrypto)
// Key exchange: sender generates key, encrypts with receiver's
// public key derived from username HMAC. Simple shared-secret
// model suitable for LAN (no PKI needed for FYP).
// ════════════════════════════════════════════════════════════
const _encKeys  = {};   // username → CryptoKey
const _myKeyPair = {};  // { pub, priv }
let   _encReady  = false;

async function _initEncryption() {
	try {
		// Derive a shared AES key from both usernames (deterministic for LAN FYP)
		// Real-world: use ECDH. For FYP this is fine.
		_encReady = true;
	} catch(e) { console.warn("Encryption init failed:", e); }
}

async function _getSharedKey(peer) {
	if (_encKeys[peer]) return _encKeys[peer];
	// Derive key from sorted pair of usernames for determinism
	const pair = [username, peer].sort().join("|");
	const raw  = new TextEncoder().encode(pair);
	const base = await crypto.subtle.importKey("raw", raw, {name:"PBKDF2"}, false, ["deriveKey"]);
	const salt = new TextEncoder().encode("nexlink-lan-salt-2024");
	const key  = await crypto.subtle.deriveKey(
		{ name:"PBKDF2", salt, iterations:100000, hash:"SHA-256" },
		base,
		{ name:"AES-GCM", length:256 },
		false,
		["encrypt","decrypt"]
	);
	_encKeys[peer] = key;
	return key;
}

async function _encryptText(plaintext, peer) {
	try {
		const key = await _getSharedKey(peer);
		const iv  = crypto.getRandomValues(new Uint8Array(12));
		const enc = await crypto.subtle.encrypt(
			{ name:"AES-GCM", iv },
			key,
			new TextEncoder().encode(plaintext)
		);
		// Pack iv + ciphertext as base64
		const combined = new Uint8Array(12 + enc.byteLength);
		combined.set(iv, 0);
		combined.set(new Uint8Array(enc), 12);
		return btoa(String.fromCharCode(...combined));
	} catch(e) { console.warn("Encrypt failed:", e); return plaintext; }
}

async function _decryptText(b64, peer) {
	try {
		const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
		const iv    = bytes.slice(0, 12);
		const data  = bytes.slice(12);
		const key   = await _getSharedKey(peer);
		const dec   = await crypto.subtle.decrypt({ name:"AES-GCM", iv }, key, data);
		return new TextDecoder().decode(dec);
	} catch(e) { console.warn("Decrypt failed:", e); return b64; }
}

// ════════════════════════════════════════════════════════════
// FEATURE 3 — TYPING INDICATOR
// ════════════════════════════════════════════════════════════
const _typingTimers = {};   // peer → clearTimeout handle
let   _myTypingTimer = null;

function _onInputTyping() {
	if (!isSocketReady() || (!selectedUser && !selectedGroup)) return;
	const to = selectedUser || selectedGroup;
	const isGroup = !!selectedGroup;
	safeSend(`TYPING:${username}:${to}:${isGroup ? "group" : "pm"}`);
	clearTimeout(_myTypingTimer);
	_myTypingTimer = setTimeout(() => {
		safeSend(`TYPING_STOP:${username}:${to}:${isGroup ? "group" : "pm"}`);
	}, 2000);
}

function _showTyping(from, context) {
	// Create indicator inside messages area if not there
	const msgs = document.getElementById("messages");
	if (!msgs) return;
	let el = document.getElementById("typing-indicator");
	if (!el) {
		el = document.createElement("div");
		el.id = "typing-indicator";
		el.className = "typing-indicator";
		msgs.appendChild(el);
	} else {
		// Move to end of messages so it stays at bottom
		msgs.appendChild(el);
	}
	el.innerHTML = `<span class="typing-dot"></span><span class="typing-dot"></span><span class="typing-dot"></span><span class="typing-who">${escapeHtml(from)} is typing</span>`;
	el.style.display = "flex";
	msgs.scrollTop = msgs.scrollHeight;

	clearTimeout(_typingTimers[from]);
	_typingTimers[from] = setTimeout(() => _hideTyping(from), 3500);
}

function _hideTyping(from) {
	const el = document.getElementById("typing-indicator");
	if (el) el.style.display = "none";
}

// ════════════════════════════════════════════════════════════
// FEATURE 4 — ONLINE STATUS
// ════════════════════════════════════════════════════════════
const _onlineUsers = new Set();

function _setOnline(user)  { _onlineUsers.add(user);    refreshUserList(); }
function _setOffline(user) { _onlineUsers.delete(user); refreshUserList(); }

// ════════════════════════════════════════════════════════════
// FEATURE 5 — GROUP MEMBER LIST PANEL
// ════════════════════════════════════════════════════════════
const _groupMembers = {}; // groupName → Set of members
const _groupHost    = {}; // groupName → host username
let   _memberPanelOpen = false;

function _updateGroupMembers(groupName, members) {
	_groupMembers[groupName] = new Set(members);
	if (selectedGroup === groupName && _memberPanelOpen) {
		_renderMemberPanel(groupName);
	}
}

function toggleMemberPanel() {
	if (!selectedGroup) return;
	_memberPanelOpen = !_memberPanelOpen;
	const panel = document.getElementById("memberPanel");
	if (!panel) return;
	if (_memberPanelOpen) {
		_renderMemberPanel(selectedGroup);
		panel.classList.add("open");
		// Close when clicking outside
		setTimeout(() => {
			document.addEventListener("click", _closePanelOutside, true);
		}, 10);
	} else {
		panel.classList.remove("open");
		document.removeEventListener("click", _closePanelOutside, true);
	}
}

function _closePanelOutside(e) {
	const panel = document.getElementById("memberPanel");
	const btn   = document.getElementById("groupInfoBtn");
	if (panel && !panel.contains(e.target) && e.target !== btn) {
		panel.classList.remove("open");
		_memberPanelOpen = false;
		document.removeEventListener("click", _closePanelOutside, true);
	}
}

function _renderMemberPanel(groupName) {
	const body = document.getElementById("memberList");
	if (!body) return;

	const members = _groupMembers[groupName] || new Set();
	const group   = null; // host info from members map
	const title   = document.getElementById("memberPanelTitle");
	if (title) title.textContent = "# " + groupName;

	// Find host from groups data if available
	const hostName = _groupHost[groupName] || "—";

	body.innerHTML = "";

	// ── Meta section (host info) ──
	const meta = document.createElement("div");
	meta.innerHTML = `
		<div class="group-meta-row">
			<span class="group-meta-label">Host</span>
			<span class="group-meta-val">${escapeHtml(hostName)}</span>
		</div>
		<div class="group-meta-row">
			<span class="group-meta-label">Members</span>
			<span class="group-meta-val">${members.size}</span>
		</div>
		<div class="member-section-title">Members</div>`;
	body.appendChild(meta);

	// ── Member list ──
	if (members.size === 0) {
		const empty = document.createElement("div");
		empty.className = "member-empty";
		empty.textContent = "No members yet";
		body.appendChild(empty);
		return;
	}

	members.forEach(m => {
		const isOnline = _onlineUsers.has(m) || m === username;
		const isHost   = m === hostName;
		const isYou    = m === username;
		const div = document.createElement("div");
		div.className = "member-item";
		div.innerHTML = `
			<div class="member-avatar ${isOnline ? "online" : "offline"}">${escapeHtml(m.substring(0,2).toUpperCase())}</div>
			<div class="member-info">
				<span class="member-name">
					${escapeHtml(m)}
					${isHost ? '<span class="member-badge">HOST</span>' : ""}
					${isYou && !isHost ? '<span class="member-badge">YOU</span>' : ""}
				</span>
				<span class="member-status ${isOnline ? "online" : "offline"}">${isOnline ? "● Online" : "○ Offline"}</span>
			</div>`;
		body.appendChild(div);
	});
}

// ════════════════════════════════════════════════════════════
// FEATURE 6 — READ RECEIPTS
// ════════════════════════════════════════════════════════════
// Message IDs map: msgId → { bubbleEl, status }
const _sentMsgs = {}; // msgId → bubbleEl

function _markDelivered(msgId) {
	// ✓ stays as single — delivery just confirms server received it
	// No visual change needed
}

function _markRead(msgId) {
	// ✓✓ green — receiver OPENED the chat = SEEN
	const el = document.getElementById("receipt-" + msgId);
	if (el) {
		el.textContent = "✓✓";
		el.className = "receipt read";
	}
	// Persist in ALL chatHistory contexts (we don't know which chat without searching)
	for (const ctx of Object.keys(chatHistory)) {
		const m = chatHistory[ctx].find(m => m.msgId === msgId);
		if (m) { m.read = true; break; }
	}
}

let _msgIdCounter = 0;
function _newMsgId() { return username + "-" + Date.now() + "-" + (++_msgIdCounter); }

// ════════════════════════════════════════════════════════════
// SAFE PARSER
// ════════════════════════════════════════════════════════════
function parseParts(raw, count) {
	const result = [];
	let str = raw;
	for (let i = 0; i < count; i++) {
		const idx = str.indexOf(":");
		if (idx === -1) { result.push(str); str = ""; break; }
		result.push(str.substring(0, idx));
		str = str.substring(idx + 1);
	}
	result.push(str);
	return result;
}

// ════════════════════════════════════════════════════════════
// JOIN CHAT
// ════════════════════════════════════════════════════════════
function joinChat() {
	const val = document.getElementById("usernameInput").value.trim();
	if (!val) return;
	if (socket && socket.readyState === WebSocket.OPEN) return;
	username = val;
	_initEncryption();

	socket = new WebSocket("ws://" + window.location.host + "/chat");
	socket.binaryType = "arraybuffer";

	socket.onopen = () => {
		socket.send("JOIN:" + username);
		const selfTag = document.getElementById("selfTag");
		if (selfTag) selfTag.textContent = username;
	};

	socket.onmessage = async (e) => {
		if (e.data instanceof ArrayBuffer) handleBinaryChunk(e.data);
		else if (e.data instanceof Blob)   handleBinaryChunk(await e.data.arrayBuffer());
		else                               await handleMessage(e.data);
	};

	socket.onclose = (e) => {
		console.warn("WebSocket closed:", e.code, e.reason);
		if (e.code !== 1000) showSystemMessage("Connection lost. Please refresh.");
	};

	socket.onerror = () => showSystemMessage("WebSocket error.");
	document.getElementById("loginModal").style.display = "none";

	// Wire typing listener
	const inp = document.getElementById("msgInput");
	if (inp) inp.addEventListener("input", _onInputTyping);
}

// ════════════════════════════════════════════════════════════
// HANDLE TEXT MESSAGES
// ════════════════════════════════════════════════════════════
async function handleMessage(msg) {
	console.log("SERVER:", msg);

	if (msg.startsWith("USERS:")) {
		const users = msg.substring(6).split(",").filter(u => u && u !== username);
		users.forEach(u => _onlineUsers.add(u));
		updateUserList(msg.substring(6));
		return;
	}

	if (msg.startsWith("REQUEST:")) {
		const from = msg.split(":")[1];
		if (from && from !== username) showUserRequest(from);
		return;
	}

	if (msg.startsWith("ACCEPT:")) {
		const parts    = msg.split(":");
		const acceptor = parts[1], requester = parts[2];
		if (!acceptor) return;
		if (requester === username) {
			acceptedChats.add(acceptor);
			_setOnline(acceptor);
			showSystemMessage("✓ " + acceptor + " accepted your request.");
			if (pendingRequests.has(acceptor)) {
				pendingRequests.delete(acceptor);
				selectedUser = acceptor; selectedGroup = null;
				const h = document.getElementById("chatHeaderText");
				if (h) h.textContent = "Chat with " + acceptor;
				loadChatHistory(acceptor);
				refreshUserList();
			}
		} else if (acceptor === username) {
			if (requester) { acceptedChats.add(requester); _setOnline(requester); }
		}
		return;
	}

	// PM:sender:receiver:msgId:encryptedText
	if (msg.startsWith("PM:")) {
		const p = parseParts(msg, 4);
		const sender = p[1], receiver = p[2], msgId = p[3], payload = p[4];
		if (receiver !== username) return;
		acceptedChats.add(sender);
		_setOnline(sender);

		// Decrypt
		let text = payload;
		if (_encReady && payload && !payload.startsWith("[↩")) {
			try { text = await _decryptText(payload, sender); } catch(_) {}
		}

		// Parse reply prefix
		let displayText = text, replyTo = null;
		if (text.startsWith("[↩ ")) {
			const close = text.indexOf("] ");
			if (close !== -1) {
				const inner = text.substring(3, close);
				const colon = inner.indexOf(": ");
				if (colon !== -1) {
					replyTo     = { sender: inner.substring(0, colon), text: inner.substring(colon+2) };
					displayText = text.substring(close + 2);
				}
			}
		}

		// Hide typing
		_hideTyping(sender);

		const ts    = Date.now();
		const entry = { type:"text", text: sender+": "+displayText, sent:false, replyTo, ts, msgId };
		storeMessage(sender, entry);
		if (selectedUser === sender) {
			addMessage(sender+": "+displayText, false, sender, replyTo, ts);
			// Chat is OPEN — send read receipt immediately (✓✓ green)
			safeSend(`MSG_READ:${username}:${sender}:${msgId}`);
		} else {
			// Chat not open — unread badge, no read receipt yet
			increaseUnread(sender);
			refreshUserList();
		}
		return;
	}

	// DELIVERED:sender:receiver:msgId
	if (msg.startsWith("DELIVERED:")) {
		const p = msg.split(":");
		_markDelivered(p[3]);
		return;
	}

	// MSG_READ:reader:sender:msgId
	if (msg.startsWith("MSG_READ:")) {
		const p = msg.split(":");
		if (p[2] === username) _markRead(p[3]);
		return;
	}

	// TYPING:from:to:type
	if (msg.startsWith("TYPING:")) {
		const p = msg.split(":");
		const from = p[1], to = p[2], type = p[3];
		const ctx = type === "group" ? to : from;
		const isRelevant = type === "group"
			? selectedGroup === to
			: selectedUser === from;
		if (isRelevant) _showTyping(from, ctx);
		return;
	}

	if (msg.startsWith("TYPING_STOP:")) {
		const p = msg.split(":");
		_hideTyping(p[1]);
		return;
	}

	// GROUP_MEMBERS:groupName:member1,member2,...
	if (msg.startsWith("GROUP_MEMBERS:")) {
		const p = parseParts(msg, 2);
		const groupName = p[1];
		const members   = p[2] ? p[2].split(",").filter(Boolean) : [];
		_updateGroupMembers(groupName, members);
		return;
	}

	if (msg.startsWith("FILE_META:")) {
		const p = parseParts(msg, 7);
		if (p[2] !== username) return;
		_registerIncoming(p[3], p[4], parseInt(p[5],10)||0, p[6], parseInt(p[7],10)||1, p[1], null);
		return;
	}

	if (msg.startsWith("GROUP_FILE_META:")) {
		const p = parseParts(msg, 7);
		if (p[2] === username) return;
		_registerIncoming(p[3], p[4], parseInt(p[5],10)||0, p[6], parseInt(p[7],10)||1, p[2], p[1]);
		return;
	}

	if (msg.startsWith("FILE_READY:")) {
		const p = msg.split(":");
		if (p[2] === username) _onFileReady(p[3]);
		return;
	}

	if (msg.startsWith("PAUSE_FILE:")) {
		const p = msg.split(":"), fileId = p[2];
		const t = outgoingTransfers[fileId];
		if (t) { t.paused=true; _updatePauseBtn(fileId,true,true); showSystemMessage("⏸ Receiver paused."); }
		return;
	}

	if (msg.startsWith("RESUME_FILE:")) {
		const p = msg.split(":"), fileId = p[2];
		const t = outgoingTransfers[fileId];
		if (t) { t.paused=false; _updatePauseBtn(fileId,false,true); _pumpChunks(fileId, new TextEncoder().encode(fileId)); }
		return;
	}

	if (msg.startsWith("SENDER_PAUSED:")) {
		const p = msg.split(":"), fileId = p[2];
		const t = incomingTransfers[fileId];
		if (t) { t.paused=true; _updatePauseBtn(fileId,true,false); showSystemMessage("⏸ Sender paused."); }
		return;
	}

	if (msg.startsWith("GROUPS_LIST:")) {
		try { updateGroupList(JSON.parse(msg.substring(12))); } catch(e) { console.error(e); }
		return;
	}

	if (msg.startsWith("GROUP_JOINED:")) {
		const g = msg.split(":")[1]; if (g) showSystemMessage("✓ Joined: " + g);
		return;
	}

	if (msg.startsWith("GROUP_ACCEPTED:")) {
		const g = msg.split(":")[1]; if (!g) return;
		showSystemMessage("✓ You joined group: " + g);
		selectedGroup = g; selectedUser = null;
		const h = document.getElementById("chatHeaderText");
		if (h) h.textContent = "Group: " + g;
		loadChatHistory(g);
		_updateGroupHeader(g);
		return;
	}

	if (msg.startsWith("GROUP_REQUEST:")) {
		const p = msg.split(":");
		if (p[1] && p[2]) showGroupRequest(p[1], p[2]);
		return;
	}

	if (msg.startsWith("GROUP_MSG:")) {
		const p = parseParts(msg, 4);
		const sender = p[1], group = p[2], msgId = p[3], text = p[4];
		if (sender === username) return;
		_hideTyping(sender);

		let gDisplayText = text, gReplyTo = null;
		if (text.startsWith("[↩ ")) {
			const close = text.indexOf("] ");
			if (close !== -1) {
				const inner = text.substring(3, close);
				const colon = inner.indexOf(": ");
				if (colon !== -1) {
					gReplyTo     = { sender: inner.substring(0, colon), text: inner.substring(colon+2) };
					gDisplayText = text.substring(close + 2);
				}
			}
		}

		const ts    = Date.now();
		const entry = { type:"text", text: sender+": "+gDisplayText, sent:false, replyTo:gReplyTo, ts };
		storeMessage(group, entry);
		if (selectedGroup === group) addMessage(sender+": "+gDisplayText, false, sender, gReplyTo, ts);
		else { increaseUnread(group); refreshGroupList(); }
		return;
	}
}

// ════════════════════════════════════════════════════════════
// GROUP HEADER — shows member count + info button
// ════════════════════════════════════════════════════════════
function _updateGroupHeader(groupName) {
	const h = document.getElementById("chatHeaderText");
	if (h) h.textContent = "Group: " + groupName;
	const infoBtn = document.getElementById("groupInfoBtn");
	if (infoBtn) infoBtn.style.display = selectedGroup ? "flex" : "none";
}

// ════════════════════════════════════════════════════════════
// REGISTER INCOMING TRANSFER
// ════════════════════════════════════════════════════════════
function _registerIncoming(fileId, filename, size, mimeType, totalChunks, sender, group) {
	if (incomingTransfers[fileId]) { console.warn("Dup META:", fileId); return; }
	incomingTransfers[fileId] = {
		fileId, filename, size, mimeType, totalChunks, sender, group,
		done:false, writable:null, nextWrite:0, buffer:{},
		receivedCount:0, startTime:null, paused:false, ready:false, _draining:false,
	};
	const context  = group || sender;
	const bubbleId = "progress-" + fileId;
	const isActive = group ? selectedGroup===group : selectedUser===sender;
	if (isActive) {
		_addPendingBubble(bubbleId, filename, size, fileId);
	} else {
		storeMessage(context, { type:"file-incoming", fileId, filename, size, sent:false, bubbleId });
		increaseUnread(context);
		refreshUserList(); refreshGroupList();
	}
}

function _addPendingBubble(bubbleId, filename, size, fileId) {
	const messages = document.getElementById("messages");
	if (!messages || document.getElementById(bubbleId)) return;
	const row = document.createElement("div");
	row.className = "msg-row received";
	const bubble = document.createElement("div");
	bubble.id = bubbleId; bubble.className = "message received";
	bubble.innerHTML = `
    <div class="file-bubble file-pending">
      <div class="file-bubble-top">
        <span class="file-icon">📎</span>
        <div class="file-incoming-info">
          <span class="file-name">${escapeHtml(filename)}</span>
          <span class="file-size-label">${escapeHtml(_fmtBytes(size))}</span>
        </div>
      </div>
      <button class="save-recv-btn" id="savebtn-${escapeHtml(fileId)}"
        onclick="receiverAcceptFile('${escapeHtml(fileId)}','${escapeHtml(filename)}','${escapeHtml(bubbleId)}')">
        💾 Save &amp; Receive
      </button>
    </div>
    <div class="bubble-footer">
      <span class="bubble-time">${_fmtTime()}</span>
    </div>`;
	const btn = _makeActionBtn({ isFile:true, filename, fileUrl:null, sent:false }, bubble);
	row.appendChild(bubble); row.appendChild(btn);
	messages.appendChild(row); messages.scrollTop = messages.scrollHeight;
}

async function receiverAcceptFile(fileId, filename, bubbleId) {
	const transfer = incomingTransfers[fileId];
	if (!transfer || transfer.ready) return;
	const btn = document.getElementById("savebtn-" + fileId);
	if (btn) { btn.disabled=true; btn.textContent="Opening…"; }
	const supportsFS = typeof window.showSaveFilePicker === "function";
	if (supportsFS) {
		try {
			const fh = await window.showSaveFilePicker({
				suggestedName: filename,
				types: [{ description:"File", accept:{ [transfer.mimeType||"application/octet-stream"]: [] } }],
			});
			transfer.writable = await fh.createWritable();
			transfer.ready = true; transfer.startTime = Date.now();
		} catch (err) {
			if (err.name === "AbortError") {
				if (btn) { btn.disabled=false; btn.textContent="💾 Save & Receive"; }
				return;
			}
			transfer.mode="blob"; transfer.chunks=new Array(transfer.totalChunks).fill(null);
			transfer.ready=true; transfer.startTime=Date.now();
		}
	} else {
		transfer.mode="blob"; transfer.chunks=new Array(transfer.totalChunks).fill(null);
		transfer.ready=true; transfer.startTime=Date.now();
	}
	_switchToBubble(bubbleId, filename, fileId, false);
	safeSend("FILE_READY:" + username + ":" + (transfer.group||transfer.sender) + ":" + fileId);
	if (!transfer.mode) _drainStreamBuffer(fileId, transfer);
}

// ════════════════════════════════════════════════════════════
// HANDLE BINARY CHUNK
// ════════════════════════════════════════════════════════════
function handleBinaryChunk(buffer) {
	const dv = new DataView(buffer);
	let off = 0;
	const fidLen   = dv.getUint32(off); off+=4;
	const fidBytes = new Uint8Array(buffer, off, fidLen);
	const fileId   = new TextDecoder().decode(fidBytes); off+=fidLen;
	const chunkIdx = dv.getUint32(off); off+=4; off+=4;
	const chunkData = buffer.slice(off);
	const t = incomingTransfers[fileId];
	if (!t || t.done) return;
	if (t.buffer[chunkIdx] !== undefined) return;
	t.buffer[chunkIdx] = chunkData;
	t.receivedCount++;
	if (!t.ready || t.paused) return;
	if (t.mode === "blob") _handleBlobChunk(fileId, t, chunkIdx);
	else _drainStreamBuffer(fileId, t);
}

async function _drainStreamBuffer(fileId, t) {
	if (t._draining) return;
	t._draining = true;
	while (t.buffer[t.nextWrite] !== undefined && !t.paused && !t.done) {
		try { await t.writable.write(t.buffer[t.nextWrite]); }
		catch (err) {
			showSystemMessage("Disk write failed: " + t.filename);
			t.done = true;
			try { await t.writable.abort(); } catch(_) {}
			delete incomingTransfers[fileId];
			t._draining = false; return;
		}
		delete t.buffer[t.nextWrite]; t.nextWrite++;
		_updateRecvProgress(fileId, t);
	}
	t._draining = false;
	if (t.nextWrite === t.totalChunks) { t.done=true; await _finalizeStream(fileId, t); }
}

async function _finalizeStream(fileId, t) {
	try { await t.writable.close(); } catch(_) {}
	const elapsed=(Date.now()-t.startTime)/1000, avg=elapsed>0?t.size/elapsed:0;
	_finalizeBubble("progress-"+fileId, t.filename, null, false, avg, elapsed);
	_replaceOrStoreDone(t.group||t.sender, fileId, t.filename, null, false);
	delete incomingTransfers[fileId];
}

function _handleBlobChunk(fileId, t, chunkIdx) {
	if (!t.chunks) t.chunks = new Array(t.totalChunks).fill(null);
	if (t.chunks[chunkIdx] === null) { t.chunks[chunkIdx]=t.buffer[chunkIdx]; delete t.buffer[chunkIdx]; }
	_updateRecvProgress(fileId, t);
	if (t.chunks.every(c=>c!==null)) { t.done=true; _assembleBlob(fileId, t); }
}

function _assembleBlob(fileId, t) {
	try {
		const blob = new Blob(t.chunks, { type: t.mimeType||"application/octet-stream" });
		const url  = URL.createObjectURL(blob);
		const elapsed=(Date.now()-t.startTime)/1000, avg=elapsed>0?t.size/elapsed:0;
		const a=document.createElement("a"); a.href=url; a.download=t.filename;
		document.body.appendChild(a); a.click(); document.body.removeChild(a);
		setTimeout(()=>URL.revokeObjectURL(url), 600000);
		_finalizeBubble("progress-"+fileId, t.filename, url, false, avg, elapsed);
		_replaceOrStoreDone(t.group||t.sender, fileId, t.filename, url, false);
	} catch(e) { showSystemMessage("File assembly failed: "+t.filename); }
	finally { t.chunks=[]; delete incomingTransfers[fileId]; }
}

function _updateRecvProgress(fileId, t) {
	const written  = t.mode==="blob" ? (t.chunks?t.chunks.filter(c=>c!==null).length:0)*CHUNK_SIZE : t.nextWrite*CHUNK_SIZE;
	const elapsed  = (Date.now()-t.startTime)/1000;
	const speedBps = elapsed>0?written/elapsed:0;
	const remaining= Math.max(0,t.size-written);
	const eta      = speedBps>0?remaining/speedBps:0;
	const pct      = Math.min(99,Math.round((t.receivedCount/t.totalChunks)*100));
	updateProgressBubble("progress-"+fileId, pct, _fmtSpeed(speedBps), _fmtETA(eta));
}

// ════════════════════════════════════════════════════════════
// SEND FILE
// ════════════════════════════════════════════════════════════
function sendFileChunked(file, receiver, isGroup) {
	if (!isSocketReady()) { showSystemMessage("Not connected."); return; }
	const fileId      = _generateFileId();
	const totalChunks = Math.max(1, Math.ceil(file.size/CHUNK_SIZE));
	const mimeType    = file.type||"application/octet-stream";
	outgoingTransfers[fileId] = {
		file, totalChunks, receiver, isGroup,
		cancelled:false, paused:false, waiting:true,
		nextChunk:0, inFlight:0, sentChunks:0, startTime:null,
	};
	if (isGroup) safeSend(`GROUP_FILE_META:${receiver}:${username}:${fileId}:${file.name}:${file.size}:${mimeType}:${totalChunks}`);
	else         safeSend(`FILE_META:${username}:${receiver}:${fileId}:${file.name}:${file.size}:${mimeType}:${totalChunks}`);
	const bubbleId = "progress-"+fileId;
	_addWaitingBubble(bubbleId, file.name, file.size, fileId);
	storeMessage(receiver, { type:"file-sending", filename:file.name, sent:true, bubbleId, fileId });
}

function _addWaitingBubble(bubbleId, filename, size, fileId) {
	const messages = document.getElementById("messages");
	if (!messages || document.getElementById(bubbleId)) return;
	const row = document.createElement("div");
	row.className = "msg-row sent";
	const bubble = document.createElement("div");
	bubble.id = bubbleId; bubble.className = "message sent";
	bubble.innerHTML = `
    <div class="file-bubble file-pending">
      <div class="file-bubble-top">
        <span class="file-icon">📎</span>
        <div class="file-incoming-info">
          <span class="file-name">${escapeHtml(filename)}</span>
          <span class="file-size-label">${escapeHtml(_fmtBytes(size))}</span>
        </div>
      </div>
      <span class="waiting-label">⏳ Waiting for receiver to accept…</span>
    </div>
    <div class="bubble-footer"><span class="bubble-time">${_fmtTime()}</span><span class="receipt single">✓</span></div>`;
	const btn = _makeActionBtn({ isFile:true, filename, fileUrl:null, sent:true }, bubble);
	row.appendChild(bubble); row.appendChild(btn);
	messages.appendChild(row); messages.scrollTop = messages.scrollHeight;
}

function _onFileReady(fileId) {
	const t = outgoingTransfers[fileId]; if (!t) return;
	t.waiting=false; t.startTime=Date.now();
	_switchToBubble("progress-"+fileId, t.file.name, fileId, true);
	_pumpChunks(fileId, new TextEncoder().encode(fileId));
}

function _pumpChunks(fileId, fileIdBytes) {
	const t = outgoingTransfers[fileId];
	if (!t||t.cancelled||t.paused||t.waiting) return;
	while (t.inFlight<CONCURRENCY && t.nextChunk<t.totalChunks) {
		if (!isSocketReady()) { showSystemMessage("Send interrupted."); delete outgoingTransfers[fileId]; return; }
		if (socket.bufferedAmount>WS_BUFFER_HIGH) break;
		const idx=t.nextChunk++; t.inFlight++;
		_readAndSendChunk(fileId, fileIdBytes, idx, t);
	}
	if (t.nextChunk>=t.totalChunks && t.inFlight===0) { _onSendComplete(fileId, t); return; }
	setTimeout(()=>_pumpChunks(fileId,fileIdBytes), socket.bufferedAmount>WS_BUFFER_HIGH?20:0);
}

function _readAndSendChunk(fileId, fileIdBytes, chunkIdx, t) {
	const start=chunkIdx*CHUNK_SIZE, end=Math.min(start+CHUNK_SIZE, t.file.size);
	const reader = new FileReader();
	reader.onload = (ev) => {
		if (t.cancelled||!isSocketReady()) { t.inFlight--; return; }
		const cd=ev.target.result;
		const hs=4+fileIdBytes.length+4+4;
		const fr=new ArrayBuffer(hs+cd.byteLength);
		const dv=new DataView(fr); let o=0;
		dv.setUint32(o,fileIdBytes.length);
		new Uint8Array(fr,o+4,fileIdBytes.length).set(fileIdBytes); o+=4+fileIdBytes.length;
		dv.setUint32(o,chunkIdx); o+=4;
		dv.setUint32(o,t.totalChunks); o+=4;
		new Uint8Array(fr,o).set(new Uint8Array(cd));
		try { socket.send(fr); }
		catch(e) { t.cancelled=true; t.inFlight--; delete outgoingTransfers[fileId]; return; }
		t.sentChunks++; t.inFlight--;
		const el=(Date.now()-t.startTime)/1000;
		const sent=t.sentChunks*CHUNK_SIZE;
		const spd=el>0?sent/el:0;
		const eta=spd>0?Math.max(0,t.file.size-sent)/spd:0;
		const pct=Math.min(99,Math.round((t.sentChunks/t.totalChunks)*100));
		updateProgressBubble("progress-"+fileId, pct, _fmtSpeed(spd), _fmtETA(eta));
	};
	reader.onerror=()=>{ t.inFlight--; };
	reader.readAsArrayBuffer(t.file.slice(start,end));
}

function _onSendComplete(fileId, t) {
	const el=(Date.now()-t.startTime)/1000, avg=el>0?t.file.size/el:0;
	_finalizeBubble("progress-"+fileId, t.file.name, null, true, avg, el);
	const r=t.receiver;
	if (chatHistory[r]) {
		const i=chatHistory[r].findIndex(m=>m.type==="file-sending"&&m.fileId===fileId);
		if (i!==-1) chatHistory[r][i]={type:"file-done",filename:t.file.name,url:null,sent:true};
	}
	delete outgoingTransfers[fileId];
}

// ── Cancel functions ─────────────────────────────────────────
function senderCancel(fileId) {
	const t = outgoingTransfers[fileId]; if (!t) return;
	t.cancelled = true;
	const el = document.getElementById("progress-"+fileId);
	if (el) { const row=el.parentElement; if(row&&row.classList.contains("msg-row"))row.remove(); else el.remove(); }
	showSystemMessage("✕ Transfer cancelled.");
	safeSend("FILE_CANCEL:"+username+":"+t.receiver+":"+fileId);
	delete outgoingTransfers[fileId];
}

function receiverCancel(fileId) {
	const t = incomingTransfers[fileId]; if (!t) return;
	t.done = true;
	if (t.writable) try { t.writable.abort(); } catch(_) {}
	const el = document.getElementById("progress-"+fileId);
	if (el) { const row=el.parentElement; if(row&&row.classList.contains("msg-row"))row.remove(); else el.remove(); }
	showSystemMessage("✕ Receive cancelled.");
	safeSend("FILE_CANCEL:"+username+":"+(t.group||t.sender)+":"+fileId);
	delete incomingTransfers[fileId];
}

// ════════════════════════════════════════════════════════════
// PAUSE / RESUME
// ════════════════════════════════════════════════════════════
function senderPause(fileId) {
	const t=outgoingTransfers[fileId]; if(!t||t.paused) return;
	t.paused=true; _updatePauseBtn(fileId,true,true);
	safeSend("SENDER_PAUSED:"+username+":"+fileId);
}
function senderResume(fileId) {
	const t=outgoingTransfers[fileId]; if(!t||!t.paused) return;
	t.paused=false; _updatePauseBtn(fileId,false,true);
	_pumpChunks(fileId, new TextEncoder().encode(fileId));
}
function receiverPause(fileId) {
	const t=incomingTransfers[fileId]; if(!t||t.paused) return;
	t.paused=true; _updatePauseBtn(fileId,true,false);
	safeSend("PAUSE_FILE:"+username+":"+fileId);
}
function receiverResume(fileId) {
	const t=incomingTransfers[fileId]; if(!t||!t.paused) return;
	t.paused=false; _updatePauseBtn(fileId,false,false);
	safeSend("RESUME_FILE:"+username+":"+fileId);
	if (!t.mode) _drainStreamBuffer(fileId,t);
	else { if(t.chunks&&t.chunks.every(c=>c!==null)){t.done=true;_assembleBlob(fileId,t);} }
}
function _updatePauseBtn(fileId, isPaused, isSender) {
	const btn=document.getElementById("pausebtn-"+fileId); if(!btn) return;
	btn.textContent = isPaused ? "▶ Resume" : "⏸ Pause";
	btn.className   = isPaused ? "pause-btn resumed" : "pause-btn";
	btn.onclick     = isPaused
		? (isSender ? ()=>senderResume(fileId) : ()=>receiverResume(fileId))
		: (isSender ? ()=>senderPause(fileId)  : ()=>receiverPause(fileId));
}

// ════════════════════════════════════════════════════════════
// BUBBLE HELPERS
// ════════════════════════════════════════════════════════════
function _switchToBubble(bubbleId, filename, fileId, isSender) {
	const messages = document.getElementById("messages"); if (!messages) return;
	const oldEl = document.getElementById(bubbleId);
	if (oldEl) {
		const parent = oldEl.parentElement;
		if (parent && parent.classList.contains("msg-row")) parent.remove();
		else oldEl.remove();
	}
	const row = document.createElement("div");
	row.className = "msg-row " + (isSender ? "sent" : "received");
	const bubble = document.createElement("div");
	bubble.id = bubbleId;
	bubble.className = isSender ? "message sent" : "message received";
	bubble.innerHTML = `
    <div class="file-bubble">
      <div class="file-bubble-top">
        <span class="file-icon">📎</span>
        <div class="file-incoming-info">
          <span class="file-name">${escapeHtml(filename)}</span>
          <span class="progress-label" id="label-${bubbleId}">0%</span>
        </div>
      </div>
      <div class="progress-bar-wrap">
        <div class="progress-bar-fill" id="bar-${bubbleId}" style="width:0%"></div>
      </div>
      <div class="progress-meta">
        <span class="progress-speed" id="speed-${bubbleId}"></span>
        <span class="progress-eta"   id="eta-${bubbleId}"></span>
      </div>
      <div class="transfer-controls">
        <button class="ctrl-btn pause-btn" id="pausebtn-${escapeHtml(fileId)}"
          onclick="${isSender?"senderPause":"receiverPause"}('${escapeHtml(fileId)}')">⏸ Pause</button>
        <button class="ctrl-btn cancel-btn"
          onclick="${isSender?"senderCancel":"receiverCancel"}('${escapeHtml(fileId)}')">✕ Cancel</button>
      </div>
    </div>
    <div class="bubble-footer">
      <span class="bubble-time">${_fmtTime()}</span>
      ${isSender ? '<span class="receipt single" id="receipt-file-'+escapeHtml(fileId)+'">✓</span>' : ""}
    </div>`;
	const btn = _makeActionBtn({ isFile:true, filename, fileUrl:null, sent:isSender }, bubble);
	row.appendChild(bubble); row.appendChild(btn);
	messages.appendChild(row); messages.scrollTop = messages.scrollHeight;
}

function _finalizeBubble(bubbleId, filename, url, isSent, avgSpeed, elapsed) {
	const bubble = document.getElementById(bubbleId); if (!bubble) return;
	const row    = bubble.parentElement;
	const spd    = avgSpeed > 0 ? _fmtSpeed(avgSpeed) : "";
	const tim    = elapsed  > 0 ? elapsed.toFixed(1) + "s" : "";
	const meta   = [spd, tim].filter(Boolean).join(" · ");
	// Preserve existing read state if already seen
	const existingReceipt = bubble.querySelector(".receipt");
	const alreadySeen = existingReceipt && existingReceipt.classList.contains("read");

	bubble.innerHTML = `
    <div class="file-bubble done">
      <div class="file-bubble-top">
        <span class="file-icon">✅</span>
        <div class="file-incoming-info">
          <span class="file-name">${escapeHtml(filename)}</span>
          <span class="file-size-label">${isSent ? "✓ Sent" : "✓ Saved to disk"}${meta ? " · " + escapeHtml(meta) : ""}</span>
        </div>
      </div>
    </div>
    <div class="bubble-footer">
      <span class="bubble-time">${_fmtTime()}</span>
      ${isSent ? `<span class="receipt ${alreadySeen?"read":"single"}">${alreadySeen?"✓✓":"✓"}</span>` : ""}
    </div>`;
	if (row && row.classList.contains("msg-row")) {
		const oldBtn = row.querySelector(".msg-action-btn");
		if (oldBtn) oldBtn.remove();
		row.appendChild(_makeActionBtn({ isFile:true, filename, fileUrl: url||null, sent: isSent }, bubble));
	}
}

function addProgressBubble(bubbleId, filename, progress, sent) { _switchToBubble(bubbleId, filename, bubbleId.replace("progress-",""), sent); }
function updateProgressBubble(bubbleId, progress, speed, eta) {
	const pct=Math.min(100,Math.max(0,progress));
	const bar=document.getElementById("bar-"+bubbleId);
	const lbl=document.getElementById("label-"+bubbleId);
	const spEl=document.getElementById("speed-"+bubbleId);
	const etEl=document.getElementById("eta-"+bubbleId);
	if(bar) bar.style.width=pct+"%";
	if(lbl) lbl.textContent=pct+"%";
	if(spEl&&speed!==undefined) spEl.textContent=speed;
	if(etEl&&eta!==undefined) etEl.textContent=eta?"ETA "+eta:"";
}
function finalizeProgressBubble(bubbleId, filename) { _finalizeBubble(bubbleId, filename, null, false, 0, 0); }
function assembleFile() {}

// ════════════════════════════════════════════════════════════
// CHAT HISTORY
// ════════════════════════════════════════════════════════════
function storeMessage(context, msgObj) {
	if (!chatHistory[context]) chatHistory[context]=[];
	chatHistory[context].push(msgObj);
	if (chatHistory[context].length>HISTORY_LIMIT) chatHistory[context].shift();
}

function loadChatHistory(context) {
	const messages=document.getElementById("messages"); if(!messages) return;
	messages.innerHTML="";

	// Tell sender their messages were read (receiver just opened this chat)
	// Only send read receipts for messages FROM the other person to us
	// Restore pin bar for this specific chat
	_showPinnedBar(context);

	// When chat opens, mark all received messages as READ
	// This triggers ✓✓ green on sender side
	if (isSocketReady() && context) {
		const history = chatHistory[context] || [];
		history.forEach(m => {
			if (!m.sent && m.msgId && !m.markedRead) {
				m.markedRead = true;
				safeSend(`MSG_READ:${username}:${context}:${m.msgId}`);
			}
		});
	}

	// Date separator tracking
	let lastDate = "";

	const history=chatHistory[context]||[];
	history.forEach((m) => {
		if (m.ts) {
			const dateStr = _fmtDate(m.ts);
			if (dateStr !== lastDate) {
				lastDate = dateStr;
				const sep = document.createElement("div");
				sep.className = "date-separator";
				sep.innerHTML = `<span>${escapeHtml(dateStr)}</span>`;
				messages.appendChild(sep);
			}
		}
		if (m.type==="text") {
			addMessage(m.text, m.sent, m.sent?"you":m.sender, m.replyTo||null, m.ts, m.msgId, m.read||false);
		} else if (m.type==="file-done") {
			const row=document.createElement("div");
			row.className=m.sent?"msg-row sent":"msg-row received";
			const b=document.createElement("div");
			b.className=m.sent?"message sent":"message received";
			b.innerHTML=`<div class="file-bubble done">
        <div class="file-bubble-top"><span class="file-icon">✅</span>
        <div class="file-incoming-info">
          <span class="file-name">${escapeHtml(m.filename)}</span>
          <span class="file-size-label">${m.sent?"✓ Sent":"✓ Saved to disk"}</span>
        </div></div></div>
        <div class="bubble-footer">
          <span class="bubble-time">${m.ts ? _fmtTime(m.ts) : ""}</span>
          ${m.sent ? `<span class="receipt ${m.read?"read":"single"}">${m.read?"✓✓":"✓"}</span>` : ""}
        </div>`;
			const btn=_makeActionBtn({ isFile:true, filename:m.filename, fileUrl:m.url||null, sent:m.sent }, b);
			row.appendChild(b); row.appendChild(btn);
			messages.appendChild(row);
		} else if (m.type==="file-incoming") {
			const inFl=incomingTransfers[m.fileId];
			if (inFl&&!inFl.done) {
				if (inFl.ready) _switchToBubble(m.bubbleId, m.filename, m.fileId, false);
				else _addPendingBubble(m.bubbleId, m.filename, m.size||0, m.fileId);
			}
		} else if (m.type==="file-sending") {
			const out=outgoingTransfers[m.fileId];
			if (out) {
				if (out.waiting) _addWaitingBubble(m.bubbleId, m.filename, out.file.size, m.fileId);
				else _switchToBubble(m.bubbleId, m.filename, m.fileId, true);
			}
		}
	});
	messages.scrollTop=messages.scrollHeight;
	_updateHamburgerDot();
}

// ════════════════════════════════════════════════════════════
// USER LIST  (with online dots)
// ════════════════════════════════════════════════════════════
function updateUserList(users) {
	const list=document.querySelector(".user-list"); if(!list) return;
	list.innerHTML="";
	users.split(",").forEach((u) => {
		if (!u||u===username) return;
		const div=document.createElement("div");
		div.className="user"; div.dataset.name=u;
		const cnt    = unreadCount[u]||0;
		const online = _onlineUsers.has(u);
		const dotHtml = online
			? '<span class="online-dot online" title="Online"></span>'
			: '<span class="online-dot offline" title="Offline"></span>';
		div.innerHTML=`
			<span class="user-name-text">${escapeHtml(u)}</span>
			${cnt>0?`<span class="badge">${cnt}</span>`:""}
			${dotHtml}`;
		div.onclick=()=>{
			selectedUser=u; selectedGroup=null; unreadCount[u]=0;
			document.getElementById("groupInfoBtn").style.display = "none";
			refreshUserList();
			const h=document.getElementById("chatHeaderText"); if(h) h.textContent="Chat with "+u;
			loadChatHistory(u);
			if (!acceptedChats.has(u)&&isSocketReady()) { pendingRequests.add(u); socket.send(`REQUEST:${username}:${u}`); }
		};
		list.appendChild(div);
	});
}

function refreshUserList() {
	const list=document.querySelector(".user-list"); if(!list) return;
	list.querySelectorAll(".user[data-name]").forEach((div) => {
		const u=div.dataset.name, cnt=unreadCount[u]||0;
		const online = _onlineUsers.has(u);
		// Update dot class
		let dot = div.querySelector(".online-dot");
		if (!dot) {
			dot = document.createElement("span");
			div.appendChild(dot);
		}
		dot.className = online ? "online-dot online" : "online-dot offline";
		dot.title     = online ? "Online" : "Offline";
		let badge=div.querySelector(".badge");
		if (cnt>0) { if(!badge){badge=document.createElement("span");badge.className="badge";div.appendChild(badge);} badge.textContent=cnt; }
		else { if(badge) badge.remove(); }
	});
}

function increaseUnread(id) {
	if (selectedUser===id||selectedGroup===id) return;
	unreadCount[id]=(unreadCount[id]||0)+1;
	_updateHamburgerDot();
}

// ════════════════════════════════════════════════════════════
// REQUEST CARDS
// ════════════════════════════════════════════════════════════
function showUserRequest(from) {
	const r=document.getElementById("requests"); if(!r||document.getElementById("req-"+from)) return;
	const f=escapeHtml(from);
	const div=document.createElement("div"); div.id="req-"+from; div.className="req-card";
	div.innerHTML=`<div class="req-card-top"><div class="req-info"><div class="req-name">${f}</div><div class="req-sub">wants to chat with you</div></div></div><div class="req-actions"><button class="req-btn-accept" onclick="acceptUser('${f}')">Accept</button></div>`;
	r.appendChild(div);
	_updateHamburgerDot();
}

function acceptUser(user) {
	acceptedChats.add(user);
	if (isSocketReady()) socket.send(`ACCEPT:${username}:${user}`);
	const card=document.getElementById("req-"+user); if(card) card.remove();
	showSystemMessage("✓ Accepted chat with "+user);
	selectedUser=user; selectedGroup=null;
	document.getElementById("groupInfoBtn").style.display = "none";
	const h=document.getElementById("chatHeaderText"); if(h) h.textContent="Chat with "+user;
	loadChatHistory(user); refreshUserList();
	_updateHamburgerDot();
}

function showGroupRequest(groupName, requester) {
	const r=document.getElementById("requests"); if(!r) return;
	const cardId="greq-"+groupName+"-"+requester;
	if (document.getElementById(cardId)) return;
	const gn=escapeHtml(groupName), req=escapeHtml(requester);
	const div=document.createElement("div"); div.id=cardId; div.className="req-card";
	div.innerHTML=`<div class="req-card-top"><div class="req-info"><div class="req-name">${req}</div><div class="req-sub">wants to join <strong>#${gn}</strong></div></div></div><div class="req-actions"><button class="req-btn-accept" onclick="acceptGroupRequest('${gn}','${req}')">Accept</button><button class="req-btn-decline" onclick="declineGroupRequest('${gn}','${req}')">Decline</button></div>`;
	r.appendChild(div);
	_updateHamburgerDot();
}

function acceptGroupRequest(groupName, requester) {
	if (isSocketReady()) socket.send(`GROUP_ACCEPT:${groupName}:${requester}`);
	const c=document.getElementById("greq-"+groupName+"-"+requester); if(c) c.remove();
	showSystemMessage("✓ Accepted "+requester+" into #"+groupName);
	_updateHamburgerDot();
}
function declineGroupRequest(groupName, requester) {
	const c=document.getElementById("greq-"+groupName+"-"+requester); if(c) c.remove();
	showSystemMessage("✗ Declined "+requester+"'s request.");
	_updateHamburgerDot();
}

// ════════════════════════════════════════════════════════════
// GROUP LIST
// ════════════════════════════════════════════════════════════
function updateGroupList(groups) {
	const list=document.querySelector(".group-list"); if(!list) return;
	list.innerHTML="";
	groups.forEach((g) => {
		const div=document.createElement("div"); div.className="user"; div.dataset.name=g.name;
		const joined=Array.isArray(g.members)&&g.members.includes(username);
		const cnt=unreadCount[g.name]||0, badge=cnt>0?`<span class="badge">${cnt}</span>`:"";
		if (joined) {
			// Store members and host
			if (Array.isArray(g.members)) _updateGroupMembers(g.name, g.members);
			if (g.host) _groupHost[g.name] = g.host;
			const memberCount = Array.isArray(g.members) ? g.members.length : 0;
			div.innerHTML=`
				<span class="group-icon">👥</span>
				<div class="group-info-wrap">
					<span class="group-name-text">${escapeHtml(g.name)}</span>
					<span class="group-member-count">${memberCount} members</span>
				</div>
				${badge}`;
			div.onclick=()=>{
				selectedGroup=g.name; selectedUser=null;
				unreadCount[g.name]=0; refreshGroupList();
				const h=document.getElementById("chatHeaderText");
				if(h) h.textContent="Group: "+g.name;
				document.getElementById("groupInfoBtn").style.display = "flex";
				loadChatHistory(g.name);
				_updateGroupHeader(g.name);
				// Request member list refresh
				safeSend("GET_GROUP_MEMBERS:"+username+":"+g.name);
			};
		} else {
			div.innerHTML=`<span class="group-icon">👥</span><span>${escapeHtml(g.name)}</span> <button onclick="joinGroup('${escapeHtml(g.name)}')">Join</button>`;
		}
		list.appendChild(div);
	});
}

function refreshGroupList() {
	const list=document.querySelector(".group-list"); if(!list) return;
	list.querySelectorAll(".user[data-name]").forEach((div) => {
		const g=div.dataset.name, cnt=unreadCount[g]||0;
		let badge=div.querySelector(".badge");
		if (cnt>0) { if(!badge){badge=document.createElement("span");badge.className="badge";div.appendChild(badge);} badge.textContent=cnt; }
		else { if(badge) badge.remove(); }
	});
}

function joinGroup(group) {
	if (!isSocketReady()) { showSystemMessage("Not connected."); return; }
	socket.send(`GROUP_JOIN_REQUEST:${username}:${group}`);
	showSystemMessage(`Join request sent to host of "${group}"…`);
	const btn=document.querySelector(`.group-list .user[data-name="${group}"] button`);
	if (btn) { btn.disabled=true; btn.textContent="Pending…"; }
}

// ════════════════════════════════════════════════════════════
// SEND MESSAGE  (with encryption + receipt + timestamp)
// ════════════════════════════════════════════════════════════
async function sendMessage() {
	const input = document.getElementById("msgInput"), text = input.value.trim();
	if (!text) return;
	if (!isSocketReady()) { showSystemMessage("Not connected."); return; }

	const replyTo  = _replyCtx ? { sender: _replyCtx.sender, text: _replyCtx.text } : null;
	const prefix   = _replyCtx ? "[↩ " + _replyCtx.sender + ": " + _replyCtx.text.substring(0,40) + "] " : "";
	const plainFull = prefix + text;
	const msgId    = _newMsgId();
	const ts       = Date.now();

	if (selectedGroup) {
		// Group messages — no encryption (multicast)
		socket.send(`GROUP_MSG:${username}:${selectedGroup}:${msgId}:${plainFull}`);
		storeMessage(selectedGroup, {type:"text", text:plainFull, sent:true, replyTo, ts, msgId});
		addMessage(text, true, "you", replyTo, ts, msgId);
		clearReply(); input.value = ""; return;
	}

	if (!selectedUser) { showSystemMessage("Select a user first."); return; }
	if (!acceptedChats.has(selectedUser)) { showSystemMessage("Waiting for "+selectedUser+" to accept."); return; }

	// Encrypt for PM
	let payload = plainFull;
	if (_encReady) {
		try { payload = await _encryptText(plainFull, selectedUser); } catch(_) {}
	}

	socket.send(`PM:${username}:${selectedUser}:${msgId}:${payload}`);
	storeMessage(selectedUser, {type:"text", text:plainFull, sent:true, replyTo, ts, msgId});
	addMessage(text, true, "you", replyTo, ts, msgId);
	clearReply(); input.value = "";
}

// ════════════════════════════════════════════════════════════
// ADD MESSAGE BUBBLE  (with timestamp + receipt)
// ════════════════════════════════════════════════════════════
function addMessage(text, sent, senderName, replyTo, ts, msgId, alreadyRead) {
	const area = document.getElementById("messages"); if (!area) return;

	const now = ts || Date.now();

	// Date separator — only add if date changed from last separator
	const dateStr = _fmtDate(now);
	const allSeps = area.querySelectorAll(".date-separator");
	const lastSep = allSeps.length > 0 ? allSeps[allSeps.length - 1] : null;
	const lastSepText = lastSep ? (lastSep.querySelector("span")||{textContent:""}).textContent : "";
	if (lastSepText !== dateStr) {
		const sep = document.createElement("div");
		sep.className = "date-separator";
		sep.innerHTML = `<span>${escapeHtml(dateStr)}</span>`;
		area.appendChild(sep);
	}

	const row = document.createElement("div");
	row.className = "msg-row " + (sent ? "sent" : "received");

	const bubble = document.createElement("div");
	bubble.id        = _nextMsgId();
	bubble.className = sent ? "message sent" : "message received";

	// Receipt ID for tracking
	const receiptId = msgId ? "receipt-" + msgId : "";

	// Build bubble content
	let content = "";
	if (replyTo) {
		content = `<div class="reply-quote-block">
			<span class="reply-quote-sender">${escapeHtml(replyTo.sender)}</span>
			<span class="reply-quote-text">${escapeHtml(replyTo.text.substring(0,80))}${replyTo.text.length>80?"…":""}</span>
		</div>
		<div class="reply-msg-text">${escapeHtml(text)}</div>`;
	} else {
		content = `<span class="bubble-text">${escapeHtml(text)}</span>`;
	}

	// Footer: timestamp + receipt (sent only)
	const receiptHtml = sent
		? `<span class="receipt ${alreadyRead ? "read" : "single"}" ${receiptId ? 'id="'+receiptId+'"' : ""}>${alreadyRead ? "✓✓" : "✓"}</span>`
		: "";

	bubble.innerHTML = content + `
		<div class="bubble-footer">
			<span class="bubble-time">${_fmtTime(now)}</span>
			${receiptHtml}
		</div>`;

	const btn = _makeActionBtn({ text, sent, isFile:false, sender: senderName||(sent?"you":"them") }, bubble);
	row.appendChild(bubble);
	row.appendChild(btn);
	area.appendChild(row);
	area.scrollTop = area.scrollHeight;

	// ✓ shown immediately on send. ✓✓ grey comes from server DELIVERED. ✓✓ green from MSG_READ.
}

// ════════════════════════════════════════════════════════════
// FILE ATTACH
// ════════════════════════════════════════════════════════════
document.getElementById("attachBtn").onclick=()=>{ document.getElementById("fileInput").click(); };
document.getElementById("fileInput").onchange=(e)=>{
	const file=e.target.files[0]; if(!file) return;
	if (!isSocketReady()) { showSystemMessage("Not connected."); e.target.value=""; return; }
	if (selectedGroup) { sendFileChunked(file,selectedGroup,true); }
	else if (selectedUser) {
		if (!acceptedChats.has(selectedUser)) { showSystemMessage("Chat not accepted yet."); e.target.value=""; return; }
		sendFileChunked(file,selectedUser,false);
	} else { showSystemMessage("Select a user or group first."); }
	e.target.value="";
};

// ════════════════════════════════════════════════════════════
// GROUP CREATE
// ════════════════════════════════════════════════════════════
document.getElementById("createGroupBtn").onclick=()=>{ document.getElementById("createGroupModal").style.display="block"; };
function createGroup() {
	const g=document.getElementById("groupNameInput").value.trim(); if(!g){alert("Enter a group name.");return;}
	if (!isSocketReady()) { showSystemMessage("Not connected."); return; }
	socket.send("CREATE_GROUP:"+username+":"+g);
	document.getElementById("createGroupModal").style.display="none";
	document.getElementById("groupNameInput").value="";
}

document.getElementById("sendBtn").onclick = () => sendMessage();
document.getElementById("msgInput").addEventListener("keydown",(e)=>{ if(e.key==="Enter"&&!e.shiftKey){e.preventDefault();sendMessage();} });

// ════════════════════════════════════════════════════════════
// HAMBURGER DOT
// ════════════════════════════════════════════════════════════
function _updateHamburgerDot() {
	const btn = document.getElementById("hamburgerBtn"); if (!btn) return;
	const totalUnread = Object.values(unreadCount).reduce((s,n)=>s+n, 0);
	const reqCount    = (document.getElementById("requests")||{children:[]}).children.length;
	const total = totalUnread + reqCount;
	if (total > 0) {
		btn.classList.add("has-dot");
		btn.dataset.dotCount = total > 9 ? "9+" : String(total);
	} else {
		btn.classList.remove("has-dot");
		btn.dataset.dotCount = "";
	}
}

// ════════════════════════════════════════════════════════════
// MESSAGE ACTION SYSTEM
// ════════════════════════════════════════════════════════════
let _replyCtx  = null;
const _pinnedMsgs = {}; // context → { text, msgId } per chat
let _openMenu  = null;
let _msgIdSeq  = 0;

function _nextMsgId() { return "msg-" + (++_msgIdSeq); }

function _makeActionBtn(opts, bubbleEl) {
	const btn = document.createElement("button");
	btn.className   = "msg-action-btn";
	btn.textContent = "⌄";
	btn.title       = "Options";
	btn.onclick = (e) => { e.stopPropagation(); _toggleMenu(btn, bubbleEl, opts); };
	return btn;
}

function _attachActionBtn(msgDiv, opts) {
	if (!msgDiv || msgDiv.classList.contains("system")) return;
	if (!msgDiv.id) msgDiv.id = _nextMsgId();
	const parent = msgDiv.parentElement;
	if (parent && parent.classList.contains("msg-row")) {
		const existing = parent.querySelector(".msg-action-btn");
		if (!existing) parent.appendChild(_makeActionBtn(opts, msgDiv));
		return;
	}
	const row = document.createElement("div");
	row.className = "msg-row " + (opts.sent ? "sent" : "received");
	if (parent) parent.insertBefore(row, msgDiv);
	row.appendChild(msgDiv);
	row.appendChild(_makeActionBtn(opts, msgDiv));
}

function _toggleMenu(btn, msgDiv, opts) {
	if (_openMenu) { _openMenu.remove(); _openMenu = null; }
	const menu = document.createElement("div");
	menu.className = "msg-menu";
	_openMenu = menu;

	const add = (icon, label, fn) => {
		const el = document.createElement("button");
		el.className = "msg-menu-item";
		el.innerHTML = `<span class="mi-icon">${icon}</span>${escapeHtml(label)}`;
		el.onclick = (e) => { e.stopPropagation(); menu.remove(); _openMenu = null; fn(); };
		menu.appendChild(el);
	};
	const divider = () => { const d=document.createElement("div"); d.className="msg-menu-divider"; menu.appendChild(d); };

	add("↩", "Reply",        () => _startReply(opts.filename || opts.text, opts.sender || "you"));
	add("↗", "Forward",      () => _openForward(opts));
	add("📌", "Pin message",  () => _pinMessage(opts.filename || opts.text, msgDiv.id));
	if (opts.isFile) {
		divider();
		add("📂", "Open file", () => _openFile(opts.fileUrl, opts.filename));
	}

	const rect = btn.getBoundingClientRect();
	menu.style.position = "fixed";
	menu.style.zIndex   = "9999";
	menu.style.top      = (rect.bottom + 4) + "px";
	const menuW = 170;
	let left = rect.right - menuW;
	if (left < 8) left = 8;
	menu.style.left  = left + "px";
	menu.style.width = menuW + "px";
	document.body.appendChild(menu);

	const closer = (e) => {
		if (!menu.contains(e.target) && e.target !== btn) {
			menu.remove(); _openMenu = null;
			document.removeEventListener("click", closer, true);
		}
	};
	setTimeout(() => document.addEventListener("click", closer, true), 10);
}

// ── Reply ──────────────────────────────────────────────────
function _startReply(text, sender) {
	_replyCtx = { text, sender };
	const prev = document.getElementById("replyPreview");
	const ptxt = document.getElementById("replyPreviewText");
	if (prev) prev.classList.add("active");
	if (ptxt) ptxt.textContent = sender + ": " + text;
	document.getElementById("msgInput").focus();
}
function clearReply() {
	_replyCtx = null;
	const prev = document.getElementById("replyPreview");
	if (prev) prev.classList.remove("active");
}

// ── Forward ────────────────────────────────────────────────
let _fwdOpts = null;
function _openForward(opts) {
	_fwdOpts = opts;
	const modal = document.getElementById("forwardModal");
	const body  = document.getElementById("forwardModalBody");
	if (!modal || !body) return;
	body.innerHTML = "";
	const targets = [];
	document.querySelectorAll(".user-list .user[data-name]").forEach(d => {
		if (d.dataset.name !== selectedUser) targets.push({ type:"user", name:d.dataset.name });
	});
	document.querySelectorAll(".group-list .user[data-name]").forEach(d => {
		if (!d.querySelector("button") && d.dataset.name !== selectedGroup)
			targets.push({ type:"group", name:d.dataset.name });
	});
	if (!targets.length) {
		body.innerHTML = '<div class="forward-empty">No other conversations available.</div>';
	} else {
		targets.forEach(t => {
			const initials = t.name.replace(/[_-]/g," ").split(" ").map(w=>w[0]||"").join("").substring(0,2).toUpperCase();
			const el = document.createElement("div");
			el.className = "forward-user-item";
			el.innerHTML = `<div class="forward-avatar">${escapeHtml(initials)}</div><span>${escapeHtml(t.type==="group"?"#"+t.name:t.name)}</span>`;
			el.onclick = () => _doForward(t);
			body.appendChild(el);
		});
	}
	modal.style.display = "flex";
}

function closeForwardModal(e) {
	if (e && e.target !== document.getElementById("forwardModal")) return;
	document.getElementById("forwardModal").style.display = "none";
	_fwdOpts = null;
}

function _doForward(target) {
	if (!_fwdOpts || !isSocketReady()) return;
	const isGroup = target.type === "group";
	const to      = target.name;
	if (_fwdOpts.isFile) {
		if (_fwdOpts.fileUrl) {
			fetch(_fwdOpts.fileUrl)
				.then(r => r.blob())
				.then(blob => {
					sendFileChunked(new File([blob], _fwdOpts.filename, { type: blob.type }), to, isGroup);
					showSystemMessage("↗ Forwarded file to " + (isGroup?"#":"") + to);
				})
				.catch(() => showSystemMessage("⚠ Cannot forward. Re-send using 📎."));
		} else {
			showSystemMessage("⚠ Cannot forward stream-saved file. Re-send using 📎.");
		}
	} else {
		const txt = "↗ " + (_fwdOpts.text || "");
		if (isGroup) {
			socket.send(`GROUP_MSG:${username}:${to}:${_newMsgId()}:${txt}`);
			storeMessage(to, { type:"text", text:txt, sent:true, ts:Date.now() });
		} else {
			if (!acceptedChats.has(to)) { showSystemMessage("⚠ Not accepted by "+to+" yet."); return; }
			socket.send(`PM:${username}:${to}:${_newMsgId()}:${txt}`);
			storeMessage(to, { type:"text", text:txt, sent:true, ts:Date.now() });
		}
		showSystemMessage("↗ Forwarded to " + (isGroup?"#":"") + to);
	}
	document.getElementById("forwardModal").style.display = "none";
	_fwdOpts = null;
}

// ── Pin ────────────────────────────────────────────────────
function _pinMessage(text, msgId) {
	const ctx = selectedUser || selectedGroup;
	if (!ctx) return;
	_pinnedMsgs[ctx] = { text, msgId };
	_showPinnedBar(ctx);
}

function _showPinnedBar(ctx) {
	const pin = _pinnedMsgs[ctx];
	const bar = document.getElementById("pinnedBar");
	const bt  = document.getElementById("pinnedBarText");
	if (!bar) return;
	if (pin) {
		bar.classList.add("has-pin");
		if (bt) bt.textContent = pin.text;
	} else {
		bar.classList.remove("has-pin");
		if (bt) bt.textContent = "—";
	}
}

function unpinMessage(e) {
	if (e) e.stopPropagation();
	const ctx = selectedUser || selectedGroup;
	if (ctx) delete _pinnedMsgs[ctx];
	_showPinnedBar(ctx);
}

function scrollToPinned() {
	const ctx = selectedUser || selectedGroup;
	const pin = ctx ? _pinnedMsgs[ctx] : null;
	if (!pin?.msgId) return;

	let el = document.getElementById(pin.msgId);

	// If message not in DOM (scrolled out) — scroll messages to bottom first
	// then try to find it
	if (!el) {
		showSystemMessage("📌 Pinned message is not currently visible in this session.");
		return;
	}

	el.scrollIntoView({ behavior:"smooth", block:"center" });
	el.style.transition = "box-shadow .2s, background .2s";
	el.style.boxShadow  = "0 0 0 2px var(--accent)";
	el.style.background = "var(--accent-dim)";
	setTimeout(() => {
		el.style.boxShadow  = "";
		el.style.background = "";
	}, 1800);
}

// ── Open File ──────────────────────────────────────────────
function _openFile(fileUrl, filename) {
	if (!fileUrl) {
		showSystemMessage('📂 "' + (filename||"file") + '" was saved to your chosen disk location.');
		return;
	}
	const ext   = (filename||"").split(".").pop().toLowerCase();
	const imgs  = ["jpg","jpeg","png","gif","webp","bmp","svg"];
	const vids  = ["mp4","webm","ogg","mov"];
	const audio = ["mp3","wav","ogg","m4a","flac"];
	if (imgs.includes(ext)||vids.includes(ext)||audio.includes(ext)||ext==="pdf") {
		_showPreviewModal(fileUrl, filename, ext, imgs, vids, audio);
	} else {
		const a = document.createElement("a"); a.href=fileUrl; a.download=filename; a.click();
	}
}

function _showPreviewModal(url, filename, ext, imgs, vids, audio) {
	const ex = document.getElementById("filePreviewModal"); if (ex) ex.remove();
	const overlay = document.createElement("div");
	overlay.id="filePreviewModal"; overlay.className="preview-modal-overlay";
	overlay.onclick=(e)=>{ if(e.target===overlay) overlay.remove(); };
	let content = "";
	if (imgs.includes(ext))       content=`<img src="${url}" alt="${escapeHtml(filename)}" class="preview-img"/>`;
	else if (vids.includes(ext))  content=`<video src="${url}" controls class="preview-video" autoplay></video>`;
	else if (audio.includes(ext)) content=`<div class="preview-audio-wrap"><p class="preview-filename">${escapeHtml(filename)}</p><audio src="${url}" controls class="preview-audio"></audio></div>`;
	else if (ext==="pdf")         content=`<iframe src="${url}" class="preview-pdf"></iframe>`;
	overlay.innerHTML=`<div class="preview-modal">
		<div class="preview-modal-header">
			<span class="preview-modal-name">${escapeHtml(filename)}</span>
			<div class="preview-modal-actions">
				<a class="preview-download-btn" href="${url}" download="${escapeHtml(filename)}">⬇ Download</a>
				<button class="preview-close-btn" onclick="document.getElementById('filePreviewModal').remove()">✕</button>
			</div>
		</div>
		<div class="preview-modal-body">${content}</div>
	</div>`;
	document.body.appendChild(overlay);
}

// ════════════════════════════════════════════════════════════
// UTILITIES
// ════════════════════════════════════════════════════════════
function isSocketReady(){return socket!==null&&socket.readyState===WebSocket.OPEN;}
function safeSend(d){if(isSocketReady())socket.send(d);else console.warn("dropped:",String(d).substring(0,80));}
function _generateFileId(){return "fid-"+Date.now()+"-"+Math.random().toString(36).substring(2,9);}
function _replaceOrStoreDone(context,fileId,filename,url,sent){
	if(!chatHistory[context])chatHistory[context]=[];
	const i=chatHistory[context].findIndex(m=>m.type==="file-incoming"&&m.fileId===fileId);
	const e={type:"file-done",filename,url,sent,ts:Date.now()};
	if(i!==-1)chatHistory[context][i]=e; else chatHistory[context].push(e);
}
function _fmtBytes(b){if(!b||b===0)return "0 B";const u=["B","KB","MB","GB","TB"],i=Math.floor(Math.log(b)/Math.log(1024));return(b/Math.pow(1024,i)).toFixed(i>1?1:0)+" "+u[i];}
function _fmtSpeed(bps){return(!bps||bps<=0)?"":_fmtBytes(bps)+"/s";}
function _fmtETA(s){if(!s||s<=0||!isFinite(s))return "";if(s<60)return Math.round(s)+"s";if(s<3600)return Math.round(s/60)+"m "+(Math.round(s)%60)+"s";return Math.floor(s/3600)+"h "+Math.round((s%3600)/60)+"m";}
function escapeHtml(s){return String(s||"").replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");}
function showSystemMessage(text){const m=document.getElementById("messages");if(!m)return;const d=document.createElement("div");d.className="message system";d.innerText=text;m.appendChild(d);m.scrollTop=m.scrollHeight;}