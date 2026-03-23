package com.lanchat.handler;

import org.springframework.web.socket.*;
import org.springframework.web.socket.handler.AbstractWebSocketHandler;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class ChatWebSocketHandler extends AbstractWebSocketHandler {

    // username → session
    private static final Map<String, WebSocketSession> users = new ConcurrentHashMap<>();

    // ── Group data ─────────────────────────────────────────────
    private final Map<String, Group> groups = new ConcurrentHashMap<>();

    class Group {
        String name;
        String host;
        List<String> members  = new ArrayList<>();
        List<String> requests = new ArrayList<>();
    }

    // Binary chunk routing: senderSessionId → "USER:receiver" or "GROUP:groupName"
    private final Map<String, String> chunkRouting = new ConcurrentHashMap<>();

    // ════════════════════════════════════════════════════════════
    // CONNECTION ESTABLISHED
    // ════════════════════════════════════════════════════════════
    @Override
    public void afterConnectionEstablished(WebSocketSession session) {
        System.out.println("Client connected: " + session.getId());
        session.setBinaryMessageSizeLimit(4 * 1024 * 1024 + 64);
        session.setTextMessageSizeLimit(2 * 1024 * 1024);
    }

    // ════════════════════════════════════════════════════════════
    // CONNECTION CLOSED
    // ════════════════════════════════════════════════════════════
    @Override
    public void afterConnectionClosed(WebSocketSession session, CloseStatus status) {
        String username = getUsername(session);
        if (username != null) {
            users.remove(username);
            chunkRouting.remove(session.getId());
            try { broadcastUsers(); } catch (Exception ignored) {}
        }
    }

    // ════════════════════════════════════════════════════════════
    // TEXT MESSAGE HANDLER
    // ════════════════════════════════════════════════════════════
    @Override
    protected void handleTextMessage(WebSocketSession session, TextMessage message) throws Exception {

        String msg = message.getPayload();
        System.out.println("RECEIVED: " + msg.substring(0, Math.min(msg.length(), 120)));

        // ── JOIN ──────────────────────────────────────────────
        if (msg.startsWith("JOIN:")) {
            String username = msg.substring(5).trim();
            users.put(username, session);
            broadcastUsers();
            broadcastGroupsList();
            return;
        }

        // ── CHAT REQUEST ──────────────────────────────────────
        // REQUEST:fromUser:toUser
        if (msg.startsWith("REQUEST:")) {
            String[] p = msg.split(":", 3);
            if (p.length >= 3) sendToUser(p[2], msg);
            return;
        }

        // ── ACCEPT ────────────────────────────────────────────
        // ACCEPT:acceptorUser:requesterUser
        if (msg.startsWith("ACCEPT:")) {
            String[] p = msg.split(":", 3);
            if (p.length >= 3) sendToUser(p[2], msg);
            return;
        }

        // ── PRIVATE MESSAGE ───────────────────────────────────
        // PM:sender:receiver:msgId:encryptedText
        if (msg.startsWith("PM:")) {
            String[] p = msg.split(":", 5);
            if (p.length >= 4) {
                String sender   = p[1];
                String receiver = p[2];
                String msgId    = p[3];
                // Forward to receiver
                sendToUser(receiver, msg);
                // Auto-send DELIVERED receipt to sender
                sendToUser(sender, "DELIVERED:" + sender + ":" + receiver + ":" + msgId);
            }
            return;
        }

        // ── READ RECEIPT ──────────────────────────────────────
        // MSG_READ:reader:originalSender:msgId
        if (msg.startsWith("MSG_READ:")) {
            String[] p = msg.split(":", 4);
            if (p.length >= 3) sendToUser(p[2], msg); // p[2] = original sender
            return;
        }

        // ── TYPING INDICATOR ──────────────────────────────────
        // TYPING:from:to:type  (type = "pm" or "group")
        if (msg.startsWith("TYPING:")) {
            String[] p = msg.split(":", 4);
            if (p.length >= 4) {
                String from = p[1];
                String to   = p[2];
                String type = p[3];
                if (type.equals("group")) {
                    Group g = groups.get(to);
                    if (g != null) {
                        for (String member : g.members) {
                            if (!member.equals(from)) sendToUser(member, msg);
                        }
                    }
                } else {
                    sendToUser(to, msg);
                }
            }
            return;
        }

        // TYPING_STOP:from:to:type
        if (msg.startsWith("TYPING_STOP:")) {
            String[] p = msg.split(":", 4);
            if (p.length >= 4) {
                String from = p[1];
                String to   = p[2];
                String type = p[3];
                if (type.equals("group")) {
                    Group g = groups.get(to);
                    if (g != null) {
                        for (String member : g.members) {
                            if (!member.equals(from)) sendToUser(member, msg);
                        }
                    }
                } else {
                    sendToUser(to, msg);
                }
            }
            return;
        }

        // ── PRIVATE FILE META ─────────────────────────────────
        // FILE_META:sender:receiver:fileId:filename:size:mimeType:totalChunks
        if (msg.startsWith("FILE_META:")) {
            String[] p = msg.split(":", 4);
            if (p.length >= 3) {
                chunkRouting.put(session.getId(), "USER:" + p[2]);
                sendToUser(p[2], msg);
            }
            return;
        }

        // ── GROUP FILE META ───────────────────────────────────
        // GROUP_FILE_META:group:sender:fileId:filename:size:mimeType:totalChunks
        if (msg.startsWith("GROUP_FILE_META:")) {
            String[] p = msg.split(":", 4);
            if (p.length >= 3) {
                String groupName = p[1];
                String sender    = p[2];
                chunkRouting.put(session.getId(), "GROUP:" + groupName);
                Group g = groups.get(groupName);
                if (g != null) {
                    for (String member : g.members) {
                        if (!member.equals(sender)) sendToUser(member, msg);
                    }
                }
            }
            return;
        }

        // ── FILE READY ────────────────────────────────────────
        // FILE_READY:receiverUser:senderUser:fileId
        if (msg.startsWith("FILE_READY:")) {
            String[] p = msg.split(":", 4);
            if (p.length >= 3) sendToUser(p[2], msg);
            return;
        }

        // ── PAUSE / RESUME / SENDER_PAUSED ───────────────────
        // PAUSE_FILE:receiverUser:senderUser:fileId
        if (msg.startsWith("PAUSE_FILE:")) {
            String[] p = msg.split(":", 4);
            if (p.length >= 3) sendToUser(p[2], msg);
            return;
        }

        // RESUME_FILE:receiverUser:senderUser:fileId
        if (msg.startsWith("RESUME_FILE:")) {
            String[] p = msg.split(":", 4);
            if (p.length >= 3) sendToUser(p[2], msg);
            return;
        }

        // SENDER_PAUSED:senderUser:receiverUser:fileId
        if (msg.startsWith("SENDER_PAUSED:")) {
            String[] p = msg.split(":", 4);
            if (p.length >= 3) sendToUser(p[2], msg);
            return;
        }

        // ── FILE CANCEL ───────────────────────────────────────
        // FILE_CANCEL:canceller:otherParty:fileId
        if (msg.startsWith("FILE_CANCEL:")) {
            String[] p = msg.split(":", 4);
            if (p.length >= 3) sendToUser(p[2], msg);
            return;
        }

        // ── CREATE GROUP ──────────────────────────────────────
        // CREATE_GROUP:username:groupName
        if (msg.startsWith("CREATE_GROUP:")) {
            String[] p = msg.split(":", 3);
            if (p.length >= 3) {
                String user      = p[1];
                String groupName = p[2];
                Group g   = new Group();
                g.name    = groupName;
                g.host    = user;
                g.members.add(user);
                groups.put(groupName, g);
                broadcastGroupsList();
            }
            return;
        }

        // ── GROUP JOIN REQUEST ────────────────────────────────
        // GROUP_JOIN_REQUEST:username:groupName
        if (msg.startsWith("GROUP_JOIN_REQUEST:")) {
            String[] p = msg.split(":", 3);
            if (p.length >= 3) {
                String user      = p[1];
                String groupName = p[2];
                Group g = groups.get(groupName);
                if (g != null && !g.requests.contains(user)) {
                    g.requests.add(user);
                    sendToUser(g.host, "GROUP_REQUEST:" + groupName + ":" + user);
                }
            }
            return;
        }

        // ── GROUP ACCEPT ──────────────────────────────────────
        // GROUP_ACCEPT:groupName:username
        if (msg.startsWith("GROUP_ACCEPT:")) {
            String[] p = msg.split(":", 3);
            if (p.length >= 3) {
                String groupName = p[1];
                String user      = p[2];
                Group g = groups.get(groupName);
                if (g != null) {
                    if (!g.members.contains(user)) g.members.add(user);
                    g.requests.remove(user);
                    sendToUser(user, "GROUP_ACCEPTED:" + groupName);
                    broadcastGroupsList();
                    broadcastGroupMembers(groupName);
                }
            }
            return;
        }

        // ── GET GROUP MEMBERS ─────────────────────────────────
        // GET_GROUP_MEMBERS:username:groupName
        if (msg.startsWith("GET_GROUP_MEMBERS:")) {
            String[] p = msg.split(":", 3);
            if (p.length >= 3) {
                String requester = p[1];
                String groupName = p[2];
                Group g = groups.get(groupName);
                if (g != null) {
                    String memberList = String.join(",", g.members);
                    sendToUser(requester, "GROUP_MEMBERS:" + groupName + ":" + memberList);
                }
            }
            return;
        }

        // ── GROUP MESSAGE ─────────────────────────────────────
        // GROUP_MSG:sender:groupName:msgId:text
        if (msg.startsWith("GROUP_MSG:")) {
            String[] p = msg.split(":", 5);
            if (p.length >= 5) {
                String sender    = p[1];
                String groupName = p[2];
                Group g = groups.get(groupName);
                if (g != null) {
                    for (String member : g.members) {
                        if (!member.equals(sender)) sendToUser(member, msg);
                    }
                }
            }
            return;
        }

        System.out.println("UNHANDLED: " + msg.substring(0, Math.min(msg.length(), 80)));
    }

    // ════════════════════════════════════════════════════════════
    // BINARY CHUNK HANDLER
    // ════════════════════════════════════════════════════════════
    @Override
    protected void handleBinaryMessage(WebSocketSession session, BinaryMessage message) throws Exception {
        String routing = chunkRouting.get(session.getId());
        if (routing == null) {
            System.out.println("WARN: No routing for binary from " + session.getId());
            return;
        }

        byte[] payload = message.getPayload().array();
        String sender  = getUsername(session);

        if (routing.startsWith("USER:")) {
            String receiver = routing.substring(5);
            WebSocketSession target = users.get(receiver);
            if (target != null && target.isOpen()) {
                target.sendMessage(new BinaryMessage(payload));
            }

        } else if (routing.startsWith("GROUP:")) {
            String groupName = routing.substring(6);
            Group g = groups.get(groupName);
            if (g != null) {
                for (String member : g.members) {
                    if (!member.equals(sender)) {
                        WebSocketSession target = users.get(member);
                        if (target != null && target.isOpen()) {
                            target.sendMessage(new BinaryMessage(payload));
                        }
                    }
                }
            }
        }
    }

    // ════════════════════════════════════════════════════════════
    // BROADCAST HELPERS
    // ════════════════════════════════════════════════════════════
    private void broadcastUsers() throws Exception {
        String list = String.join(",", users.keySet());
        TextMessage tm = new TextMessage("USERS:" + list);
        for (WebSocketSession s : users.values()) {
            if (s.isOpen()) s.sendMessage(tm);
        }
    }

    private void broadcastGroupsList() throws Exception {
        List<Map<String, Object>> list = new ArrayList<>();
        for (Group g : groups.values()) {
            Map<String, Object> m = new HashMap<>();
            m.put("name",    g.name);
            m.put("host",    g.host);
            m.put("members", g.members);
            list.add(m);
        }
        String json = new ObjectMapper().writeValueAsString(list);
        TextMessage tm = new TextMessage("GROUPS_LIST:" + json);
        for (WebSocketSession s : users.values()) {
            if (s.isOpen()) s.sendMessage(tm);
        }
    }

    // Send updated member list to all members of a group
    private void broadcastGroupMembers(String groupName) throws Exception {
        Group g = groups.get(groupName);
        if (g == null) return;
        String memberList = String.join(",", g.members);
        String msg = "GROUP_MEMBERS:" + groupName + ":" + memberList;
        for (String member : g.members) {
            sendToUser(member, msg);
        }
    }

    // ════════════════════════════════════════════════════════════
    // SEND TO A SPECIFIC USER
    // ════════════════════════════════════════════════════════════
    private void sendToUser(String username, String msg) throws Exception {
        WebSocketSession s = users.get(username);
        if (s != null && s.isOpen()) {
            s.sendMessage(new TextMessage(msg));
        }
    }

    // ════════════════════════════════════════════════════════════
    // REVERSE LOOKUP: session → username
    // ════════════════════════════════════════════════════════════
    private String getUsername(WebSocketSession session) {
        for (Map.Entry<String, WebSocketSession> entry : users.entrySet()) {
            if (entry.getValue().getId().equals(session.getId())) {
                return entry.getKey();
            }
        }
        return null;
    }
}