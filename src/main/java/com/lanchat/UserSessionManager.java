package com.lanchat;

import java.util.concurrent.ConcurrentHashMap;
import org.springframework.web.socket.WebSocketSession;

public class UserSessionManager {

    private static ConcurrentHashMap<String, WebSocketSession> users = new ConcurrentHashMap<>();

    public static void addUser(String username, WebSocketSession session) {
        users.put(username, session);
    }

    public static void removeUser(String username) {
        users.remove(username);
    }

    public static WebSocketSession getUserSession(String username) {
        return users.get(username);
    }

    public static ConcurrentHashMap<String, WebSocketSession> getUsers() {
        return users;
    }
}