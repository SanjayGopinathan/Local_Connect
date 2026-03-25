Local\_Connect — LAN Chat \& File Transfer

 #A real-time LAN-based chat and file transfer application.
  Works WITHOUT internet connection.
-Private messaging with AES-GCM encryption
- Group chat system
- Chunk-based file transfer (supports 100MB+ files)
- Typing indicator
- Read receipts (single tick / double tick)
- Online/offline status
- File pause and resume
- Works on browser and mobile


# Tech Stack

- Backend  : Spring Boot, Java, WebSocket

- Frontend : HTML, CSS, Vanilla JavaScript

- Protocol : Custom WebSocket binary + text frames

- Security : AES-GCM 256-bit end-to-end encryption (HKDF)


# How to Run

# Requirements

- Java 17+

- Maven 3.x

# 

# Run on Local Network

#bash

#mvn clean package -DskipTests

#java -jar target/lanchat.jar

Open browser on any device on same WiFi:

# http://YOUR\_IP:8080

# Find your IP using ipconfig (Windows) or hostname -I (Linux)



# Why This Project?

- Works without internet — perfect for hospitals, offices, exam halls

- Data never leaves your network — complete privacy

- File transfer at full LAN speed with no size limit

- No phone number needed — just a username



#

# Sanjay Gopinathan

