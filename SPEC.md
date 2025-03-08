# XSMTP Protocol Specification

This document describes the XSMTP proxy protocol, designed to resist censorship by masquerading as SMTPS traffic.

**1. Requirements Language**

The keywords "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://tools.ietf.org/html/rfc2119).

**2. Underlying Protocol & Wire Format**

The XSMTP protocol **MUST** be implemented on top of the standard TCP transport protocol. After the initial SMTP STARTTLS handshake and authentication, all subsequent data is transmitted over an established TLS encrypted channel.

All multibyte numbers use Big Endian format.

All variable-length integers ("varints") are encoded/decoded as defined in QUIC (RFC 9000). *Note: While QUIC varint is mentioned for technical completeness, for simplicity in XSMTP's TCP-based implementation, standard integer types (e.g., uint32, uint16, varint as needed) can be used directly.*

**3. Masquerading as SMTPS - Detailed Process**

The XSMTP server **MUST** behave like a standard SMTP server during the initial connection, STARTTLS handshake, and authentication. The detailed process steps are as follows:

**3.1. STARTTLS Handshake - Detailed Steps**

*   **3.1.1. Client Connection and Service Ready**
    *   **Client Behavior:**
        *   The client initiates a TCP connection to the server's specified IP address and port.
        *   The client waits for the TCP connection to be established.
    *   **Server Behavior:**
        *   The server listens on the specified port and accepts client TCP connections.
        *   Upon connection establishment, the server **immediately** sends an SMTP Service Ready message:
            ```
            220 <Server Hostname> ESMTP XSMTP Proxy Ready
            ```
            *   `<Server Hostname>` **SHOULD** simulate a common email service provider domain, such as `smtp.gmail.com`. This hostname should be configured in the server's JSON configuration (`masquerade_hostname` field).
*   **3.1.2. EHLO Exchange and STARTTLS Check**
    *   **Client Behavior:**
        *   The client sends the `EHLO` command, declaring the client's hostname:
            ```
            EHLO <Client Hostname>
            ```
            *   `<Client Hostname>` can be any valid domain or hostname.
        *   The client waits for the server's `250` response.
        *   The client **MUST** check if the server's `250` response includes the `STARTTLS` extension declaration, for example:
            ```
            250-STARTTLS
            ```
        *   **Error Handling:**
            *   If the server's response is **not** a `250` status code, or if the `250` response **does not** include the `STARTTLS` extension, the client **MUST immediately disconnect the TCP connection** and terminate the process, considering the STARTTLS handshake failed.
    *   **Server Behavior:**
        *   Upon receiving the `EHLO` command, the server sends a `250` response, which **MUST** include the `STARTTLS` and `AUTH` extension declarations, as well as other optional SMTP extensions. For example:
            ```
            250-<Server Hostname>
            250-SIZE 20480000
            250-AUTH PLAIN LOGIN CRAM-MD5
            250-STARTTLS
            250 8BITMIME
            ```
            *   `<Server Hostname>` **MUST** be consistent with the hostname used in the "220 Service Ready" message and read from the server's JSON configuration (`masquerade_hostname` field).
*   **3.1.3. STARTTLS Command and TLS Upgrade**
    *   **Client Behavior:**
        *   If the client detects the `STARTTLS` extension in the `EHLO` response, it sends the `STARTTLS` command:
            ```
            STARTTLS
            ```
        *   The client waits for the server's `220 2.0.0 Ready to start TLS` response to the `STARTTLS` command.
        *   **Error Handling:**
            *   If the server's response is **not** `220 2.0.0 Ready to start TLS`, the client **MUST immediately disconnect the TCP connection** and terminate the process, considering the STARTTLS handshake failed.
        *   If the correct `220` response is received, the client **immediately initiates the standard TLS handshake (TLS/SSL Handshake)**.
    *   **Server Behavior:**
        *   Upon receiving the `STARTTLS` command, the server sends the `220 2.0.0 Ready to start TLS` response:
            ```
            220 2.0.0 Ready to start TLS
            ```
        *   After sending the `220` response, the server **immediately initiates the standard TLS handshake (TLS/SSL Handshake)**.
*   **3.1.4. TLS Handshake Completion**
    *   **Client Behavior:**
        *   The client completes the TLS handshake. The TLS handshake process uses standard TLS protocols, such as TLS 1.2 or TLS 1.3.
        *   Upon successful TLS handshake, the client's TLS connection is established.
    *   **Server Behavior:**
        *   The server completes the TLS handshake.
        *   Upon successful TLS handshake, the server's TLS connection is established.

**3.2. SMTP AUTH Authentication - Detailed Steps**

*   **3.2.1. EHLO Exchange and AUTH Mechanism Check in Encrypted Channel**
    *   **Client Behavior:**
        *   After the TLS encrypted channel is established, the client **MUST resend the `EHLO` command** (within the TLS encrypted channel):
            ```
            EHLO <Client Hostname>
            ```
        *   The client waits for the server's `250` response to the `EHLO` command in the encrypted channel.
        *   The client **MUST** check if the server's `250` response in the encrypted channel includes the `AUTH` extension declaration, for example:
            ```
            250-AUTH PLAIN LOGIN CRAM-MD5
            ```
        *   The client needs to choose a suitable AUTH mechanism (e.g., `PLAIN`, `LOGIN`, `CRAM-MD5`) based on its own configuration and the mechanisms supported by the server. XSMTP clients **SHOULD prioritize the `PLAIN` mechanism** because it is the most common and simple to implement.
        *   **Error Handling:**
            *   If the server's response is **not** a `250` status code, or if the `250` response **does not** include the `AUTH` extension, the client **MUST immediately disconnect the TCP connection** and terminate the process, considering AUTH negotiation failed (even though STARTTLS succeeded, AUTH is mandatory).
            *   If the server's `250` response includes the `AUTH` extension, but **does not support the authentication mechanism expected by the client**, the client **MAY choose to disconnect** or **attempt other mechanisms declared by the server** (if the client supports multiple mechanisms). For implementation simplicity, it is **RECOMMENDED that the client disconnect directly when the mechanism does not match.**
    *   **Server Behavior:**
        *   Upon receiving the `EHLO` command in the encrypted channel, the server sends a `250` response, which **MUST** include the `AUTH` extension declaration and list the supported authentication mechanisms (e.g., `PLAIN`, `LOGIN`, `CRAM-MD5`). For example:
            ```
            250-<Server Hostname>
            250-SIZE 20480000
            250-AUTH PLAIN LOGIN CRAM-MD5
            250 8BITMIME
            ```
            *   `<Server Hostname>` **MUST** be consistent with the hostname used in the "220 Service Ready" message and the initial `EHLO` response, and read from the server's JSON configuration (`masquerade_hostname` field).
*   **3.2.2. AUTH Command and Authentication**
    *   **Client Behavior:**
        *   The client sends the `AUTH <Authentication Mechanism>` command based on the chosen AUTH mechanism. For example, choosing the `PLAIN` mechanism:
            ```
            AUTH PLAIN
            ```
        *   **Depending on the chosen authentication mechanism, the client may need to perform a challenge-response interaction with the server.**
            *   **PLAIN Mechanism:** The client directly sends the Base64 encoded authentication information (including optional authorization identity, authentication username, and password, separated by null bytes) either immediately after the `AUTH PLAIN` command or after receiving a `334` response from the server. The username and password should be read from the client's JSON configuration (`username` and `password` fields).
            *   **LOGIN Mechanism:** After receiving the `334 VXNlcm5hbWU6` (Base64 for "Username:") response from the server, the client sends the Base64 encoded username (read from the client's JSON configuration `username` field). The server then returns a `334 UGFzc3dvcmQ6` (Base64 for "Password:") response, and the client sends the Base64 encoded password (read from the client's JSON configuration `password` field).
            *   **CRAM-MD5 Mechanism:** After receiving the `334 <challenge>` response (Base64 encoded challenge string) from the server, the client needs to use MD5 and the secret key (password, read from the client's JSON configuration `password` field) to hash the challenge, and send the result (containing username and hash value) Base64 encoded to the server. Refer to RFC 2195 for specific algorithm details.
        *   The client waits for the server's final response to the `AUTH` command or challenge-response process.
        *   **Success Response:** If authentication is successful, the server SHOULD return a `235 2.7.0 Authentication successful` response.
            ```
            235 2.7.0 Authentication successful
            ```
            Upon receiving the `235` response, the client **enters XSMTP Data Forwarding Mode**.
        *   **Failure Response:** If authentication fails, the server SHOULD return a `535 5.7.8 Authentication credentials invalid` or other `5xx` error response (e.g., `501 5.5.4 Syntax error in parameters or arguments`, `504 5.5.1 Unrecognized authentication type`).
            ```
            535 5.7.8 Authentication credentials invalid
            ```
            Upon receiving a `5xx` error response, the client **MUST immediately disconnect the TCP connection** and terminate the process, considering AUTH authentication failed.
    *   **Server Behavior:**
        *   Upon receiving the `AUTH <Authentication Mechanism>` command, the server performs challenge-response interaction with the client according to the chosen mechanism (if required).
        *   The server **MUST** verify the authentication information (username and password) provided by the client. The verification method is **simple configuration-based verification**. The server reads the `username` and `password` fields from the server's JSON configuration file and performs an **exact match comparison** with the credentials provided by the client.
        *   **Authentication Success:** If the username and password match, the server sends a `235 2.7.0 Authentication successful` response and prepares to enter XSMTP Data Forwarding Mode.
        *   **Authentication Failure:** If the username or password does not match, the server sends a `535 5.7.8 Authentication credentials invalid` response, and **MUST handle the connection according to the standard SMTP server's handling of failed authentication traffic**, which is typically to immediately disconnect the connection.

**4. Proxy Requests**

After successful STARTTLS handshake and SMTP AUTH authentication, the XSMTP connection enters **XSMTP Data Forwarding Mode**. In this mode, the client and server exchange proxy requests and data over the established TLS encrypted channel, deviating from the standard SMTP protocol. The specific protocol and message format definitions for data forwarding mode are detailed in sections 4.1 and 4.2 of the XSMTP Protocol Specification v1.0.

**4.1. TCP Proxy**

For each TCP connection to be proxied, the client **MUST** create a new logical "TCP Stream" within the XSMTP connection and send a `TCPRequest` message.

`TCPRequest` message format:

```
[varint] 0x01 (TCPRequest Type Identifier)
[varint] Address Length
[bytes] Address String (host:port - e.g., "google.com:80")
[varint] Padding Length
[bytes] Random Padding (Optional)
```

Upon receiving a `TCPRequest`, the server **MUST** attempt to establish a TCP connection to the specified `Address String`.

The server **MUST** return a `TCPResponse` message:

```
[uint8] Status (0x00 = OK, 0x01 = Error)
[varint] Message Length
[bytes] Message String (Error message if Status is Error)
[varint] Padding Length
[bytes] Random Padding (Optional)
```

If the `TCPResponse` status is `0x00 (OK)`, the server **MUST** begin forwarding data between the XSMTP client connection and the newly established TCP connection to the target address. Data forwarding continues until either side closes the connection. Data forwarding within the TLS stream **SHOULD** be raw TCP data.

If the `TCPResponse` status is `0x01 (Error)`, the server **MUST** close the logical "TCP Stream". The client **SHOULD** handle the error appropriately.

**4.2. UDP Proxy**

UDP packets **MUST** be encapsulated in the following `UDPMessage` format and sent over the TLS encrypted TCP connection.

```
[varint] 0x02 (UDPMessage Type Identifier)
[uint32] Session ID
[uint16] Packet ID
[uint8] Fragment ID
[uint8] Fragment Count
[varint] Address Length
[bytes] Address String (host:port - e.g., "8.8.8.8:53")
[varint] Payload Length
[bytes] Payload (UDP packet payload)
```

The client **MUST** use a unique `Session ID` for each UDP session. The server **SHOULD** assign a unique UDP port for each `Session ID` for forwarding.

The protocol does not provide an explicit way to close a UDP session. The server **SHOULD** release and reassign the port associated with a `Session ID` after a period of inactivity or based on other criteria.

If the server does not support UDP relay (configurable option), it **SHOULD** silently discard all `UDPMessage` messages received from the client.

*Note: For a simplified XSMTP implementation, UDP fragmentation **MAY** be omitted.*

**5. Connection Closure and Error Handling**

*   **SMTP AUTH Authentication Failure**: If SMTP AUTH authentication fails, the server **MUST** handle the connection according to the standard SMTP server's handling of failed authentication traffic. This typically includes returning error codes such as `530 5.7.0 Authentication Required` or `535 5.7.8 Authentication credentials invalid` and immediately disconnecting the connection. Upon receiving an authentication failure error response, the client **MUST** disconnect the connection.
*   **XSMTP Connection Closure**: In XSMTP Data Forwarding Mode, the client and server can actively close the connection as needed. The method of closing the connection can be customized, such as through a custom closing signal or directly closing the TCP connection.
*   **Standard SMTP Connection Closure (Normal Termination)**: The client sends the `QUIT` command, the server returns a `221 2.0.0 Bye` response, and then both parties close the TCP connection.
*   **Other Error Handling**: During the STARTTLS handshake, SMTP AUTH authentication, and XSMTP Data Forwarding Mode, if any protocol errors or network errors occur, the XSMTP client and server **SHOULD** handle errors according to standard network programming practices, such as logging error messages, retrying connections (if applicable), and disconnecting connections.

**6. XSMTP Configuration**

XSMTP client and server configurations **MUST** follow the JSON format.

**6.1. Client Configuration (client-config.json)**

```json
{
  "protocol": "xsmtp",
  "server_ip": "your_xsmtp_server_ip",
  "server_port": 587,
  "username": "xsmtp_user",
  "password": "xsmtp_password"
}
```

**Client Configuration Field Descriptions:**

*   `protocol`:  **MUST** be `"xsmtp"`.
*   `server_ip`:  **MUST**, XSMTP server IP address.
*   `server_port`: **MUST**, XSMTP server port number.
*   `username`:  **MUST**, SMTP AUTH authentication username.
*   `password`:  **MUST**, SMTP AUTH authentication password.

**6.2. Server Configuration (server-config.json)**

```json
{
  "protocol": "xsmtp",
  "server_ip": "0.0.0.0",
  "server_port": 587,
  "masquerade_hostname": "smtp.gmail.com",
  "username": "xsmtp_server_user",
  "password": "xsmtp_server_password",
  "udp_relay": true
}
```

**Server Configuration Field Descriptions:**

*   `protocol`:  **MUST** be `"xsmtp"`.
*   `server_ip`:  **MUST**, server listening IP address, `"0.0.0.0"` indicates listening on all interfaces.
*   `server_port`: **MUST**, server listening port number.
*   `masquerade_hostname`: **MUST**, hostname used for "220 Service Ready" message and EHLO response, for masquerading. It is recommended to use a common email service provider domain.
*   `username`:  **MUST**, SMTP AUTH authentication username, used by the server to verify client identity.
*   `password`:  **MUST**, SMTP AUTH authentication password, used by the server to verify client identity.
*   `udp_relay`: **Optional**, boolean value, indicating whether to enable UDP relay functionality. Defaults to `true`. If set to `false`, the server will discard all received `UDPMessage` messages.

**7. Security Considerations**

*   **Mandatory TLS Encryption**: The XSMTP protocol **MUST** always use TLS encryption to protect all communication data, including handshake, authentication, and data forwarding.
*   **SMTP AUTH Authentication**: The XSMTP protocol **MUST** enforce SMTP AUTH authentication to verify client identity and prevent unauthorized access. The server should configure strong passwords and securely store configuration files.
*   **Masquerading**: To enhance censorship resistance, it is **STRONGLY RECOMMENDED** that the server configure `masquerade_hostname` to a common email service provider domain and carefully simulate the behavior of a standard SMTPS server.
*   **UDP Relay Security**: If UDP relay is enabled, UDP-related security risks, such as UDP Flood attacks, **MUST** be considered. Implementing rate limiting, connection number limits, and other measures can mitigate risks.

**8. Future Extensions (Optional)**

*   **UDP Fragmentation**: In the current version, UDP fragmentation is optional. Future versions may add UDP fragmentation support based on actual needs to transmit larger UDP packets.
*   **Obfuscation**: Adding an additional obfuscation layer (e.g., "Salamander" obfuscation) in XSMTP Data Forwarding Mode can be considered to further enhance protocol stealth.
*   **More Flexible Authentication**: Future versions may consider supporting more types of SMTP AUTH mechanisms or integrating with external authentication systems to provide more flexible authentication methods.
