# XSMTP Proxy Protocol

note: The "dev" branch is under heavy development. Use at your own risk.

## Introduction

XSMTP (eXtended SMTPS Proxy) is a lightweight proxy protocol designed to circumvent network censorship by masquerading as legitimate SMTPS (SMTP over TLS) traffic. It establishes a connection that initially resembles a standard SMTPS session, complete with TLS encryption and SMTP authentication, before transitioning into a data forwarding mode for general-purpose proxying. This masquerading technique aims to make XSMTP traffic blend in with regular email communication, thus evading detection and blocking by censorship systems that might be looking for proxy-specific signatures.

**Disclaimer:** XSMTP is intended for research and educational purposes in circumventing network censorship. Use it responsibly and at your own risk. No warranty is provided.

## Key Features

*   **SMTPS Masquerading:**  Mimics the initial handshake and authentication process of the SMTPS protocol, making it harder to distinguish from legitimate email traffic.
*   **TLS Encryption:**  All communication after the initial handshake is encrypted using TLS, ensuring data confidentiality and integrity.
*   **Mandatory SMTP AUTH:**  Requires SMTP Authentication (AUTH) for client verification, adding another layer of security and mimicking standard SMTPS behavior. Supports PLAIN, LOGIN, and CRAM-MD5 authentication mechanisms.
*   **TCP and UDP Proxying:** Supports proxying both TCP and UDP traffic, enabling a wide range of applications.
*   **Simple Configuration:**  Configuration is managed through easy-to-edit JSON files for both client and server.
*   **Lightweight and Efficient:** Designed for minimal overhead, focusing on core proxy functionality and SMTPS masquerade.

## Usage

### Server Setup

1.  **Configuration:**
    *   Create a `server-config.json` file with the following structure (example):

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

    *   **Configuration Field Descriptions:**
        *   `protocol`:  **MUST** be `"xsmtp"`.
        *   `server_ip`:  **MUST**, server listening IP address (`"0.0.0.0"` for all interfaces).
        *   `server_port`: **MUST**, server listening port number (e.g., `587` or `25`).
        *   `masquerade_hostname`: **MUST**, hostname for "220 Service Ready" and EHLO responses (e.g., `"smtp.gmail.com"`). Choose a common email service provider domain for better masquerading.
        *   `username`:  **MUST**, SMTP AUTH username for server-side authentication.
        *   `password`:  **MUST**, SMTP AUTH password for server-side authentication.
        *   `udp_relay`: **Optional**, boolean, enable/disable UDP relay (defaults to `true`).

2.  **Run the XSMTP Server:**
    *   (Implementation-specific instructions will be added here once server-side code is available.  This would typically involve running an executable or script that loads `server-config.json` and starts the XSMTP server.)

### Client Setup

1.  **Configuration:**
    *   Create a `client-config.json` file with the following structure (example):

    ```json
    {
      "protocol": "xsmtp",
      "server_ip": "your_xsmtp_server_ip",
      "server_port": 587,
      "auth": "login",
      "username": "xsmtp_user",
      "password": "xsmtp_password"
    }
    ```

    *   **Configuration Field Descriptions:**
        *   `protocol`:  **MUST** be `"xsmtp"`.
        *   `server_ip`:  **MUST**, IP address of your XSMTP server.
        *   `server_port`: **MUST**, port number of your XSMTP server.
        *   `username`:  **MUST**, SMTP AUTH username for authentication (must match server configuration).
        *   `password`:  **MUST**, SMTP AUTH password for authentication (must match server configuration).

2.  **Run the XSMTP Client:**
    *   (Implementation-specific instructions will be added here once client-side code is available. This would typically involve running an executable or script that loads `client-config.json` and establishes a connection to the XSMTP server.)

3.  **Proxy Usage:**
    *   Once the XSMTP client is running and connected, configure your applications (e.g., web browser, other software) to use the XSMTP client as a SOCKS5 or HTTP proxy (depending on the client implementation). The client will handle forwarding traffic through the XSMTP server.

## Protocol Details

For detailed information about the XSMTP protocol, message formats, and handshake procedures, please refer to the [XSMTP Protocol Specification](SPEC.md).

## Security Considerations

*   **TLS Encryption is Mandatory:** XSMTP relies on TLS encryption to secure all communication. Ensure TLS is correctly implemented and enabled on both client and server.
*   **SMTP AUTH is Mandatory:**  SMTP AUTH is enforced for client authentication. Use strong and unique usernames and passwords. Securely store your configuration files.
*   **Masquerading for Censorship Resistance:** The effectiveness of XSMTP in bypassing censorship depends on the accuracy of SMTPS protocol emulation and the sophistication of censorship techniques. Regularly update and refine configurations to maintain masquerading effectiveness.
*   **UDP Relay Security:** If UDP relay is enabled, be aware of potential UDP-related security risks. Consider implementing rate limiting and connection limits on the server to mitigate potential abuse.

## Future Extensions (Optional)

*   **UDP Fragmentation:**  Support for UDP fragmentation can be added to handle larger UDP packets if needed.
*   **Obfuscation:**  Further traffic obfuscation techniques can be implemented to enhance stealth and resistance to advanced censorship methods.
*   **Flexible Authentication:**  Support for more SMTP AUTH mechanisms or integration with external authentication systems could be added for increased flexibility.

## License

[MIT License](LICENSE)
