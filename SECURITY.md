# Security

Run the API on loopback with authentication. Explicit active mode is required for extraction writes and LAN listeners. LAN listeners permit only the selected phone IPs; this is an IP access control, not cryptographic phone authentication. Capture history may contain private headers and bodies: store and share it deliberately.

HTTPS upstream certificates and hostnames are verified. Use an explicit trusted test CA for a private origin. Installing the capx CA on a phone does not imply that every application will use or trust the proxy.

Report vulnerabilities through the repository host's private vulnerability reporting feature when enabled. Until such a channel is configured, do not create public issues containing working credentials, real device data or sensitive exploit details. Describe reproducible cases using self-owned fixtures and affected versions.

The default build is the current supported security baseline. Optional process injection and native hooks require separate validation; iOS automation is not integrated. CI and vulnerability scanners supplement code review and do not constitute an all-app decryption or security guarantee.
