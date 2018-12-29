# Cryptography, Security and Privacy

## Cryptography

DSD uses modern cryptographic primitives provided by libsodium, specifically Ed25519 for signing, and XSalsa20/Poly1305 for symmetric encryption / decryption, and SHA-256 hashes. It is intended that future protocol versions may support alternative cryptographic functions, and fields have been reserved for this possibility.


## Threats
- Service Impersonation / Hijacking / Person in the Middle
- Information Leakage / Privacy
- Denial of Service
- Misuse

## Mitigations

Service impersonation is mitigated through the use of cryptographically derived service identifiers and public key signatures, requiring the associated public-private key pair to publish pages or send messages as a service. These keys are pinned on first use, decreasing the opportunity for collision attacks were it possible to generate a colliding public/private key pair with the same service ID. In addition, on receiving a message the peer MAY perform a page lookup to validate the id and public key match those attached to the message, (though this MUST be ignored if no results are found to allow node bootstrapping).

Privacy is provided using symmetric encryption over page body and secure option fields. This allows services to be published to DSD while containing private information such as IP Addresses or other metadata. In order to perform successful discovery of encrypted services the discovering party must have a copy of the symmetric encryption key.

Denial of service attacks are mitigated through the use of cryptographic identities (increasing the cost of creating arbitrary nodes) as well as using an aggressive approach to temporarily blocking clients and addresses on a per-node basis.

A danger of any distributed system is abuse for storage or other malicious purposes. This is considered to be an undesirable but unavoidable side effect of designing secure and privacy preserving software. The impact of this abuse is mitigated in DSD through the use of strictly typed messages, size limits on encrypted (and thus un-observable) fields, and client rate limiting. As a further mitigation it is proposed that shared blocklists may be used to permanently disable known bad nodes.
