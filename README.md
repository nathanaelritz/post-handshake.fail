# Proof of Insecurity of Post-handshake Attestation 🤷

> [!NOTE]
>  [draft-fossati-seat-expat-05](https://www.ietf.org/archive/id/draft-fossati-seat-expat-05.html#section-4-4.2.1) closes the gaps outlined in this report. However, the current language of -05 incidentally disqualifies the use of cached Attestation Results. This operational concern is a separate issue we expect will be resolved over time. The original report for `draft-fossati-seat-expat-04` is below.

### Impact analysis of draft-fossati-seat-expat-04

This report details a critical specification flaw in [Section 4](https://www.ietf.org/archive/id/draft-fossati-seat-expat-04.html#section-4-4.2.1) of `draft-fossati-seat-expat-04` regarding the Passport Model. By omitting the requirement for the Relying Party to cross-check the Authenticator Identity Key (AIK) against the Attestation Result (AR), the current text completely breaks the cryptographic binding between the Attestation Credential and the TLS connection.

Symbolic analysis in ProVerif demonstrates high risk if implementations strictly follow the seat-expat-04 text, and may become vulnerable to **unconstrained cross-connection AR replay** and **full MITM (Machine-in-the-Middle) impersonation**: nullifying the primary security guarantees of Attested TLS.

---

####  Background

According to the abstract, Remote Attestation with Exported Authenticators should support both the passport and background check models from the RATS architecture while ensuring that attestation remains bound to the underlying communication channel. Unfortunately, as highlighted in [Issue #67](https://github.com/tls-attestation/exported-attestation/issues/67#issue-5931968911), the draft provides only the following validation steps for the Passport Model:

> "Verify the Attestation Result: The Relying Party MUST check that the Attestation Result is correctly signed by the issuing authority and that it meets the Relying Party's security requirements."

The initial architectural challenge was shared first shared in [in July on the SEAT mailing list](https://mailarchive.ietf.org/arch/msg/seat/Xwf2c1jfUWeGgHjWGFliKqtqANM/):

> "The challenge the charter requirement gives us when the TLS client is the
> RP and the TLS server is the Attester is that we do not seem to have a
> common understanding (let alone a performant approach) for binding a cached
> Attestation Result (AR) on a per-connection basis."

As Imran Siddique later followed up on [October 19th](https://github.com/tls-attestation/exported-attestation/issues/67#issue-5931968911), it was further clarified that a Relying Party implementation strictly following the passport text found in seat-expat-04 would accept "any Attestation Result the Verifier signed, for any AIK, on any connection."

Certain risks persist if seat-expat continues to advance without integrating the remediation proposed in Issue #67:

* **Vulnerable Implementations**: Developers implementing the Passport Model to the letter of the specification will introduce systemic vulnerabilities. They may assume the TLS library handles binding, while the TLS library assumes the application validates the claims.

* **False Security Assurances in Confidential Computing:** Systems deploying this protocol under the assumption of hardware-enforced enclave protection will leak sensitive application workloads directly to active network adversaries, completely defeating the purpose of TEE-based workload isolation.

---

#### The Specification Flaw in seat-expat-04: Cross-Connection AR Replay

Because the specification text does not mandate the binding check, an active attacker can execute the following identity-spoofing attack:

1. **Interception**: The Attacker monitors a legitimate Server and harvests a valid, Verifier-signed Attestation Result (AR) intended for the Server's authentic key (`pubEK_server`).

2. **Connection Establishment**: The Attacker initiates a new TLS session with a Client (the Relying Party) using an ephemeral key generated entirely by the Attacker (`pubEK_attacker`).

3. **Replay**: During the Exported Authenticator post-handshake phase, the Attacker embeds the harvested AR alongside their own `pubEK_attacker` in the Certificate message, and signs the CertificateVerify with their own private key.

4. **Exploitation**: Following Section 4 of seat-expat-04, the Client verifies the Verifier's signature on the AR. It succeeds. The Client accepts the connection.

**Result**: The Client believes it has established a secure session with a Trusted Execution Environment (TEE). In reality, the attacker holds the TLS application traffic secrets.

---

#### Formal Verification Impact (ProVerif Analysis)

The absence of the `pubEK_cnf = pubEK` check structurally collapses the security proofs in the formal model. The failure of the following queries mathematically proves that the protocol, as written in Section 4, fails its primary security objectives:

| Security Goal | ProVerif Query Impact | Practical Consequence |
| --- | --- | --- |
| **Composition Agreement** | `ClientEAComp ==> ServerEAComp` evaluates to false. | The Client finishes the EA handshake with different parameters than the Server. An attacker can hijack the post-handshake phase without compromising the TEE. |
| **Attestation Binding** | `ClientRA ==> ServerRA` evaluates to false. | Attestation parameters (like device state) are completely uncoupled from the TLS session identity. |
| **Server Authentication** | `ClientFinishedWithID ==> PreServerFinishedWithID` evaluates to false. | MitM is viable. If Web PKI CA trust is removed or compromised, the protocol offers zero defense against server impersonation. |
| **Claim Freshness & Attribution** | `AcceptedRdata ==> SentRdata` evaluates to false. | Per-session measurement freshness per [RFC9334](https://www.rfc-editor.org/rfc/rfc9334.html#name-freshness) is invalidated. The Relying Party accepts measurements harvested from past or foreign sessions, allowing untrusted machines to claim valid reference states regardless of expiry. |
| **Evidence Delivery Authenticity** | `ClientConn ==> Sent` evaluates to false. | Evidence provenance is broken. An adversary can forward or substitute genuine attestation tokens, binding the connection to evidence the peer never asserted. |
| **Application Traffic Secrecy** | `attacker(kc) ==> LeakedEK` evaluates to false. | Transport confidentiality collapses. The adversary negotiates the TLS session directly with their own keys, holding application traffic secrets (`kc`) in the clear without compromising the TEE. |
| **Composite State Synchronization** | `ClientComp ==> PreServerComp` evaluates to false. | The protocol establishes a spliced session state, binding lower-layer adversary TLS parameters to upper-layer legitimate attestation evidence. |

#### Detailed Breakdown of Cascading Failures

Beyond the initial breakdown of server authentication, the lack of confirmation binding triggers systemic failures across multiple operational guarantees:

* **Loss of Evidentiary Claim Freshness (`AcceptedRdata ==> SentRdata`)**: While the Relying Party successfully validates the cryptographic signature of the Attestation Result against reference values (`dev_statusRef`), it fails to verify that the claims belong to the active connection. An attacker can indefinitely replay captured, valid attestation tokens, causing the Relying Party to accept stale or third-party platform measurements.

* **Failure of Evidence Delivery Provenance (`ClientConn ==> Sent`)**: The protocol fails to prove that the authentic server intended to present the evidence in question to this specific client. An active adversary can intercept and splice legitimate quotes into rogue sessions, creating false provenance without possessing the underlying signing keys.

* **Total Exposure of Post-Handshake Application Traffic (`attacker(kc) ==> LeakedEK` / `LeakedAK`)**: In a secure attested channel, application data keys (`kc`) should be compromised only if the attestation key (`privAK`) or ephemeral key (`privEK`) is leaked. Because the attacker supplies their own ephemeral keypair during the handshake while replaying the victim's Attestation Result, the attacker derives and controls `kc` directly. All subsequent encrypted application traffic is exposed in plaintext to the adversary despite the Relying Party verifying valid attestation.

* **Session State Desynchronization (`ClientComp ==> PreServerComp`)**: Injective agreement over the full composite state fails unconditionally. The client’s state machine records an active connection bound to the adversary’s handshake parameters alongside the victim server's attestation identity, destroying the cryptographic continuum required between transport security and hardware attestation.

#### Recommendations for Remediation

Thankfully, the recommended action for remediation is straightforward. We recommend the authors of draft-fossati-seat-expat update the Passport Model validation steps in Section 4 so that the text explicitly requires that an Attestation Credential, (such as a cached AR), it must enable a Relying Party to cross-check the public key used to sign the authenticator's `CertificateVerify` message. 


### Appendix: The Applied Cryptography Behind the Fix

The [Security Considerations](https://www.rfc-editor.org/info/rfc9261/#name-security-considerations) of RFC 9261 note the underlying foundation of Exported Authenticators:

> "The Certificate/Verify/Finished pattern intentionally looks like the TLS 1.3 pattern that now has been analyzed several times. For example, [SIGMAC] presents a relevant framework for analysis, and Appendix E.1.6 of [RFC8446] contains a comprehensive set of references."


The recommended remediation—requiring the Relying Party to explicitly verify that the public key authenticated in the Exported Authenticator matches the key certified within the Attestation Result (`pubEK_cnf == pubEK`)—rests on four core principles of applied protocol cryptography:

---

#### 1. RFC 9261 Implements an Autonomous "Shadow" TLS 1.3 Flight

RFC 9261 acts as an application-layer replica of the TLS 1.3 authentication exchange, decoupled from transport record framing. Rather than altering the underlying TLS state machine, it extracts two directional, session-bound secrets from the TLS Exporter Master Secret (`ems`) via the TLS-Exporter interface (`RFC 8446` §7.5).

Because `CertificateVerify` is signed by the private key corresponding to `pubEK` over the synthetic transcript hash (containing the connection-derived handshake context, the request message, and the certificate), RFC 9261 provides explicit, unforgeable **Proof of Possession (PoP)** of `privEK` bound to the active TLS session, following in the security properties of TLS 1.3 itself. 

---

#### 2. Wire-Level Freshness Injection in the Passport Model

The RATS architecture distinguishes two primary conveyance models based on where and when evidence is appraised:

* **Background-Check Model**: The Attester produces Evidence dynamically during connection establishment, allowing a fresh session nonce or transcript checkpoint to be embedded directly into the hardware quote at origin.

* **Passport Model**: Evidence is appraised asynchronously out-of-band by an off-path Verifier. The resulting Attestation Result (AR) is signed by the Verifier (`pubARK`), cached by the Attester, and subsequently presented across multiple transport connections to reduce transport latency.

Because an Attestation Result in the Passport model is pre-computed, the token itself cannot carry a session-specific nonce from an uninitiated TLS handshake. Freshness cannot be generated at origin; it must be established at the transport wire.

RFC 9261 accomplishes this by executing a live Proof-of-Possession flight. Even though the Attestation Result is static, the `CertificateVerify` signature generated by `privEK` is computed dynamically over the active session's transcript. This transforms the static, cached credential into an ephemeral, connection-bound assertion.

---

#### 3. Cryptographic Key Confirmation as the Transitive Bridge

The live Proof-of-Possession flight proves that the peer holds `privEK` on the active connection. The Verifier's signature on the Attestation Result proves that a genuine Trusted Execution Environment (TEE) exists with verified reference values.

However, these two operations originate in independent cryptographic domains. The remediation—enforcing `pubEK_cnf == pubEK`—acts as the transitive bridge linking them:

```
Live TLS Connection
       │
       │  RFC 9261 Proof of Possession (CertificateVerify over ems transcript)
       ▼
  [ pubEK ]
       │
       │  Strict Equality Check (pubEK_cnf == pubEK)
       ▼
 [ pubEK_cnf ]  (Confirmation Claim inside Attestation Result)
       │
       │  Verifier Signature (pubARK) over TEE measurements
       ▼
Attested Enclave (TEE)

```

1. **Transport Binding**: RFC 9261 cryptographically binds `pubEK` to the live TLS session.

2. **Key Confirmation**: The Relying Party verifies that `pubEK` matches the key confirmation claim `pubEK_cnf` embedded in the Verifier-signed token.

3. **Platform Integrity**: The Verifier's signature over `pubEK_cnf` confirms that the key pair was generated inside, and remains confined to, the attested enclave boundary.

By verifying `pubEK_cnf == pubEK`, the Relying Party establishes transitive closure: the entity terminating the TLS connection is mathematically guaranteed to be the exact execution environment validated by the Verifier.

---

#### 4. Fail-Closed Binding Semantics

Requiring the Relying Party to cross-check `pubEK_cnf == pubEK` establishes a fail-closed guarantee. It prevents an untrusted host or active intermediary from decoupling valid hardware evidence from an unconfined transport session, ensuring that neither session replay nor key substitution can compromise the attested channel.

## Acknowledgements

This work is a unique adaptation and extension incorporating input from the following prior art:

* [Identity Crisis in Confidential Computing: Formal analysis of attested TLS protocols](https://github.com/CCC-Attestation/formal-spec-id-crisis/tree/main)
* [Intra-handshake.fail (CVE-2026-33697): High-severity CVE in Attested TLS](https://www.researchgate.net/publication/408219182_Intra-handshakefail_CVE-2026-33697_High-severity_CVE_in_Attested_TLS)
* [Verified Models and Reference Implementations for the TLS 1.3 Standard Candidate](https://ieeexplore.ieee.org/document/7958594)

Thank you to all involved authors and researchers!

## Copyright and License

Copyright 2017 Bhargavan et al.
Copyright 2026 Sardar et al.
Copyright 2026 Nathanael Ritz.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
