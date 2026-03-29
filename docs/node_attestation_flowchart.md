# SPIRE PKCS#11 X.509 POP Node Attestation Sequence Diagram

This sequence diagram illustrates the interaction between the SPIRE Agent and SPIRE Server during the node attestation process for the PKCS#11 X.509 Proof of Possession (POP) plugin.

## Sequence Diagram

```mermaid
sequenceDiagram
    participant Agent as SPIRE Agent
    participant Server as SPIRE Server

    Note over Agent,Server: Attestation Start
    Agent->>Agent: Load X.509 Certificate Chain from PEM
    Agent->>Server: Send Certificate Chain
    Server->>Server: Validate Certificate Chain against CA Bundle
    alt Certificate Valid
        Server->>Agent: Send Random Nonce (Challenge)
        Agent->>Agent: Initialize PKCS#11 Client (Load Module, Open Session)
        Agent->>Agent: Find Private Key by ID/Label
        Agent->>Agent: Sign Nonce using PKCS#11 Private Key
        Agent->>Server: Send Signature
        Server->>Server: Verify Signature using Leaf Certificate Public Key
        alt Signature Valid
            Server->>Server: Extract SPIFFE ID and Selectors from Certificate
            Server->>Agent: Return Attestation Result (SPIFFE ID)
            Note over Agent,Server: Attestation Success
        else Signature Invalid
            Server->>Agent: Reject Attestation
            Note over Agent,Server: Attestation Failure
        end
    else Certificate Invalid
        Server->>Agent: Reject Attestation
        Note over Agent,Server: Attestation Failure
    end
```

## Description

- **Agent Side**: The SPIRE agent loads the X.509 certificate chain, sends it to the server, receives a nonce challenge, signs it using a PKCS#11 token (e.g., SoftHSM or YubiKey), and returns the signature.
- **Server Side**: The SPIRE server validates the certificate chain, sends a nonce, verifies the signature, and issues a SPIFFE ID if successful.
- **Key Features**: Uses PKCS#11 for secure key management and Proof of Possession to ensure the agent possesses the private key corresponding to the certificate.