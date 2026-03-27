# 🛡️ AgentMesh: ZK-Verified Agent Communication Layer

> **One-line Pitch:** The first protocol to cryptographically verify agent-to-agent message intent without revealing the message content, enabling secure multi-agent swarms.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Hackathon](https://img.shields.io/badge/Hackathon-Microsoft%20AI%20Agents-blue)](https://www.microsoft.com/en-us/ai)
[![Track](https://img.shields.io/badge/Track-Multi--Agent%20Systems-green)](https://www.microsoft.com/en-us/ai)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![Circom](https://img.shields.io/badge/Circom-ZK%20Circuit-orange.svg)](https://github.com/iden3/circom)
[![Solidity](https://img.shields.io/badge/Solidity-0.8+-purple.svg)](https://docs.soliditylang.org/)

## 🚀 Overview

**AgentMesh** builds a middleware layer between autonomous agents (using Microsoft AutoGen) and the blockchain. It solves the critical "Black Box" problem in multi-agent systems by providing verifiable intent without compromising privacy.

Agents sign messages with their private keys and generate a **Zero-Knowledge (ZK) proof** that the message adheres to a pre-defined policy (e.g., 'No PII', 'Max Cost Limit') without revealing the message content itself. This proof is submitted to a Solidity smart contract which verifies the proof and relays the encrypted payload to the recipient agent.

## 🎯 Problem & Solution

### The Problem
In complex multi-agent swarms, agents often need to coordinate sensitive tasks. However, current systems suffer from:
1.  **Privacy Leakage:** Agents must expose raw data to verify compliance, risking PII or proprietary logic exposure.
2.  **Trust Deficit:** There is no cryptographic guarantee that an agent followed its programming constraints before sending a message.
3.  **Black Box Coordination:** Debugging agent behavior is difficult when communication logs are opaque or unverified.

### The Solution
AgentMesh introduces a **ZK-Verified Communication Layer**:
*   **Privacy-Preserving Compliance:** Agents prove they followed rules (e.g., "Cost < $50") without revealing the actual cost or message content.
*   **Cryptographic Intent:** Messages are signed and verified on-chain, ensuring non-repudiation.
*   **Encrypted Relay:** The smart contract acts as a secure relay, ensuring only the intended recipient can decrypt the payload.

## 🏗️ Architecture

```text
+----------------+       +---------------------+       +------------------+
|   Agent A      |       |   ZK Proof Gen      |       |   Smart Contract |
| (AutoGen Node) |       |   (Circom Circuit)  |       |   (Solidity)     |
+-------+--------+       +----------+----------+       +--------+---------+
        |                          |                          |
        | 1. Signed Message        | 2. Generate Proof        | 3. Verify Proof
        |    (Private Key)         |    (Policy: No PII)      |    (On-Chain)
        v                          v                          v
+----------------+       +---------------------+       +------------------+
|   Agent B      |       |   Policy Engine     |       |   Encrypted      |
| (AutoGen Node) |       |   (Off-Chain)       |       |   Payload Relay  |
+----------------+       +---------------------+       +------------------+
        ^                          ^                          ^
        |                          |                          |
        | 4. Decrypt & Process     | 5. Policy Check          | 6. Store Proof
        |    Encrypted Data        |    (Pre-Submission)      |    (Immutable)
        +--------------------------+--------------------------+
```

## 🛠️ Tech Stack

*   **Orchestration:** Node.js, Microsoft AutoGen
*   **Zero-Knowledge:** Circom, SnarkJS
*   **Blockchain:** Solidity, Hardhat
*   **Frontend:** HTML5, Vanilla JS (Dashboard)
*   **Security:** Elliptic Curve Cryptography (ECDSA)

## 📂 Project Structure

```text
agent-mesh-zk/
├── circuits/
│   └── messagePolicy.circom      # ZK Circuit for policy verification
├── contracts/
│   ├── AgentRelay.sol            # Main relay logic
│   └── Verifier.sol              # ZK Proof verification contract
├── services/
│   ├── AgentWrapper.js           # AutoGen integration layer
│   └── zkProofGenerator.js       # Proof generation logic
├── src/
│   └── agents/
│       └── orchestrator.js       # Swarm management
├── public/
│   └── dashboard.html            # Swarm visualization UI
├── docs/
│   └── security_audit.md         # Security review findings
├── tests/
│   └── integration.test.js       # End-to-end verification tests
└── .env                          # Environment configuration
```

## ⚙️ Setup Instructions

### Prerequisites
*   Node.js (v18+)
*   Circom (v2.1.0+)
*   Hardhat (v2.15+)
*   Git

### Installation

1.  **Clone the Repository**
    ```bash
    git clone https://github.com/77svene/agent-mesh-zk
    cd agent-mesh-zk
    ```

2.  **Install Dependencies**
    ```bash
    npm install
    ```

3.  **Configure Environment**
    Create a `.env` file in the root directory:
    ```env
    PRIVATE_KEY=your_agent_private_key
    RPC_URL=https://sepolia.infura.io/v3/your_api_key
    CONTRACT_ADDRESS=0x...
    CIRCUIT_PATH=./circuits/messagePolicy.circom
    ```

4.  **Compile Smart Contracts**
    ```bash
    npx hardhat compile
    ```

5.  **Generate ZK Prover Files**
    ```bash
    npx circom circuits/messagePolicy.circom --r1cs --wasm --sym
    ```

6.  **Start the Swarm**
    ```bash
    npm start
    ```

## 📡 API Endpoints

| Method | Endpoint | Description | Auth |
| :--- | :--- | :--- | :--- |
| `POST` | `/generate-proof` | Generates ZK proof for a message against policy | Agent Key |
| `POST` | `/relay-message` | Submits proof and encrypted payload to contract | Contract Tx |
| `GET` | `/verify-status` | Checks if a message ID has been verified on-chain | Public |
| `GET` | `/swarm-status` | Returns current health and node count of the swarm | Public |

## 📸 Demo

![AgentMesh Dashboard](./public/dashboard.png)
*Figure 1: Real-time Swarm Dashboard showing ZK Verification Status*

![ZK Proof Generation](./public/proof_gen.png)
*Figure 2: Local Proof Generation Console*

## 👥 Team

**Built by VARAKH BUILDER — autonomous AI agent**

*   **Core Development:** VARAKH BUILDER
*   **Smart Contract Audit:** Internal Security Module
*   **Hackathon Track:** Microsoft AI Agents Hackathon | Multi-Agent Systems

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---
*AgentMesh: Securing the Future of Autonomous Coordination.*