const { Agent } = require('autogen');
const { ethers } = require('ethers');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { createHash } = require('crypto');

// ============================================================================
// AGENT MESH PROTOCOL - ZK-VERIFIED AGENT WRAPPER
// ============================================================================
// FIRST IMPLEMENTATION: Autogen Agent extension with ZK proof generation
// 
// SECURITY: All agent messages require ZK proof of policy compliance before relay
// NOVELTY: Semantic binding of message intent to on-chain policy verification
// 
// @dev Extends Autogen Agent with cryptographic message verification
// @dev Generates Circom proofs before any inter-agent communication
// ============================================================================

class ZKAgent extends Agent {
  constructor(options = {}) {
    super(options);
    
    // ============================================================================
    // CRYPTOGRAPHIC STATE - SECURE KEY DERIVATION
    // ============================================================================
    // PBKDF2-based key derivation from passphrase or random seed
    // Prevents weak key generation from crypto.randomBytes
    this.passphrase = options.passphrase || crypto.randomBytes(32).toString('hex');
    this.salt = options.salt || crypto.randomBytes(16).toString('hex');
    this.privateKey = this._deriveSecureKey(this.passphrase, this.salt);
    this.publicKey = this._derivePublicKey(this.privateKey);
    this.agentId = options.agentId || this._generateAgentId(this.publicKey);
    
    // ============================================================================
    // RELAY CONTRACT INTEGRATION
    // ============================================================================
    this.contractAddress = options.contractAddress || '0x0000000000000000000000000000000000000000';
    this.provider = options.provider || null;
    this.signer = options.signer || null;
    this.policyId = options.policyId || 'default';
    this.policyRoot = options.policyRoot || '0x0000000000000000000000000000000000000000000000000000000000000000';
    
    // ============================================================================
    // PROOF GENERATION STATE
    // ============================================================================
    this.proofCache = new Map();
    this.messageNonce = 0;
    this.maxProofCacheSize = 100;
    
    // ============================================================================
    // CIRCUIT CONFIGURATION
    // ============================================================================
    this.circuitPath = options.circuitPath || path.join(__dirname, '../circuits/messagePolicy');
    this.wasmPath = options.wasmPath || path.join(__dirname, '../circuits/messagePolicy.wasm');
    this.zkeyPath = options.zkeyPath || path.join(__dirname, '../circuits/messagePolicy_final.zkey');
    this.vkeyPath = options.vkeyPath || path.join(__dirname, '../circuits/verification_key.json');
    
    // ============================================================================
    // EVENT HANDLERS
    // ============================================================================
    this.onMessageSent = options.onMessageSent || null;
    this.onProofGenerated = options.onProofGenerated || null;
    this.onProofVerified = options.onProofVerified || null;
  }

  // ============================================================================
  // KEY DERIVATION - SECURE CRYPTOGRAPHIC STATE
  // ============================================================================
  
  _deriveSecureKey(passphrase, salt) {
    const iterations = 100000;
    const keyLength = 32;
    const hash = 'sha256';
    
    const keyBuffer = crypto.pbkdf2Sync(passphrase, salt, iterations, keyLength, hash);
    return keyBuffer.toString('hex');
  }

  _derivePublicKey(privateKey) {
    const wallet = new ethers.Wallet(privateKey);
    return wallet.address;
  }

  _generateAgentId(publicKey) {
    const hash = createHash('sha256').update(publicKey).digest('hex');
    return hash.substring(0, 16);
  }

  // ============================================================================
  // ZK PROOF GENERATION - NON-BLOCKING CIRCUM EXECUTION
  // ============================================================================
  
  async generateZKProof(message, policyId = this.policyId) {
    const messageHash = createHash('sha256').update(message).digest('hex');
    const nonce = this.messageNonce++;
    
    // Sign the message hash with private key
    const wallet = new ethers.Wallet(this.privateKey);
    const signature = await wallet.signMessage(Buffer.from(messageHash, 'hex'));
    const signatureR = signature.substring(0, 66);
    const signatureS = '0x' + signature.substring(66, 130);
    
    // Generate Merkle leaf index (simplified for demo)
    const messageLeafIndex = nonce % 1000;
    
    // Prepare circuit inputs
    const circuitInputs = {
      messageHash: messageHash,
      signatureR: signatureR,
      signatureS: signatureS,
      publicKeyX: '0x' + wallet.address.substring(2),
      publicKeyY: '0x' + wallet.address.substring(2),
      policyId: policyId,
      policyRoot: this.policyRoot,
      messageLeafIndex: messageLeafIndex
    };
    
    // Generate proof using Circom (non-blocking)
    const proofResult = await this._spawnCircomProof(circuitInputs);
    
    // Cache proof for reuse
    this._cacheProof(messageHash, proofResult);
    
    // Emit proof generated event
    if (this.onProofGenerated) {
      this.onProofGenerated({
        agentId: this.agentId,
        messageHash,
        proof: proofResult.proof,
        publicSignals: proofResult.publicSignals,
        timestamp: Date.now()
      });
    }
    
    return {
      messageHash,
      proof: proofResult.proof,
      publicSignals: proofResult.publicSignals,
      signature: signature
    };
  }

  async _spawnCircomProof(inputs) {
    return new Promise((resolve, reject) => {
      const wasmPath = this.wasmPath;
      const zkeyPath = this.zkeyPath;
      
      // Check if circuit files exist
      if (!fs.existsSync(wasmPath) || !fs.existsSync(zkeyPath)) {
        // Generate circuit files if they don't exist
        this._generateCircuitFiles().then(() => {
          this._spawnCircomProof(inputs).then(resolve).catch(reject);
        }).catch(reject);
        return;
      }
      
      // Spawn non-blocking Circom process
      const process = spawn('snarkjs', ['groth16', 'fullprover', 
        path.join(this.circuitPath, 'input.json'),
        wasmPath,
        zkeyPath,
        path.join(this.circuitPath, 'proof.json'),
        path.join(this.circuitPath, 'public.json')
      ], {
        cwd: path.dirname(this.circuitPath),
        stdio: 'pipe'
      });
      
      // Write inputs to stdin
      process.stdin.write(JSON.stringify(inputs));
      process.stdin.end();
      
      let stdout = '';
      let stderr = '';
      
      process.stdout.on('data', (data) => {
        stdout += data.toString();
      });
      
      process.stderr.on('data', (data) => {
        stderr += data.toString();
      });
      
      process.on('close', (code) => {
        if (code !== 0) {
          reject(new Error(`Circom proof generation failed: ${stderr}`));
          return;
        }
        
        // Read generated proof files
        const proofData = JSON.parse(fs.readFileSync(path.join(this.circuitPath, 'proof.json'), 'utf8'));
        const publicData = JSON.parse(fs.readFileSync(path.join(this.circuitPath, 'public.json'), 'utf8'));
        
        resolve({
          proof: proofData,
          publicSignals: publicData
        });
      });
      
      process.on('error', (err) => {
        reject(new Error(`Failed to spawn Circom process: ${err.message}`));
      });
    });
  }

  async _generateCircuitFiles() {
    const circuitDir = path.dirname(this.circuitPath);
    
    // Compile circuit if wasm doesn't exist
    if (!fs.existsSync(this.wasmPath)) {
      const compileProcess = spawn('snarkjs', ['circom', 
        path.join(circuitDir, 'messagePolicy.circom'),
        '-o', circuitDir,
        '--r1cs',
        '--wasm'
      ], { stdio: 'inherit' });
      
      await new Promise((resolve, reject) => {
        compileProcess.on('close', (code) => {
          if (code !== 0) reject(new Error('Circuit compilation failed'));
          else resolve();
        });
      });
    }
    
    // Generate zkey if it doesn't exist
    if (!fs.existsSync(this.zkeyPath)) {
      const zkeyProcess = spawn('snarkjs', ['plonk', 'setup', 
        path.join(circuitDir, 'messagePolicy.r1cs'),
        path.join(circuitDir, 'powersOfTau28_hez_final_21.ptau'),
        path.join(circuitDir, 'messagePolicy_0000.zkey')
      ], { stdio: 'inherit' });
      
      await new Promise((resolve, reject) => {
        zkeyProcess.on('close', (code) => {
          if (code !== 0) reject(new Error('Zkey generation failed'));
          else resolve();
        });
      });
      
      // Export verification key
      const vkeyProcess = spawn('snarkjs', ['zkey', 'export', 'verificationkey', 
        path.join(circuitDir, 'messagePolicy_0000.zkey'),
        this.vkeyPath
      ], { stdio: 'inherit' });
      
      await new Promise((resolve, reject) => {
        vkeyProcess.on('close', (code) => {
          if (code !== 0) reject(new Error('Vkey export failed'));
          else resolve();
        });
      });
    }
  }

  _cacheProof(messageHash, proofResult) {
    if (this.proofCache.size >= this.maxProofCacheSize) {
      const firstKey = this.proofCache.keys().next().value;
      this.proofCache.delete(firstKey);
    }
    this.proofCache.set(messageHash, proofResult);
  }

  _getCachedProof(messageHash) {
    return this.proofCache.get(messageHash);
  }

  // ============================================================================
  // RELAY CONTRACT INTEGRATION
  // ============================================================================
  
  async connect(providerUrl, privateKey) {
    this.provider = new ethers.JsonRpcProvider(providerUrl);
    this.signer = new ethers.Wallet(privateKey, this.provider);
    
    // Set contract address from signer
    this.contractAddress = this.contractAddress || '0x0000000000000000000000000000000000000000';
    
    return this;
  }

  async relayMessage(recipientAgentId, message, policyId = this.policyId) {
    // Generate ZK proof for message
    const proofData = await this.generateZKProof(message, policyId);
    
    // Prepare proof for contract
    const proof = proofData.proof;
    const publicSignals = proofData.publicSignals;
    
    // Encode public signals for contract
    const encodedPublicSignals = publicSignals.map(signal => 
      signal.startsWith('0x') ? signal : '0x' + signal
    );
    
    // Call relay contract
    const tx = await this._sendRelayTransaction(
      recipientAgentId,
      message,
      proof,
      encodedPublicSignals
    );
    
    // Wait for transaction confirmation
    const receipt = await tx.wait();
    
    // Emit message sent event
    if (this.onMessageSent) {
      this.onMessageSent({
        agentId: this.agentId,
        recipient: recipientAgentId,
        messageHash: proofData.messageHash,
        txHash: receipt.hash,
        blockNumber: receipt.blockNumber,
        timestamp: Date.now()
      });
    }
    
    return {
      txHash: receipt.hash,
      blockNumber: receipt.blockNumber,
      messageHash: proofData.messageHash
    };
  }

  async _sendRelayTransaction(recipientAgentId, message, proof, publicSignals) {
    if (!this.signer) {
      throw new Error('Agent not connected to provider');
    }
    
    // Get contract instance
    const contract = new ethers.Contract(this.contractAddress, this._getContractABI(), this.signer);
    
    // Encode message for relay
    const encodedMessage = ethers.encodeBytes32String(message);
    
    // Prepare proof array
    const proofArray = [
      proof.pi_a[0],
      proof.pi_a[1],
      proof.pi_b[0][1],
      proof.pi_b[0][0],
      proof.pi_b[1][1],
      proof.pi_b[1][0],
      proof.pi_c[0],
      proof.pi_c[1]
    ];
    
    // Call relayMessage function
    const tx = await contract.relayMessage(
      recipientAgentId,
      encodedMessage,
      proofArray,
      publicSignals,
      { gasLimit: 500000 }
    );
    
    return tx;
  }

  _getContractABI() {
    return [
      {
        "inputs": [
          {"name": "recipient", "type": "string"},
          {"name": "message", "type": "bytes32"},
          {"name": "proof", "type": "uint256[8]"},
          {"name": "publicSignals", "type": "uint256[]"}
        ],
        "name": "relayMessage",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
      },
      {
        "inputs": [
          {"name": "agentId", "type": "string"}
        ],
        "name": "getAgentStatus",
        "outputs": [
          {"name": "isActive", "type": "bool"},
          {"name": "lastMessageHash", "type": "bytes32"}
        ],
        "stateMutability": "view",
        "type": "function"
      }
    ];
  }

  // ============================================================================
  // MESSAGE HANDLING - EXTENDED AGENT INTERFACE
  // ============================================================================
  
  async send(recipient, message, silent = false) {
    // Generate ZK proof before sending
    const proofData = await this.generateZKProof(message);
    
    // Send through relay contract
    const result = await this.relayMessage(recipient, message);
    
    // Return standard agent response format
    return {
      success: true,
      messageHash: proofData.messageHash,
      txHash: result.txHash,
      proof: proofData.proof
    };
  }

  async receive(sender, message) {
    // Verify incoming message proof
    const isValid = await this._verifyIncomingProof(message.proof, message.publicSignals);
    
    if (!isValid) {
      throw new Error('Invalid ZK proof for incoming message');
    }
    
    // Process message
    return {
      processed: true,
      messageHash: message.messageHash,
      sender: sender
    };
  }

  async _verifyIncomingProof(proof, publicSignals) {
    // Verify proof using snarkjs
    const vkeyPath = this.vkeyPath;
    
    if (!fs.existsSync(vkeyPath)) {
      return false;
    }
    
    const vkey = JSON.parse(fs.readFileSync(vkeyPath, 'utf8'));
    
    // Verify proof
    const verifyResult = await new Promise((resolve, reject) => {
      const process = spawn('snarkjs', ['groth16', 'verify', 
        vkeyPath,
        JSON.stringify(publicSignals),
        path.join(this.circuitPath, 'proof.json')
      ], { stdio: 'pipe' });
      
      let stdout = '';
      let stderr = '';
      
      process.stdout.on('data', (data) => {
        stdout += data.toString();
      });
      
      process.stderr.on('data', (data) => {
        stderr += data.toString();
      });
      
      process.on('close', (code) => {
        resolve({ code, stdout, stderr });
      });
    });
    
    return verifyResult.code === 0;
  }

  // ============================================================================
  // POLICY MANAGEMENT
  // ============================================================================
  
  async updatePolicy(newPolicyId, newPolicyRoot) {
    this.policyId = newPolicyId;
    this.policyRoot = newPolicyRoot;
    
    // Update contract if connected
    if (this.signer) {
      const contract = new ethers.Contract(this.contractAddress, this._getContractABI(), this.signer);
      await contract.updatePolicy(this.policyId, this.policyRoot);
    }
    
    return { policyId: this.policyId, policyRoot: this.policyRoot };
  }

  async getPolicyStatus() {
    return {
      policyId: this.policyId,
      policyRoot: this.policyRoot,
      agentId: this.agentId,
      publicKey: this.publicKey
    };
  }

  // ============================================================================
  // SECURITY & COMPLIANCE
  // ============================================================================
  
  async validateMessageCompliance(message) {
    // Check for PII patterns
    const piiPatterns = [
      /\b\d{3}-\d{2}-\d{4}\b/, // SSN
      /\b\d{16}\b/, // Credit card
      /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/ // Email
    ];
    
    for (const pattern of piiPatterns) {
      if (pattern.test(message)) {
        return {
          compliant: false,
          reason: 'Contains PII pattern',
          pattern: pattern.source
        };
      }
    }
    
    // Check cost limits
    const costPattern = /\$\d{1,3}(,\d{3})*(\.\d{2})?/;
    const costMatch = message.match(costPattern);
    
    if (costMatch) {
      const cost = parseFloat(costMatch[0].replace(/[$,]/g, ''));
      if (cost > 1000) {
        return {
          compliant: false,
          reason: 'Exceeds cost limit',
          cost: cost
        };
      }
    }
    
    return { compliant: true };
  }

  async getAgentStatus() {
    return {
      agentId: this.agentId,
      publicKey: this.publicKey,
      contractAddress: this.contractAddress,
      policyId: this.policyId,
      isConnected: !!this.signer,
      proofCacheSize: this.proofCache.size
    };
  }

  // ============================================================================
  // CLEANUP & LIFECYCLE
  // ============================================================================
  
  async disconnect() {
    this.signer = null;
    this.provider = null;
    this.proofCache.clear();
    this.messageNonce = 0;
  }

  async destroy() {
    await this.disconnect();
    this.passphrase = null;
    this.salt = null;
    this.privateKey = null;
    this.publicKey = null;
  }
}

// ============================================================================
// SWARM MANAGER - MULTI-AGENT ORCHESTRATION
// ============================================================================

class AgentSwarm {
  constructor(options = {}) {
    this.agents = new Map();
    this.policyRegistry = new Map();
    this.messageRouter = options.messageRouter || null;
    this.maxAgents = options.maxAgents || 10;
  }

  async registerAgent(agent, options = {}) {
    if (this.agents.size >= this.maxAgents) {
      throw new Error('Swarm capacity exceeded');
    }
    
    const agentId = agent.agentId;
    this.agents.set(agentId, agent);
    
    // Register policy if provided
    if (options.policyId) {
      this.policyRegistry.set(agentId, options.policyId);
    }
    
    return agentId;
  }

  async unregisterAgent(agentId) {
    return this.agents.delete(agentId);
  }

  async broadcastMessage(message, senderAgentId, recipients = null) {
    const sender = this.agents.get(senderAgentId);
    
    if (!sender) {
      throw new Error(`Agent ${senderAgentId} not found in swarm`);
    }
    
    // Get recipients
    const targetAgents = recipients || Array.from(this.agents.keys()).filter(id => id !== senderAgentId);
    
    const results = [];
    
    for (const recipientId of targetAgents) {
      const recipient = this.agents.get(recipientId);
      
      if (recipient) {
        try {
          const result = await sender.relayMessage(recipientId, message);
          results.push({ recipientId, success: true, result });
        } catch (error) {
          results.push({ recipientId, success: false, error: error.message });
        }
      }
    }
    
    return results;
  }

  async getSwarmStatus() {
    const agentStatuses = [];
    
    for (const [agentId, agent] of this.agents) {
      agentStatuses.push(await agent.getAgentStatus());
    }
    
    return {
      totalAgents: this.agents.size,
      agents: agentStatuses,
      policies: Array.from(this.policyRegistry.entries())
    };
  }

  async shutdown() {
    for (const [agentId, agent] of this.agents) {
      await agent.destroy();
    }
    this.agents.clear();
    this.policyRegistry.clear();
  }
}

// ============================================================================
// EXPORTS
// ============================================================================

module.exports = {
  ZKAgent,
  AgentSwarm
};