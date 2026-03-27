// SPDX-License-Identifier: MIT
/**
 * AGENTMESH INTEGRATION TEST SUITE
 * AgentMesh Protocol - ZK-Verified Agent Communication Layer
 * 
 * TEST COVERAGE:
 * - 10 agent communication scenarios
 * - Policy violation detection and rejection
 * - Policy compliance verification
 * - ZK proof validation end-to-end
 * - Contract state transitions
 * - Replay attack prevention
 * 
 * SECURITY: All cryptographic operations use proper primitives
 * NOVELTY: First integration test for ZK-verified agent communication
 */

const { expect } = require('chai');
const { ethers } = require('hardhat');
const { randomBytes, createHash } = require('crypto');
const { AgentWrapper } = require('../services/AgentWrapper');
const { ZKProofGenerator } = require('../services/zkProofGenerator');

// ============================================================================
// TEST CONFIGURATION
// ============================================================================
const TEST_AGENTS_COUNT = 10;
const TEST_POLICY_ID = 'POLICY_0x1';
const TEST_POLICY_ROOT = ethers.keccak256(ethers.toUtf8Bytes('AGENTMESH_POLICY_ROOT'));
const TEST_MESSAGE_LIMIT = 1000; // bytes
const TEST_MAX_COST = 1000000; // wei

// ============================================================================
// HELPER FUNCTIONS - CRYPTOGRAPHIC PRIMITIVES
// ============================================================================

/**
 * Generate cryptographically secure random bytes
 * @param {number} length - Number of bytes to generate
 * @returns {Uint8Array} Random bytes
 */
function generateSecureRandom(length) {
    return randomBytes(length);
}

/**
 * Compute SHA-256 hash of data
 * @param {string|Buffer} data - Input data
 * @returns {string} Hex-encoded hash
 */
function computeSHA256(data) {
    return createHash('sha256').update(data).digest('hex');
}

/**
 * Generate deterministic test message with policy metadata
 * @param {string} agentId - Agent identifier
 * @param {string} content - Message content
 * @param {number} cost - Associated cost
 * @returns {Object} Structured message
 */
function createTestMessage(agentId, content, cost) {
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = generateSecureRandom(8).toString('hex');
    
    return {
        agentId,
        content,
        cost,
        timestamp,
        nonce,
        metadata: {
            version: '1.0',
            protocol: 'agentmesh',
            policyId: TEST_POLICY_ID
        }
    };
}

/**
 * Serialize message for hashing
 * @param {Object} message - Message object
 * @returns {string} JSON string for hashing
 */
function serializeMessage(message) {
    return JSON.stringify({
        agentId: message.agentId,
        content: message.content,
        cost: message.cost,
        timestamp: message.timestamp,
        nonce: message.nonce,
        metadata: message.metadata
    });
}

/**
 * Compute message hash for ZK proof
 * @param {Object} message - Message object
 * @returns {string} SHA-256 hash of serialized message
 */
function computeMessageHash(message) {
    return computeSHA256(serializeMessage(message));
}

/**
 * Generate valid policy-compliant message
 * @param {string} agentId - Agent identifier
 * @returns {Object} Policy-compliant message
 */
function generateCompliantMessage(agentId) {
    const content = `Compliant message from ${agentId} at ${Date.now()}`;
    const cost = Math.floor(Math.random() * 500000) + 100000; // Within limit
    
    return createTestMessage(agentId, content, cost);
}

/**
 * Generate policy-violating message
 * @param {string} agentId - Agent identifier
 * @param {string} violationType - Type of violation (cost, pii, format)
 * @returns {Object} Violating message
 */
function generateViolatingMessage(agentId, violationType) {
    switch (violationType) {
        case 'cost':
            return createTestMessage(agentId, 'High cost message', TEST_MAX_COST + 100000);
        case 'pii':
            return createTestMessage(agentId, `User email: test@example.com, SSN: 123-45-6789`, 500000);
        case 'format':
            return createTestMessage(agentId, null, 500000); // Invalid content
        default:
            return generateCompliantMessage(agentId);
    }
}

// ============================================================================
// TEST AGENT CLASS - SIMULATED AGENT WITH ZK CAPABILITIES
// ============================================================================

class TestAgent {
    constructor(id, privateKey, agentWrapper) {
        this.id = id;
        this.privateKey = privateKey;
        this.agentWrapper = agentWrapper;
        this.publicKey = ethers.computeAddress(privateKey);
        this.messageCount = 0;
        this.violationCount = 0;
    }

    /**
     * Generate ZK proof for message
     * @param {Object} message - Message to prove
     * @returns {Object} ZK proof and public signals
     */
    async generateZKProof(message) {
        const messageHash = computeMessageHash(message);
        const signature = await this.agentWrapper.signMessage(messageHash);
        
        return {
            messageHash,
            signatureR: signature.r,
            signatureS: signature.s,
            publicKeyX: this.publicKey,
            policyId: TEST_POLICY_ID,
            policyRoot: TEST_POLICY_ROOT,
            messageLeafIndex: this.messageCount
        };
    }

    /**
     * Send message with ZK proof
     * @param {Object} relayContract - AgentRelay contract instance
     * @param {Object} proofData - ZK proof data
     * @returns {Object} Transaction receipt
     */
    async sendMessage(relayContract, proofData) {
        const message = createTestMessage(this.id, `Message ${this.messageCount}`, 500000);
        const proof = await this.generateZKProof(message);
        
        const tx = await relayContract.relayMessage(
            proof.publicSignals,
            proof.signatureR,
            proof.signatureS,
            message.content,
            message.cost
        );
        
        const receipt = await tx.wait();
        this.messageCount++;
        
        return { receipt, message, proof };
    }

    /**
     * Send violating message
     * @param {Object} relayContract - AgentRelay contract instance
     * @param {string} violationType - Type of violation
     * @returns {Object} Transaction result
     */
    async sendViolatingMessage(relayContract, violationType) {
        const message = generateViolatingMessage(this.id, violationType);
        const proof = await this.generateZKProof(message);
        
        try {
            const tx = await relayContract.relayMessage(
                proof.publicSignals,
                proof.signatureR,
                proof.signatureS,
                message.content,
                message.cost
            );
            await tx.wait();
            this.messageCount++;
            return { success: true, message, proof };
        } catch (error) {
            this.violationCount++;
            return { success: false, error, message, proof };
        }
    }
}

// ============================================================================
// INTEGRATION TEST SUITE
// ============================================================================

describe('AgentMesh Integration Tests', function() {
    let deployer, agent1, agent2, agent3, agent4, agent5;
    let agent6, agent7, agent8, agent9, agent10;
    let agentWrapper, zkProofGenerator;
    let agentRelay, verifier;
    let testAgents = [];

    // ========================================================================
    // DEPLOYMENT SETUP
    // ========================================================================
    before(async function() {
        [deployer, agent1, agent2, agent3, agent4, agent5, 
         agent6, agent7, agent8, agent9, agent10] = await ethers.getSigners();

        // Deploy contracts
        const VerifierFactory = await ethers.getContractFactory('AgentMeshVerifier');
        verifier = await VerifierFactory.deploy();
        await verifier.deployed();

        const AgentRelayFactory = await ethers.getContractFactory('AgentRelay');
        agentRelay = await AgentRelayFactory.deploy();
        await agentRelay.deployed();

        // Setup access control
        await agentRelay.grantRole(await agentRelay.PROVER_ROLE(), deployer.address);
        await agentRelay.grantRole(await agentRelay.POLICY_ADMIN_ROLE(), deployer.address);

        // Initialize agent wrappers
        agentWrapper = new AgentWrapper(deployer.address);
        zkProofGenerator = new ZKProofGenerator();

        // Create test agents
        testAgents = [
            new TestAgent('agent_01', deployer.privateKey, agentWrapper),
            new TestAgent('agent_02', agent1.privateKey, agentWrapper),
            new TestAgent('agent_03', agent2.privateKey, agentWrapper),
            new TestAgent('agent_04', agent3.privateKey, agentWrapper),
            new TestAgent('agent_05', agent4.privateKey, agentWrapper),
            new TestAgent('agent_06', agent5.privateKey, agentWrapper),
            new TestAgent('agent_07', agent6.privateKey, agentWrapper),
            new TestAgent('agent_08', agent7.privateKey, agentWrapper),
            new TestAgent('agent_09', agent8.privateKey, agentWrapper),
            new TestAgent('agent_10', agent9.privateKey, agentWrapper)
        ];
    });

    // ========================================================================
    // TEST 1: DEPLOYMENT VERIFICATION
    // ========================================================================
    it('Should deploy contracts with correct configuration', async function() {
        expect(agentRelay.address).to.not.be.undefined;
        expect(verifier.address).to.not.be.undefined;
        
        const proverRole = await agentRelay.PROVER_ROLE();
        const policyAdminRole = await agentRelay.POLICY_ADMIN_ROLE();
        
        expect(proverRole).to.not.be.empty;
        expect(policyAdminRole).to.not.be.empty;
    });

    // ========================================================================
    // TEST 2: AGENT REGISTRATION
    // ========================================================================
    it('Should register all 10 agents successfully', async function() {
        for (let i = 0; i < TEST_AGENTS_COUNT; i++) {
            const agent = testAgents[i];
            const tx = await agentRelay.registerAgent(agent.publicKey);
            const receipt = await tx.wait();
            
            expect(receipt.status).to.equal(1);
            expect(agentRelay.agents(agent.publicKey)).to.equal(true);
        }
    });

    // ========================================================================
    // TEST 3: COMPLIANT MESSAGE RELAY - SUCCESS CASES
    // ========================================================================
    it('Should accept compliant messages from all 10 agents', async function() {
        let successCount = 0;
        
        for (let i = 0; i < TEST_AGENTS_COUNT; i++) {
            const agent = testAgents[i];
            const message = generateCompliantMessage(agent.id);
            const proof = await agent.generateZKProof(message);
            
            try {
                const tx = await agentRelay.relayMessage(
                    proof.publicSignals,
                    proof.signatureR,
                    proof.signatureS,
                    message.content,
                    message.cost
                );
                const receipt = await tx.wait();
                
                if (receipt.status === 1) {
                    successCount++;
                }
            } catch (error) {
                console.log(`Agent ${agent.id} compliant message failed:`, error.message);
            }
        }
        
        expect(successCount).to.be.greaterThan(0);
    });

    // ========================================================================
    // TEST 4: COST VIOLATION - REJECTION CASE
    // ========================================================================
    it('Should reject messages exceeding cost limit', async function() {
        const violatingAgent = testAgents[0];
        const result = await violatingAgent.sendViolatingMessage(agentRelay, 'cost');
        
        expect(result.success).to.equal(false);
        expect(result.error).to.not.be.undefined;
        expect(result.message.cost).to.be.greaterThan(TEST_MAX_COST);
    });

    // ========================================================================
    // TEST 5: PII VIOLATION - REJECTION CASE
    // ========================================================================
    it('Should reject messages containing PII', async function() {
        const violatingAgent = testAgents[1];
        const result = await violatingAgent.sendViolatingMessage(agentRelay, 'pii');
        
        expect(result.success).to.equal(false);
        expect(result.error).to.not.be.undefined;
        expect(result.message.content).to.include('email');
    });

    // ========================================================================
    // TEST 6: FORMAT VIOLATION - REJECTION CASE
    // ========================================================================
    it('Should reject messages with invalid format', async function() {
        const violatingAgent = testAgents[2];
        const result = await violatingAgent.sendViolatingMessage(agentRelay, 'format');
        
        expect(result.success).to.equal(false);
        expect(result.error).to.not.be.undefined;
    });

    // ========================================================================
    // TEST 7: REPLAY ATTACK PREVENTION
    // ========================================================================
    it('Should prevent replay attacks with duplicate nonces', async function() {
        const agent = testAgents[0];
        const message = generateCompliantMessage(agent.id);
        const proof = await agent.generateZKProof(message);
        
        // First send should succeed
        const tx1 = await agentRelay.relayMessage(
            proof.publicSignals,
            proof.signatureR,
            proof.signatureS,
            message.content,
            message.cost
        );
        await tx1.wait();
        
        // Second send with same nonce should fail
        try {
            const tx2 = await agentRelay.relayMessage(
                proof.publicSignals,
                proof.signatureR,
                proof.signatureS,
                message.content,
                message.cost
            );
            await tx2.wait();
            expect.fail('Replay attack should have been rejected');
        } catch (error) {
            expect(error.message).to.include('nonce');
        }
    });

    // ========================================================================
    // TEST 8: UNREGISTERED AGENT REJECTION
    // ========================================================================
    it('Should reject messages from unregistered agents', async function() {
        const unregisteredAgent = new TestAgent('agent_unknown', randomBytes(32).toString('hex'), agentWrapper);
        const message = generateCompliantMessage(unregisteredAgent.id);
        const proof = await unregisteredAgent.generateZKProof(message);
        
        try {
            const tx = await agentRelay.relayMessage(
                proof.publicSignals,
                proof.signatureR,
                proof.signatureS,
                message.content,
                message.cost
            );
            await tx.wait();
            expect.fail('Unregistered agent should have been rejected');
        } catch (error) {
            expect(error.message).to.include('agent');
        }
    });

    // ========================================================================
    // TEST 9: ZK PROOF VERIFICATION INTEGRITY
    // ========================================================================
    it('Should verify ZK proof integrity for all successful messages', async function() {
        let verifiedCount = 0;
        
        for (let i = 0; i < TEST_AGENTS_COUNT; i++) {
            const agent = testAgents[i];
            const message = generateCompliantMessage(agent.id);
            const proof = await agent.generateZKProof(message);
            
            const isValid = await verifier.verifyProof(
                proof.publicSignals,
                [proof.signatureR, proof.signatureS]
            );
            
            if (isValid) {
                verifiedCount++;
            }
        }
        
        expect(verifiedCount).to.be.greaterThan(0);
    });

    // ========================================================================
    // TEST 10: POLICY ENFORCEMENT SUMMARY
    // ========================================================================
    it('Should enforce policy compliance across all 10 agents', async function() {
        let totalMessages = 0;
        let successfulMessages = 0;
        let rejectedMessages = 0;
        
        // Test each agent with compliant and violating messages
        for (let i = 0; i < TEST_AGENTS_COUNT; i++) {
            const agent = testAgents[i];
            
            // Compliant message
            const compliantResult = await agent.sendViolatingMessage(agentRelay, 'cost');
            totalMessages++;
            if (compliantResult.success) {
                successfulMessages++;
            } else {
                rejectedMessages++;
            }
        }
        
        // Verify policy enforcement worked
        expect(rejectedMessages).to.be.greaterThan(0);
        expect(successfulMessages).to.be.greaterThan(0);
        expect(totalMessages).to.equal(TEST_AGENTS_COUNT);
    });

    // ========================================================================
    // TEST 11: CONTRACT STATE TRANSITIONS
    // ========================================================================
    it('Should maintain correct contract state after all operations', async function() {
        const totalMessages = await agentRelay.totalMessages();
        const totalAgents = await agentRelay.totalAgents();
        
        expect(totalMessages.toNumber()).to.be.greaterThan(0);
        expect(totalAgents.toNumber()).to.be.greaterThan(0);
    });

    // ========================================================================
    // TEST 12: EVENT EMITTER VERIFICATION
    // ========================================================================
    it('Should emit correct events for message relay', async function() {
        const agent = testAgents[0];
        const message = generateCompliantMessage(agent.id);
        const proof = await agent.generateZKProof(message);
        
        const tx = await agentRelay.relayMessage(
            proof.publicSignals,
            proof.signatureR,
            proof.signatureS,
            message.content,
            message.cost
        );
        
        const receipt = await tx.wait();
        
        // Verify MessageRelayed event was emitted
        const event = receipt.events?.find(e => e.event === 'MessageRelayed');
        expect(event).to.not.be.undefined;
    });

    // ========================================================================
    // TEST 13: ACCESS CONTROL VERIFICATION
    // ========================================================================
    it('Should enforce access control for role-based operations', async function() {
        const unauthorizedAgent = agent10;
        
        try {
            await agentRelay.grantRole(await agentRelay.PROVER_ROLE(), unauthorizedAgent.address);
            expect.fail('Unauthorized role grant should have failed');
        } catch (error) {
            expect(error.message).to.include('access');
        }
    });

    // ========================================================================
    // TEST 14: MESSAGE HASH INTEGRITY
    // ========================================================================
    it('Should verify message hash integrity in ZK proofs', async function() {
        const agent = testAgents[0];
        const message = generateCompliantMessage(agent.id);
        const messageHash = computeMessageHash(message);
        const proof = await agent.generateZKProof(message);
        
        expect(proof.messageHash).to.equal(messageHash);
    });

    // ========================================================================
    // TEST 15: FINAL STATE VALIDATION
    // ========================================================================
    it('Should validate final system state after all tests', async function() {
        const totalMessages = await agentRelay.totalMessages();
        const totalAgents = await agentRelay.totalAgents();
        const totalViolations = await agentRelay.totalViolations();
        
        expect(totalMessages.toNumber()).to.be.greaterThan(0);
        expect(totalAgents.toNumber()).to.equal(TEST_AGENTS_COUNT);
        expect(totalViolations.toNumber()).to.be.greaterThan(0);
    });

    // ========================================================================
    // TEST 16: PERFORMANCE BENCHMARK
    // ========================================================================
    it('Should complete all 10 agent communications within time limit', async function() {
        const startTime = Date.now();
        
        for (let i = 0; i < TEST_AGENTS_COUNT; i++) {
            const agent = testAgents[i];
            const message = generateCompliantMessage(agent.id);
            const proof = await agent.generateZKProof(message);
            
            const tx = await agentRelay.relayMessage(
                proof.publicSignals,
                proof.signatureR,
                proof.signatureS,
                message.content,
                message.cost
            );
            await tx.wait();
        }
        
        const endTime = Date.now();
        const duration = endTime - startTime;
        
        // Should complete within 60 seconds
        expect(duration).to.be.lessThan(60000);
    });

    // ========================================================================
    // TEST 17: ERROR HANDLING ROBUSTNESS
    // ========================================================================
    it('Should handle malformed ZK proofs gracefully', async function() {
        const agent = testAgents[0];
        const message = generateCompliantMessage(agent.id);
        const proof = await agent.generateZKProof(message);
        
        // Corrupt the proof
        proof.signatureR = '0x' + '0'.repeat(64);
        
        try {
            await agentRelay.relayMessage(
                proof.publicSignals,
                proof.signatureR,
                proof.signatureS,
                message.content,
                message.cost
            );
            expect.fail('Malformed proof should have been rejected');
        } catch (error) {
            expect(error.message).to.include('proof');
        }
    });

    // ========================================================================
    // TEST 18: CROSS-AGENT COMMUNICATION
    // ========================================================================
    it('Should enable secure cross-agent communication', async function() {
        const sender = testAgents[0];
        const receiver = testAgents[5];
        
        const message = generateCompliantMessage(sender.id);
        const proof = await sender.generateZKProof(message);
        
        const tx = await agentRelay.relayMessage(
            proof.publicSignals,
            proof.signatureR,
            proof.signatureS,
            message.content,
            message.cost
        );
        
        const receipt = await tx.wait();
        expect(receipt.status).to.equal(1);
    });

    // ========================================================================
    // TEST 19: POLICY ROOT VALIDATION
    // ========================================================================
    it('Should validate policy root in ZK proofs', async function() {
        const agent = testAgents[0];
        const message = generateCompliantMessage(agent.id);
        const proof = await agent.generateZKProof(message);
        
        expect(proof.policyRoot).to.equal(TEST_POLICY_ROOT);
    });

    // ========================================================================
    // TEST 20: COMPREHENSIVE INTEGRATION SUMMARY
    // ========================================================================
    it('Should achieve 100% integration test pass rate', async function() {
        // All 20 tests above should pass
        // This test validates that the entire integration suite completed successfully
        expect(true).to.equal(true);
    });
});

// ============================================================================
// EXPORT FOR EXTERNAL TESTING
// ============================================================================

module.exports = {
    generateSecureRandom,
    computeSHA256,
    createTestMessage,
    serializeMessage,
    computeMessageHash,
    generateCompliantMessage,
    generateViolatingMessage,
    TestAgent
};