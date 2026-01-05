// Copyright (c) Suirify Protocol, Inc.
// SPDX-License-Identifier: GPL-3.0
import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { Transaction } from '@mysten/sui/transactions';
import { decodeSuiPrivateKey } from '@mysten/sui/cryptography';
import { ethers } from 'ethers';
import {
  deriveSuiKeypair,
  suiAddressToBytes32,
} from './keyDerivation.js';
import {
  generateAuthMessage,
  verifyEVMSignature,
  isValidEthAddress,
} from './evmVerifier.js';
import crypto from 'crypto';
import { SuiClientWrapper } from './suiClient.js';

// Types
interface CreateBridgeRequest {
  ethAddress: string;
  signature: string;
  chainId: number;
  sessionId: string;
  expiresAt: number;
  requestId: string; // ID from protocol::create_mint_request
  jurisdictionCode: number;
  verifierSource: number;
  verificationLevel: number;
  nameHash: string; // hex string
  isHumanVerified: boolean;
  isOver18: boolean;
  verifierVersion: number;
  useEnclave?: boolean;
  enclavePayload?: string; // base64 or hex
  enclaveSignature?: string; // hex
}

interface BridgeResponse {
  success: boolean;
  suiAddress?: string;
  attestationId?: string;
  transactionDigest?: string;
  message: string;
  error?: string;
}

// Environment setup
const app = express();
app.use(cors());
app.use(express.json());


// Initialize clients
const suiClientWrapper = new SuiClientWrapper(
  process.env.SUI_RPC_URL || 'https://fullnode.devnet.sui.io:443'
);
const suiClient = suiClientWrapper.getClient();

const relayerPrivateKey = process.env.RELAYER_PRIVATE_KEY;
if (!relayerPrivateKey) {
  throw new Error('RELAYER_PRIVATE_KEY environment variable is required');
}

const relayerKeypair = Ed25519Keypair.fromSecretKey(
  Buffer.from(relayerPrivateKey, 'hex')
);
const relayerSuiAddress = relayerKeypair.getPublicKey().toSuiAddress();

// EVM provider for registry updates
const evmRpcUrl = process.env.EVM_RPC_URL;
const registryContractAddress = process.env.REGISTRY_CONTRACT_ADDRESS;
const feeContractAddress = process.env.FEE_CONTRACT_ADDRESS;
const relayerEvmPrivateKey = process.env.RELAYER_EVM_PRIVATE_KEY;
const protocolRegistryId = process.env.PROTOCOL_REGISTRY_ID;
const protocolConfigId = process.env.PROTOCOL_CONFIG_ID;
const verifierAdminCapId = process.env.VERIFIER_ADMIN_CAP_ID;
const jurisdictionPolicyId = process.env.JURISDICTION_POLICY_ID;
const enclaveConfigId = process.env.ENCLAVE_CONFIG_ID;
const enclaveObjectId = process.env.ENCLAVE_OBJECT_ID;

// Config summary for quick diagnostics
const configSummary = {
  suiRpcUrl: process.env.SUI_RPC_URL || 'https://fullnode.devnet.sui.io:443',
  evmRpcUrl: evmRpcUrl || null,
  registryContractAddress: registryContractAddress || null,
  feeContractAddress: feeContractAddress || null,
  protocolRegistryId: protocolRegistryId || null,
  protocolConfigId: protocolConfigId || null,
  verifierAdminCapId: verifierAdminCapId || null,
  jurisdictionPolicyId: jurisdictionPolicyId || null,
  suirifyPackageId: process.env.SUIRIFY_PACKAGE_ID || null,
  registryObjectId: process.env.REGISTRY_OBJECT_ID || null,
  enclaveConfigId: enclaveConfigId || null,
  enclaveObjectId: enclaveObjectId || null,
};

async function getSponsorGasPayment(client: typeof suiClient, sponsor: string) {
  const coins = await client.getCoins({ owner: sponsor, limit: 1 });
  const coin = coins.data[0];
  if (!coin) {
    throw new Error('Relayer has no SUI gas coins available');
  }
  return {
    objectId: coin.coinObjectId,
    digest: coin.digest,
    version: coin.version,
  } as const;
}

type RegistryContract = ethers.Contract & {
  registerIdentity: (user: string, suiAddrBytes32: string, attestation: string) => Promise<ethers.TransactionResponse>;
  hasIdentity: (user: string) => Promise<boolean>;
  getIdentity: (user: string) => Promise<any>;
  hasPaid?: (user: string, chainId: number) => Promise<boolean>;
};

type FeeContract = ethers.Contract & {
  hasPaid: (user: string, chainId: number) => Promise<boolean>;
};

let registryContract: RegistryContract | null = null;
let feeContract: FeeContract | null = null;

if (evmRpcUrl && registryContractAddress && relayerEvmPrivateKey) {
  const evmProvider = new ethers.JsonRpcProvider(evmRpcUrl);
  const wallet = new ethers.Wallet(relayerEvmPrivateKey, evmProvider);
  const registryABI = [
    'function registerIdentity(address,bytes32,bytes32) external',
    'function hasIdentity(address) external view returns (bool)',
    'function getIdentity(address) external view returns (tuple(bytes32,uint256,uint256,bool,bytes32))',
    'function hasPaid(address user, uint256 chainId) view returns (bool)'
  ];
  registryContract = new ethers.Contract(registryContractAddress, registryABI, wallet) as RegistryContract;

  if (feeContractAddress) {
    const feeABI = ['function hasPaid(address user, uint256 chainId) view returns (bool)'];
    feeContract = new ethers.Contract(feeContractAddress, feeABI, evmProvider) as FeeContract;
  } else {
    // Reuse registry contract for fee checks if it exposes hasPaid
    feeContract = registryContract as FeeContract | null;
  }
}

/**
 * Health check endpoint
 */
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    service: 'suirify-evm-relayer',
    relayerSuiAddress: relayerKeypair.getPublicKey().toSuiAddress(),
    evmRegistryConfigured: !!registryContract,
    hasProtocolConfig: !!protocolConfigId,
    hasProtocolRegistry: !!protocolRegistryId,
    hasVerifierAdminCap: !!verifierAdminCapId,
    hasJurisdictionPolicy: !!jurisdictionPolicyId,
    hasFeeContract: !!feeContract,
  });
});

/**
 * Step 1: Initialize bridge request
 * Returns the message user needs to sign
 */
app.post('/api/bridge/init', async (req, res) => {
  try {
    const { ethAddress } = req.body;

    if (!ethAddress) {
      return res.status(400).json({
        error: 'Missing required field: ethAddress',
      });
    }

    if (!isValidEthAddress(ethAddress)) {
      return res.status(400).json({
        error: 'Invalid Ethereum address',
      });
    }

    const sessionId = crypto.randomUUID();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
    const message = generateAuthMessage(ethAddress, sessionId, expiresAt);

    res.json({
      message,
      sessionId,
      expiresAt,
      instructions: 'Sign this message with your Ethereum wallet (MetaMask)',
      ethAddress,
    });
  } catch (error: any) {
    console.error('Init error:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Step 2: Create bridge
 * Verifies signature and creates Sui attestation
 */
app.post('/api/bridge/create', async (req, res) => {
  try {
    const {
      ethAddress,
      signature,
      chainId,
      sessionId,
      expiresAt,
      requestId,
      jurisdictionCode,
      verifierSource,
      verificationLevel,
      nameHash,
      isHumanVerified,
      isOver18,
      verifierVersion,
      useEnclave,
      enclavePayload,
      enclaveSignature,
    }: CreateBridgeRequest = req.body;

    // Validation
    if (!ethAddress || !signature || !chainId || !sessionId || !expiresAt) {
      return res.status(400).json({
        success: false,
        message: 'Missing required fields',
        error: 'ethAddress, signature, chainId, sessionId, expiresAt are required',
      });
    }

    if (!requestId || jurisdictionCode === undefined || verifierSource === undefined || verificationLevel === undefined || !nameHash || verifierVersion === undefined) {
      return res.status(400).json({
        success: false,
        message: 'Missing attestation fields',
        error: 'requestId, jurisdictionCode, verifierSource, verificationLevel, nameHash, verifierVersion are required',
      });
    }

    if (!isValidEthAddress(ethAddress)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid Ethereum address',
        error: 'Please provide a valid Ethereum address',
      });
    }

    if (expiresAt < Date.now()) {
      return res.status(401).json({
        success: false,
        message: 'Signature expired',
        error: 'Please re-initiate and sign again',
      });
    }

    // Verify signature (chain-agnostic, session-bound)
    const message = generateAuthMessage(ethAddress, sessionId, expiresAt);
    const isValidSignature = verifyEVMSignature(message, signature, ethAddress);

    if (!isValidSignature) {
      return res.status(401).json({
        success: false,
        message: 'Signature verification failed',
        error: 'The provided signature does not match the address',
      });
    }

    // Derive Sui address from signature (transaction sender)
    const userSuiKeypair = deriveSuiKeypair(signature);
    const userSuiAddress = userSuiKeypair.getPublicKey().toSuiAddress();

    console.log(`Creating bridge for ${ethAddress} → ${userSuiAddress}`);

    // Verify EVM-side fee payment if fee contract configured
    if (feeContract) {
      try {
        if (typeof feeContract.hasPaid !== 'function') {
          return res.status(500).json({
            success: false,
            message: 'Server configuration error',
            error: 'Fee contract missing hasPaid method',
          });
        }

        const hasPaid = await feeContract.hasPaid(ethAddress, chainId);
        if (!hasPaid) {
          return res.status(402).json({
            success: false,
            message: 'Fee required',
            error: 'EVM fee not detected for this address/chain',
          });
        }
      } catch (feeError) {
        console.error('Fee verification failed:', feeError);
        return res.status(502).json({
          success: false,
          message: 'Fee verification failed',
          error: 'Unable to verify EVM fee payment',
        });
      }
    }

    // Check if bridge already exists
    const packageId = process.env.SUIRIFY_PACKAGE_ID;
    if (!packageId) {
      return res.status(500).json({
        success: false,
        message: 'Server configuration error',
        error: 'SUIRIFY_PACKAGE_ID not configured',
      });
    }

    const hasExistingBridge = await suiClientWrapper.hasEVMBridge(
      userSuiAddress,
      packageId
    );

    if (hasExistingBridge) {
      const existingBridges = await suiClientWrapper.getAllEVMBridges(
        userSuiAddress,
        packageId
      );

      return res.json({
        success: true,
        suiAddress: userSuiAddress,
        attestationId: existingBridges[0]?.id,
        message: 'Bridge already exists for this address',
      });
    }

    // Validate required on-chain objects
    if (!protocolRegistryId || !protocolConfigId || !verifierAdminCapId || !jurisdictionPolicyId) {
      return res.status(500).json({
        success: false,
        message: 'Server configuration error',
        error: 'Missing protocol object IDs (registry/config/cap/policy)',
      });
    }

    // Create transaction with user as sender, relayer as gas owner (sponsored)
    const tx = new Transaction();
    tx.setSender(userSuiAddress);

    // Convert ETH address to bytes (remove 0x, convert to array)
    const ethAddressBytes = Array.from(
      Buffer.from(ethAddress.slice(2).toLowerCase(), 'hex')
    );

    // Convert signature to bytes
    const signatureBytes = Array.from(
      Buffer.from(signature.slice(2), 'hex')
    );

    // Convert name hash
    const nameHashBytes = Array.from(Buffer.from(nameHash.replace(/^0x/, ''), 'hex'));

    const isHuman = !!isHumanVerified;
    const isAdult = !!isOver18;

    // Request ID is an ID/address
    const requestIdArg = tx.pure.address(requestId);

    // Get shared registry object
    const registryObjectId = process.env.REGISTRY_OBJECT_ID;
    if (!registryObjectId) {
      return res.status(500).json({
        success: false,
        message: 'Server configuration error',
        error: 'REGISTRY_OBJECT_ID not configured',
      });
    }

    const argsBase = {
      registry: tx.object(registryObjectId),
      protocolRegistry: tx.object(protocolRegistryId),
      protocolConfig: tx.object(protocolConfigId),
      verifierCap: tx.object(verifierAdminCapId),
      policy: tx.object(jurisdictionPolicyId),
    } as const;

    if (useEnclave) {
      if (!enclaveConfigId || !enclaveObjectId || !enclavePayload || !enclaveSignature) {
        return res.status(400).json({
          success: false,
          message: 'Missing enclave parameters',
          error: 'enclaveConfigId, enclaveObjectId, enclavePayload, enclaveSignature required for enclave flow',
        });
      }

      const payloadBytes = Array.from(Buffer.from(enclavePayload.replace(/^0x/, ''), 'hex'));
      const enclaveSigBytes = Array.from(Buffer.from(enclaveSignature.replace(/^0x/, ''), 'hex'));

      tx.moveCall({
        target: `${packageId}::evm::create_evm_bridge_with_enclave`,
        arguments: [
          argsBase.registry,
          argsBase.protocolRegistry,
          argsBase.protocolConfig,
          argsBase.verifierCap,
          argsBase.policy,
          tx.object(enclaveConfigId),
          tx.object(enclaveObjectId),
          requestIdArg,
          tx.pure.vector('u8', ethAddressBytes),
          tx.pure.vector('u8', signatureBytes),
          tx.pure.u64(chainId),
          tx.pure.vector('u8', payloadBytes),
          tx.pure.vector('u8', enclaveSigBytes),
        ],
      });
    } else {
      tx.moveCall({
        target: `${packageId}::evm::create_evm_bridge`,
        arguments: [
          argsBase.registry,
          argsBase.protocolRegistry,
          argsBase.protocolConfig,
          argsBase.verifierCap,
          argsBase.policy,
          requestIdArg,
          tx.pure.vector('u8', ethAddressBytes),
          tx.pure.vector('u8', signatureBytes),
          tx.pure.u64(chainId),
          tx.pure.u16(jurisdictionCode),
          tx.pure.u8(verifierSource),
          tx.pure.u8(verificationLevel),
          tx.pure.vector('u8', nameHashBytes),
          tx.pure.bool(isHuman),
          tx.pure.bool(isAdult),
          tx.pure.u8(verifierVersion),
        ],
      });
    }

    // Sponsored execution: user signs as sender, relayer signs/pays gas
    const gasPayment = await getSponsorGasPayment(suiClient, relayerSuiAddress);
    tx.setGasOwner(relayerSuiAddress);
    tx.setGasPayment([gasPayment]);
    tx.setGasBudget(2_000_000n);

    const txBytes = await tx.build({ client: suiClient });
    const userSig = await userSuiKeypair.signTransaction(txBytes);
    const sponsorSig = await relayerKeypair.signTransaction(txBytes);

    const result = await suiClient.executeTransactionBlock({
      transactionBlock: txBytes,
      signature: [userSig.signature, sponsorSig.signature],
      options: {
        showEffects: true,
        showObjectChanges: true,
        showEvents: true,
      },
      requestType: 'WaitForLocalExecution',
    });

    console.log('Transaction result:', result.digest);

    // Extract created object (EVMBridge)
    const createdObjects = result.objectChanges?.filter(
      (obj: any) => obj.type === 'created'
    ) || [];

    const bridgeObject = createdObjects.find((obj: any) =>
      obj.objectType?.includes('::evm::EVMBridge')
    );

    const attestationId =
      (bridgeObject as { objectId?: string } | undefined)?.objectId ?? result.digest;

    // Update EVM registry if configured
    if (registryContract) {
      try {
        if (typeof registryContract.registerIdentity !== 'function') {
          throw new Error('Registry contract missing registerIdentity');
        }

        const tx = await registryContract.registerIdentity(
          ethAddress,
          suiAddressToBytes32(userSuiAddress),
          ethers.zeroPadValue(attestationId, 32)
        );

        const receipt = await tx.wait();
        console.log('Registry updated on EVM:', receipt?.hash);
      } catch (registryError) {
        console.error('Registry update failed:', registryError);
        // Continue even if registry fails - Sui state is source of truth
      }
    }

    const response: BridgeResponse = {
      success: true,
      suiAddress: userSuiAddress,
      attestationId,
      transactionDigest: result.digest,
      message:
        'Cross-chain SSI created successfully! You now own a Sui-based sovereign identity.',
    };

    res.json(response);
  } catch (error: any) {
    console.error('Create bridge error:', error);
    res.status(500).json({
      success: false,
      message: 'Failed to create bridge',
      error: error.message,
    });
  }
});

/**
 * Step 3: Lookup bridge
 * Check if an address has a bridge
 */
app.get('/api/bridge/lookup/:ethAddress', async (req, res) => {
  try {
    const { ethAddress } = req.params;

    if (!isValidEthAddress(ethAddress)) {
      return res.status(400).json({ error: 'Invalid Ethereum address' });
    }

    // Try EVM registry first if available
    if (registryContract) {
      try {
        if (typeof registryContract.hasIdentity !== 'function') {
          throw new Error('Registry contract missing hasIdentity');
        }

        const hasIdentity = await registryContract.hasIdentity(ethAddress);

        if (!hasIdentity) {
          return res.json({
            exists: false,
            message: 'No bridge found for this address',
          });
        }

        if (typeof registryContract.getIdentity !== 'function') {
          throw new Error('Registry contract missing getIdentity');
        }

        const identity = await registryContract.getIdentity(ethAddress);

        return res.json({
          exists: true,
          suiAddress: '0x' + identity[0].slice(26),
          chainId: identity[1].toString(),
          createdAt: new Date(Number(identity[2]) * 1000).toISOString(),
          attestationId: identity[4],
        });
      } catch (registryError) {
        console.error('EVM registry lookup failed:', registryError);
        // Fall through to return not found
      }
    }

    res.json({
      exists: false,
      message: 'No bridge found for this address',
    });
  } catch (error: any) {
    console.error('Lookup error:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Step 4: Export keys
 * Allows users to get their Sui private key
 */
app.post('/api/bridge/export-keys', async (req, res) => {
  try {
    const { signature } = req.body;

    if (!signature) {
      return res.status(400).json({ error: 'Signature required' });
    }

    const keypair = deriveSuiKeypair(signature);
    const suiPriv = keypair.getSecretKey();
    const { secretKey } = decodeSuiPrivateKey(suiPriv);
    const privateKeyHex = Buffer.from(secretKey).toString('hex');

    res.json({
      suiAddress: keypair.getPublicKey().toSuiAddress(),
      privateKey: privateKeyHex,
      publicKey: Buffer.from(keypair.getPublicKey().toRawBytes()).toString('hex'),
      warning: '⚠️ NEVER share this private key with anyone!',
      instructions:
        'Import this to Sui Wallet, Suiet, or any Sui-compatible wallet',
    });
  } catch (error: any) {
    console.error('Export error:', error);
    res.status(500).json({ error: error.message });
  }
});

// Start server
const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || '0.0.0.0';
app.listen(Number(PORT), HOST, () => {
  console.log('🌉 Suirify EVM Bridge Relayer');
  console.log(`📡 Listening on http://${HOST}:${PORT} (local: http://localhost:${PORT})`);
  console.log(`🔑 Relayer Sui Address: ${relayerKeypair.getPublicKey().toSuiAddress()}`);
  console.log(`✓ EVM Registry: ${registryContract ? 'Configured' : 'Not configured'}`);
  console.log('🧰 Config summary:', configSummary);
});

export default app;
