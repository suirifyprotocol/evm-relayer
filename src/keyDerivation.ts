// Copyright (c) Suirify Protocol, Inc.
// SPDX-License-Identifier: GPL-3.0
import { Ed25519Keypair } from '@mysten/sui/keypairs/ed25519';
import { ethers } from 'ethers';

/**
 * Derives a deterministic Sui keypair from EVM signature
 * This ensures the same ETH address always generates the same Sui address
 */
export function deriveSuiKeypair(ethSignature: string): Ed25519Keypair {
  // Remove 0x prefix if present
  const sig = ethSignature.startsWith('0x') ? ethSignature.slice(2) : ethSignature;
  
  // Hash the signature to get deterministic seed
  const seed = ethers.keccak256('0x' + sig);
  
  // Take first 32 bytes as seed for Ed25519 keypair
  const seedBytes = Buffer.from(seed.slice(2, 66), 'hex');

  // Latest Mysten SDK uses fromSecretKey for raw 32-byte seeds
  return Ed25519Keypair.fromSecretKey(new Uint8Array(seedBytes));
}

/**
 * Get Sui address without creating full keypair
 */
export function getSuiAddressFromEthSig(ethSignature: string): string {
  const keypair = deriveSuiKeypair(ethSignature);
  return keypair.getPublicKey().toSuiAddress();
}

/**
 * Convert Sui address to bytes32 for Solidity
 */
export function suiAddressToBytes32(suiAddress: string): string {
  // Sui addresses are 32 bytes, represented as 0x + 64 hex chars
  return suiAddress.padStart(66, '0'); // Ensure 0x + 64 chars
}

/**
 * Convert Sui address to ethers.getAddress compatible format
 */
export function normalizeSuiAddress(suiAddress: string): string {
  // Remove leading zeros and ensure 0x prefix
  const cleaned = suiAddress.replace(/^0x/, '');
  const normalized = '0x' + cleaned.slice(-64); // Take last 64 chars
  return normalized;
}
