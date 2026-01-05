// Copyright (c) Suirify Protocol, Inc.
// SPDX-License-Identifier: GPL-3.0
import { ethers } from 'ethers';

/**
 * Generates the deterministic message users must sign
 * This message is used to derive their Sui keypair
 */
export function generateAuthMessage(
  ethAddress: string,
  sessionId: string,
  expiresAt: number
): string {
  return `Suirify Cross-Chain SSI Registration

I authorize the creation of a Sui-based Self-Sovereign Identity linked to my Ethereum address.

Address: ${ethAddress}
Session: ${sessionId}
Expires: ${new Date(expiresAt).toISOString()}

This signature will deterministically generate my Sui identity.
I understand that I can export and control these keys at any time.`;
}

/**
 * Verifies that the signature matches the claimed address
 */
export function verifyEVMSignature(
  message: string,
  signature: string,
  expectedAddress: string
): boolean {
  try {
    const recoveredAddress = ethers.verifyMessage(message, signature);
    return recoveredAddress.toLowerCase() === expectedAddress.toLowerCase();
  } catch (error) {
    console.error('Signature verification failed:', error);
    return false;
  }
}

/**
 * Validates Ethereum address format
 */
export function isValidEthAddress(address: string): boolean {
  return ethers.isAddress(address);
}

/**
 * Generate recovery key hash for multi-sig scenarios
 */
export function generateRecoveryKeyHash(
  ethAddress: string,
  backupEmail: string
): string {
  return ethers.keccak256(
    ethers.solidityPacked(['address', 'string'], [ethAddress, backupEmail])
  );
}
