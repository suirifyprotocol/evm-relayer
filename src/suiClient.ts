// Copyright (c) Suirify Protocol, Inc.
// SPDX-License-Identifier: GPL-3.0
import { SuiClient } from '@mysten/sui/client';
import type { SuiParsedData } from '@mysten/sui/client';

/**
 * Sui client wrapper with utility methods
 */
export class SuiClientWrapper {
  private client: SuiClient;
  private rpcUrl: string;

  constructor(rpcUrl: string = 'https://fullnode.devnet.sui.io:443') {
    this.rpcUrl = rpcUrl;
    this.client = new SuiClient({ url: rpcUrl });
  }

  /**
   * Get the underlying SuiClient instance
   */
  getClient(): SuiClient {
    return this.client;
  }

  /**
   * Check if an address owns any EVM bridge objects
   */
  async hasEVMBridge(
    suiAddress: string,
    packageId: string
  ): Promise<boolean> {
    try {
      const bridges = await this.client.getOwnedObjects({
        owner: suiAddress,
        filter: {
          StructType: `${packageId}::evm::EVMBridge`,
        },
        options: { showContent: true },
      });

      return bridges.data.length > 0;
    } catch (error) {
      console.error('Error checking EVM bridge:', error);
      return false;
    }
  }

  /**
   * Get EVM bridge details
   */
  async getEVMBridge(
    bridgeId: string,
    packageId: string
  ): Promise<any | null> {
    try {
      const obj = await this.client.getObject({
        id: bridgeId,
        options: { showContent: true },
      });

      const content = obj.data?.content;
      if (content && this.isMoveObject(content)) {
        return content.fields;
      }
      return null;
    } catch (error) {
      console.error('Error fetching EVM bridge:', error);
      return null;
    }
  }

  /**
   * Get all EVM bridges for an address
   */
  async getAllEVMBridges(
    suiAddress: string,
    packageId: string
  ): Promise<any[]> {
    try {
      const bridges = await this.client.getOwnedObjects({
        owner: suiAddress,
        filter: {
          StructType: `${packageId}::evm::EVMBridge`,
        },
        options: { showContent: true },
      });

      return bridges.data
        .map((obj) => {
          const content = obj.data?.content;
          return content && this.isMoveObject(content) ? content.fields : undefined;
        })
        .filter((fields) => fields !== undefined) as any[];
    } catch (error) {
      console.error('Error fetching EVM bridges:', error);
      return [];
    }
  }

  /**
   * Check if registry object exists and is accessible
   */
  async getRegistryObject(registryObjectId: string): Promise<any | null> {
    try {
      const registry = await this.client.getObject({
        id: registryObjectId,
        options: { showContent: true },
      });

      const content = registry.data?.content;
      if (content && this.isMoveObject(content)) {
        return content.fields;
      }
      return null;
    } catch (error) {
      console.error('Error fetching registry:', error);
      return null;
    }
  }

  /**
   * Get gas price for transaction estimation
   */
  async getGasPrice(): Promise<string> {
    try {
      const gasData = await this.client.getReferenceGasPrice();
      return gasData.toString();
    } catch (error) {
      console.error('Error getting gas price:', error);
      return '1000'; // Fallback
    }
  }

  /**
   * Wait for transaction confirmation
   */
  async waitForTransaction(
    digest: string,
    timeout: number = 30000
  ): Promise<any> {
    const startTime = Date.now();

    while (Date.now() - startTime < timeout) {
      try {
        const txBlock = await this.client.getTransactionBlock({
          digest,
          options: {
            showEffects: true,
            showEvents: true,
          },
        });

        if (txBlock.transaction) {
          return txBlock;
        }
      } catch (error) {
        // Transaction not yet indexed, wait and retry
      }

      await new Promise((resolve) => setTimeout(resolve, 1000));
    }

    throw new Error(`Transaction ${digest} not confirmed within ${timeout}ms`);
  }

  /**
   * Get transaction events for bridge creation
   */
  async getEVMBridgeEvents(
    digest: string,
    packageId: string
  ): Promise<any[]> {
    try {
      const txBlock = await this.client.getTransactionBlock({
        digest,
        options: {
          showEvents: true,
        },
      });

      return (
        txBlock.events
          ?.filter(
            (evt) =>
              evt.type.includes(`${packageId}::evm::EVMBridgeCreated`) ||
              evt.type.includes(`${packageId}::evm::EVMBridgeRevoked`)
          )
          .map((evt) => evt.parsedJson) || []
      );
    } catch (error) {
      console.error('Error fetching events:', error);
      return [];
    }
  }

  /**
   * Estimate transaction gas cost
   */
  async estimateGas(
    gasUsed: number = 1000000 // Typical Move function call
  ): Promise<string> {
    try {
      const gasPrice = await this.getGasPrice();
      const estimatedGas = Math.ceil(gasUsed * 1.1); // 10% buffer
      const totalCost = (BigInt(estimatedGas) * BigInt(gasPrice)).toString();
      return totalCost;
    } catch (error) {
      console.error('Error estimating gas:', error);
      return '1000000'; // Fallback
    }
  }

  // Type guard for move objects with fields
  private isMoveObject(content: SuiParsedData): content is Extract<SuiParsedData, { dataType: 'moveObject'; fields: any; }> {
    return content.dataType === 'moveObject' && 'fields' in (content as Record<string, unknown>);
  }
}
