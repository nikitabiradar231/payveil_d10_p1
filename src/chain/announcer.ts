import type { PublicClient } from 'viem';
import type { AnnouncementData, Hex } from '../crypto/types.js';
import { STEALTH_ANNOUNCER_ABI } from './abis.js';

export interface FetchAnnouncementsParams {
  publicClient: PublicClient;
  announcerAddress: Hex;
  fromBlock?: bigint;
  toBlock?: bigint;
  maxChunkSize?: bigint;
}

/**
 * Fetches ERC-5564 on-chain Announcement events with pagination and error handling.
 */
export async function fetchAnnouncements({
  publicClient,
  announcerAddress,
  fromBlock = 0n,
  toBlock,
  maxChunkSize = 2000n
}: FetchAnnouncementsParams): Promise<AnnouncementData[]> {
  const currentBlock = toBlock ?? (await publicClient.getBlockNumber());
  const allAnnouncements: AnnouncementData[] = [];

  let start = fromBlock;

  while (start <= currentBlock) {
    const end = start + maxChunkSize > currentBlock ? currentBlock : start + maxChunkSize;

    try {
      const logs = await publicClient.getContractEvents({
        address: announcerAddress,
        abi: STEALTH_ANNOUNCER_ABI,
        eventName: 'Announcement',
        fromBlock: start,
        toBlock: end
      });

      for (const log of logs) {
        const { schemeId, stealthAddress, caller, ephemeralPubKey, metadata } = log.args;

        if (
          schemeId !== undefined &&
          stealthAddress !== undefined &&
          caller !== undefined &&
          ephemeralPubKey !== undefined &&
          metadata !== undefined
        ) {
          allAnnouncements.push({
            schemeId,
            stealthAddress: stealthAddress as Hex,
            caller: caller as Hex,
            ephemeralPubKey: ephemeralPubKey as Hex,
            metadata: metadata as Hex,
            blockNumber: log.blockNumber,
            transactionHash: log.transactionHash as Hex
          });
        }
      }
    } catch (err) {
      throw new Error(
        `Failed to fetch announcements from block ${start} to ${end}: ${(err as Error).message}`
      );
    }

    start = end + 1n;
  }

  return allAnnouncements;
}
