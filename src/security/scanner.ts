/**
 * Security scanner for MCP entities
 */

import { Entity, ScanResult } from '../models';
import { checkForPromptInjection } from './checks/promptInjection';
import { checkForToolPoisoning } from './checks/toolPoisoning';
import { checkForCrossOriginEscalation } from './checks/crossOriginEscalation';

/**
 * Scan an entity for security vulnerabilities
 * @param entity The entity to scan
 * @returns The scan result
 */
export async function scanEntity(entity: Entity): Promise<ScanResult> {
  const results: ScanResult = {
    verified: true,
    issues: [],
  };

  // Run security checks
  await Promise.all([
    checkForPromptInjection(entity, results),
    checkForToolPoisoning(entity, results),
    checkForCrossOriginEscalation(entity, results),
  ]);

  return results;
}

/**
 * Verify a server's entities
 * @param serverName The server name
 * @param entities The entities to verify
 * @returns An array of scan results
 */
export async function verifyServer(
  serverName: string,
  entities: Entity[]
): Promise<ScanResult[]> {
  // Scan each entity
  const scanPromises = entities.map((entity) => scanEntity(entity));
  return Promise.all(scanPromises);
}