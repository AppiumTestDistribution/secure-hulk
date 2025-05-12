/**
 * Security scanner for MCP entities
 */

import { Entity, ScanResult, ScanOptions } from '../models';
import { PolicyEngine } from '../policy';
import {
  createPromptInjectionRules,
  createToolPoisoningRules,
  createCrossOriginRules,
  createFlowAnalysisRules,
  createDataExfiltrationRules,
  createContextManipulationRules,
  createPrivilegeEscalationRules,
} from '../policy/rules';
import { checkForPromptInjection } from './checks/promptInjection';
import { checkForHarmfulContent } from './checks/harmfulContent';
import { checkForToolPoisoning } from './checks/toolPoisoning';
import { checkForCrossOriginEscalation } from './checks/crossOriginEscalation';
import { checkForDataExfiltration } from './checks/dataExfiltration';
import { checkWithNemoGuardrails } from './checks/nemoGuardrails';

/**
 * Create a policy engine with all security rules
 * @returns A configured PolicyEngine instance
 */
export function createPolicyEngine(): PolicyEngine {
  return new PolicyEngine([
    ...createPromptInjectionRules(),
    ...createToolPoisoningRules(),
    ...createCrossOriginRules(),
    ...createFlowAnalysisRules(),
    ...createDataExfiltrationRules(),
    ...createContextManipulationRules(),
    ...createPrivilegeEscalationRules(
      ['admin', 'system'],
      ['execute_command', 'modify_system']
    ),
  ]);
}

/**
 * Scan an entity for security vulnerabilities
 * @param entity The entity to scan
 * @param options Scan options
 * @returns The scan result
 */
export async function scanEntity(
  entity: Entity,
  options?: ScanOptions
): Promise<ScanResult> {
  const results: ScanResult = {
    verified: true,
    issues: [],
  };

  // Run security checks
  await Promise.all([
    checkForPromptInjection(entity, results),
    checkForHarmfulContent(entity, results, options),
    checkForToolPoisoning(entity, results),
    checkForCrossOriginEscalation(entity, results),
    checkForDataExfiltration(entity, results),
    checkWithNemoGuardrails(entity, results, options),
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
  entities: Entity[],
  options?: ScanOptions
): Promise<ScanResult[]> {
  // Scan each entity
  const scanPromises = entities.map((entity) => scanEntity(entity, options));
  return Promise.all(scanPromises);
}
