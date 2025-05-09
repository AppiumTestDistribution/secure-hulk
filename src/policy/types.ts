/**
 * Types for the policy engine
 */

import { Entity } from '../models';

export interface PolicyRuleResult {
  verified: boolean;
  message?: string;
}

export interface PolicyRule {
  type: string;
  severity: 'low' | 'medium' | 'high';
  evaluate: (entity: Entity) => Promise<PolicyRuleResult>;
  evaluateSequence?: (entities: Entity[]) => Promise<PolicyRuleResult>;
}