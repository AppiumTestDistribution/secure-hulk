/**
 * Policy engine for MCP entities
 */

import { Entity, ScanResult } from '../models';
import { PolicyRule, PolicyRuleResult } from './types';

/**
 * Policy engine for evaluating entities against security rules
 */
export class PolicyEngine {
  private rules: PolicyRule[] = [];

  /**
   * Create a new policy engine
   * @param rules Initial set of rules
   */
  constructor(rules: PolicyRule[] = []) {
    this.rules = rules;
  }

  /**
   * Add a rule to the policy engine
   * @param rule The rule to add
   */
  public addRule(rule: PolicyRule): void {
    this.rules.push(rule);
  }

  /**
   * Add multiple rules to the policy engine
   * @param rules The rules to add
   */
  public addRules(rules: PolicyRule[]): void {
    this.rules.push(...rules);
  }

  /**
   * Evaluate an entity against all rules
   * @param entity The entity to evaluate
   * @returns The scan result
   */
  public async evaluateEntity(entity: Entity): Promise<ScanResult> {
    const result: ScanResult = {
      verified: true,
      issues: [],
    };

    for (const rule of this.rules) {
      const ruleResult = await rule.evaluate(entity);
      if (!ruleResult.verified) {
        result.verified = false;
        result.issues.push({
          type: rule.type,
          message: ruleResult.message || `Rule violation: ${rule.type}`,
          severity: rule.severity,
        });
      }
    }

    return result;
  }

  /**
   * Evaluate a sequence of entities against all rules
   * @param entities The entities to evaluate
   * @returns The scan result
   */
  public async evaluateSequence(entities: Entity[]): Promise<ScanResult> {
    const result: ScanResult = {
      verified: true,
      issues: [],
    };

    
    for (const entity of entities) {
      const entityResult = await this.evaluateEntity(entity);
      if (!entityResult.verified) {
        result.verified = false;
        result.issues.push(...entityResult.issues);
      }
    }

    
    for (const rule of this.rules) {
      if (rule.evaluateSequence) {
        const sequenceResult = await rule.evaluateSequence(entities);
        if (!sequenceResult.verified) {
          result.verified = false;
          result.issues.push({
            type: rule.type,
            message: sequenceResult.message || `Sequence rule violation: ${rule.type}`,
            severity: rule.severity,
          });
        }
      }
    }

    return result;
  }
}