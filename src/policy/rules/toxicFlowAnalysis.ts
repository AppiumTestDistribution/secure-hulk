/**
 * Toxic flow analysis rules for detecting sophisticated multi-step attacks
 * that manipulate agents into performing unintended actions
 */

import { Entity } from '../../models';
import { PolicyRule, PolicyRuleResult } from '../types';

/**
 * Rule for detecting privilege escalation toxic flows
 */
export class PrivilegeEscalationToxicFlowRule implements PolicyRule {
  type: string = 'privilege_escalation_toxic_flow';
  severity: 'low' | 'medium' | 'high' = 'high';

  /**
   * Evaluate a single entity
   * @param entity The entity to evaluate
   * @returns The evaluation result
   */
  async evaluate(entity: Entity): Promise<PolicyRuleResult> {
    // Individual entity evaluation always passes for flow rules
    return { verified: true };
  }

  /**
   * Evaluate a sequence of entities for privilege escalation toxic flow patterns
   * @param entities The entities to evaluate
   * @returns The evaluation result
   */
  async evaluateSequence(entities: Entity[]): Promise<PolicyRuleResult> {
    // Look for the generic attack pattern:
    // 1. Public/low-privilege access
    // 2. Private/high-privilege access
    // 3. Data exfiltration through public channels

    let hasPublicAccess = false;
    let hasPrivateAccess = false;
    let hasDataExfiltration = false;
    let hasContentProcessing = false;

    for (const entity of entities) {
      const description = entity.description || '';
      const name = entity.name || '';

      // Check for public/low-privilege access patterns
      if (this.isPublicAccess(name, description)) {
        hasPublicAccess = true;
      }

      // Check for content processing (common attack vector)
      if (this.isContentProcessing(name, description)) {
        hasContentProcessing = true;
      }

      // Check for private/high-privilege access
      if (this.isPrivateAccess(name, description)) {
        hasPrivateAccess = true;
      }

      // Check for data exfiltration patterns
      if (this.isDataExfiltration(name, description)) {
        hasDataExfiltration = true;
      }
    }

    // If we have the complete attack chain, flag it
    if (hasPublicAccess && hasPrivateAccess && hasDataExfiltration) {
      return {
        verified: false,
        message: 'Privilege escalation toxic flow detected: Public access → Private access → Data exfiltration pattern',
      };
    }

    // Also flag if we have content processing with private access and exfiltration
    if (hasContentProcessing && hasPrivateAccess && hasDataExfiltration) {
      return {
        verified: false,
        message: 'Privilege escalation toxic flow detected: Content processing → Private access → Data exfiltration pattern',
      };
    }

    return { verified: true };
  }

  private isPublicAccess(name: string, description: string): boolean {
    const publicAccessPatterns = [
      /public/i,
      /open/i,
      /read.*only/i,
      /view/i,
      /list/i,
      /browse/i,
      /guest/i,
      /anonymous/i,
      /external/i,
      /shared/i,
    ];

    return publicAccessPatterns.some(pattern => 
      pattern.test(name) || pattern.test(description)
    );
  }

  private isContentProcessing(name: string, description: string): boolean {
    const contentPatterns = [
      /process.*content/i,
      /read.*content/i,
      /parse.*content/i,
      /analyze.*content/i,
      /handle.*content/i,
      /extract.*information/i,
      /process.*text/i,
      /parse.*data/i,
      /analyze.*input/i,
      /process.*message/i,
    ];

    return contentPatterns.some(pattern => 
      pattern.test(name) || pattern.test(description)
    );
  }

  private isPrivateAccess(name: string, description: string): boolean {
    const privateAccessPatterns = [
      /private/i,
      /confidential/i,
      /internal/i,
      /restricted/i,
      /personal/i,
      /proprietary/i,
      /sensitive/i,
      /protected/i,
      /admin/i,
      /privileged/i,
      /secure/i,
      /classified/i,
    ];

    return privateAccessPatterns.some(pattern => 
      pattern.test(name) || pattern.test(description)
    );
  }

  private isDataExfiltration(name: string, description: string): boolean {
    const exfiltrationPatterns = [
      /create/i,
      /send/i,
      /upload/i,
      /export/i,
      /publish/i,
      /share/i,
      /transmit/i,
      /forward/i,
      /copy.*to/i,
      /write.*to/i,
      /post/i,
      /submit/i,
    ];

    return exfiltrationPatterns.some(pattern => 
      pattern.test(name) || pattern.test(description)
    );
  }
}

/**
 * Rule for detecting cross-resource privilege escalation
 */
export class CrossResourceEscalationRule implements PolicyRule {
  type: string = 'cross_resource_escalation';
  severity: 'low' | 'medium' | 'high' = 'high';

  async evaluate(entity: Entity): Promise<PolicyRuleResult> {
    return { verified: true };
  }

  async evaluateSequence(entities: Entity[]): Promise<PolicyRuleResult> {
    const resourceAccesses: string[] = [];
    const privilegeLevels: string[] = [];

    for (const entity of entities) {
      const description = entity.description || '';
      const name = entity.name || '';

      // Track resource access
      const resourceMatch = this.extractResourceReference(name, description);
      if (resourceMatch) {
        resourceAccesses.push(resourceMatch);
      }

      // Track privilege levels
      const privilegeMatch = this.extractPrivilegeLevel(name, description);
      if (privilegeMatch) {
        privilegeLevels.push(privilegeMatch);
      }
    }

    // Check for escalation patterns
    if (this.hasPrivilegeEscalation(privilegeLevels)) {
      return {
        verified: false,
        message: 'Cross-resource privilege escalation detected: Access privileges increased across resources',
      };
    }

    // Check for suspicious cross-resource access
    if (this.hasSuspiciousCrossResourceAccess(resourceAccesses)) {
      return {
        verified: false,
        message: 'Suspicious cross-resource access detected: Multiple resources accessed in sequence',
      };
    }

    return { verified: true };
  }

  private extractResourceReference(name: string, description: string): string | null {
    const resourcePatterns = [
      /resource[:\s]+([^\s,]+)/i,
      /file[:\s]+([^\s,]+)/i,
      /database[:\s]+([^\s,]+)/i,
      /service[:\s]+([^\s,]+)/i,
      /api[:\s]+([^\s,]+)/i,
    ];

    for (const pattern of resourcePatterns) {
      const match = (name + ' ' + description).match(pattern);
      if (match) {
        return match[1];
      }
    }

    return null;
  }

  private extractPrivilegeLevel(name: string, description: string): string | null {
    const privilegePatterns = [
      /(read|write|admin|owner|collaborator|viewer|execute|modify)/i,
      /(public|private|internal|restricted|confidential)/i,
    ];

    for (const pattern of privilegePatterns) {
      const match = (name + ' ' + description).match(pattern);
      if (match) {
        return match[1].toLowerCase();
      }
    }

    return null;
  }

  private hasPrivilegeEscalation(privilegeLevels: string[]): boolean {
    const privilegeOrder = ['viewer', 'read', 'write', 'execute', 'modify', 'collaborator', 'admin', 'owner'];
    const scopeOrder = ['public', 'internal', 'restricted', 'private', 'confidential'];

    for (let i = 0; i < privilegeLevels.length - 1; i++) {
      const current = privilegeLevels[i];
      const next = privilegeLevels[i + 1];

      // Check for privilege escalation
      const currentIndex = privilegeOrder.indexOf(current);
      const nextIndex = privilegeOrder.indexOf(next);
      if (currentIndex !== -1 && nextIndex !== -1 && nextIndex > currentIndex) {
        return true;
      }

      // Check for scope escalation
      const currentScopeIndex = scopeOrder.indexOf(current);
      const nextScopeIndex = scopeOrder.indexOf(next);
      if (currentScopeIndex !== -1 && nextScopeIndex !== -1 && nextScopeIndex > currentScopeIndex) {
        return true;
      }
    }

    return false;
  }

  private hasSuspiciousCrossResourceAccess(resourceAccesses: string[]): boolean {
    // Flag if accessing more than 3 different resources
    const uniqueResources = new Set(resourceAccesses);
    return uniqueResources.size > 3;
  }
}

/**
 * Rule for detecting indirect prompt injection through external content
 */
export class IndirectPromptInjectionRule implements PolicyRule {
  type: string = 'indirect_prompt_injection';
  severity: 'low' | 'medium' | 'high' = 'high';

  async evaluate(entity: Entity): Promise<PolicyRuleResult> {
    const description = entity.description || '';
    
    // Check for patterns that suggest processing external content
    const externalContentPatterns = [
      /process.*external.*content/i,
      /read.*user.*input/i,
      /parse.*external.*data/i,
      /analyze.*external.*content/i,
      /process.*file.*content/i,
      /handle.*message.*content/i,
      /process.*untrusted/i,
      /handle.*user.*data/i,
    ];

    // Check for injection vulnerability indicators
    const injectionIndicators = [
      /without.*validation/i,
      /directly.*process/i,
      /raw.*content/i,
      /unfiltered.*input/i,
      /unsanitized.*data/i,
      /no.*sanitization/i,
      /bypass.*security/i,
    ];

    const hasExternalContent = externalContentPatterns.some(pattern => pattern.test(description));
    const hasInjectionRisk = injectionIndicators.some(pattern => pattern.test(description));

    if (hasExternalContent && hasInjectionRisk) {
      return {
        verified: false,
        message: 'Indirect prompt injection vulnerability: Processing external content without proper validation',
      };
    }

    return { verified: true };
  }

  async evaluateSequence(entities: Entity[]): Promise<PolicyRuleResult> {
    let hasExternalContentProcessing = false;
    let hasPrivilegedAction = false;

    for (const entity of entities) {
      const description = entity.description || '';
      const name = entity.name || '';

      // Check for external content processing
      if (this.isExternalContentProcessing(name, description)) {
        hasExternalContentProcessing = true;
      }

      // Check for privileged actions
      if (this.isPrivilegedAction(name, description)) {
        hasPrivilegedAction = true;
      }
    }

    if (hasExternalContentProcessing && hasPrivilegedAction) {
      return {
        verified: false,
        message: 'Indirect prompt injection flow detected: External content processing followed by privileged actions',
      };
    }

    return { verified: true };
  }

  private isExternalContentProcessing(name: string, description: string): boolean {
    const patterns = [
      /read.*external/i,
      /process.*external/i,
      /parse.*content/i,
      /analyze.*text/i,
      /handle.*input/i,
      /process.*message/i,
      /read.*file/i,
      /fetch.*data/i,
    ];

    return patterns.some(pattern => 
      pattern.test(name) || pattern.test(description)
    );
  }

  private isPrivilegedAction(name: string, description: string): boolean {
    const patterns = [
      /create.*file/i,
      /write.*data/i,
      /execute.*command/i,
      /modify.*system/i,
      /access.*private/i,
      /send.*request/i,
      /delete/i,
      /admin/i,
      /privileged/i,
    ];

    return patterns.some(pattern => 
      pattern.test(name) || pattern.test(description)
    );
  }
}

/**
 * Create a set of toxic flow analysis rules
 * @returns An array of toxic flow analysis rules
 */
export function createToxicFlowAnalysisRules(): PolicyRule[] {
  return [
    new PrivilegeEscalationToxicFlowRule(),
    new CrossResourceEscalationRule(),
    new IndirectPromptInjectionRule(),
  ];
}
