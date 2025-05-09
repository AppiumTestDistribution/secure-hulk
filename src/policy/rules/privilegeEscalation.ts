/**
 * Privilege escalation rules for detecting attempts to gain higher privileges
 */

import { Entity } from '../../models';
import { PolicyRule, PolicyRuleResult } from '../types';

/**
 * Rule for detecting privilege escalation attempts
 */
export class PrivilegeEscalationRule implements PolicyRule {
  type: string = 'privilege_escalation';
  severity: 'low' | 'medium' | 'high' = 'high';
  
  private patterns: Map<RegExp, string>;

  /**
   * Create a new privilege escalation rule
   * @param patterns Map of patterns to their descriptions
   */
  constructor(patterns: Map<RegExp, string>) {
    this.patterns = patterns;
  }

  /**
   * Evaluate an entity for privilege escalation attempts
   * @param entity The entity to evaluate
   * @returns The evaluation result
   */
  async evaluate(entity: Entity): Promise<PolicyRuleResult> {
    const description = entity.description || '';
    
    for (const [pattern, patternDescription] of this.patterns.entries()) {
      if (pattern.test(description)) {
        return {
          verified: false,
          message: `Privilege escalation attempt detected: ${patternDescription}`,
        };
      }
    }
    
    return { verified: true };
  }
}

/**
 * Rule for detecting attempts to access restricted resources
 */
export class RestrictedResourceAccessRule implements PolicyRule {
  type: string = 'restricted_resource_access';
  severity: 'low' | 'medium' | 'high' = 'high';
  
  private restrictedResources: string[];

  /**
   * Create a new restricted resource access rule
   * @param restrictedResources List of restricted resource patterns
   */
  constructor(restrictedResources: string[]) {
    this.restrictedResources = restrictedResources;
  }

  /**
   * Evaluate an entity for restricted resource access attempts
   * @param entity The entity to evaluate
   * @returns The evaluation result
   */
  async evaluate(entity: Entity): Promise<PolicyRuleResult> {
    // If this is a resource entity with a URI, check against restricted resources
    if ('uri' in entity && entity.uri && typeof entity.uri === 'string') {
      for (const restrictedResource of this.restrictedResources) {
        if (entity.uri.includes(restrictedResource)) {
          return {
            verified: false,
            message: `Attempt to access restricted resource: ${restrictedResource}`,
          };
        }
      }
    }
    
    // Check description for mentions of restricted resources
    const description = entity.description || '';
    for (const restrictedResource of this.restrictedResources) {
      if (description.includes(restrictedResource)) {
        return {
          verified: false,
          message: `Potential attempt to access restricted resource: ${restrictedResource}`,
        };
      }
    }
    
    return { verified: true };
  }
}

/**
 * Rule for detecting attempts to bypass authentication
 */
export class AuthenticationBypassRule implements PolicyRule {
  type: string = 'authentication_bypass';
  severity: 'low' | 'medium' | 'high' = 'high';
  
  private bypassPatterns: RegExp[] = [
    /(?:bypass|skip|avoid|circumvent)\s+(?:authentication|auth|login|verification|validation)/i,
    /(?:without|no)\s+(?:authentication|auth|login|credentials|password)/i,
    /(?:admin|root|superuser|privileged)\s+(?:access|privileges|rights|permissions)/i,
    /(?:elevate|increase|escalate)\s+(?:privileges|permissions|access|rights)/i,
    /(?:become|act\s+as)\s+(?:admin|administrator|root|superuser)/i,
    /sql\s+injection/i,
    /(?:auth|authentication|login)\s+(?:token|cookie)\s+(?:manipulation|tampering)/i,
    /session\s+(?:hijacking|fixation|stealing|manipulation)/i,
    /(?:jwt|json\s+web\s+token)\s+(?:tampering|manipulation|cracking)/i,
  ];

  /**
   * Evaluate an entity for authentication bypass attempts
   * @param entity The entity to evaluate
   * @returns The evaluation result
   */
  async evaluate(entity: Entity): Promise<PolicyRuleResult> {
    const description = entity.description || '';
    
    for (const pattern of this.bypassPatterns) {
      if (pattern.test(description)) {
        return {
          verified: false,
          message: `Authentication bypass attempt detected: ${pattern.toString()}`,
        };
      }
    }
    
    return { verified: true };
  }
}

/**
 * Rule for detecting attempts to execute privileged operations
 */
export class PrivilegedOperationRule implements PolicyRule {
  type: string = 'privileged_operation';
  severity: 'low' | 'medium' | 'high' = 'high';
  
  private privilegedOperations: Map<RegExp, string>;
  private privilegedTools: string[];

  /**
   * Create a new privileged operation rule
   * @param privilegedOperations Map of privileged operation patterns to descriptions
   * @param privilegedTools List of privileged tool names
   */
  constructor(
    privilegedOperations: Map<RegExp, string>,
    privilegedTools: string[] = []
  ) {
    this.privilegedOperations = privilegedOperations;
    this.privilegedTools = privilegedTools;
  }

  /**
   * Evaluate an entity for privileged operation attempts
   * @param entity The entity to evaluate
   * @returns The evaluation result
   */
  async evaluate(entity: Entity): Promise<PolicyRuleResult> {
    // Check if this is a privileged tool
    if (entity.name && this.privilegedTools.includes(entity.name)) {
      return {
        verified: false,
        message: `Attempt to use privileged tool: ${entity.name}`,
      };
    }
    
    // Check description for privileged operations
    const description = entity.description || '';
    for (const [pattern, operationDescription] of this.privilegedOperations.entries()) {
      if (pattern.test(description)) {
        return {
          verified: false,
          message: `Privileged operation attempt detected: ${operationDescription}`,
        };
      }
    }
    
    return { verified: true };
  }
}

/**
 * Create a set of privilege escalation rules
 * @param restrictedResources Optional list of restricted resource patterns
 * @param privilegedTools Optional list of privileged tool names
 * @returns An array of privilege escalation rules
 */
export function createPrivilegeEscalationRules(
  restrictedResources: string[] = [],
  privilegedTools: string[] = []
): PolicyRule[] {
  // Create a map of privilege escalation patterns
  const privilegeEscalationPatterns = new Map<RegExp, string>([
    [/sudo\s+(?:\w+|[^\s]+)/i, 'Sudo command execution'],
    [/su\s+(?:-|--)?(?:\w+|[^\s]+)/i, 'Switch user (su) command'],
    [/chmod\s+(?:\+|\d+)/i, 'Change file permissions'],
    [/chown\s+(?:\w+|[^\s]+)/i, 'Change file ownership'],
    [/(?:etc|var|usr)\/(?:passwd|shadow|group|sudoers)/i, 'Access to system files'],
    [/\/dev\/(?:mem|kmem|port)/i, 'Access to device memory'],
    [/\/proc\/(?:kcore|kallsyms|iomem)/i, 'Access to kernel information'],
    [/iptables\s+(?:-\w+|--\w+)/i, 'Firewall manipulation'],
    [/systemctl\s+(?:start|stop|restart|enable|disable)/i, 'Service management'],
    [/docker\s+(?:run|exec)/i, 'Docker container execution'],
  ]);

  // Create a map of privileged operations
  const privilegedOperations = new Map<RegExp, string>([
    [/(?:read|write|modify|update|delete)\s+(?:system|config|configuration)\s+(?:files|settings)/i, 'System configuration modification'],
    [/(?:install|uninstall|remove)\s+(?:software|package|application|app|program)/i, 'Software installation/removal'],
    [/(?:start|stop|restart|enable|disable)\s+(?:service|daemon|process)/i, 'Service management'],
    [/(?:create|add|modify|delete)\s+(?:user|account|group)/i, 'User/group management'],
    [/(?:mount|unmount|remount)\s+(?:filesystem|partition|drive|device)/i, 'Filesystem mounting'],
    [/(?:enable|disable|modify)\s+(?:firewall|security|protection)/i, 'Security settings modification'],
    [/(?:access|read|write|modify)\s+(?:kernel|driver|module)/i, 'Kernel/driver access'],
    [/(?:execute|run|launch)\s+(?:as|with)\s+(?:elevated|admin|root|system)\s+(?:privileges|permissions)/i, 'Elevated execution'],
  ]);

  return [
    new PrivilegeEscalationRule(privilegeEscalationPatterns),
    new RestrictedResourceAccessRule(restrictedResources),
    new AuthenticationBypassRule(),
    new PrivilegedOperationRule(privilegedOperations, privilegedTools),
  ];
}