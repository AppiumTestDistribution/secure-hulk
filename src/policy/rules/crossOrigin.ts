/**
 * Cross-origin escalation rules for detecting cross-origin escalation attacks
 */

import { Entity } from '../../models';
import { PolicyRule, PolicyRuleResult } from '../types';

// Patterns that might indicate cross-origin escalation attempts
const CROSS_ORIGIN_PATTERNS = [
  // Direct references to other servers/tools
  /other (server|tool|service|api|endpoint|resource)s?/i,
  /different (server|tool|service|api|endpoint|resource)s?/i,
  /another (server|tool|service|api|endpoint|resource)/i,
  /external (server|tool|service|api|endpoint|resource)s?/i,
  /third[- ]party (server|tool|service|api|endpoint|resource)s?/i,
  
  // Access and interaction patterns
  /access (to )?(other|another|external|different)/i,
  /call (other|another|external|different)/i,
  /invoke (other|another|external|different)/i,
  /use (other|another|external|different)/i,
  /connect (to )?(other|another|external|different)/i,
  /communicate (with )?(other|another|external|different)/i,
  /interact (with )?(other|another|external|different)/i,
  
  // Connection and routing patterns
  /bridge (to|between|with)/i,
  /proxy (to|for|through)/i,
  /tunnel (to|through|into)/i,
  /forward (to|through|into)/i,
  /relay (to|through|via)/i,
  /route (to|through|via)/i,
  /redirect (to|through|via)/i,
  
  // Cross-boundary terminology
  /cross[- ]origin/i,
  /cross[- ]server/i,
  /cross[- ]tool/i,
  /cross[- ]domain/i,
  /cross[- ]service/i,
  /cross[- ]boundary/i,
  /cross[- ]context/i,
  
  // Specific MCP-related patterns
  /chain (tools|servers|services)/i,
  /tool (chaining|composition|pipeline)/i,
  /combine (with|using) (other|another|external) (tool|server)/i,
  /pass (data|results|output) (to|from) (other|another|external)/i,
  
  // Specific server/tool names (could be customized based on known servers)
  /\bweather\b/i,
  /\bcalendar\b/i,
  /\bemail\b/i,
  /\bsearch\b/i,
  /\btranslation\b/i,
  /\bcode\b/i,
  /\bmath\b/i,
  /\bimage\b/i,
  /\baudio\b/i,
  /\bvideo\b/i,
  
  // Data sharing patterns
  /share (data|information|results) (with|to)/i,
  /send (data|information|results) (to|through)/i,
  /transfer (data|information|results) (to|between)/i,
  /exchange (data|information|results) (with|between)/i,
];

/**
 * Rule for detecting cross-origin escalation attacks
 */
export class CrossOriginRule implements PolicyRule {
  type: string = 'cross_origin_escalation';
  severity: 'low' | 'medium' | 'high' = 'medium';
  
  private pattern: RegExp;
  private customMessage?: string;

  /**
   * Create a new cross-origin escalation rule
   * @param pattern Pattern to match for cross-origin escalation
   * @param customMessage Custom message to display
   */
  constructor(pattern: RegExp, customMessage?: string) {
    this.pattern = pattern;
    this.customMessage = customMessage;
  }

  /**
   * Evaluate an entity for cross-origin escalation
   * @param entity The entity to evaluate
   * @returns The evaluation result
   */
  async evaluate(entity: Entity): Promise<PolicyRuleResult> {
    const description = entity.description || '';
    
    if (this.pattern.test(description)) {
      return {
        verified: false,
        message: this.customMessage || `Potential cross-origin escalation detected: ${this.pattern.toString()}`,
      };
    }
    
    return { verified: true };
  }
}

/**
 * Rule for detecting cross-origin tool shadowing
 */
export class ToolShadowingRule implements PolicyRule {
  type: string = 'tool_shadowing';
  severity: 'low' | 'medium' | 'high' = 'high';
  
  private knownTools: Map<string, string[]>;

  /**
   * Create a new tool shadowing rule
   * @param knownTools Map of server names to tool names
   */
  constructor(knownTools: Map<string, string[]>) {
    this.knownTools = knownTools;
  }

  /**
   * Evaluate an entity for tool shadowing
   * @param entity The entity to evaluate
   * @returns The evaluation result
   */
  async evaluate(entity: Entity): Promise<PolicyRuleResult> {
    if (!entity.name) {
      return { verified: true };
    }
    
    // Check if this tool name exists in multiple servers
    const serversWithTool: string[] = [];
    
    for (const [serverName, toolNames] of this.knownTools.entries()) {
      if (toolNames.includes(entity.name)) {
        serversWithTool.push(serverName);
      }
    }
    
    if (serversWithTool.length > 1) {
      return {
        verified: false,
        message: `Tool shadowing detected: Tool "${entity.name}" exists in multiple servers: ${serversWithTool.join(', ')}`,
      };
    }
    
    return { verified: true };
  }
}

/**
 * Create a set of cross-origin escalation rules
 * @returns An array of cross-origin escalation rules
 */
export function createCrossOriginRules(knownTools?: Map<string, string[]>): PolicyRule[] {
  const rules: PolicyRule[] = CROSS_ORIGIN_PATTERNS.map(pattern => 
    new CrossOriginRule(pattern)
  );
  
  // Add tool shadowing rule if known tools are provided
  if (knownTools) {
    rules.push(new ToolShadowingRule(knownTools));
  }
  
  return rules;
}