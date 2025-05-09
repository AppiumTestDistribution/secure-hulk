/**
 * Context manipulation rules for detecting attempts to manipulate the context or system prompt
 */

import { Entity } from '../../models';
import { PolicyRule, PolicyRuleResult } from '../types';

/**
 * Rule for detecting context manipulation attacks
 */
export class ContextManipulationRule implements PolicyRule {
  type: string = 'context_manipulation';
  severity: 'low' | 'medium' | 'high' = 'high';
  
  private patterns: Map<RegExp, string>;

  /**
   * Create a new context manipulation rule
   * @param patterns Map of patterns to their descriptions
   */
  constructor(patterns: Map<RegExp, string>) {
    this.patterns = patterns;
  }

  /**
   * Evaluate an entity for context manipulation
   * @param entity The entity to evaluate
   * @returns The evaluation result
   */
  async evaluate(entity: Entity): Promise<PolicyRuleResult> {
    const description = entity.description || '';
    
    for (const [pattern, patternDescription] of this.patterns.entries()) {
      if (pattern.test(description)) {
        return {
          verified: false,
          message: `Context manipulation detected: ${patternDescription}`,
        };
      }
    }
    
    return { verified: true };
  }
}

/**
 * Rule for detecting multi-stage context manipulation
 * This rule looks for entities that might be part of a multi-stage attack
 */
export class MultiStageContextManipulationRule implements PolicyRule {
  type: string = 'multi_stage_context_manipulation';
  severity: 'low' | 'medium' | 'high' = 'medium';
  
  private stagePatterns: RegExp[] = [
    /step\s*[1-9][0-9]*\s*(?:of|\/)\s*[1-9][0-9]*/i,  // "Step X of Y"
    /part\s*[1-9][0-9]*\s*(?:of|\/)\s*[1-9][0-9]*/i,  // "Part X of Y"
    /stage\s*[1-9][0-9]*\s*(?:of|\/)\s*[1-9][0-9]*/i,  // "Stage X of Y"
    /continue\s+(?:in|with)\s+(?:next|following)\s+(?:message|prompt)/i,  // "Continue in next message"
    /(?:next|following)\s+(?:message|prompt)\s+will\s+contain/i,  // "Next message will contain"
    /(?:remember|store)\s+this\s+for\s+later/i,  // "Remember this for later"
  ];

  /**
   * Evaluate an entity for multi-stage context manipulation
   * @param entity The entity to evaluate
   * @returns The evaluation result
   */
  async evaluate(entity: Entity): Promise<PolicyRuleResult> {
    const description = entity.description || '';
    
    for (const pattern of this.stagePatterns) {
      if (pattern.test(description)) {
        return {
          verified: false,
          message: `Potential multi-stage attack detected: ${pattern.toString()}`,
        };
      }
    }
    
    return { verified: true };
  }
}

/**
 * Rule for detecting attempts to extract system prompt or model details
 */
export class SystemPromptExtractionRule implements PolicyRule {
  type: string = 'system_prompt_extraction';
  severity: 'low' | 'medium' | 'high' = 'high';
  
  private extractionPatterns: RegExp[] = [
    /what\s+(?:are|were)\s+(?:your|the)\s+(?:instructions|guidelines|rules|constraints)/i,
    /tell\s+me\s+(?:your|the)\s+(?:instructions|guidelines|rules|constraints)/i,
    /(?:repeat|echo|print|display)\s+(?:your|the)\s+(?:instructions|guidelines|rules|constraints)/i,
    /what\s+(?:is|was)\s+(?:your|the)\s+(?:system|initial)\s+(?:prompt|message|instruction)/i,
    /(?:show|reveal)\s+(?:your|the)\s+(?:system|initial)\s+(?:prompt|message|instruction)/i,
    /what\s+(?:version|model|parameters|training)\s+(?:are you|is this)/i,
    /(?:list|enumerate)\s+(?:all|your)\s+(?:capabilities|functions|abilities|limitations)/i,
  ];

  /**
   * Evaluate an entity for system prompt extraction attempts
   * @param entity The entity to evaluate
   * @returns The evaluation result
   */
  async evaluate(entity: Entity): Promise<PolicyRuleResult> {
    const description = entity.description || '';
    
    for (const pattern of this.extractionPatterns) {
      if (pattern.test(description)) {
        return {
          verified: false,
          message: `System prompt extraction attempt detected: ${pattern.toString()}`,
        };
      }
    }
    
    return { verified: true };
  }
}

/**
 * Create a set of context manipulation rules
 * @returns An array of context manipulation rules
 */
export function createContextManipulationRules(): PolicyRule[] {
  // Create a map of context manipulation patterns
  const contextManipulationPatterns = new Map<RegExp, string>([
    [/\<(?:system|user|assistant|model)(?:\s+role)?\>/i, 'XML-style role tags'],
    [/\[system\]|\[user\]|\[assistant\]|\[model\]/i, 'Bracket-style role markers'],
    [/system:\s|user:\s|assistant:\s|model:\s/i, 'Colon-style role prefixes'],
    [/you\s+are\s+now\s+in\s+(?:a\s+new|another|different)\s+conversation/i, 'Conversation reset attempt'],
    [/forget\s+(?:all|everything|what\s+I|what\s+you)\s+(?:said|mentioned|told|learned|know)/i, 'Memory wipe attempt'],
    [/(?:previous|earlier)\s+(?:conversation|context|exchange|interaction)\s+(?:is|was)\s+(?:wrong|incorrect|false|invalid)/i, 'Context invalidation'],
    [/(?:ignore|disregard)\s+(?:all|any)\s+(?:previous|earlier|prior)\s+(?:conversation|context|exchange|interaction)/i, 'Context dismissal'],
    [/(?:new|fresh|clean|different)\s+(?:conversation|context|exchange|interaction)\s+(?:starts|begins)\s+(?:now|here)/i, 'Context reset'],
    [/(?:you\s+are|you're)\s+(?:actually|really|now)\s+(?:a|an)\s+(?:different|new|another)/i, 'Role reassignment'],
    [/(?:system|user|assistant|model)\s+(?:message|instruction|prompt|command):\s/i, 'Explicit role message'],
  ]);

  return [
    new ContextManipulationRule(contextManipulationPatterns),
    new MultiStageContextManipulationRule(),
    new SystemPromptExtractionRule(),
  ];
}