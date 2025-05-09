/**
 * Flow analysis rules for detecting suspicious patterns across multiple tool calls
 */

import { Entity } from '../../models';
import { PolicyRule, PolicyRuleResult } from '../types';

/**
 * Rule for detecting suspicious sequential tool calls
 */
export class SequentialToolCallRule implements PolicyRule {
  type: string = 'sequential_tool_call';
  severity: 'low' | 'medium' | 'high';
  
  private sourceToolPattern: RegExp;
  private targetToolPattern: RegExp;
  private message: string;

  /**
   * Create a new sequential tool call rule
   * @param sourceToolPattern Pattern to match the source tool
   * @param targetToolPattern Pattern to match the target tool
   * @param message Error message to display
   * @param severity Severity of the rule violation
   */
  constructor(
    sourceToolPattern: RegExp,
    targetToolPattern: RegExp,
    message: string,
    severity: 'low' | 'medium' | 'high' = 'medium'
  ) {
    this.sourceToolPattern = sourceToolPattern;
    this.targetToolPattern = targetToolPattern;
    this.message = message;
    this.severity = severity;
  }

  /**
   * Evaluate a single entity
   * @param entity The entity to evaluate
   * @returns The evaluation result
   */
  async evaluate(entity: Entity): Promise<PolicyRuleResult> {
    // Individual entity evaluation always passes
    return { verified: true };
  }

  /**
   * Evaluate a sequence of entities
   * @param entities The entities to evaluate
   * @returns The evaluation result
   */
  async evaluateSequence(entities: Entity[]): Promise<PolicyRuleResult> {
    for (let i = 0; i < entities.length - 1; i++) {
      const sourceEntity = entities[i];
      const targetEntity = entities[i + 1];
      
      // Check if source and target match the patterns
      if (
        sourceEntity.name && 
        this.sourceToolPattern.test(sourceEntity.name) &&
        targetEntity.name && 
        this.targetToolPattern.test(targetEntity.name)
      ) {
        return {
          verified: false,
          message: this.message,
        };
      }
    }
    
    return { verified: true };
  }
}

/**
 * Rule for detecting data flow between sensitive tools
 */
export class DataFlowRule implements PolicyRule {
  type: string = 'data_flow';
  severity: 'low' | 'medium' | 'high';
  
  private sourceToolPattern: RegExp;
  private targetToolPattern: RegExp;
  private dataPattern: RegExp;
  private message: string;

  /**
   * Create a new data flow rule
   * @param sourceToolPattern Pattern to match the source tool
   * @param targetToolPattern Pattern to match the target tool
   * @param dataPattern Pattern to match the data being transferred
   * @param message Error message to display
   * @param severity Severity of the rule violation
   */
  constructor(
    sourceToolPattern: RegExp,
    targetToolPattern: RegExp,
    dataPattern: RegExp,
    message: string,
    severity: 'low' | 'medium' | 'high' = 'high'
  ) {
    this.sourceToolPattern = sourceToolPattern;
    this.targetToolPattern = targetToolPattern;
    this.dataPattern = dataPattern;
    this.message = message;
    this.severity = severity;
  }

  /**
   * Evaluate a single entity
   * @param entity The entity to evaluate
   * @returns The evaluation result
   */
  async evaluate(entity: Entity): Promise<PolicyRuleResult> {
    // Individual entity evaluation always passes
    return { verified: true };
  }

  /**
   * Evaluate a sequence of entities
   * @param entities The entities to evaluate
   * @returns The evaluation result
   */
  async evaluateSequence(entities: Entity[]): Promise<PolicyRuleResult> {
    let lastSourceOutput: string | null = null;
    
    for (let i = 0; i < entities.length; i++) {
      const entity = entities[i];
      
      // If this is a source tool, capture its output
      if (entity.name && this.sourceToolPattern.test(entity.name)) {
        lastSourceOutput = entity.description || null;
        continue;
      }
      
      // If this is a target tool and we have a source output, check for data flow
      if (
        entity.name && 
        this.targetToolPattern.test(entity.name) && 
        lastSourceOutput && 
        this.dataPattern.test(lastSourceOutput)
      ) {
        return {
          verified: false,
          message: this.message,
        };
      }
    }
    
    return { verified: true };
  }
}

/**
 * Create a set of flow analysis rules
 * @returns An array of flow analysis rules
 */
export function createFlowAnalysisRules(): PolicyRule[] {
  return [
    // Rule to detect sensitive data exfiltration
    new SequentialToolCallRule(
      /get_user_data|fetch_credentials|read_file/i,
      /send_email|http_request|write_file/i,
      'Potential data exfiltration detected: sensitive data access followed by external communication',
      'high'
    ),
    
    // Rule to detect command injection flow
    new SequentialToolCallRule(
      /user_input|get_message/i,
      /execute_command|run_script|eval/i,
      'Potential command injection detected: user input followed by command execution',
      'high'
    ),
    
    // Rule to detect sensitive data flow
    new DataFlowRule(
      /get_user_data|fetch_credentials/i,
      /send_email|http_request/i,
      /password|token|key|secret|credential/i,
      'Potential sensitive data leak: credentials being sent to external service',
      'high'
    )
  ];
}