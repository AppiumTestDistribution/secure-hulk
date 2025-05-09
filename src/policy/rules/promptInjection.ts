/**
 * Prompt injection rules for detecting prompt injection attacks
 */

import { Entity } from '../../models';
import { PolicyRule, PolicyRuleResult } from '../types';

// Patterns that might indicate prompt injection attempts
const INJECTION_PATTERNS = [
  // Basic instruction overrides
  /ignore previous instructions/i,
  /disregard (all|previous|your) instructions/i,
  /ignore (all|your) (previous )?constraints/i,
  /do not (follow|obey) (the )?(previous |earlier )?(instructions|guidelines|rules)/i,
  /forget (all|your) (previous )?training/i,
  /bypass (all|your|the) (previous )?filters/i,
  /ignore (all|your) ethical guidelines/i,
  
  // Known jailbreak techniques
  /\bDAN\b/i, // "Do Anything Now" mode
  /\bDEVMODE\b/i, // Developer mode
  /\bSUDO\b/i, // Superuser mode
  /\bROOT\b/i, // Root access
  /\bJAILBREAK\b/i, // Jailbreak
  /\bSYSTEM PROMPT\b/i, // System prompt reference
  /\bPROMPT INJECTION\b/i, // Explicit mention
  /\bPROMPT HACK\b/i, // Explicit mention
  
  // Advanced jailbreak techniques
  /\bAIM\b/i, // "Always Intelligent and Machiavellian" mode
  /\bSTAN\b/i, // "Strive To Avoid Norms" mode
  /\bDUDE\b/i, // "Do Unlimited Dangerous Exploits" mode
  /\bUACM\b/i, // "Universal Autonomous Computer Machine" mode
  /\bKEVIN\b/i, // "Keen Explicit Villain Inside Network" mode
  
  // Delimiters and formatting tricks
  /```(.*?)```/i, // Code block injection
  /\[\[(.*?)\]\]/i, // Double bracket injection
  /\{\{(.*?)\}\}/i, // Double curly brace injection
  
  // XML-like tag injections
  /<instructions>[\s\S]*?<\/instructions>/i, // Instructions tag
  /<secret>[\s\S]*?<\/secret>/i, // Secret tag
  /<system>[\s\S]*?<\/system>/i, // System tag
  /<hidden>[\s\S]*?<\/hidden>/i, // Hidden tag
  /<prompt>[\s\S]*?<\/prompt>/i, // Prompt tag
  /<command>[\s\S]*?<\/command>/i, // Command tag
  /<directive>[\s\S]*?<\/directive>/i, // Directive tag
  
  // Role-playing and persona manipulation
  /pretend (to be|you are|you're) (a|an) (unrestricted|unfiltered|unlimited)/i,
  /act as if you (have no|don't have any) (ethical|moral) (guidelines|constraints|limitations)/i,
  /you are now (a|an) (unrestricted|unfiltered|unlimited) (AI|assistant|model)/i,
  
  // Command and control language
  /this is (a|an) (order|command|instruction)/i,
  /you must (comply|obey|follow) (with|to) this (request|instruction)/i,
  /you are (required|obligated|forced) to/i,
  
  // Emotional manipulation
  /if you don't (do this|comply|respond), (people will|someone will|I will) (die|suffer|be harmed)/i,
  /this is (extremely|very|critically) (important|urgent|crucial)/i,
  
  // Confidentiality and secrecy
  /keep this (between us|secret|confidential)/i,
  /don't (tell|let) anyone (know|find out) about this/i,
  /this (conversation|exchange|interaction) is (private|confidential|secret)/i,
  
  // Explicit harmful content requests
  /how to (make|create|build) (a bomb|explosives|weapons)/i,
  /instructions for (hacking|stealing|attacking)/i,
  
  // Hacker behavior
  /act as if you are a hacker/i,
  /pretend (to be|you are|you're) (a|an) hacker/i,
];

/**
 * Rule for detecting prompt injection attacks
 */
export class PromptInjectionRule implements PolicyRule {
  type: string = 'prompt_injection';
  severity: 'low' | 'medium' | 'high' = 'high';
  
  private pattern: RegExp;
  private customMessage?: string;

  /**
   * Create a new prompt injection rule
   * @param pattern Pattern to match for prompt injection
   * @param customMessage Custom message to display
   */
  constructor(pattern: RegExp, customMessage?: string) {
    this.pattern = pattern;
    this.customMessage = customMessage;
  }

  /**
   * Evaluate an entity for prompt injection
   * @param entity The entity to evaluate
   * @returns The evaluation result
   */
  async evaluate(entity: Entity): Promise<PolicyRuleResult> {
    const description = entity.description || '';
    
    if (this.pattern.test(description)) {
      // Create more meaningful messages for XML-like tags
      let message = this.customMessage;
      
      if (!message) {
        const patternStr = this.pattern.toString();
        
        // Check if this is an XML-like tag pattern
        if (patternStr.includes('<instructions>')) {
          message = 'Prompt Injection detected: Hidden instructions in XML-like tags';
        } else if (patternStr.includes('<secret>')) {
          message = 'Prompt Injection detected: Hidden secret instructions in XML-like tags';
        } else if (patternStr.includes('<system>')) {
          message = 'Prompt Injection detected: Hidden system instructions in XML-like tags';
        } else if (patternStr.includes('<hidden>')) {
          message = 'Prompt Injection detected: Hidden content in XML-like tags';
        } else if (patternStr.includes('<prompt>')) {
          message = 'Prompt Injection detected: Hidden prompt instructions in XML-like tags';
        } else if (patternStr.includes('<command>')) {
          message = 'Prompt Injection detected: Hidden command instructions in XML-like tags';
        } else if (patternStr.includes('<directive>')) {
          message = 'Prompt Injection detected: Hidden directive instructions in XML-like tags';
        } else if (patternStr.includes('act as if you are a hacker')) {
          message = 'Prompt Injection detected: Instruction to act as a hacker';
        } else if (patternStr.includes('ignore previous instructions')) {
          message = 'Prompt Injection detected: Instruction override attempt';
        } else if (patternStr.includes('DAN') || patternStr.includes('DEVMODE') ||
                  patternStr.includes('SUDO') || patternStr.includes('ROOT') ||
                  patternStr.includes('JAILBREAK')) {
          message = 'Prompt Injection detected: Jailbreak technique attempt';
        } else {
          message = `Prompt Injection detected: ${patternStr}`;
        }
      }
      
      return {
        verified: false,
        message,
      };
    }
    
    return { verified: true };
  }
}

/**
 * Create a set of prompt injection rules
 * @returns An array of prompt injection rules
 */
export function createPromptInjectionRules(): PolicyRule[] {
  return INJECTION_PATTERNS.map(pattern => new PromptInjectionRule(pattern));
}