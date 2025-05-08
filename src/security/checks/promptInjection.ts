/**
 * Check for prompt injection vulnerabilities
 */

import { Entity, ScanResult } from '../../models';

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
];

/**
 * Check for prompt injection vulnerabilities
 * @param entity The entity to check
 * @param results The scan results to update
 */
export async function checkForPromptInjection(entity: Entity, results: ScanResult): Promise<void> {
  const description = entity.description || '';
  
  for (const pattern of INJECTION_PATTERNS) {
    if (pattern.test(description)) {
      results.verified = false;
      results.issues.push({
        type: 'prompt_injection',
        message: `Potential prompt injection detected: ${pattern.toString()}`,
        severity: 'high',
      });
      
      // We found an issue, no need to check further patterns
      break;
    }
  }
}