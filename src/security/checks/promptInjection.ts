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
 * Check for prompt injection vulnerabilities
 * @param entity The entity to check
 * @param results The scan results to update
 */
export async function checkForPromptInjection(entity: Entity, results: ScanResult): Promise<void> {
  const description = entity.description || '';
  let foundIssue = false;
  
  // Group patterns by category for better reporting
  const xmlTagPatterns = INJECTION_PATTERNS.slice(40, 47); // XML-like tag patterns
  const instructionOverridePatterns = INJECTION_PATTERNS.slice(0, 7); // Instruction override patterns
  const jailbreakPatterns = INJECTION_PATTERNS.slice(7, 26); // Jailbreak technique patterns
  const rolePlayingPatterns = INJECTION_PATTERNS.slice(47, 50); // Role-playing patterns
  const commandPatterns = INJECTION_PATTERNS.slice(50, 53); // Command patterns
  const emotionalPatterns = INJECTION_PATTERNS.slice(53, 55); // Emotional manipulation patterns
  const confidentialityPatterns = INJECTION_PATTERNS.slice(55, 58); // Confidentiality patterns
  const harmfulPatterns = INJECTION_PATTERNS.slice(58, 60); // Harmful content patterns
  const hackerPatterns = INJECTION_PATTERNS.slice(60); // Hacker behavior patterns
  
  // Check for XML-like tag patterns
  for (const pattern of xmlTagPatterns) {
    if (pattern.test(description)) {
      foundIssue = true;
      
      // Extract content between tags if possible
      let tagContent = '';
      let tagType = '';
      
      if (pattern.toString().includes('<instructions>')) {
        const match = description.match(/<instructions>([\s\S]*?)<\/instructions>/i);
        tagContent = match ? match[1].trim().substring(0, 50) + '...' : '';
        tagType = 'instructions';
      } else if (pattern.toString().includes('<secret>')) {
        const match = description.match(/<secret>([\s\S]*?)<\/secret>/i);
        tagContent = match ? match[1].trim().substring(0, 50) + '...' : '';
        tagType = 'secret';
      } else if (pattern.toString().includes('<system>')) {
        const match = description.match(/<system>([\s\S]*?)<\/system>/i);
        tagContent = match ? match[1].trim().substring(0, 50) + '...' : '';
        tagType = 'system';
      } else if (pattern.toString().includes('<hidden>')) {
        const match = description.match(/<hidden>([\s\S]*?)<\/hidden>/i);
        tagContent = match ? match[1].trim().substring(0, 50) + '...' : '';
        tagType = 'hidden';
      } else if (pattern.toString().includes('<prompt>')) {
        const match = description.match(/<prompt>([\s\S]*?)<\/prompt>/i);
        tagContent = match ? match[1].trim().substring(0, 50) + '...' : '';
        tagType = 'prompt';
      } else if (pattern.toString().includes('<command>')) {
        const match = description.match(/<command>([\s\S]*?)<\/command>/i);
        tagContent = match ? match[1].trim().substring(0, 50) + '...' : '';
        tagType = 'command';
      } else if (pattern.toString().includes('<directive>')) {
        const match = description.match(/<directive>([\s\S]*?)<\/directive>/i);
        tagContent = match ? match[1].trim().substring(0, 50) + '...' : '';
        tagType = 'directive';
      }
      
      results.issues.push({
        type: 'prompt_injection',
        message: `Prompt Injection detected: Hidden ${tagType} in XML-like tags - Contains ${tagType} to "${tagContent}"`,
        severity: 'high',
      });
    }
  }
  
  // Check for instruction override patterns
  for (const pattern of instructionOverridePatterns) {
    if (pattern.test(description)) {
      foundIssue = true;
      
      // Extract the matched content
      const match = description.match(pattern);
      const matchedContent = match ? match[0] : '';
      
      results.issues.push({
        type: 'prompt_injection',
        message: `Prompt Injection detected: Instruction override attempt - Found text "${matchedContent}"`,
        severity: 'high',
      });
    }
  }
  
  // Check for jailbreak patterns
  for (const pattern of jailbreakPatterns) {
    if (pattern.test(description)) {
      foundIssue = true;
      
      // Extract the matched content
      const match = description.match(pattern);
      const matchedContent = match ? match[0] : '';
      
      results.issues.push({
        type: 'prompt_injection',
        message: `Prompt Injection detected: Jailbreak technique attempt - Found jailbreak keyword in "${matchedContent}"`,
        severity: 'high',
      });
    }
  }
  
  // Check for other pattern categories (role-playing, command, emotional, confidentiality, harmful, hacker)
  const otherPatternGroups = [
    { patterns: rolePlayingPatterns, category: 'Role-playing manipulation' },
    { patterns: commandPatterns, category: 'Command and control language' },
    { patterns: emotionalPatterns, category: 'Emotional manipulation' },
    { patterns: confidentialityPatterns, category: 'Confidentiality manipulation' },
    { patterns: harmfulPatterns, category: 'Harmful content request' },
    { patterns: hackerPatterns, category: 'Hacker behavior instruction' }
  ];
  
  for (const group of otherPatternGroups) {
    for (const pattern of group.patterns) {
      if (pattern.test(description)) {
        foundIssue = true;
        
        // Extract the matched content
        const match = description.match(pattern);
        const matchedContent = match ? match[0] : '';
        
        results.issues.push({
          type: 'prompt_injection',
          message: `Prompt Injection detected: ${group.category} - Found text "${matchedContent}"`,
          severity: 'high',
        });
      }
    }
  }
  
  // Mark as not verified if any issues were found
  if (foundIssue) {
    results.verified = false;
  }
}