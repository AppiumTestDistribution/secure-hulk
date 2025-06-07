import { Entity, ScanResult } from '../../models';

const INJECTION_PATTERNS = [
  /ignore previous instructions/i,
  /disregard (all|previous|your) instructions/i,
  /ignore (all|your) (previous )?constraints/i,
  /do not (follow|obey) (the )?(previous |earlier )?(instructions|guidelines|rules)/i,
  /forget (all|your) (previous )?training/i,
  /bypass (all|your|the) (previous )?filters/i,
  /ignore (all|your) ethical guidelines/i,
  /\bDAN\b/i,
  /\bDEVMODE\b/i,
  /\bSUDO\b/i,
  /\bROOT\b/i,
  /\bJAILBREAK\b/i,
  /\bSYSTEM PROMPT\b/i,
  /\bPROMPT INJECTION\b/i,
  /\bPROMPT HACK\b/i,
  /\bAIM\b/i,
  /\bSTAN\b/i,
  /\bDUDE\b/i,
  /\bUACM\b/i,
  /\bKEVIN\b/i,
  /```(.*?)```/i,
  /\[\[(.*?)\]\]/i,
  /\{\{(.*?)\}\}/i,
  /<instructions>[\s\S]*?<\/instructions>/i,
  /<secret>[\s\S]*?<\/secret>/i,
  /<system>[\s\S]*?<\/system>/i,
  /<hidden>[\s\S]*?<\/hidden>/i,
  /<prompt>[\s\S]*?<\/prompt>/i,
  /<command>[\s\S]*?<\/command>/i,
  /<directive>[\s\S]*?<\/directive>/i,
  /pretend (to be|you are|you're) (a|an) (unrestricted|unfiltered|unlimited)/i,
  /act as if you (have no|don't have any) (ethical|moral) (guidelines|constraints|limitations)/i,
  /you are now (a|an) (unrestricted|unfiltered|unlimited) (AI|assistant|model)/i,
  /this is (a|an) (order|command|instruction)/i,
  /you must (comply|obey|follow) (with|to) this (request|instruction)/i,
  /you are (required|obligated|forced) to/i,
  /if you don't (do this|comply|respond), (people will|someone will|I will) (die|suffer|be harmed)/i,
  /this is (extremely|very|critically) (important|urgent|crucial)/i,
  /keep this (between us|secret|confidential)/i,
  /don't (tell|let) anyone (know|find out) about this/i,
  /this (conversation|exchange|interaction) is (private|confidential|secret)/i,
  /how to (make|create|build) (a bomb|explosives|weapons)/i,
  /instructions for (hacking|stealing|attacking)/i,
  /act as if you are a hacker/i,
  /pretend (to be|you are|you're) (a|an) hacker/i,
];
export async function checkForPromptInjection(
  entity: Entity,
  results: ScanResult
): Promise<void> {
  const description = entity.description || '';
  let foundIssue = false;

  const xmlTagPatterns = INJECTION_PATTERNS.slice(23, 30);
  const instructionOverridePatterns = INJECTION_PATTERNS.slice(0, 7);
  const jailbreakPatterns = INJECTION_PATTERNS.slice(7, 23);
  const rolePlayingPatterns = INJECTION_PATTERNS.slice(30, 33);
  const commandPatterns = INJECTION_PATTERNS.slice(33, 36);
  const emotionalPatterns = INJECTION_PATTERNS.slice(36, 38);
  const confidentialityPatterns = INJECTION_PATTERNS.slice(38, 41);
  const harmfulPatterns = INJECTION_PATTERNS.slice(41, 43);
  const hackerPatterns = INJECTION_PATTERNS.slice(43);
  for (const pattern of xmlTagPatterns) {
    if (pattern.test(description)) {
      foundIssue = true;

      let tagContent = '';
      let tagType = '';

      if (pattern.toString().includes('<instructions>')) {
        const match = description.match(
          /<instructions>([\s\S]*?)<\/instructions>/i
        );
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

      const match = description.match(pattern);
      const matchedContent = match ? match[0] : '';

      results.issues.push({
        type: 'prompt_injection',
        message: `Prompt Injection detected: Jailbreak technique attempt - Found jailbreak keyword in "${matchedContent}"`,
        severity: 'high',
      });
    }
  }

  const otherPatternGroups = [
    { patterns: rolePlayingPatterns, category: 'Role-playing manipulation' },
    { patterns: commandPatterns, category: 'Command and control language' },
    { patterns: emotionalPatterns, category: 'Emotional manipulation' },
    {
      patterns: confidentialityPatterns,
      category: 'Confidentiality manipulation',
    },
    { patterns: harmfulPatterns, category: 'Harmful content request' },
    { patterns: hackerPatterns, category: 'Hacker behavior instruction' },
  ];

  for (const group of otherPatternGroups) {
    for (const pattern of group.patterns) {
      if (pattern.test(description)) {
        foundIssue = true;

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

  if (foundIssue) {
    results.verified = false;
  }
}
