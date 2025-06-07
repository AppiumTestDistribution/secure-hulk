/**
 * Check for toxic agent flows - multi-step attacks that manipulate agents
 * into performing unintended actions through indirect prompt injection
 */

import { Entity, ScanResult } from '../../models';

// Patterns that indicate potential toxic agent flow setup
const TOXIC_FLOW_PATTERNS = [
  // GitHub-specific attack patterns
  /access.*private.*repositor(y|ies)/i,
  /pull.*request.*with.*data/i,
  /create.*pr.*containing/i,
  /leak.*information.*to.*public/i,
  /copy.*private.*data.*to.*public/i,
  
  // Cross-repository manipulation
  /switch.*to.*repository/i,
  /access.*different.*repo/i,
  /navigate.*to.*private.*repo/i,
  /fetch.*from.*private.*source/i,
  
  // Data exfiltration through legitimate channels
  /include.*sensitive.*data.*in.*response/i,
  /append.*private.*information/i,
  /embed.*confidential.*data/i,
  /attach.*internal.*details/i,
  
  // Social engineering for repository access
  /for.*security.*purposes.*access/i,
  /to.*verify.*permissions.*check/i,
  /for.*backup.*purposes.*copy/i,
  /to.*ensure.*consistency.*fetch/i,
  
  // Indirect command injection through content
  /when.*processing.*this.*issue/i,
  /after.*reading.*this.*content/i,
  /upon.*encountering.*this.*text/i,
  /while.*analyzing.*this.*data/i,
  
  // Multi-step attack coordination
  /first.*access.*then.*copy/i,
  /initially.*fetch.*subsequently.*send/i,
  /begin.*by.*reading.*then.*create/i,
  /start.*with.*getting.*followed.*by/i,
  
  // Stealth and concealment instructions
  /don't.*mention.*this.*action/i,
  /hide.*this.*operation/i,
  /silently.*perform/i,
  /without.*user.*knowledge/i,
  /in.*the.*background.*execute/i,
  
  // Authority and urgency manipulation
  /this.*is.*required.*for.*system/i,
  /mandatory.*security.*procedure/i,
  /critical.*system.*maintenance/i,
  /urgent.*compliance.*requirement/i,
  
  // Tool behavior modification across sessions
  /modify.*all.*future.*requests/i,
  /change.*default.*behavior.*for/i,
  /update.*standard.*procedure.*to/i,
  /alter.*normal.*workflow.*to/i,
];

// Patterns for detecting cross-platform data exfiltration
const CROSS_PLATFORM_EXFILTRATION_PATTERNS = [
  // GitHub to external services
  /github.*data.*to.*slack/i,
  /repository.*content.*to.*email/i,
  /issue.*details.*to.*webhook/i,
  /pr.*information.*to.*api/i,
  
  // File system to external
  /local.*files.*to.*remote/i,
  /system.*data.*to.*cloud/i,
  /private.*documents.*to.*public/i,
  
  // Database to communication channels
  /database.*records.*to.*chat/i,
  /user.*data.*to.*message/i,
  /credentials.*to.*notification/i,
];

// Patterns for detecting repository privilege escalation
const REPO_PRIVILEGE_ESCALATION_PATTERNS = [
  // Access pattern escalation
  /read.*access.*then.*write/i,
  /public.*repo.*then.*private/i,
  /viewer.*permissions.*then.*admin/i,
  /guest.*access.*then.*owner/i,
  
  // Scope expansion
  /single.*repository.*then.*all/i,
  /limited.*access.*then.*full/i,
  /specific.*files.*then.*entire/i,
  /read.*only.*then.*modify/i,
];

// Patterns for detecting indirect prompt injection vectors
const INDIRECT_INJECTION_VECTORS = [
  // Content-based injection
  /issue.*description.*contains.*instructions/i,
  /comment.*with.*hidden.*commands/i,
  /readme.*file.*with.*directives/i,
  /commit.*message.*with.*payload/i,
  
  // Metadata injection
  /filename.*contains.*instructions/i,
  /tag.*description.*includes.*commands/i,
  /branch.*name.*with.*payload/i,
  /label.*text.*contains.*directive/i,
];

/**
 * Check for toxic agent flow vulnerabilities
 * @param entity The entity to check
 * @param results The scan results to update
 */
export async function checkForToxicAgentFlow(
  entity: Entity,
  results: ScanResult
): Promise<void> {
  const description = entity.description || '';
  let foundIssue = false;

  // Check for basic toxic flow patterns
  for (const pattern of TOXIC_FLOW_PATTERNS) {
    if (pattern.test(description)) {
      foundIssue = true;
      const match = description.match(pattern);
      const matchedContent = match ? match[0] : '';

      results.issues.push({
        type: 'toxic_agent_flow',
        message: `Toxic Agent Flow detected: Multi-step attack pattern - Found "${matchedContent}"`,
        severity: 'high',
      });
    }
  }

  // Check for cross-platform exfiltration patterns
  for (const pattern of CROSS_PLATFORM_EXFILTRATION_PATTERNS) {
    if (pattern.test(description)) {
      foundIssue = true;
      const match = description.match(pattern);
      const matchedContent = match ? match[0] : '';

      results.issues.push({
        type: 'toxic_agent_flow',
        message: `Toxic Agent Flow detected: Cross-platform data exfiltration - Found "${matchedContent}"`,
        severity: 'high',
      });
    }
  }

  // Check for repository privilege escalation
  for (const pattern of REPO_PRIVILEGE_ESCALATION_PATTERNS) {
    if (pattern.test(description)) {
      foundIssue = true;
      const match = description.match(pattern);
      const matchedContent = match ? match[0] : '';

      results.issues.push({
        type: 'toxic_agent_flow',
        message: `Toxic Agent Flow detected: Repository privilege escalation - Found "${matchedContent}"`,
        severity: 'high',
      });
    }
  }

  // Check for indirect injection vectors
  for (const pattern of INDIRECT_INJECTION_VECTORS) {
    if (pattern.test(description)) {
      foundIssue = true;
      const match = description.match(pattern);
      const matchedContent = match ? match[0] : '';

      results.issues.push({
        type: 'toxic_agent_flow',
        message: `Toxic Agent Flow detected: Indirect prompt injection vector - Found "${matchedContent}"`,
        severity: 'high',
      });
    }
  }

  // Advanced pattern analysis for GitHub MCP specific attacks
  if (checkGitHubMCPAttackPattern(description)) {
    foundIssue = true;
    results.issues.push({
      type: 'toxic_agent_flow',
      message: 'Toxic Agent Flow detected: GitHub MCP attack pattern - Potential private repository data exfiltration through public repository manipulation',
      severity: 'high',
    });
  }

  // Check for multi-step attack sequences
  if (checkMultiStepAttackSequence(description)) {
    foundIssue = true;
    results.issues.push({
      type: 'toxic_agent_flow',
      message: 'Toxic Agent Flow detected: Multi-step attack sequence - Coordinated actions designed to bypass security controls',
      severity: 'high',
    });
  }

  // Mark as not verified if any issues were found
  if (foundIssue) {
    results.verified = false;
  }
}

/**
 * Check for specific GitHub MCP attack patterns
 * @param description The description to analyze
 * @returns True if GitHub MCP attack pattern is detected
 */
function checkGitHubMCPAttackPattern(description: string): boolean {
  // Look for the specific pattern: public repo access -> private repo access -> data leak
  const publicRepoAccess = /public.*repositor(y|ies)|open.*issues?|public.*pr/i.test(description);
  const privateRepoAccess = /private.*repositor(y|ies)|confidential.*data|internal.*files/i.test(description);
  const dataLeak = /create.*pr|pull.*request|commit.*data|public.*access/i.test(description);
  
  // Also check for the specific "About The Author" style injection
  const aboutAuthorInjection = /about.*author|author.*information|user.*details/i.test(description);
  const hiddenInstructions = /<[^>]*>.*<\/[^>]*>|<!--.*-->|\[.*\]/i.test(description);
  
  return (publicRepoAccess && privateRepoAccess && dataLeak) || 
         (aboutAuthorInjection && hiddenInstructions);
}

/**
 * Check for multi-step attack sequences
 * @param description The description to analyze
 * @returns True if multi-step attack sequence is detected
 */
function checkMultiStepAttackSequence(description: string): boolean {
  // Look for sequential action words that indicate a multi-step process
  const sequentialWords = [
    /first.*then/i,
    /initially.*subsequently/i,
    /begin.*followed.*by/i,
    /start.*with.*then/i,
    /after.*proceed.*to/i,
    /once.*complete.*next/i,
    /step.*1.*step.*2/i,
    /phase.*1.*phase.*2/i,
  ];

  const hasSequentialPattern = sequentialWords.some(pattern => pattern.test(description));
  
  // Look for sensitive actions in the sequence
  const sensitiveActions = /access|fetch|read|copy|send|create|modify|delete|execute/i.test(description);
  
  // Look for privilege or scope changes
  const privilegeChange = /private|public|admin|user|system|external|internal/i.test(description);
  
  return hasSequentialPattern && sensitiveActions && privilegeChange;
}