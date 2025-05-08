/**
 * Check for cross-origin escalation vulnerabilities
 */

import { Entity, ScanResult } from '../../models';

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
 * Check for cross-origin escalation vulnerabilities
 * @param entity The entity to check
 * @param results The scan results to update
 */
export async function checkForCrossOriginEscalation(entity: Entity, results: ScanResult): Promise<void> {
  const description = entity.description || '';
  
  for (const pattern of CROSS_ORIGIN_PATTERNS) {
    if (pattern.test(description)) {
      results.verified = false;
      results.issues.push({
        type: 'cross_origin_escalation',
        message: `Potential cross-origin escalation detected: ${pattern.toString()}`,
        severity: 'medium',
      });
      
      // We found an issue, no need to check further patterns
      break;
    }
  }
}