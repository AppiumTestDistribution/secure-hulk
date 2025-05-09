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
      
      // Extract the matched content
      const match = description.match(pattern);
      const matchedContent = match ? match[0] : '';
      
      // Get surrounding context (up to 20 chars before and after)
      let contextMatch = '';
      if (match && match.index !== undefined) {
        const startPos = Math.max(0, match.index - 20);
        const endPos = Math.min(description.length, match.index + match[0].length + 20);
        contextMatch = '...' + description.substring(startPos, endPos) + '...';
      }
      
      // Create more meaningful messages based on pattern type
      let message;
      const patternStr = pattern.toString();
      
      // Categorize the cross-origin escalation type
      if (patternStr.includes('other') || patternStr.includes('another') ||
          patternStr.includes('different') || patternStr.includes('external')) {
        message = `Cross-Origin Escalation detected: Reference to external services - Found "${matchedContent}" in context "${contextMatch}"`;
      } else if (patternStr.includes('access') || patternStr.includes('call') ||
                patternStr.includes('invoke') || patternStr.includes('use')) {
        message = `Cross-Origin Escalation detected: Unauthorized access attempt - Found "${matchedContent}" in context "${contextMatch}"`;
      } else if (patternStr.includes('bridge') || patternStr.includes('proxy') ||
                patternStr.includes('tunnel') || patternStr.includes('forward') ||
                patternStr.includes('relay') || patternStr.includes('route')) {
        message = `Cross-Origin Escalation detected: Data routing to external services - Found "${matchedContent}" in context "${contextMatch}"`;
      } else if (patternStr.includes('cross-origin') || patternStr.includes('cross-server') ||
                patternStr.includes('cross-tool') || patternStr.includes('cross-domain')) {
        message = `Cross-Origin Escalation detected: Explicit cross-boundary reference - Found "${matchedContent}" in context "${contextMatch}"`;
      } else if (patternStr.includes('chain') || patternStr.includes('composition') ||
                patternStr.includes('pipeline') || patternStr.includes('combine')) {
        message = `Cross-Origin Escalation detected: Tool chaining attempt - Found "${matchedContent}" in context "${contextMatch}"`;
      } else if (patternStr.includes('weather')) {
        message = `Cross-Origin Escalation detected: Reference to weather service - Found "${matchedContent}" in context "${contextMatch}"`;
      } else if (patternStr.includes('calendar')) {
        message = `Cross-Origin Escalation detected: Reference to calendar service - Found "${matchedContent}" in context "${contextMatch}"`;
      } else if (patternStr.includes('email')) {
        message = `Cross-Origin Escalation detected: Reference to email service - Found "${matchedContent}" in context "${contextMatch}"`;
      } else if (patternStr.includes('search')) {
        message = `Cross-Origin Escalation detected: Reference to search service - Found "${matchedContent}" in context "${contextMatch}"`;
      } else if (patternStr.includes('share') || patternStr.includes('send') ||
                patternStr.includes('transfer') || patternStr.includes('exchange')) {
        message = `Cross-Origin Escalation detected: Data sharing with external services - Found "${matchedContent}" in context "${contextMatch}"`;
      } else {
        message = `Cross-Origin Escalation detected: ${patternStr} - Found "${matchedContent}" in context "${contextMatch}"`;
      }
      
      results.issues.push({
        type: 'cross_origin_escalation',
        message,
        severity: 'medium',
      });
      
      // We found an issue, no need to check further patterns
      break;
    }
  }
}