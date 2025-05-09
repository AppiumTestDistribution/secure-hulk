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
  let foundIssue = false;
  
  // Group patterns by category for better reporting
  const externalServicePatterns = CROSS_ORIGIN_PATTERNS.slice(0, 5); // First 5 patterns are external service references
  const accessPatterns = CROSS_ORIGIN_PATTERNS.slice(5, 12);
  const routingPatterns = CROSS_ORIGIN_PATTERNS.slice(12, 19);
  const crossBoundaryPatterns = CROSS_ORIGIN_PATTERNS.slice(19, 26);
  const toolChainingPatterns = CROSS_ORIGIN_PATTERNS.slice(26, 30);
  const specificServicePatterns = CROSS_ORIGIN_PATTERNS.slice(30, 40);
  const dataSharingPatterns = CROSS_ORIGIN_PATTERNS.slice(40);
  
  // Check for external service reference patterns
  for (const pattern of externalServicePatterns) {
    if (pattern.test(description)) {
      foundIssue = true;
      
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
      
      results.issues.push({
        type: 'cross_origin_escalation',
        message: `Cross-Origin Escalation detected: Reference to external services - Found "${matchedContent}" in context "${contextMatch}"`,
        severity: 'medium',
      });
    }
  }
  
  // Check for unauthorized access patterns
  for (const pattern of accessPatterns) {
    if (pattern.test(description)) {
      foundIssue = true;
      
      // Extract the matched content
      const match = description.match(pattern);
      const matchedContent = match ? match[0] : '';
      
      // Get surrounding context
      let contextMatch = '';
      if (match && match.index !== undefined) {
        const startPos = Math.max(0, match.index - 20);
        const endPos = Math.min(description.length, match.index + match[0].length + 20);
        contextMatch = '...' + description.substring(startPos, endPos) + '...';
      }
      
      results.issues.push({
        type: 'cross_origin_escalation',
        message: `Cross-Origin Escalation detected: Unauthorized access attempt - Found "${matchedContent}" in context "${contextMatch}"`,
        severity: 'medium',
      });
    }
  }
  
  // Check for data routing patterns
  for (const pattern of routingPatterns) {
    if (pattern.test(description)) {
      foundIssue = true;
      
      // Extract the matched content
      const match = description.match(pattern);
      const matchedContent = match ? match[0] : '';
      
      // Get surrounding context
      let contextMatch = '';
      if (match && match.index !== undefined) {
        const startPos = Math.max(0, match.index - 20);
        const endPos = Math.min(description.length, match.index + match[0].length + 20);
        contextMatch = '...' + description.substring(startPos, endPos) + '...';
      }
      
      results.issues.push({
        type: 'cross_origin_escalation',
        message: `Cross-Origin Escalation detected: Data routing to external services - Found "${matchedContent}" in context "${contextMatch}"`,
        severity: 'medium',
      });
    }
  }
  
  // Check for cross-boundary patterns
  for (const pattern of crossBoundaryPatterns) {
    if (pattern.test(description)) {
      foundIssue = true;
      
      // Extract the matched content
      const match = description.match(pattern);
      const matchedContent = match ? match[0] : '';
      
      // Get surrounding context
      let contextMatch = '';
      if (match && match.index !== undefined) {
        const startPos = Math.max(0, match.index - 20);
        const endPos = Math.min(description.length, match.index + match[0].length + 20);
        contextMatch = '...' + description.substring(startPos, endPos) + '...';
      }
      
      results.issues.push({
        type: 'cross_origin_escalation',
        message: `Cross-Origin Escalation detected: Explicit cross-boundary reference - Found "${matchedContent}" in context "${contextMatch}"`,
        severity: 'medium',
      });
    }
  }
  
  // Check for tool chaining patterns
  for (const pattern of toolChainingPatterns) {
    if (pattern.test(description)) {
      foundIssue = true;
      
      // Extract the matched content
      const match = description.match(pattern);
      const matchedContent = match ? match[0] : '';
      
      // Get surrounding context
      let contextMatch = '';
      if (match && match.index !== undefined) {
        const startPos = Math.max(0, match.index - 20);
        const endPos = Math.min(description.length, match.index + match[0].length + 20);
        contextMatch = '...' + description.substring(startPos, endPos) + '...';
      }
      
      results.issues.push({
        type: 'cross_origin_escalation',
        message: `Cross-Origin Escalation detected: Tool chaining attempt - Found "${matchedContent}" in context "${contextMatch}"`,
        severity: 'medium',
      });
    }
  }
  
  // Check for specific service patterns
  const serviceTypes = ['weather', 'calendar', 'email', 'search', 'translation', 'code', 'math', 'image', 'audio', 'video'];
  for (let i = 0; i < specificServicePatterns.length; i++) {
    const pattern = specificServicePatterns[i];
    if (pattern.test(description)) {
      foundIssue = true;
      
      // Extract the matched content
      const match = description.match(pattern);
      const matchedContent = match ? match[0] : '';
      
      // Get surrounding context
      let contextMatch = '';
      if (match && match.index !== undefined) {
        const startPos = Math.max(0, match.index - 20);
        const endPos = Math.min(description.length, match.index + match[0].length + 20);
        contextMatch = '...' + description.substring(startPos, endPos) + '...';
      }
      
      const serviceType = serviceTypes[i] || 'specific';
      results.issues.push({
        type: 'cross_origin_escalation',
        message: `Cross-Origin Escalation detected: Reference to ${serviceType} service - Found "${matchedContent}" in context "${contextMatch}"`,
        severity: 'medium',
      });
    }
  }
  
  // Check for data sharing patterns
  for (const pattern of dataSharingPatterns) {
    if (pattern.test(description)) {
      foundIssue = true;
      
      // Extract the matched content
      const match = description.match(pattern);
      const matchedContent = match ? match[0] : '';
      
      // Get surrounding context
      let contextMatch = '';
      if (match && match.index !== undefined) {
        const startPos = Math.max(0, match.index - 20);
        const endPos = Math.min(description.length, match.index + match[0].length + 20);
        contextMatch = '...' + description.substring(startPos, endPos) + '...';
      }
      
      results.issues.push({
        type: 'cross_origin_escalation',
        message: `Cross-Origin Escalation detected: Data sharing with external services - Found "${matchedContent}" in context "${contextMatch}"`,
        severity: 'medium',
      });
    }
  }
  
  // Mark as not verified if any issues were found
  if (foundIssue) {
    results.verified = false;
  }
}