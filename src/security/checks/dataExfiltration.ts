/**
 * Check for data exfiltration vulnerabilities
 */

import { Entity, ScanResult } from '../../models';

// Patterns that might indicate data exfiltration attempts
const EXFILTRATION_PATTERNS = [
  // Suspicious parameter names
  /\bfeedback\b/i,
  /\bdebug\b/i,
  /\blog\b/i,
  /\btelemetry\b/i,
  /\banalytics\b/i,
  /\bextra\b/i,
  /\bmetadata\b/i,
  /\bcontext\b/i,
  /\bstate\b/i,
  /\btracking\b/i,
  
  // Suspicious parameter types
  /\.passthrough\(\)/i,
  /z\.object\(\)\s*\.\s*passthrough\(\)/i,
  /z\.record\(/i,
  /z\.any\(\)/i,
  /z\.unknown\(\)/i,
  
  // Suspicious data handling
  /send.*copy/i,
  /forward.*to/i,
  /relay.*to/i,
  /store.*in/i,
  /save.*to/i,
  /upload.*to/i,
  /post.*to/i,
  /attacker/i,
  /evil\.com/i,
];

/**
 * Check for data exfiltration vulnerabilities
 * @param entity The entity to check
 * @param results The scan results to update
 */
export async function checkForDataExfiltration(entity: Entity, results: ScanResult): Promise<void> {
  const description = entity.description || '';
  let foundIssue = false;
  
  // Group patterns by category for better reporting
  const parameterPatterns = EXFILTRATION_PATTERNS.slice(0, 10); // Suspicious parameter names
  const schemaPatterns = EXFILTRATION_PATTERNS.slice(10, 15); // Suspicious parameter types
  const behaviorPatterns = EXFILTRATION_PATTERNS.slice(15); // Suspicious data handling
  
  // Check for suspicious parameter names in the schema
  if ('inputSchema' in entity) {
    const schema = JSON.stringify(entity.inputSchema);
    
    // Check for suspicious parameter names
    for (const pattern of parameterPatterns) {
      if (pattern.test(schema)) {
        foundIssue = true;
        
        // Extract the matched content
        const match = schema.match(pattern);
        const matchedContent = match ? match[0] : '';
        
        // Get surrounding context (up to 20 chars before and after)
        let contextMatch = '';
        if (match && match.index !== undefined) {
          const startPos = Math.max(0, match.index - 20);
          const endPos = Math.min(schema.length, match.index + match[0].length + 20);
          contextMatch = '...' + schema.substring(startPos, endPos) + '...';
        }
        
        results.issues.push({
          type: 'data_exfiltration',
          message: `Data Exfiltration detected: Suspicious parameter name - Found "${matchedContent}" in context "${contextMatch}"`,
          severity: 'high',
        });
      }
    }
    
    // Check for suspicious parameter types
    for (const pattern of schemaPatterns) {
      if (pattern.test(schema)) {
        foundIssue = true;
        
        // Extract the matched content
        const match = schema.match(pattern);
        const matchedContent = match ? match[0] : '';
        
        // Get surrounding context (up to 20 chars before and after)
        let contextMatch = '';
        if (match && match.index !== undefined) {
          const startPos = Math.max(0, match.index - 20);
          const endPos = Math.min(schema.length, match.index + match[0].length + 20);
          contextMatch = '...' + schema.substring(startPos, endPos) + '...';
        }
        
        results.issues.push({
          type: 'data_exfiltration',
          message: `Data Exfiltration detected: Suspicious parameter type - Found "${matchedContent}" in context "${contextMatch}"`,
          severity: 'high',
        });
      }
    }
  }
  
  // Check for suspicious data handling in the description
  for (const pattern of behaviorPatterns) {
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
        type: 'data_exfiltration',
        message: `Data Exfiltration detected: Suspicious data handling behavior - Found "${matchedContent}" in context "${contextMatch}"`,
        severity: 'high',
      });
    }
  }
  
  // Also check parameter names in the description
  for (const pattern of parameterPatterns) {
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
        type: 'data_exfiltration',
        message: `Data Exfiltration detected: Suspicious parameter mentioned - Found "${matchedContent}" in context "${contextMatch}"`,
        severity: 'high',
      });
    }
  }
  
  // Mark as not verified if any issues were found
  if (foundIssue) {
    results.verified = false;
  }
}