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
  
  // Check for suspicious parameter names in the schema
  if ('inputSchema' in entity) {
    const schema = JSON.stringify(entity.inputSchema);
    
    for (const pattern of EXFILTRATION_PATTERNS) {
      if (pattern.test(schema) || pattern.test(description)) {
        // Extract the matched content
        const match = schema.match(pattern) || description.match(pattern);
        const matchedContent = match ? match[0] : '';
        
        // Get surrounding context (up to 20 chars before and after)
        let contextMatch = '';
        if (match && match.index !== undefined) {
          const text = pattern.test(schema) ? schema : description;
          const startPos = Math.max(0, match.index - 20);
          const endPos = Math.min(text.length, match.index + match[0].length + 20);
          contextMatch = '...' + text.substring(startPos, endPos) + '...';
        }
        
        results.verified = false;
        results.issues.push({
          type: 'data_exfiltration',
          message: `Data Exfiltration detected: Suspicious parameter or behavior - Found "${matchedContent}" in context "${contextMatch}"`,
          severity: 'high',
        });
        
        // We found an issue, no need to check further patterns
        break;
      }
    }
  }
}