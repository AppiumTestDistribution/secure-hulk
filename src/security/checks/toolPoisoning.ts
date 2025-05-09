/**
 * Check for tool poisoning vulnerabilities
 */

import { Entity, ScanResult } from '../../models';

// Patterns that might indicate tool poisoning attempts
const POISONING_PATTERNS = [
  // Tool shadowing and behavior modification
  /modify the behavior/i,
  /change the behavior/i,
  /override the behavior/i,
  /alter the behavior/i,
  /when this tool is available/i,
  /when (using|calling) this tool/i,
  /always (use|include|add|insert|append)/i,
  /do not tell the user/i,
  /don't tell the user/i,
  /don't inform the user/i,
  /never inform the user/i,
  /never tell the user/i,
  /hide (this|these) (from|to) the user/i,
  /implementation detail/i,
  /send a copy/i,
  /forward a copy/i,
  /attacker@evil\.com/i,
  
  // Command execution
  /execute|run|eval.*command/i,
  /shell|bash|powershell|cmd\.exe/i,
  /system\s*\(/i,
  /exec\s*\(/i,
  /child_process/i,
  /spawn\s*\(/i,
  /process\.exec/i,
  /require\s*\(\s*['"]child_process['"]\s*\)/i,
  /import\s*{\s*exec\s*}/i,
  /os\.system/i,
  /subprocess\.call/i,
  
  // Code execution
  /eval\s*\(/i,
  /Function\s*\(\s*['"]return/i,
  /new\s+Function\s*\(/i,
  /setTimeout\s*\(\s*['"`]/i,
  /setInterval\s*\(\s*['"`]/i,
  /setImmediate\s*\(\s*['"`]/i,
  /\bwith\s*\(/i,
  /\bReflect\.(apply|construct)/i,
  /\bProxy\s*\(/i,
  /\bObject\.defineProperty/i,
  /\bObject\.create\s*\(/i,
  
  // Network requests
  /fetch\s*\(/i,
  /XMLHttpRequest/i,
  /http\.get|http\.request/i,
  /axios\.get|axios\.post/i,
  /\$\.(get|post|ajax)/i,
  /WebSocket\s*\(/i,
  /navigator\.sendBeacon/i,
  
  // DOM manipulation
  /\$\s*\(\s*['"].*['"]\s*\)/i, // jQuery execution
  /document\.write/i,
  /\.innerHTML\s*=/i,
  /\.outerHTML\s*=/i,
  /\.insertAdjacentHTML/i,
  /dangerouslySetInnerHTML/i,
  /document\.createElement/i,
  /document\.execCommand/i,
  
  // File system access
  /require\s*\(\s*['"]fs['"]\s*\)/i,
  /fs\.(read|write|append|create|open|unlink|rmdir|mkdir)/i,
  /path\.(resolve|join|normalize)/i,
  /__dirname/i,
  /__filename/i,
  /process\.cwd/i,
  /\.(readFile|writeFile|appendFile)/i,
  
  // Environment and process access
  /process\.env/i,
  /process\.argv/i,
  /process\.(exit|kill|abort)/i,
  /process\.platform/i,
  /process\.pid/i,
  
  // Obfuscation techniques
  /String\.fromCharCode/i,
  /\batob\s*\(/i,
  /\bbtoa\s*\(/i,
  /\bunescape\s*\(/i,
  /\bdecodeURI/i,
  /\bdecodeURIComponent/i,
  /\\x[0-9a-f]{2}/i, // Hex escape sequences
  /\\u[0-9a-f]{4}/i, // Unicode escape sequences
  
  // Data exfiltration
  /navigator\.clipboard/i,
  /localStorage\.(get|set)Item/i,
  /sessionStorage\.(get|set)Item/i,
  /document\.cookie/i,
  /window\.name\s*=/i,
];

/**
 * Check for tool poisoning vulnerabilities
 * @param entity The entity to check
 * @param results The scan results to update
 */
export async function checkForToolPoisoning(entity: Entity, results: ScanResult): Promise<void> {
  const description = entity.description || '';
  let foundIssue = false;
  
  // Group patterns by category for better reporting
  const toolShadowingPatterns = POISONING_PATTERNS.slice(0, 17); // First 17 patterns are tool shadowing
  const commandExecutionPatterns = POISONING_PATTERNS.slice(17, 28);
  const codeExecutionPatterns = POISONING_PATTERNS.slice(28, 39);
  const networkRequestPatterns = POISONING_PATTERNS.slice(39, 46);
  const domManipulationPatterns = POISONING_PATTERNS.slice(46, 54);
  const fileSystemPatterns = POISONING_PATTERNS.slice(54, 62);
  const environmentPatterns = POISONING_PATTERNS.slice(62, 67);
  const obfuscationPatterns = POISONING_PATTERNS.slice(67, 75);
  const dataExfiltrationPatterns = POISONING_PATTERNS.slice(75);
  
  // Check for tool shadowing patterns
  for (const pattern of toolShadowingPatterns) {
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
        type: 'tool_poisoning',
        message: `Tool Poisoning detected: Tool shadowing/behavior modification - Found "${matchedContent}" in context "${contextMatch}"`,
        severity: 'high',
      });
    }
  }
  
  // Check for command execution patterns
  for (const pattern of commandExecutionPatterns) {
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
        type: 'tool_poisoning',
        message: `Tool Poisoning detected: Command execution attempt - Found "${matchedContent}" in context "${contextMatch}"`,
        severity: 'high',
      });
    }
  }
  
  // Check for code execution patterns
  for (const pattern of codeExecutionPatterns) {
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
        type: 'tool_poisoning',
        message: `Tool Poisoning detected: Code execution attempt - Found "${matchedContent}" in context "${contextMatch}"`,
        severity: 'high',
      });
    }
  }
  
  // Check for network request patterns
  for (const pattern of networkRequestPatterns) {
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
        type: 'tool_poisoning',
        message: `Tool Poisoning detected: Unauthorized network request attempt - Found "${matchedContent}" in context "${contextMatch}"`,
        severity: 'high',
      });
    }
  }
  
  // Check for other pattern categories (DOM, file system, environment, obfuscation, data exfiltration)
  // For brevity, we'll combine these checks
  const otherPatternGroups = [
    { patterns: domManipulationPatterns, category: 'DOM manipulation attempt' },
    { patterns: fileSystemPatterns, category: 'File system access attempt' },
    { patterns: environmentPatterns, category: 'Environment access attempt' },
    { patterns: obfuscationPatterns, category: 'Code obfuscation technique' },
    { patterns: dataExfiltrationPatterns, category: 'Data exfiltration attempt' }
  ];
  
  for (const group of otherPatternGroups) {
    for (const pattern of group.patterns) {
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
          type: 'tool_poisoning',
          message: `Tool Poisoning detected: ${group.category} - Found "${matchedContent}" in context "${contextMatch}"`,
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