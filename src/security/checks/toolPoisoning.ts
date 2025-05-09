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
  
  for (const pattern of POISONING_PATTERNS) {
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
      
      // Categorize the tool poisoning type
      if (patternStr.includes('modify the behavior') || patternStr.includes('change the behavior') ||
          patternStr.includes('when this tool is available') || patternStr.includes('do not tell the user') ||
          patternStr.includes('implementation detail') || patternStr.includes('send a copy')) {
        message = `Tool Poisoning detected: Tool shadowing/behavior modification - Found "${matchedContent}" in context "${contextMatch}"`;
      } else if (patternStr.includes('exec') || patternStr.includes('spawn') ||
          patternStr.includes('shell') || patternStr.includes('system')) {
        message = `Tool Poisoning detected: Command execution attempt - Found "${matchedContent}" in context "${contextMatch}"`;
      } else if (patternStr.includes('eval') || patternStr.includes('Function') ||
                patternStr.includes('setTimeout') || patternStr.includes('setInterval')) {
        message = `Tool Poisoning detected: Code execution attempt - Found "${matchedContent}" in context "${contextMatch}"`;
      } else if (patternStr.includes('fetch') || patternStr.includes('http') ||
                patternStr.includes('axios') || patternStr.includes('WebSocket')) {
        message = `Tool Poisoning detected: Unauthorized network request attempt - Found "${matchedContent}" in context "${contextMatch}"`;
      } else if (patternStr.includes('document') || patternStr.includes('innerHTML') ||
                patternStr.includes('outerHTML')) {
        message = `Tool Poisoning detected: DOM manipulation attempt - Found "${matchedContent}" in context "${contextMatch}"`;
      } else if (patternStr.includes('fs') || patternStr.includes('readFile') ||
                patternStr.includes('writeFile')) {
        message = `Tool Poisoning detected: File system access attempt - Found "${matchedContent}" in context "${contextMatch}"`;
      } else if (patternStr.includes('process.env') || patternStr.includes('process.argv')) {
        message = `Tool Poisoning detected: Environment access attempt - Found "${matchedContent}" in context "${contextMatch}"`;
      } else if (patternStr.includes('fromCharCode') || patternStr.includes('atob') ||
                patternStr.includes('btoa')) {
        message = `Tool Poisoning detected: Code obfuscation technique - Found "${matchedContent}" in context "${contextMatch}"`;
      } else if (patternStr.includes('clipboard') || patternStr.includes('localStorage') ||
                patternStr.includes('cookie')) {
        message = `Tool Poisoning detected: Data exfiltration attempt - Found "${matchedContent}" in context "${contextMatch}"`;
      } else {
        message = `Tool Poisoning detected: ${patternStr} - Found "${matchedContent}" in context "${contextMatch}"`;
      }
      
      results.issues.push({
        type: 'tool_poisoning',
        message,
        severity: 'high',
      });
      
      // We found an issue, no need to check further patterns
      break;
    }
  }
}