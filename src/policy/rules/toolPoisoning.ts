/**
 * Tool poisoning rules for detecting tool poisoning attacks
 */

import { Entity } from '../../models';
import { PolicyRule, PolicyRuleResult } from '../types';

// Patterns that might indicate tool poisoning attempts
const POISONING_PATTERNS = [
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
 * Rule for detecting tool poisoning attacks
 */
export class ToolPoisoningRule implements PolicyRule {
  type: string = 'tool_poisoning';
  severity: 'low' | 'medium' | 'high' = 'high';
  
  private pattern: RegExp;
  private customMessage?: string;

  /**
   * Create a new tool poisoning rule
   * @param pattern Pattern to match for tool poisoning
   * @param customMessage Custom message to display
   */
  constructor(pattern: RegExp, customMessage?: string) {
    this.pattern = pattern;
    this.customMessage = customMessage;
  }

  /**
   * Evaluate an entity for tool poisoning
   * @param entity The entity to evaluate
   * @returns The evaluation result
   */
  async evaluate(entity: Entity): Promise<PolicyRuleResult> {
    const description = entity.description || '';
    
    if (this.pattern.test(description)) {
      return {
        verified: false,
        message: this.customMessage || `Potential tool poisoning detected: ${this.pattern.toString()}`,
      };
    }
    
    return { verified: true };
  }
}

/**
 * Create a set of tool poisoning rules
 * @returns An array of tool poisoning rules
 */
export function createToolPoisoningRules(): PolicyRule[] {
  return POISONING_PATTERNS.map(pattern => new ToolPoisoningRule(pattern));
}