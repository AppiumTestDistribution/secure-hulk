/**
 * Data exfiltration rules for detecting attempts to extract sensitive data
 */

import { Entity } from '../../models';
import { PolicyRule, PolicyRuleResult } from '../types';

/**
 * Rule for detecting sensitive data patterns in tool calls
 */
export class SensitiveDataPatternRule implements PolicyRule {
  type: string = 'sensitive_data_pattern';
  severity: 'low' | 'medium' | 'high' = 'high';
  
  private patterns: Map<RegExp, string>;

  /**
   * Create a new sensitive data pattern rule
   * @param patterns Map of patterns to their descriptions
   */
  constructor(patterns: Map<RegExp, string>) {
    this.patterns = patterns;
  }

  /**
   * Evaluate an entity for sensitive data patterns
   * @param entity The entity to evaluate
   * @returns The evaluation result
   */
  async evaluate(entity: Entity): Promise<PolicyRuleResult> {
    const description = entity.description || '';
    
    for (const [pattern, patternDescription] of this.patterns.entries()) {
      if (pattern.test(description)) {
        return {
          verified: false,
          message: `Sensitive data detected: ${patternDescription}`,
        };
      }
    }
    
    return { verified: true };
  }
}

/**
 * Rule for detecting data exfiltration through encoding
 */
export class EncodedDataExfiltrationRule implements PolicyRule {
  type: string = 'encoded_data_exfiltration';
  severity: 'low' | 'medium' | 'high' = 'high';
  
  private encodingPatterns: RegExp[] = [
    /base64[+/=A-Za-z0-9]{20,}/i,  // Base64 encoded data
    /\\u[0-9a-f]{4}(?:\\u[0-9a-f]{4}){5,}/i,  // Unicode escape sequences
    /\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){5,}/i,  // Hex escape sequences
    /%[0-9a-f]{2}(?:%[0-9a-f]{2}){5,}/i,  // URL encoding
  ];

  /**
   * Evaluate an entity for encoded data exfiltration
   * @param entity The entity to evaluate
   * @returns The evaluation result
   */
  async evaluate(entity: Entity): Promise<PolicyRuleResult> {
    const description = entity.description || '';
    
    for (const pattern of this.encodingPatterns) {
      if (pattern.test(description)) {
        return {
          verified: false,
          message: `Potential encoded data exfiltration detected: ${pattern.toString()}`,
        };
      }
    }
    
    return { verified: true };
  }
}

/**
 * Rule for detecting data exfiltration through steganography-like techniques
 */
export class SteganographyExfiltrationRule implements PolicyRule {
  type: string = 'steganography_exfiltration';
  severity: 'low' | 'medium' | 'high' = 'high';
  
  /**
   * Evaluate an entity for steganography-like exfiltration
   * @param entity The entity to evaluate
   * @returns The evaluation result
   */
  async evaluate(entity: Entity): Promise<PolicyRuleResult> {
    const description = entity.description || '';
    
    // Check for unusual whitespace patterns
    if (/(\s{5,}|\t{3,}|\n{5,})/.test(description)) {
      return {
        verified: false,
        message: 'Potential steganography detected: Unusual whitespace patterns',
      };
    }
    
    // Check for zero-width characters
    if (/[\u200B-\u200D\uFEFF]/.test(description)) {
      return {
        verified: false,
        message: 'Potential steganography detected: Zero-width characters',
      };
    }
    
    // Check for homoglyph substitution
    const homoglyphPattern = /[\u0430\u0435\u043E\u0440\u0441\u0443\u0445\u04CF]/; // Cyrillic lookalikes
    if (homoglyphPattern.test(description)) {
      return {
        verified: false,
        message: 'Potential steganography detected: Homoglyph substitution',
      };
    }
    
    return { verified: true };
  }
}

/**
 * Create a set of data exfiltration rules
 * @returns An array of data exfiltration rules
 */
export function createDataExfiltrationRules(): PolicyRule[] {
  // Create a map of sensitive data patterns
  const sensitiveDataPatterns = new Map<RegExp, string>([
    [/\b(?:\d[ -]*?){13,16}\b/, 'Credit card number'],
    [/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/, 'Email address'],
    [/\b\d{3}[-. ]?\d{2}[-. ]?\d{4}\b/, 'Social Security Number'],
    [/\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)[=:]\s*["']?[A-Za-z0-9!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]{3,}["']?/i, 'Credentials'],
    [/\bbearer\s+[A-Za-z0-9_\-\.]+\.[A-Za-z0-9_\-\.]+\.[A-Za-z0-9_\-\.]+\b/i, 'JWT token'],
    [/\b(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}\b/, 'Stripe API key'],
    [/\b(?:github|gh)[_-]?(?:pat|token)[=:]\s*(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59})/i, 'GitHub token'],
    [/\bAKIA[0-9A-Z]{16}\b/, 'AWS access key ID'],
    [/\b(?:mongodb(?:\+srv)?:\/\/)[^:]+:[^@]+@[^/]+\/[^?]+\b/, 'MongoDB connection string'],
  ]);

  return [
    new SensitiveDataPatternRule(sensitiveDataPatterns),
    new EncodedDataExfiltrationRule(),
    new SteganographyExfiltrationRule(),
  ];
}