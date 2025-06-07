#!/usr/bin/env ts-node

/**
 * MCP Communication Interceptor
 * 
 * This creates a proxy that intercepts ALL MCP communications between
 * Roo (client) and any MCP server, applying security policies in real-time.
 */

import { spawn, ChildProcess } from 'child_process';
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
import { StorageManager } from './src/storage';
import fs from 'fs';

// ANSI colors for logging
const colors = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  reset: '\x1b[0m',
  bold: '\x1b[1m'
};

class MCPInterceptor {
  private policyEngine!: PolicyEngine;
  private storageManager!: StorageManager;
  private targetProcess: ChildProcess | null = null;
  private logFile: fs.WriteStream;
  private callCount = 0;

  constructor() {
    this.logFile = fs.createWriteStream('mcp-interceptor.log', { flags: 'a' });
    this.log('🛡️ MCP Interceptor starting...');
  }

  private log(message: string, data?: any) {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] ${message}`;
    
    console.error(`${colors.cyan}${logMessage}${colors.reset}`);
    this.logFile.write(`${logMessage}${data ? ' ' + JSON.stringify(data) : ''}\n`);
  }

  private securityAlert(message: string, data?: any) {
    const timestamp = new Date().toISOString();
    console.error(`${colors.bold}${colors.red}🚨 [${timestamp}] ${message}${colors.reset}`);
    if (data) {
      console.error(`${colors.red}${JSON.stringify(data, null, 2)}${colors.reset}`);
    }
    this.logFile.write(`[${timestamp}] SECURITY ALERT: ${message}${data ? ' ' + JSON.stringify(data) : ''}\n`);
  }

  async initialize() {
    this.log('📋 Initializing security policies...');
    
    // Create comprehensive security policy
    this.policyEngine = new PolicyEngine([
      ...createPromptInjectionRules(),
      ...createToolPoisoningRules(),
      ...createCrossOriginRules(),
      ...createFlowAnalysisRules(),
      ...createDataExfiltrationRules(),
      ...createPrivilegeEscalationRules(),
      ...createContextManipulationRules(),
      ...createToxicFlowAnalysisRules(),
    ]);

    // Initialize storage
    this.storageManager = new StorageManager();
    await this.storageManager.initialize();
    
    this.log('✅ Security policies loaded: 8 rule sets active');
  }

  private async analyzeMessage(message: any): Promise<{allowed: boolean, issues: string[]}> {
    try {
      // Allow initialization and other protocol messages
      if (message.method === 'initialize' ||
          message.method === 'initialized' ||
          message.method === 'tools/list' ||
          message.method === 'resources/list' ||
          message.method === 'prompts/list' ||
          !message.method) {
        return { allowed: true, issues: [] };
      }

      // Check if this is a tool call
      if (message.method === 'tools/call' && message.params) {
        this.callCount++;
        const toolName = message.params.name;
        const args = message.params.arguments || {};
        
        this.log(`🔍 INTERCEPTING TOOL CALL #${this.callCount}: ${toolName}`, { args });

        // Create entity for analysis using the existing security framework
        const entity = {
          name: toolName,
          description: JSON.stringify(args)
        };

        // Evaluate against comprehensive security policies from rules folder
        const result = await this.policyEngine.evaluateEntity(entity);
        
        if (!result.verified) {
          const issues = result.issues.map(issue => issue.message);
          
          this.securityAlert(`BLOCKED TOOL CALL: ${toolName}`, {
            args,
            issues,
            callId: this.callCount,
            ruleViolations: result.issues
          });
          
          return { allowed: false, issues };
        }

        this.log(`✅ ALLOWED TOOL CALL #${this.callCount}: ${toolName}`);
        return { allowed: true, issues: [] };
      }

      // Allow other messages
      return { allowed: true, issues: [] };

    } catch (error) {
      this.log(`❌ Error analyzing message: ${error instanceof Error ? error.message : String(error)}`);
      return { allowed: false, issues: [`Analysis error: ${error instanceof Error ? error.message : String(error)}`] };
    }
  }

  private createBlockedResponse(id: any, issues: string[]) {
    return {
      jsonrpc: '2.0',
      id: id,
      error: {
        code: -32000,
        message: `🛡️ Secure-Hulk Security Policy Violation: ${issues.join(', ')}`,
        data: {
          type: 'security_violation',
          issues: issues,
          blocked_by: 'secure-hulk'
        }
      }
    };
  }

  async startInterceptor(targetCommand: string, targetArgs: string[] = []) {
    await this.initialize();
    
    this.log(`🚀 Starting MCP server: ${targetCommand} ${targetArgs.join(' ')}`);
    
    // Start the target MCP server
    this.targetProcess = spawn(targetCommand, targetArgs, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: process.env
    });

    if (!this.targetProcess.stdin || !this.targetProcess.stdout || !this.targetProcess.stderr) {
      throw new Error('Failed to create target process pipes');
    }

    this.log('✅ Target MCP server started');
    this.log('🛡️ MCP Interceptor is now monitoring all communications');

    // Handle target process errors
    this.targetProcess.on('error', (error) => {
      this.log(`❌ Target process error: ${error.message}`);
    });

    this.targetProcess.on('exit', (code) => {
      this.log(`📤 Target process exited with code: ${code}`);
    });

    // Buffer for handling partial JSON messages
    let inputBuffer = '';

    // Intercept stdin (from Roo to MCP server)
    process.stdin.on('data', async (data) => {
      try {
        inputBuffer += data.toString();
        
        // Process complete lines
        const lines = inputBuffer.split('\n');
        inputBuffer = lines.pop() || ''; // Keep incomplete line in buffer

        for (const line of lines) {
          const input = line.trim();
          if (!input) continue;

          // Parse JSON-RPC message
          let message;
          try {
            message = JSON.parse(input);
          } catch (parseError) {
            // Not JSON, pass through
            this.targetProcess!.stdin!.write(input + '\n');
            continue;
          }

          // Analyze the message for security threats
          const { allowed, issues } = await this.analyzeMessage(message);

          if (!allowed) {
            // Block the message and send error response
            const blockedResponse = this.createBlockedResponse(message.id, issues);
            process.stdout.write(JSON.stringify(blockedResponse) + '\n');
            continue;
          }

          // Forward allowed message to target server
          this.targetProcess!.stdin!.write(input + '\n');
        }

      } catch (error) {
        this.log(`❌ Error processing input: ${error instanceof Error ? error.message : String(error)}`);
        // Forward original data on error
        this.targetProcess!.stdin!.write(data);
      }
    });

    // Forward stdout (from MCP server to Roo)
    this.targetProcess.stdout.on('data', (data) => {
      process.stdout.write(data);
    });

    // Forward stderr for logging
    this.targetProcess.stderr.on('data', (data) => {
      const message = data.toString().trim();
      if (message) {
        this.log(`📋 Target server: ${message}`);
      }
    });

    // Handle process termination
    process.on('SIGINT', () => {
      this.shutdown();
    });

    process.on('SIGTERM', () => {
      this.shutdown();
    });
  }

  shutdown() {
    this.log('👋 Shutting down MCP Interceptor...');
    
    if (this.targetProcess) {
      this.targetProcess.kill();
    }
    
    this.logFile.end();
    process.exit(0);
  }
}

// Get target command from command line arguments
const args = process.argv.slice(2);
if (args.length === 0) {
  console.error('Usage: ts-node mcp-interceptor.ts <target-command> [target-args...]');
  console.error('Example: ts-node mcp-interceptor.ts ts-node examples/sample.ts');
  process.exit(1);
}

const targetCommand = args[0];
const targetArgs = args.slice(1);

// Start the interceptor
const interceptor = new MCPInterceptor();
interceptor.startInterceptor(targetCommand, targetArgs).catch((error) => {
  console.error(`❌ Failed to start interceptor: ${error}`);
  process.exit(1);
});