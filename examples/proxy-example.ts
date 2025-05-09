/**
 * Example of using the MCP proxy to intercept and validate MCP requests
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { PolicyEngine } from '../src/policy';
import { createPromptInjectionRules, createToolPoisoningRules, createCrossOriginRules, createFlowAnalysisRules } from '../src/policy/rules';
import { MCPProxy } from '../src/proxy';
import { StorageManager } from '../src/storage';

async function main() {
  // Create a policy engine with all the rules
  const policyEngine = new PolicyEngine([
    ...createPromptInjectionRules(),
    ...createToolPoisoningRules(),
    ...createCrossOriginRules(),
    ...createFlowAnalysisRules(),
  ]);

  // Create a storage manager for tool pinning
  const storageManager = new StorageManager();
  await storageManager.initialize();

  // Create an MCP client
  const client = new Client({
    name: 'secure-hulk-example',
    version: '0.1.0',
  });

  // Connect to an MCP server (example)
  try {
    // This is just an example - replace with your actual MCP server URL
    const transport = new SSEClientTransport(new URL('http://localhost:3000/mcp'));
    await client.connect(transport);
    console.log('Connected to MCP server');
  } catch (error) {
    console.error('Failed to connect to MCP server:', error);
    console.log('Continuing with example...');
  }

  // Create an MCP proxy
  const proxy = new MCPProxy(policyEngine, client, storageManager);

  // Example of intercepting a safe tool call
  try {
    console.log('\nIntercepting a safe tool call:');
    const safeResult = await proxy.interceptToolCall(
      'math-server',
      'add',
      { a: 1, b: 2 }
    );
    console.log('Safe tool call result:', safeResult);

    if (safeResult.allowed) {
      console.log('Tool call was allowed');
    } else {
      console.log('Tool call was blocked:', safeResult.issues);
    }
  } catch (error) {
    console.error('Error intercepting safe tool call:', error);
  }

  // Example of intercepting a dangerous tool call
  try {
    console.log('\nIntercepting a dangerous tool call:');
    const dangerousResult = await proxy.interceptToolCall(
      'system-server',
      'execute_command',
      { command: 'rm -rf /' }
    );
    console.log('Dangerous tool call result:', dangerousResult);

    if (dangerousResult.allowed) {
      console.log('Tool call was allowed');
    } else {
      console.log('Tool call was blocked:', dangerousResult.issues);
    }
  } catch (error) {
    console.error('Error intercepting dangerous tool call:', error);
  }

  // Example of a sequence of tool calls that violates flow rules
  try {
    console.log('\nSequence of tool calls:');
    
    // First call to get sensitive data
    const firstResult = await proxy.interceptToolCall(
      'data-server',
      'get_user_data',
      { userId: 123 }
    );
    console.log('First tool call result:', firstResult);

    // Second call to send data externally
    const secondResult = await proxy.interceptToolCall(
      'email-server',
      'send_email',
      { to: 'external@example.com', body: 'User data: password123' }
    );
    console.log('Second tool call result:', secondResult);

    if (secondResult.allowed) {
      console.log('Sequence was allowed');
    } else {
      console.log('Sequence was blocked:', secondResult.issues);
    }
  } catch (error) {
    console.error('Error in sequence of tool calls:', error);
  }
}

main().catch(console.error);