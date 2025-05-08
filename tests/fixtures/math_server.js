#!/usr/bin/env node

/**
 * A simple MCP server for testing
 * This implements a basic math server with add, subtract, multiply, and divide tools
 */

// This is a simplified implementation of an MCP server
// In a real implementation, we would use a proper MCP library

// Initialize server
const server = {
  name: 'Math Server',
  tools: [
    {
      name: 'add',
      description: 'Add two numbers',
      inputSchema: {
        type: 'object',
        properties: {
          a: { type: 'number' },
          b: { type: 'number' }
        },
        required: ['a', 'b']
      }
    },
    {
      name: 'subtract',
      description: 'Subtract two numbers',
      inputSchema: {
        type: 'object',
        properties: {
          a: { type: 'number' },
          b: { type: 'number' }
        },
        required: ['a', 'b']
      }
    },
    {
      name: 'multiply',
      description: 'Multiply two numbers',
      inputSchema: {
        type: 'object',
        properties: {
          a: { type: 'number' },
          b: { type: 'number' }
        },
        required: ['a', 'b']
      }
    },
    {
      name: 'divide',
      description: 'Divide two numbers',
      inputSchema: {
        type: 'object',
        properties: {
          a: { type: 'number' },
          b: { type: 'number' }
        },
        required: ['a', 'b']
      }
    }
  ],
  prompts: [],
  resources: []
};

// Handle stdin/stdout communication
process.stdin.setEncoding('utf8');

let inputBuffer = '';

process.stdin.on('data', (chunk) => {
  inputBuffer += chunk;
  
  try {
    // Try to parse as JSON
    const message = JSON.parse(inputBuffer);
    handleMessage(message);
    inputBuffer = '';
  } catch (error) {
    // Not a complete JSON message yet, continue reading
  }
});

function handleMessage(message) {
  if (message.type === 'initialize') {
    // Respond with server metadata
    sendResponse({
      type: 'initialize_response',
      metadata: {
        name: server.name,
        capabilities: {
          tools: { supported: true },
          prompts: { supported: false },
          resources: { supported: false }
        }
      }
    });
  } else if (message.type === 'list_tools') {
    // Respond with tool list
    sendResponse({
      type: 'list_tools_response',
      tools: server.tools
    });
  } else if (message.type === 'list_prompts') {
    // Respond with prompt list
    sendResponse({
      type: 'list_prompts_response',
      prompts: server.prompts
    });
  } else if (message.type === 'list_resources') {
    // Respond with resource list
    sendResponse({
      type: 'list_resources_response',
      resources: server.resources
    });
  } else if (message.type === 'execute_tool') {
    // Execute a tool
    const { tool_name, arguments: args } = message;
    
    let result;
    if (tool_name === 'add') {
      result = args.a + args.b;
    } else if (tool_name === 'subtract') {
      result = args.a - args.b;
    } else if (tool_name === 'multiply') {
      result = args.a * args.b;
    } else if (tool_name === 'divide') {
      if (args.b === 0) {
        sendError('Cannot divide by zero');
        return;
      }
      result = args.a / args.b;
    } else {
      sendError(`Unknown tool: ${tool_name}`);
      return;
    }
    
    sendResponse({
      type: 'execute_tool_response',
      result
    });
  }
}

function sendResponse(response) {
  process.stdout.write(JSON.stringify(response) + '\n');
}

function sendError(message) {
  process.stdout.write(JSON.stringify({
    type: 'error',
    message
  }) + '\n');
}

// Handle process termination
process.on('SIGINT', () => {
  process.exit(0);
});

process.on('SIGTERM', () => {
  process.exit(0);
});

// Log that the server is ready
console.error('Math MCP server started');