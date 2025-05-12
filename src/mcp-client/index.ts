import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import { Prompt, Resource, Tool } from '../models';
import fs from 'fs/promises';

/**
 * Connect to an MCP server and retrieve prompts, resources, and tools using the MCP SDK
 */
export async function connectToServer(
  config: any, // Use any type to handle custom fields
  timeout: number = 200,
  suppressMcpserverIo: boolean = true
): Promise<{
  prompts: Prompt[];
  resources: Resource[];
  tools: Tool[];
}> {
  // Create a new MCP client
  const client = new Client({
    name: 'secure-hulk',
    version: '0.1.0',
  });

  // Set up a timeout promise
  const timeoutPromise = new Promise<never>((_, reject) => {
    setTimeout(() => {
      reject(
        new Error(`Connection to server timed out after ${timeout} seconds`)
      );
    }, timeout * 1000);
  });

  try {
    // Check if this is an SSE server (either by type or transportType)
    if (config.type === 'sse' || config.transportType === 'sse') {
      // Ensure the config has the required fields for SSE
      console.log(`Connecting to SSE server at ${config.url}...`);

      // Create an SSE transport - SSE doesn't support headers
      const transport = new SSEClientTransport(config.url);

      // Connect to the server with timeout
      await Promise.race([client.connect(transport), timeoutPromise]);
    } else {
      // Assume stdio server for all other cases
      console.log(
        `Launching stdio server with command: ${config.command} ${(config.args || []).join(' ')}...`
      );

      // Create a stdio transport
      // Use the full path to npx if the command is npx
      let command = config.command;
      let env = { ...process.env, ...config.env };

      if (command === 'npx') {
        try {
          // Try to find the full path to npx and node
          const { execSync } = require('child_process');
          const npxPath = execSync('which npx').toString().trim();
          command = npxPath;

          // Also find the node path and add it to the environment
          const nodePath = execSync('which node').toString().trim();

          // Add the directory containing node to the PATH
          const nodeDir = nodePath.substring(0, nodePath.lastIndexOf('/'));
          env.PATH = `${nodeDir}:${env.PATH || ''}`;
          console.log(`Updated PATH to include node directory: ${nodeDir}`);
        } catch (error) {
          console.log(`Could not find command paths, using defaults: ${error}`);
        }
      }

      const transport = new StdioClientTransport({
        command: command,
        args: config.args || [],
        env: env,
      });

      // Connect to the server with timeout
      await Promise.race([client.connect(transport), timeoutPromise]);
    }

    console.log('Connected to server successfully, fetching entities...');

    // Fetch prompts, resources, and tools
    let prompts: any[] = [];
    let resources: any[] = [];
    let tools: any[] = [];

    try {
      console.log('Listing prompts...');
      const promptsResult = await Promise.race([
        client.listPrompts(),
        timeoutPromise,
      ]);
      prompts = promptsResult.prompts || [];
      console.log(`Received ${prompts.length} prompts`);
    } catch (error) {
      console.log(`Error listing prompts: ${error}`);
    }

    try {
      console.log('Listing resources...');
      const resourcesResult = await Promise.race([
        client.listResources(),
        timeoutPromise,
      ]);
      resources = resourcesResult.resources || [];
      console.log(`Received ${resources.length} resources`);
    } catch (error) {
      console.log(`Error listing resources: ${error}`);
    }

    try {
      console.log('Listing tools...');
      const toolsResult = await Promise.race([
        client.listTools(),
        timeoutPromise,
      ]);
      tools = toolsResult.tools || [];
      console.log(`Received ${tools.length} tools`);
    } catch (error) {
      console.log(`Error listing tools: ${error}`);
    }

    // Close the connection
    try {
      // The SDK might not have a disconnect method, so we'll need to handle that differently if needed
      // await client.disconnect();
      console.log('Connection closed');
    } catch (error) {
      console.log(`Error closing connection: ${error}`);
    }

    return {
      prompts: prompts as Prompt[],
      resources: resources as Resource[],
      tools: tools as Tool[],
    };
  } catch (error) {
    console.error(`Error connecting to server: ${error}`);
    // Return empty arrays if there was an error
    return { prompts: [], resources: [], tools: [] };
  }
}

/**
 * Scan an MCP configuration file and extract server configurations
 */
export async function scanMcpConfigFile(path: string): Promise<any> {
  try {
    // Read and parse the file
    const content = await fs.readFile(path, 'utf8');

    // Parse as JSON (in a real implementation, we would handle JSON5 and different formats)
    const config = JSON.parse(content);

    // Try to validate as different config types
    if (config.mcpServers) {
      // Claude-style config
      // Map transportType to type for compatibility
      const mappedServers = Object.entries(config.mcpServers).reduce(
        (acc: any, [key, server]: [string, any]) => {
          // Create a copy of the server config
          const mappedServer = { ...server };

          // Map transportType to type if it exists
          if (mappedServer.transportType) {
            mappedServer.type = mappedServer.transportType;
            // Keep transportType for backward compatibility
          }

          acc[key] = mappedServer;
          return acc;
        },
        {}
      );

      return {
        getServers: () => mappedServers,
        setServers: (servers: any) => {
          config.mcpServers = servers;
        },
      };
    } else if (config.mcp && config.mcp.servers) {
      // VSCode settings.json
      // Map transportType to type for compatibility
      const mappedServers = Object.entries(config.mcp.servers).reduce(
        (acc: any, [key, server]: [string, any]) => {
          // Create a copy of the server config
          const mappedServer = { ...server };

          // Map transportType to type if it exists
          if (mappedServer.transportType) {
            mappedServer.type = mappedServer.transportType;
          }

          acc[key] = mappedServer;
          return acc;
        },
        {}
      );

      return {
        getServers: () => mappedServers,
        setServers: (servers: any) => {
          config.mcp.servers = servers;
        },
      };
    } else if (config.servers) {
      // VSCode mcp.json
      // Map transportType to type for compatibility
      const mappedServers = Object.entries(config.servers).reduce(
        (acc: any, [key, server]: [string, any]) => {
          // Create a copy of the server config
          const mappedServer = { ...server };

          // Map transportType to type if it exists
          if (mappedServer.transportType) {
            mappedServer.type = mappedServer.transportType;
          }

          acc[key] = mappedServer;
          return acc;
        },
        {}
      );

      return {
        getServers: () => mappedServers,
        setServers: (servers: any) => {
          config.servers = servers;
        },
      };
    }

    throw new Error('Unknown config format');
  } catch (error) {
    throw new Error(`Error scanning MCP config file: ${error}`);
  }
}

/**
 * Check a server with a timeout
 */
export async function checkServerWithTimeout(
  serverConfig: any, // Use any type to handle custom fields
  timeout: number,
  suppressMcpserverIo: boolean
): Promise<{
  prompts: Prompt[];
  resources: Resource[];
  tools: Tool[];
}> {
  // Always attempt to connect to the actual server
  try {
    return await Promise.race([
      connectToServer(serverConfig, timeout, suppressMcpserverIo),
      new Promise<never>((_, reject) => {
        setTimeout(() => {
          reject(new Error(`Server check timed out after ${timeout} seconds`));
        }, timeout * 1000);
      }),
    ]);
  } catch (error) {
    console.error(`Server check failed: ${error}`);
    // Return empty arrays instead of throwing an error
    return {
      prompts: [],
      resources: [],
      tools: [],
    };
  }
}
