/**
 * Core scanner implementation
 */

import path from 'path';
import os from 'os';
import {
  ScanOptions,
  ScanPathResult,
  ServerScanResult,
  EntityScanResult,
  SSEServerConfig,
  StdioServerConfig,
  WhitelistOptions
} from '../models';
import { scanMcpConfigFile, checkServerWithTimeout } from '../mcp-client';
import { verifyServer } from '../security/scanner';
import { StorageManager } from '../storage';
import { checkCrossReferences } from './crossReference';
import { ToolPinningManager } from './toolPinning';

// Well-known MCP configuration paths by platform
const WELL_KNOWN_MCP_PATHS: Record<string, string[]> = {
  linux: [
    '~/.codeium/windsurf/mcp_config.json',  // windsurf
    '~/.cursor/mcp.json',                   // cursor
    '~/.vscode/mcp.json',                   // vscode
    '~/.config/Code/User/settings.json',    // vscode linux
  ],
  darwin: [
    '~/.codeium/windsurf/mcp_config.json',                      // windsurf
    '~/.cursor/mcp.json',                                       // cursor
    '~/Library/Application Support/Claude/claude_desktop_config.json',  // Claude Desktop mac
    '~/.vscode/mcp.json',                                       // vscode
    '~/Library/Application Support/Code/User/settings.json',    // vscode mac
  ],
  win32: [
    '~/.codeium/windsurf/mcp_config.json',                // windsurf
    '~/.cursor/mcp.json',                                 // cursor
    '~/AppData/Roaming/Claude/claude_desktop_config.json', // Claude Desktop windows
    '~/.vscode/mcp.json',                                 // vscode
    '~/AppData/Roaming/Code/User/settings.json',          // vscode windows
  ],
};

/**
 * Get well-known MCP configuration paths for the current platform
 * @returns Array of well-known MCP configuration paths
 */
function getWellKnownPaths(): string[] {
  const platform = os.platform();
  return WELL_KNOWN_MCP_PATHS[platform] || [];
}

/**
 * Expand a path with tilde
 * @param filePath The path to expand
 * @returns The expanded path
 */
function expandPath(filePath: string): string {
  if (filePath.startsWith('~/')) {
    return path.join(os.homedir(), filePath.slice(2));
  }
  return filePath;
}

/**
 * Scan MCP configurations for security vulnerabilities
 * @param files Array of file paths to scan
 * @param options Scan options
 * @returns Array of scan results
 */
export async function scan(
  files: string[] = [],
  options: ScanOptions = {}
): Promise<ScanPathResult[]> {
  console.log('Starting MCP scan...');
  
  // Use provided files or well-known paths
  const pathsToScan = files.length > 0 ? files : getWellKnownPaths();
  console.log(`Found ${pathsToScan.length} configuration paths to scan`);
  
  // Initialize storage manager
  console.log('Initializing storage manager...');
  const storageManager = new StorageManager(options.storageFile);
  await storageManager.initialize();
  
  // Initialize tool pinning manager
  console.log('Initializing tool pinning manager...');
  const toolPinningManager = new ToolPinningManager(storageManager);
  
  // Scan each path
  const results: ScanPathResult[] = [];
  
  for (let i = 0; i < pathsToScan.length; i++) {
    const filePath = pathsToScan[i];
    const expandedPath = expandPath(filePath);
    console.log(`\nScanning configuration [${i+1}/${pathsToScan.length}]: ${expandedPath}`);
    const result = await scanPath(expandedPath, options, storageManager, toolPinningManager);
    results.push(result);
  }
  
  console.log('\nScan completed successfully');
  return results;
}

/**
 * Scan a single MCP configuration file
 * @param path Path to the configuration file
 * @param options Scan options
 * @param storageManager Storage manager
 * @param toolPinningManager Tool pinning manager
 * @returns Scan result for the path
 */
async function scanPath(
  path: string,
  options: ScanOptions,
  storageManager: StorageManager,
  toolPinningManager: ToolPinningManager
): Promise<ScanPathResult> {
  const result: ScanPathResult = {
    path,
    servers: [],
  };
  
  try {
    // Parse the configuration file
    console.log(`Reading and parsing configuration file: ${path}`);
    const config = await scanMcpConfigFile(path);
    const servers = config.getServers();
    
    // Create server scan results
    const serverCount = Object.keys(servers).length;
    console.log(`Found ${serverCount} MCP servers in configuration`);
    
    result.servers = Object.entries(servers).map(([name, server]) => ({
      name,
      server: server as SSEServerConfig | StdioServerConfig,
      prompts: [],
      resources: [],
      tools: [],
      entities: [],
    }));
    
    // Scan each server
    for (let i = 0; i < result.servers.length; i++) {
      const serverName = result.servers[i].name || `unnamed-server-${i}`;
      console.log(`\nScanning server [${i+1}/${result.servers.length}]: ${serverName}`);
      result.servers[i] = await scanServer(
        result.servers[i],
        options,
        storageManager,
        toolPinningManager,
        false
      );
    }
    
    // Check for cross-references
    result.crossRefResult = checkCrossReferences(result.servers);
  } catch (error) {
    result.error = {
      message: `Error scanning path: ${path}`,
      exception: error instanceof Error ? error : new Error(String(error)),
    };
  }
  
  return result;
}

/**
 * Scan a single MCP server
 * @param serverResult Server scan result
 * @param options Scan options
 * @param storageManager Storage manager
 * @param toolPinningManager Tool pinning manager
 * @param inspectOnly Whether to only inspect the server without verification
 * @returns Updated server scan result
 */
async function scanServer(
  serverResult: ServerScanResult,
  options: ScanOptions,
  storageManager: StorageManager,
  toolPinningManager: ToolPinningManager,
  inspectOnly: boolean = false
): Promise<ServerScanResult> {
  const result = { ...serverResult };
  const serverName = result.name || 'unnamed server';
  
  try {
    // Connect to the server and retrieve entities
    const serverTimeout = options.serverTimeout || 200;
    const suppressMcpserverIo = options.suppressMcpserverIo !== false;
    
    console.log(`Connecting to server "${serverName}" (timeout: ${serverTimeout}s)...`);
    const { prompts, resources, tools } = await checkServerWithTimeout(
      result.server,
      serverTimeout,
      suppressMcpserverIo
    );
    
    result.prompts = prompts;
    result.resources = resources;
    result.tools = tools;
    result.entities = [...prompts, ...resources, ...tools];
    
    console.log(`Retrieved ${prompts.length} prompts, ${resources.length} resources, and ${tools.length} tools from "${serverName}"`);
    
    if (!inspectOnly) {
      // Verify the server's entities
      console.log(`Verifying ${result.entities.length} entities from "${serverName}"...`);
      const verificationResults = await verifyServer(result.name || '', result.entities);
      
      // Create entity scan results
      result.result = result.entities.map((entity, index) => {
        const scanResult = verificationResults[index];
        const entityResult: EntityScanResult = {
          verified: scanResult.verified,
          messages: scanResult.issues.map(issue => issue.message),
        };
        
        return entityResult;
      });
      
      const verifiedCount = result.result?.filter(r => r.verified).length || 0;
      console.log(`Verified ${verifiedCount}/${result.entities.length} entities from "${serverName}"`);
      
      // Check for changes and update whitelist status
      for (let i = 0; i < result.entities.length; i++) {
        const entity = result.entities[i];
        const entityResult = result.result[i];
        
        // Check for changes
        if (entityResult.verified !== false) {
          const pinningResult = await toolPinningManager.checkAndUpdateEntity(
            result.name || '',
            entity,
            entityResult.verified || false
          );
          
          entityResult.changed = pinningResult.changed;
          entityResult.messages.push(...pinningResult.messages);
          
          // If changed, mark as not verified
          if (pinningResult.changed) {
            entityResult.verified = false;
          }
        }
        
        // Check whitelist
        entityResult.whitelisted = storageManager.isWhitelisted(entity);
        
        // If whitelisted and not verified, mark as verified
        if (entityResult.whitelisted && !entityResult.verified) {
          entityResult.verified = true;
        }
      }
    }
  } catch (error) {
    result.error = {
      message: `Error scanning server: ${result.name}`,
      exception: error instanceof Error ? error : new Error(String(error)),
    };
  }
  
  return result;
}

/**
 * Inspect MCP configurations without verification
 * @param files Array of file paths to inspect
 * @param options Scan options
 * @returns Array of scan results
 */
export async function inspect(
  files: string[] = [],
  options: ScanOptions = {}
): Promise<ScanPathResult[]> {
  // Use provided files or well-known paths
  const pathsToScan = files.length > 0 ? files : getWellKnownPaths();
  
  // Initialize storage manager
  const storageManager = new StorageManager(options.storageFile);
  await storageManager.initialize();
  
  // Initialize tool pinning manager
  const toolPinningManager = new ToolPinningManager(storageManager);
  
  // Scan each path
  const results: ScanPathResult[] = [];
  
  for (const filePath of pathsToScan) {
    const expandedPath = expandPath(filePath);
    const result = await inspectPath(expandedPath, options, storageManager, toolPinningManager);
    results.push(result);
  }
  
  return results;
}

/**
 * Inspect a single MCP configuration file without verification
 * @param path Path to the configuration file
 * @param options Scan options
 * @param storageManager Storage manager
 * @param toolPinningManager Tool pinning manager
 * @returns Scan result for the path
 */
async function inspectPath(
  path: string,
  options: ScanOptions,
  storageManager: StorageManager,
  toolPinningManager: ToolPinningManager
): Promise<ScanPathResult> {
  const result: ScanPathResult = {
    path,
    servers: [],
  };
  
  try {
    // Parse the configuration file
    const config = await scanMcpConfigFile(path);
    const servers = config.getServers();
    
    // Create server scan results
    result.servers = Object.entries(servers).map(([name, server]) => ({
      name,
      server: server as SSEServerConfig | StdioServerConfig,
      prompts: [],
      resources: [],
      tools: [],
      entities: [],
    }));
    
    // Inspect each server
    for (let i = 0; i < result.servers.length; i++) {
      result.servers[i] = await scanServer(
        result.servers[i],
        options,
        storageManager,
        toolPinningManager,
        true
      );
    }
  } catch (error) {
    result.error = {
      message: `Error inspecting path: ${path}`,
      exception: error instanceof Error ? error : new Error(String(error)),
    };
  }
  
  return result;
}

/**
 * Manage the whitelist
 * @param type Entity type
 * @param name Entity name
 * @param hash Entity hash
 * @param options Whitelist options
 */
export async function whitelist(
  type?: string,
  name?: string,
  hash?: string,
  options: WhitelistOptions = {}
): Promise<void> {
  // Initialize storage manager
  const storageManager = new StorageManager(options.storageFile);
  await storageManager.initialize();
  
  if (options.reset) {
    // Reset the whitelist
    await storageManager.resetWhitelist();
    console.log('Whitelist reset');
  } else if (!type && !name && !hash) {
    // Print the whitelist
    storageManager.printWhitelist();
  } else if (type && name && hash) {
    // Add to whitelist
    await storageManager.addToWhitelist(type, name, hash);
    console.log(`Added ${type} '${name}' to whitelist`);
    storageManager.printWhitelist();
  } else {
    throw new Error('Please provide all three parameters: type, name, and hash');
  }
}