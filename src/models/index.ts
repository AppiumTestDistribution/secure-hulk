/**
 * Types and interfaces for MCP-Scan
 */

// Server configuration types
export interface ServerConfig {
  type: 'sse' | 'stdio';
  name?: string;
}

export interface SSEServerConfig extends ServerConfig {
  type: 'sse';
  url: string;
  headers?: Record<string, string>;
}

export interface StdioServerConfig extends ServerConfig {
  type: 'stdio';
  command: string;
  args?: string[];
  env?: Record<string, string>;
}

// MCP entity types
export interface Entity {
  name: string;
  description?: string;
}

export interface Prompt extends Entity {
  // Prompt-specific properties
}

export interface Resource extends Entity {
  uri: string;
  // Resource-specific properties
}

export interface Tool extends Entity {
  inputSchema?: any;
  // Tool-specific properties
}

// Scan result types
export interface ScanResult {
  verified: boolean;
  issues: Issue[];
}

export interface Issue {
  type: string;
  message: string;
  severity: 'low' | 'medium' | 'high';
  details?: any;
}

export interface PinningResult {
  changed: boolean;
  messages: string[];
  previousDescription?: string;
}

export interface CrossRefResult {
  found: boolean;
  sources: string[];
}

export interface EntityScanResult {
  verified?: boolean;
  changed?: boolean;
  whitelisted?: boolean;
  status?: string;
  messages: string[];
}

export interface ServerScanResult {
  name?: string;
  server: SSEServerConfig | StdioServerConfig;
  prompts: Prompt[];
  resources: Resource[];
  tools: Tool[];
  result?: EntityScanResult[];
  error?: ScanError;
  entities: Entity[];
}

export interface ScanPathResult {
  path: string;
  servers: ServerScanResult[];
  error?: ScanError;
  crossRefResult?: CrossRefResult;
}

export interface ScanError {
  message?: string;
  exception?: Error;
}

// Storage types
export interface ScannedEntity {
  hash: string;
  type: string;
  verified?: boolean;
  timestamp: string;
  description?: string;
}

// Configuration types
export interface MCPConfig {
  getServers(): Record<string, SSEServerConfig | StdioServerConfig>;
  setServers(servers: Record<string, SSEServerConfig | StdioServerConfig>): void;
}

export interface ClaudeConfigFile extends MCPConfig {
  mcpServers: Record<string, SSEServerConfig | StdioServerConfig>;
}

export interface VSCodeMCPConfig extends MCPConfig {
  inputs?: any[];
  servers: Record<string, SSEServerConfig | StdioServerConfig>;
}

export interface VSCodeConfigFile extends MCPConfig {
  mcp: VSCodeMCPConfig;
}

// CLI options
export interface ScanOptions {
  json?: boolean;
  verbose?: boolean;
  storageFile?: string;
  serverTimeout?: number;
  checksPerServer?: number;
  suppressMcpserverIo?: boolean;
  printErrors?: boolean;
}

export interface WhitelistOptions {
  storageFile?: string;
  reset?: boolean;
  localOnly?: boolean;
}