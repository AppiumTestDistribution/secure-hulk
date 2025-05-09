/**
 * MCP proxy for intercepting and validating MCP requests
 */

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { z } from 'zod';
import { PolicyEngine } from '../policy';
import { Entity, Tool, Resource, Prompt } from '../models';
import { StorageManager } from '../storage';
import { ToolPinningManager } from '../scanner/toolPinning';

/**
 * MCP proxy for intercepting and validating MCP requests
 */
export class MCPProxy {
  private policyEngine: PolicyEngine;
  private client: Client;
  private toolPinningManager?: ToolPinningManager;
  private entityHistory: Entity[] = [];
  private maxHistorySize: number = 100;
  
  /**
   * Create a new MCP proxy
   * @param policyEngine Policy engine for validating requests
   * @param client MCP client
   * @param storageManager Optional storage manager for tool pinning
   */
  constructor(
    policyEngine: PolicyEngine, 
    client: Client, 
    storageManager?: StorageManager
  ) {
    this.policyEngine = policyEngine;
    this.client = client;
    
    if (storageManager) {
      this.toolPinningManager = new ToolPinningManager(storageManager);
    }
  }

  /**
   * Intercept a tool call and validate it against the policy engine
   * @param serverName Server name
   * @param toolName Tool name
   * @param args Tool arguments
   * @returns Whether the tool call is allowed
   */
  async interceptToolCall(
    serverName: string,
    toolName: string,
    args: any
  ): Promise<{allowed: boolean, issues: string[]}> {
    // Create an entity from the tool call
    const entity: Entity = {
      name: toolName,
      description: JSON.stringify(args),
    };
    
    // Add to history
    this.addToHistory(entity);
    
    // Evaluate the entity against the policy engine
    const result = await this.policyEngine.evaluateEntity(entity);
    
    // Evaluate the sequence against the policy engine
    const sequenceResult = await this.policyEngine.evaluateSequence(this.entityHistory);
    
    // Check tool pinning if available
    let pinningChanged = false;
    if (this.toolPinningManager) {
      const pinningResult = await this.toolPinningManager.checkAndUpdateEntity(
        serverName,
        entity,
        result.verified && sequenceResult.verified
      );
      pinningChanged = pinningResult.changed;
    }
    
    // Combine issues from both results
    const issues = [
      ...result.issues.map(issue => issue.message),
      ...sequenceResult.issues.map(issue => issue.message),
    ];
    
    if (pinningChanged) {
      issues.push('Tool description has changed since last scan');
    }
    
    // Return true if the tool call is allowed, false otherwise
    return {
      allowed: result.verified && sequenceResult.verified && !pinningChanged,
      issues
    };
  }
  
  /**
   * Execute a tool call after validating it
   * @param serverName Server name
   * @param toolName Tool name
   * @param args Tool arguments
   * @returns The result of the tool call
   */
  async executeToolCall(
    serverName: string,
    toolName: string,
    args: any
  ): Promise<any> {
    // Check if the tool call is allowed
    const { allowed, issues } = await this.interceptToolCall(serverName, toolName, args);
    
    if (!allowed) {
      throw new Error(`Tool call to ${toolName} was blocked by policy: ${issues.join(', ')}`);
    }
    
    // Execute the tool call
    // Execute the tool call
    // This is a simplified implementation - in a real implementation,
    // you would need to handle the specific MCP SDK methods
    try {
      // @ts-ignore - Simplified for demonstration
      const response = await this.client.executeTool(toolName, args);
      return response;
    } catch (error) {
      console.error(`Error executing tool ${toolName}:`, error);
      throw error;
    }
  }
  
  /**
   * Intercept a resource access and validate it against the policy engine
   * @param serverName Server name
   * @param uri Resource URI
   * @returns Whether the resource access is allowed
   */
  async interceptResourceAccess(
    serverName: string,
    uri: string
  ): Promise<{allowed: boolean, issues: string[]}> {
    // Create an entity from the resource access
    const entity: Entity = {
      name: uri,
      description: `Resource access: ${uri}`,
    };
    
    // Add to history
    this.addToHistory(entity);
    
    // Evaluate the entity against the policy engine
    const result = await this.policyEngine.evaluateEntity(entity);
    
    // Evaluate the sequence against the policy engine
    const sequenceResult = await this.policyEngine.evaluateSequence(this.entityHistory);
    
    // Combine issues from both results
    const issues = [
      ...result.issues.map(issue => issue.message),
      ...sequenceResult.issues.map(issue => issue.message),
    ];
    
    // Return true if the resource access is allowed, false otherwise
    return {
      allowed: result.verified && sequenceResult.verified,
      issues
    };
  }
  
  /**
   * Access a resource after validating it
   * @param serverName Server name
   * @param uri Resource URI
   * @returns The resource content
   */
  async accessResource(
    serverName: string,
    uri: string
  ): Promise<any> {
    // Check if the resource access is allowed
    const { allowed, issues } = await this.interceptResourceAccess(serverName, uri);
    
    if (!allowed) {
      throw new Error(`Resource access to ${uri} was blocked by policy: ${issues.join(', ')}`);
    }
    
    // Access the resource
    // Access the resource
    // This is a simplified implementation - in a real implementation,
    // you would need to handle the specific MCP SDK methods
    try {
      // @ts-ignore - Simplified for demonstration
      const response = await this.client.accessResource(uri);
      return response;
    } catch (error) {
      console.error(`Error accessing resource ${uri}:`, error);
      throw error;
    }
  }
  
  /**
   * Add an entity to the history
   * @param entity The entity to add
   */
  private addToHistory(entity: Entity): void {
    this.entityHistory.push(entity);
    
    // Trim history if it exceeds the maximum size
    if (this.entityHistory.length > this.maxHistorySize) {
      this.entityHistory = this.entityHistory.slice(-this.maxHistorySize);
    }
  }
  
  /**
   * Clear the entity history
   */
  public clearHistory(): void {
    this.entityHistory = [];
  }
  
  /**
   * Get the current entity history
   * @returns The entity history
   */
  public getHistory(): Entity[] {
    return [...this.entityHistory];
  }
}