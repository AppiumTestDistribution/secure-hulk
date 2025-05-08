/**
 * Tool pinning implementation for MCP entities
 */

import { createHash } from 'crypto';
import { Entity, PinningResult } from '../models';
import { StorageManager } from '../storage';

/**
 * Tool pinning manager
 * Detects changes in entity descriptions to prevent MCP rug pull attacks
 */
export class ToolPinningManager {
  private storage: StorageManager;

  /**
   * Create a new tool pinning manager
   * @param storage Storage manager
   */
  constructor(storage: StorageManager) {
    this.storage = storage;
  }

  /**
   * Calculate the hash of an entity
   * @param entity The entity to hash
   * @returns The hash of the entity
   */
  public hashEntity(entity: Entity): string {
    if (!entity.description) {
      return '';
    }
    
    return createHash('md5')
      .update(entity.description)
      .digest('hex');
  }

  /**
   * Check if an entity has changed and update its record
   * @param serverName The server name
   * @param entity The entity to check
   * @param verified Whether the entity is verified
   * @returns The pinning result
   */
  public async checkAndUpdateEntity(
    serverName: string,
    entity: Entity,
    verified: boolean
  ): Promise<PinningResult> {
    const entityType = this.getEntityType(entity);
    const key = `${serverName}.${entityType}.${entity.name}`;
    const hash = this.hashEntity(entity);
    
    const result: PinningResult = {
      changed: false,
      messages: [],
    };

    const previousEntity = await this.storage.getEntity(key);
    
    if (previousEntity && previousEntity.hash !== hash) {
      result.changed = true;
      result.messages.push(
        `Entity has changed since last scan (${new Date(previousEntity.timestamp).toLocaleString()})`
      );
      result.previousDescription = previousEntity.description;
    }

    await this.storage.saveEntity(key, {
      hash,
      type: entityType,
      verified,
      timestamp: new Date().toISOString(),
      description: entity.description,
    });

    return result;
  }

  /**
   * Get the type of an entity
   * @param entity The entity
   * @returns The entity type
   */
  private getEntityType(entity: Entity): string {
    // Determine entity type based on properties
    if ('inputSchema' in entity) return 'tool';
    if ('uri' in entity) return 'resource';
    return 'prompt';
  }
}