/**
 * Storage manager for scan results and whitelist
 */

import fs from 'fs/promises';
import path from 'path';
import { createHash } from 'crypto';
import { Entity, ScannedEntity } from '../models';

/**
 * Storage manager for scan results and whitelist
 */
export class StorageManager {
  private storagePath: string;
  private scannedEntities: Record<string, ScannedEntity> = {};
  private whitelist: Record<string, string> = {};

  /**
   * Create a new storage manager
   * @param storagePath Path to the storage directory
   */
  constructor(storagePath: string = '~/.secure-hulk') {
    this.storagePath = this.expandPath(storagePath);
  }

  /**
   * Initialize the storage manager
   */
  public async initialize(): Promise<void> {
    await this.ensureDirectoryExists();
    await this.loadData();
  }

  /**
   * Get a scanned entity by key
   * @param key The entity key
   * @returns The scanned entity, or undefined if not found
   */
  public async getEntity(key: string): Promise<ScannedEntity | undefined> {
    return this.scannedEntities[key];
  }

  /**
   * Save a scanned entity
   * @param key The entity key
   * @param entity The entity to save
   */
  public async saveEntity(key: string, entity: ScannedEntity): Promise<void> {
    this.scannedEntities[key] = entity;
    await this.saveData();
  }

  /**
   * Check if an entity is whitelisted
   * @param entity The entity to check
   * @returns True if the entity is whitelisted, false otherwise
   */
  public isWhitelisted(entity: Entity): boolean {
    const hash = this.hashEntity(entity);
    return Object.values(this.whitelist).includes(hash);
  }

  /**
   * Add an entity to the whitelist
   * @param entityType The entity type
   * @param name The entity name
   * @param hash The entity hash
   */
  public async addToWhitelist(
    entityType: string,
    name: string,
    hash: string
  ): Promise<void> {
    const key = `${entityType}.${name}`;
    this.whitelist[key] = hash;
    await this.saveData();
  }

  /**
   * Reset the whitelist
   */
  public async resetWhitelist(): Promise<void> {
    this.whitelist = {};
    await this.saveData();
  }

  /**
   * Print the whitelist
   */
  public printWhitelist(): void {
    const whitelistKeys = Object.keys(this.whitelist).sort();

    for (const key of whitelistKeys) {
      let entityType: string;
      let name: string;

      if (key.includes('.')) {
        [entityType, name] = key.split('.', 2);
      } else {
        entityType = 'tool';
        name = key;
      }

      console.log(entityType, name, this.whitelist[key]);
    }

    console.log(`${whitelistKeys.length} entries in whitelist`);
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

    return createHash('md5').update(entity.description).digest('hex');
  }

  /**
   * Load data from storage
   */
  private async loadData(): Promise<void> {
    try {
      const scannedEntitiesPath = path.join(
        this.storagePath,
        'scanned_entities.json'
      );
      const whitelistPath = path.join(this.storagePath, 'whitelist.json');

      const [scannedEntitiesData, whitelistData] = await Promise.all([
        fs.readFile(scannedEntitiesPath, 'utf8').catch(() => '{}'),
        fs.readFile(whitelistPath, 'utf8').catch(() => '{}'),
      ]);

      this.scannedEntities = JSON.parse(scannedEntitiesData);
      this.whitelist = JSON.parse(whitelistData);
    } catch (error) {
      console.error('Error loading storage data:', error);
    }
  }

  /**
   * Save data to storage
   */
  private async saveData(): Promise<void> {
    try {
      const scannedEntitiesPath = path.join(
        this.storagePath,
        'scanned_entities.json'
      );
      const whitelistPath = path.join(this.storagePath, 'whitelist.json');

      await Promise.all([
        fs.writeFile(
          scannedEntitiesPath,
          JSON.stringify(this.scannedEntities, null, 2)
        ),
        fs.writeFile(whitelistPath, JSON.stringify(this.whitelist, null, 2)),
      ]);
    } catch (error) {
      console.error('Error saving storage data:', error);
    }
  }

  /**
   * Ensure the storage directory exists
   */
  private async ensureDirectoryExists(): Promise<void> {
    await fs.mkdir(this.storagePath, { recursive: true });
  }

  /**
   * Expand a path with tilde
   * @param filePath The path to expand
   * @returns The expanded path
   */
  private expandPath(filePath: string): string {
    if (filePath.startsWith('~/')) {
      return path.join(process.env.HOME || '', filePath.slice(2));
    }
    return filePath;
  }
}
