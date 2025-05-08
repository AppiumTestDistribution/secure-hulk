/**
 * Whitelist command implementation
 */

import chalk from 'chalk';
import { whitelist as whitelistScanner } from '../../scanner';

/**
 * Manage the whitelist of approved entities
 * @param type Entity type
 * @param name Entity name
 * @param hash Entity hash
 * @param options Whitelist options
 */
export async function whitelist(
  type: string | undefined,
  name: string | undefined,
  hash: string | undefined,
  options: any
): Promise<void> {
  try {
    await whitelistScanner(type, name, hash, {
      storageFile: options.storageFile,
      reset: options.reset,
      localOnly: options.localOnly,
    });
  } catch (error) {
    console.error(chalk.red('Error managing whitelist:'), error);
    throw error;
  }
}