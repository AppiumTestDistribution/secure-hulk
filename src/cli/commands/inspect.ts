/**
 * Inspect command implementation
 */

import chalk from 'chalk';
import { inspect as inspectScanner } from '../../scanner';
import { formatResults } from '../formatter';

/**
 * Inspect MCP configurations without verification
 * @param files Array of file paths to inspect
 * @param options Inspection options
 */
export async function inspect(files: string[], options: any): Promise<void> {
  try {
    console.log(chalk.blue('Inspecting MCP configurations...'));
    
    const results = await inspectScanner(files, {
      storageFile: options.storageFile,
      serverTimeout: parseInt(options.serverTimeout, 10),
      suppressMcpserverIo: options.suppressMcpserverIo === 'true',
      verbose: options.verbose,
    });
    
    if (options.json) {
      // Output as JSON
      console.log(JSON.stringify(results, null, 2));
    } else {
      // Format and print results
      formatResults(results, options.printErrors);
    }
  } catch (error) {
    console.error(chalk.red('Error during inspection:'), error);
    throw error;
  }
}