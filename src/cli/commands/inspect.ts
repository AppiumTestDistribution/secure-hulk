import chalk from 'chalk';
import { inspect as inspectScanner } from '../../scanner';
import { formatResults } from '../formatter';

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
      console.log(JSON.stringify(results, null, 2));
    } else {
      formatResults(results, options.printErrors);
    }
  } catch (error) {
    console.error(chalk.red('Error during inspection:'), error);
    throw error;
  }
}
