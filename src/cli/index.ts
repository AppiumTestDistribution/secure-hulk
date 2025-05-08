import { Command } from 'commander';
import { scan } from '../scanner';
import { inspect } from './commands/inspect';
import { whitelist } from './commands/whitelist';
import { version } from '../../package.json';
import chalk from 'chalk';
import { formatResults } from './formatter';

const program = new Command();

/**
 * Run the CLI application
 */
export function runCli(): void {
  console.log(chalk.blue.bold(`MCP-Scan TypeScript v${version}`));
  console.log('');

  program
    .name('secure-hulk')
    .description(
      'Security scanner for Model Context Protocol servers and tools'
    )
    .version(version);

  program
    .command('scan')
    .description('Scan MCP configurations for security vulnerabilities')
    .option('-j, --json', 'Output results in JSON format')
    .option('-v, --verbose', 'Enable verbose output')
    .option(
      '--storage-file <path>',
      'Path to store scan results and whitelist information',
      '~/.secure-hulk'
    )
    .option(
      '--server-timeout <seconds>',
      'Seconds to wait before timing out server connections',
      '200'
    )
    .option(
      '--checks-per-server <number>',
      'Number of times to check each server',
      '1'
    )
    .option(
      '--suppress-mcpserver-io <boolean>',
      'Suppress stdout/stderr from MCP servers',
      'true'
    )
    .argument(
      '[files...]',
      'Path(s) to MCP config file(s). If not provided, well-known paths will be checked'
    )
    .action(async (files, options) => {
      try {
        const results = await scan(files, options);
        if (options.json) {
          console.log(JSON.stringify(results, null, 2));
        } else {
          // Format and print results
          formatResults(results, options.verbose);
        }
      } catch (error) {
        console.error(chalk.red('Error during scan:'), error);
        process.exit(1);
      }
    });

  // Add inspect command
  program
    .command('inspect')
    .description(
      'Print descriptions of tools, prompts, and resources without verification'
    )
    .option('-j, --json', 'Output results in JSON format')
    .option('-v, --verbose', 'Enable verbose output')
    .option(
      '--storage-file <path>',
      'Path to store scan results and whitelist information',
      '~/.secure-hulk'
    )
    .option(
      '--server-timeout <seconds>',
      'Seconds to wait before timing out server connections',
      '200'
    )
    .option(
      '--suppress-mcpserver-io <boolean>',
      'Suppress stdout/stderr from MCP servers',
      'true'
    )
    .argument(
      '[files...]',
      'Path(s) to MCP config file(s). If not provided, well-known paths will be checked'
    )
    .action(async (files, options) => {
      try {
        await inspect(files, options);
      } catch (error) {
        console.error(chalk.red('Error during inspection:'), error);
        process.exit(1);
      }
    });

  // Add whitelist command
  program
    .command('whitelist')
    .description('Manage the whitelist of approved entities')
    .option(
      '--storage-file <path>',
      'Path to store scan results and whitelist information',
      '~/.secure-hulk'
    )
    .option('--reset', 'Reset the entire whitelist')
    .option(
      '--local-only',
      "Only update local whitelist, don't contribute to global whitelist"
    )
    .argument(
      '[type]',
      'Type of entity to whitelist: "tool", "prompt", or "resource"'
    )
    .argument('[name]', 'Name of the entity to whitelist')
    .argument('[hash]', 'Hash of the entity to whitelist')
    .action(async (type, name, hash, options) => {
      try {
        await whitelist(type, name, hash, options);
      } catch (error) {
        console.error(chalk.red('Error managing whitelist:'), error);
        process.exit(1);
      }
    });

  // Add help command
  program
    .command('help')
    .description('Show detailed help information')
    .action(() => {
      program.help();
    });

  // Parse arguments (default to 'scan' if no command provided)
  if (process.argv.length <= 2) {
    process.argv.push('scan');
  }

  program.parse(process.argv);
}
