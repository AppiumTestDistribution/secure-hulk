import { Command } from 'commander';
import { scan } from '../scanner';
import { inspect } from './commands/inspect';
import { whitelist } from './commands/whitelist';
import { version } from '../../package.json';
import chalk from 'chalk';
import { formatResults } from './formatter';
import { generateHtmlReport } from './htmlReporter';

const program = new Command();

/**
 * Run the CLI application
 */
export function runCli(): void {
  console.log(chalk.blue.bold(`Secure Hulk v${version}`));
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
    .option('--html <path>', 'Generate HTML report and save to specified path')
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
    .option(
      '--use-openai-moderation',
      'Use OpenAI Moderation API to detect harmful content in entity descriptions',
      false
    )
    .option(
      '--openai-api-key <key>',
      'OpenAI API key for Moderation API (required if using OpenAI moderation)'
    )
    .option(
      '--openai-moderation-model <model>',
      'OpenAI Moderation model to use',
      'omni-moderation-latest'
    )
    .option(
      '--use-nemo-guardrails',
      'Use NVIDIA NeMo Guardrails to detect harmful content in entity descriptions',
      false
    )
    .option(
      '--nemo-guardrails-config-path <path>',
      'Path to NeMo Guardrails configuration directory (required if using NeMo Guardrails)'
    )
    .option(
      '--nemo-guardrails-timeout <milliseconds>',
      'Timeout for NeMo Guardrails checks in milliseconds',
      '5000'
    )
    .option(
      '--python-path <path>',
      'Path to Python executable for NeMo Guardrails',
      'python'
    )
    .argument(
      '[files...]',
      'Path(s) to MCP config file(s). If not provided, well-known paths will be checked'
    )
    .action(async (files, options) => {
      try {
        console.log('CLI options:', JSON.stringify(options, null, 2));
        const results = await scan(files, options);

        // Output results based on format options
        if (options.json) {
          console.log(JSON.stringify(results, null, 2));
        } else {
          // Format and print results to console
          formatResults(results, options.verbose);
        }

        // Generate HTML report if requested
        if (options.html) {
          console.log(chalk.blue(`Generating HTML report at: ${options.html}`));

          // Process each server in the results
          for (const pathResult of results) {
            if (pathResult.error) continue;

            for (const serverResult of pathResult.servers) {
              if (serverResult.error) continue;

              // Create entity scan results for the HTML report
              const entityResults: { entity: any; messages: string[] }[] = [];

              // Process each entity
              for (let i = 0; i < serverResult.entities.length; i++) {
                const entity = serverResult.entities[i];
                const result = serverResult.result?.[i];

                if (result && !result.verified) {
                  entityResults.push({
                    entity,
                    messages: result.messages || [],
                  });
                }
              }

              // Generate the HTML report
              generateHtmlReport(
                serverResult.name || 'unknown',
                serverResult.server.type,
                serverResult.entities,
                serverResult.result?.map((r) => ({
                  verified: r.verified || false,
                  issues:
                    r.messages?.map((m) => ({
                      type: m.includes('Prompt Injection')
                        ? 'prompt_injection'
                        : m.includes('Tool Poisoning')
                          ? 'tool_poisoning'
                          : m.includes('Cross-Origin')
                            ? 'cross_origin_escalation'
                            : m.includes('Data Exfiltration')
                              ? 'data_exfiltration'
                              : 'other',
                      message: m,
                      severity: 'high',
                    })) || [],
                })) || [],
                options.html
              );
            }
          }
        }
        process.exit(1);
      } catch (error) {
        console.error(chalk.red('Error during scan:'), error);
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
