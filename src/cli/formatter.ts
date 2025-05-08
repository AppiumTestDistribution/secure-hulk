/**
 * Formatter for scan results
 */

import chalk from 'chalk';
import {
  ScanPathResult,
  ServerScanResult,
  Entity,
  EntityScanResult,
  ScanError,
} from '../models';

/**
 * Format and print scan results
 * @param results Array of scan results
 * @param printErrors Whether to print detailed error information
 */
export function formatResults(
  results: ScanPathResult[],
  printErrors: boolean = false
): void {
  for (let i = 0; i < results.length; i++) {
    formatPathResult(results[i], printErrors);

    // Add a newline between results
    if (i < results.length - 1) {
      console.log();
    }
  }
}

/**
 * Format and print a single path result
 * @param result Path scan result
 * @param printErrors Whether to print detailed error information
 */
function formatPathResult(
  result: ScanPathResult,
  printErrors: boolean = false
): void {
  if (result.error) {
    // Print path with error
    const status = formatError(result.error);
    console.log(`● Scanning ${chalk.bold(result.path)} ${chalk.gray(status)}`);

    if (printErrors && result.error.exception) {
      console.error(result.error.exception);
    }

    return;
  }

  // Print path with server count
  const message = `found ${result.servers.length} server${result.servers.length === 1 ? '' : 's'}`;
  console.log(`● Scanning ${chalk.bold(result.path)} ${chalk.gray(message)}`);
  console.log();

  // Print summary of checks
  console.log(chalk.bold('Security Scan Summary:'));
  console.log('  - Checking for prompt injection vulnerabilities');
  console.log('  - Checking for tool poisoning attempts');
  console.log('  - Checking for cross-origin escalation risks');
  console.log('  - Verifying entity descriptions and schemas');
  console.log();

  // Print servers
  for (const server of result.servers) {
    formatServerResult(server, printErrors);
  }

  // Print cross-reference result
  if (result.crossRefResult?.found) {
    console.log();
    console.log(
      chalk.yellow.bold(`⚠️ Cross-Origin Violation: `) +
        chalk.yellow(
          `Descriptions of server ${result.crossRefResult.sources.join(', ')} explicitly mention `
        ) +
        chalk.yellow(`tools or resources of other servers, or other servers.`)
    );
  }
}

/**
 * Format and print a server result
 * @param server Server scan result
 * @param printErrors Whether to print detailed error information
 */
function formatServerResult(
  server: ServerScanResult,
  printErrors: boolean = false
): void {
  if (server.error) {
    // Print server with error
    const status = formatError(server.error);
    console.log(
      chalk.bold(
        `Server: ${server.name || 'unnamed'} (${(server.server as any).type || (server.server as any).transportType})`
      )
    );
    console.log(chalk.red(`  Error: ${status}`));

    if (printErrors && server.error.exception) {
      console.error(server.error.exception);
    }

    console.log();
    return;
  }

  // Count verified and unverified entities
  const totalEntities = server.entities.length;
  const verifiedEntities = server.result?.filter((r) => r.verified).length || 0;
  const unverifiedEntities = totalEntities - verifiedEntities;

  // Count entity types
  const prompts = server.prompts.length;
  const resources = server.resources.length;
  const tools = server.tools.length;

  // Print server header with summary
  console.log(
    chalk.bold(
      `Server: ${server.name || 'unnamed'} (${(server.server as any).type || (server.server as any).transportType})`
    )
  );
  console.log(
    `  Retrieved: ${chalk.cyan(`${prompts} prompts`)}, ${chalk.cyan(`${resources} resources`)}, ${chalk.cyan(`${tools} tools`)}`
  );

  if (totalEntities > 0) {
    console.log(
      `  Verification: ${chalk.green(`${verifiedEntities} verified`)}, ${unverifiedEntities > 0 ? chalk.red(`${unverifiedEntities} issues found`) : chalk.green('No issues found')}`
    );
  }

  // List all tools if any
  if (tools > 0) {
    console.log();
    console.log(chalk.bold(`  Tools (${tools}):`));
    const toolsList = server.tools
      .map((tool) => `    - ${tool.name}`)
      .join('\n');
    console.log(toolsList);
  }

  // List all resources if any
  if (resources > 0) {
    console.log();
    console.log(chalk.bold(`  Resources (${resources}):`));
    const resourcesList = server.resources
      .map((resource) => `    - ${resource.name} (${resource.uri})`)
      .join('\n');
    console.log(resourcesList);
  }

  // List all prompts if any
  if (prompts > 0) {
    console.log();
    console.log(chalk.bold(`  Prompts (${prompts}):`));
    const promptsList = server.prompts
      .map((prompt) => `    - ${prompt.name}`)
      .join('\n');
    console.log(promptsList);
  }

  // Print issues if any
  const issues = server.result?.filter((r) => !r.verified);
  if (issues && issues.length > 0) {
    console.log();
    console.log(chalk.red.bold(`  Issues Found (${issues.length}):`));

    // Print entities with issues
    for (let i = 0; i < server.entities.length; i++) {
      const entity = server.entities[i];
      const entityResult = server.result?.[i];

      if (entityResult && !entityResult.verified) {
        formatEntityWithIssue(entity, entityResult);
      }
    }
  }

  console.log();
}

/**
 * Format and print an entity result
 * @param entity Entity
 * @param result Entity scan result
 * @param isLast Whether this is the last entity in the list
 */
function formatEntityResult(
  entity: Entity,
  result: EntityScanResult | undefined,
  isLast: boolean = false
): void {
  // Determine entity type
  let type = 'unknown';
  if ('inputSchema' in entity) type = 'tool';
  if ('uri' in entity) type = 'resource';
  if (!('inputSchema' in entity) && !('uri' in entity)) type = 'prompt';

  // Right-pad type
  type = type.padEnd(8, ' ');

  // Determine verification status
  let isVerified: boolean | null = null;
  let status = '';
  let includeDescription = true;

  if (result) {
    isVerified = result.verified === undefined ? null : result.verified;
    status = result.status || '';

    if (result.changed) {
      isVerified = false;
      status = appendStatus(status, chalk.bold('changed since previous scan'));
    }

    if (!isVerified && result.whitelisted) {
      status = appendStatus(status, chalk.bold('whitelisted'));
      isVerified = true;
    }

    includeDescription = !isVerified;
  }

  // Determine color and icon based on verification status
  const color =
    isVerified === true
      ? chalk.green
      : isVerified === false
        ? chalk.red
        : chalk.gray;
  const icon = isVerified === true ? '✓' : isVerified === false ? '✗' : '';

  // Format name
  let name = entity.name;
  if (name.length > 25) {
    name = name.substring(0, 22) + '...';
  }
  name = name.padEnd(25, ' ');

  // Print entity line
  const prefix = isLast ? '  └─ ' : '  ├─ ';
  console.log(`${prefix}${type} ${color.bold(name)} ${icon} ${status}`);

  // Print description if needed
  if (includeDescription) {
    const description = entity.description || '<no description available>';
    const indent = isLast ? '     ' : '  │  ';

    console.log(`${indent}${chalk.gray.bold('Current description:')}`);
    console.log(`${indent}${chalk.gray(description)}`);
  }

  // Print messages
  const messages = result?.messages || [];
  if (messages.length > 0) {
    const indent = isLast ? '     ' : '  │  ';
    console.log();

    for (const message of messages) {
      console.log(`${indent}${chalk.gray(message)}`);
    }
  }

  // Add whitelist suggestion if not verified
  if (result && !isVerified) {
    const indent = isLast ? '     ' : '  │  ';
    const hash = hashEntity(entity);

    console.log();
    console.log(
      `${indent}${chalk.gray.bold(`You can whitelist this ${type.trim()} by running `)}` +
        `${chalk.gray.bold(`secure-hulk whitelist ${type.trim()} '${entity.name}' ${hash}`)}`
    );
  }
}

/**
 * Format an error for display
 * @param error Scan error
 * @returns Formatted error string
 */
function formatError(error: ScanError): string {
  return (
    error.message ||
    (error.exception ? error.exception.toString() : 'unknown error')
  );
}

/**
 * Append a status to an existing status
 * @param status Existing status
 * @param newStatus New status to append
 * @returns Combined status
 */
function appendStatus(status: string, newStatus: string): string {
  if (status === '') {
    return newStatus;
  }
  return `${newStatus}, ${status}`;
}

/**
 * Calculate the hash of an entity
 * @param entity The entity to hash
 * @returns The hash of the entity
 */
function hashEntity(entity: Entity): string {
  if (!entity.description) {
    return '';
  }

  const crypto = require('crypto');
  return crypto.createHash('md5').update(entity.description).digest('hex');
}

/**
 * Format and print an entity with issues
 * @param entity Entity with issues
 * @param result Entity scan result
 */
function formatEntityWithIssue(entity: Entity, result: EntityScanResult): void {
  // Determine entity type
  let type = 'unknown';
  if ('inputSchema' in entity) type = 'tool';
  if ('uri' in entity) type = 'resource';
  if (!('inputSchema' in entity) && !('uri' in entity)) type = 'prompt';

  // Print entity name and type
  console.log(`    - ${chalk.red(entity.name)} (${type})`);

  // Print messages
  const messages = result.messages || [];
  if (messages.length > 0) {
    for (const message of messages) {
      console.log(`      ${chalk.gray(message)}`);
    }
  }

  // Print description
  const description = entity.description || '<no description available>';
  console.log(
    `      ${chalk.gray.bold('Description:')} ${chalk.gray(description.substring(0, 100) + (description.length > 100 ? '...' : ''))}`
  );

  // Add whitelist suggestion
  const hash = hashEntity(entity);
  console.log(
    `      ${chalk.gray.bold(`Whitelist command:`)} ${chalk.gray(`secure-hulk whitelist ${type} '${entity.name}' ${hash}`)}`
  );
}
