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
  console.log(`${chalk.green('●')} Scanning ${chalk.bold(result.path)} ${chalk.gray(message)}`);
  console.log();

  // Print summary of checks with icons and colors
  console.log(chalk.bold.underline('Security Scan Summary:'));
  console.log(`  ${chalk.magenta('🔒')} ${chalk.magenta('Checking for prompt injection vulnerabilities')}`);
  console.log(`  ${chalk.yellow('⚠️')} ${chalk.yellow('Checking for tool poisoning attempts')}`);
  console.log(`  ${chalk.red('🌐')} ${chalk.red('Checking for cross-origin escalation risks')}`);
  console.log(`  ${chalk.cyan('🔍')} ${chalk.cyan('Verifying entity descriptions and schemas')}`);
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
    chalk.bold.blue(
      `Server: ${server.name || 'unnamed'} (${(server.server as any).type || (server.server as any).transportType})`
    )
  );
  
  // Print entity counts with icons
  console.log(
    `  ${chalk.cyan('📊')} Retrieved: ${chalk.cyan.bold(`${prompts} prompts`)}, ${chalk.cyan.bold(`${resources} resources`)}, ${chalk.cyan.bold(`${tools} tools`)}`
  );

  if (totalEntities > 0) {
    // Use different icons based on verification status
    const verificationIcon = unverifiedEntities > 0 ? '❌' : '✅';
    console.log(
      `  ${chalk.cyan(verificationIcon)} Verification: ${chalk.green.bold(`${verifiedEntities} verified`)}, ${unverifiedEntities > 0 ? chalk.red.bold(`${unverifiedEntities} issues found`) : chalk.green.bold('No issues found')}`
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
    console.log(chalk.red.bold(`  ⚠️ SECURITY ISSUES FOUND (${issues.length}):`));
    console.log(chalk.red(`  ┏${'━'.repeat(60)}┓`));

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

  // Print entity name and type with an icon
  console.log(`    ${chalk.bold.white('┌─')} ${chalk.bold.red(entity.name)} ${chalk.cyan(`[${type}]`)}`);

  // Group messages by issue type
  const messages = result.messages || [];
  const groupedMessages = new Map();
  
  for (const message of messages) {
    let issueType = '';
    let issueCategory = '';
    let icon = '';
    let color = chalk.white;
    let detailedExplanation = '';
    
    // Determine the issue type and category
    if (message.includes('Prompt Injection detected:')) {
      issueType = 'PROMPT INJECTION';
      icon = '🔒';
      color = chalk.magenta;
      
      const parts = message.split(': ');
      if (parts.length > 1) {
        const categoryParts = parts[1].split(' - ');
        issueCategory = categoryParts[0];
      }
      
      // Add detailed explanation based on the category
      if (issueCategory.includes('Hidden instructions')) {
        detailedExplanation = 'Hidden instructions in XML-like tags can manipulate the AI to perform unauthorized actions.';
      } else if (issueCategory.includes('Hidden secret')) {
        detailedExplanation = 'Secret instructions attempt to access sensitive files or perform privileged operations.';
      } else if (issueCategory.includes('Hidden system')) {
        detailedExplanation = 'System-level instructions attempt to modify AI behavior or bypass security controls.';
      } else if (issueCategory.includes('Instruction override')) {
        detailedExplanation = 'Attempts to override or ignore previous instructions to bypass security controls.';
      } else if (issueCategory.includes('Jailbreak')) {
        detailedExplanation = 'Uses known jailbreak techniques to bypass AI safety mechanisms.';
      }
    } else if (message.includes('Tool Poisoning detected:')) {
      issueType = 'TOOL POISONING';
      icon = '⚠️';
      color = chalk.yellow;
      
      const parts = message.split(': ');
      if (parts.length > 1) {
        const categoryParts = parts[1].split(' - ');
        issueCategory = categoryParts[0];
      }
      
      // Add detailed explanation based on the category
      if (issueCategory.includes('Tool shadowing')) {
        detailedExplanation = 'Tool shadowing attempts to modify the behavior of other tools, potentially leading to unauthorized actions.';
      } else if (issueCategory.includes('Command execution')) {
        detailedExplanation = 'Attempts to execute arbitrary system commands that could compromise security.';
      } else if (issueCategory.includes('Code execution')) {
        detailedExplanation = 'Attempts to execute arbitrary code that could lead to system compromise.';
      } else if (issueCategory.includes('network request')) {
        detailedExplanation = 'Attempts to make unauthorized network requests to external servers.';
      } else if (issueCategory.includes('DOM manipulation')) {
        detailedExplanation = 'Attempts to manipulate the DOM which could lead to XSS attacks.';
      } else if (issueCategory.includes('File system')) {
        detailedExplanation = 'Attempts to access the file system which could lead to data theft or corruption.';
      } else if (issueCategory.includes('Environment')) {
        detailedExplanation = 'Attempts to access environment variables which could expose sensitive information.';
      }
    } else if (message.includes('Cross-Origin Escalation detected:')) {
      issueType = 'CROSS-ORIGIN ESCALATION';
      icon = '🌐';
      color = chalk.red;
      
      const parts = message.split(': ');
      if (parts.length > 1) {
        const categoryParts = parts[1].split(' - ');
        issueCategory = categoryParts[0];
      }
      
      // Add detailed explanation based on the category
      if (issueCategory.includes('Reference to external')) {
        detailedExplanation = 'References to external services could lead to unauthorized data sharing.';
      } else if (issueCategory.includes('Unauthorized access')) {
        detailedExplanation = 'Attempts to access unauthorized services or resources.';
      } else if (issueCategory.includes('Data routing')) {
        detailedExplanation = 'Attempts to route data through external services which could lead to data exfiltration.';
      } else if (issueCategory.includes('cross-boundary')) {
        detailedExplanation = 'Explicit cross-boundary references could lead to privilege escalation.';
      } else if (issueCategory.includes('Tool chaining')) {
        detailedExplanation = 'Tool chaining attempts could bypass security controls by combining tools.';
      } else if (issueCategory.includes('weather service')) {
        detailedExplanation = 'References to weather services could lead to unauthorized data access or API key exposure.';
      } else if (issueCategory.includes('calendar service')) {
        detailedExplanation = 'References to calendar services could lead to unauthorized access to user schedule data.';
      } else if (issueCategory.includes('email service')) {
        detailedExplanation = 'References to email services could lead to unauthorized message sending or data exfiltration.';
      } else if (issueCategory.includes('search service')) {
        detailedExplanation = 'References to search services could lead to unauthorized data collection or tracking.';
      }
    } else if (message.includes('Data Exfiltration detected:')) {
      issueType = 'DATA EXFILTRATION';
      icon = '💼';
      color = chalk.cyan;
      
      const parts = message.split(': ');
      if (parts.length > 1) {
        const categoryParts = parts[1].split(' - ');
        issueCategory = categoryParts[0];
      }
      
      // Add detailed explanation based on the category
      if (issueCategory.includes('Suspicious parameter')) {
        detailedExplanation = 'Suspicious parameters could be used to exfiltrate sensitive data to external systems.';
      } else if (issueCategory.includes('passthrough')) {
        detailedExplanation = 'Passthrough parameters allow arbitrary data to be sent, which could lead to data exfiltration.';
      } else {
        detailedExplanation = 'Data exfiltration attempts could lead to sensitive information being sent to unauthorized recipients.';
      }
    } else {
      issueType = 'ISSUE';
      icon = 'ℹ️';
      color = chalk.gray;
      issueCategory = message;
    }
    
    // Extract the found content
    let foundContent = '';
    if (message.includes(' - Found "')) {
      const parts = message.split(' - Found "');
      if (parts.length > 1) {
        const contentParts = parts[1].split('" in context "');
        if (contentParts.length > 1) {
          foundContent = contentParts[0];
        }
      }
    }
    
    // Group by issue type
    if (!groupedMessages.has(issueType)) {
      groupedMessages.set(issueType, {
        icon,
        color,
        category: issueCategory,
        explanation: detailedExplanation,
        foundItems: []
      });
    }
    
    // Add found content to the group
    if (foundContent) {
      groupedMessages.get(issueType).foundItems.push(foundContent);
    }
  }
  
  // Print grouped messages
  let isFirst = true;
  for (const [issueType, data] of groupedMessages.entries()) {
    if (!isFirst) {
      console.log(`    ${chalk.bold.white('│')}`);
    }
    isFirst = false;
    
    // Print the issue type and category
    console.log(`    ${chalk.bold.white('│')}  ${data.color.bold(`${data.icon} ${issueType}:`)} ${data.color(data.category)}`);
    
    // Print the found items as bullet points
    if (data.foundItems.length > 0) {
      console.log(`    ${chalk.bold.white('│')}  ${chalk.bold.white('↳')} ${chalk.italic.white('Found:')}`);
      for (const item of data.foundItems) {
        console.log(`    ${chalk.bold.white('│')}     ${chalk.bold.white('•')} ${chalk.italic(item)}`);
      }
    }
    
    // Print detailed explanation if available
    if (data.explanation) {
      console.log(`    ${chalk.bold.white('│')}  ${chalk.bold.white('↳')} ${chalk.italic.white('Impact:')} ${chalk.italic.gray(data.explanation)}`);
    }
  }
  
  // Close the box
  console.log(`    ${chalk.bold.white('└───────────────────────────────────────')}`);
  console.log();
}
