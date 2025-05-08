/**
 * Utility to parse and rebalance command arguments
 */

/**
 * Rebalance command and arguments
 * This function takes a command string and an array of arguments,
 * and rebalances them to ensure the command is a single executable
 * and the arguments are properly separated.
 * 
 * @param command The command string
 * @param args The arguments array
 * @returns An object with the rebalanced command and args
 */
export function rebalanceCommandArgs(
  command: string | undefined,
  args: string[] = []
): { command: string; args: string[] } {
  // Handle undefined or null command
  if (!command) {
    return {
      command: '',
      args: args,
    };
  }
  
  // Split the command on whitespace
  const commandParts = command.trim().split(/\s+/);
  
  // The first part is the actual command
  const actualCommand = commandParts[0];
  
  // The rest are additional arguments
  const additionalArgs = commandParts.slice(1);
  
  // Combine additional args with the provided args
  const combinedArgs = [...additionalArgs, ...args];
  
  return {
    command: actualCommand,
    args: combinedArgs,
  };
}

/**
 * A more sophisticated version would use a proper parser to handle
 * quoted arguments, escaped spaces, etc. In a real implementation,
 * we might use a library like 'shell-quote' or implement a more
 * robust parser.
 */