export function rebalanceCommandArgs(
  command: string | undefined,
  args: string[] = []
): { command: string; args: string[] } {
  if (!command) {
    return {
      command: '',
      args: args,
    };
  }
  
  const commandParts = command.trim().split(/\s+/);
  const actualCommand = commandParts[0];
  const additionalArgs = commandParts.slice(1);
  const combinedArgs = [...additionalArgs, ...args];
  
  return {
    command: actualCommand,
    args: combinedArgs,
  };
}