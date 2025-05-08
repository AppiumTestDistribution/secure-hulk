/**
 * Utility to suppress stdout and stderr during execution
 */

/**
 * Suppress stdout and stderr during execution of a function
 * @param fn Function to execute with suppressed IO
 * @returns The result of the function
 */
export function suppressStdio<T>(fn: () => T): T {
  // Save original stdout and stderr write functions
  const originalStdoutWrite = process.stdout.write;
  const originalStderrWrite = process.stderr.write;

  // Replace with no-op functions
  process.stdout.write = () => true;
  process.stderr.write = () => true;

  try {
    // Execute the function
    return fn();
  } finally {
    // Restore original functions
    process.stdout.write = originalStdoutWrite;
    process.stderr.write = originalStderrWrite;
  }
}