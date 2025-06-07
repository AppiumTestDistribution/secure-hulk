export function suppressStdio<T>(fn: () => T): T {
  const originalStdoutWrite = process.stdout.write;
  const originalStderrWrite = process.stderr.write;

  process.stdout.write = () => true;
  process.stderr.write = () => true;

  try {
    return fn();
  } finally {
    process.stdout.write = originalStdoutWrite;
    process.stderr.write = originalStderrWrite;
  }
}