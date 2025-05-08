# Secure Hulk

Security scanning tool for Model Context Protocol (MCP) servers and tools. This tool scans MCP configurations for security vulnerabilities like prompt injections, tool poisoning, and cross-origin escalations.

## Features

- Scanning of Claude, Cursor, Windsurf, and other file-based MCP client configurations
- Detection of prompt injection attacks in tool descriptions
- Detection of tool poisoning attacks
- Detection of cross-origin escalation attacks (tool shadowing)
- Tool Pinning to detect and prevent MCP rug pull attacks via hashing
- Whitelisting capability for approved tools

## Installation

## Usage

### Scanning MCP Configurations

```bash
# Scan all known MCP configs
secure-hulk-ts

# Scan a specific config file
secure-hulk-ts scan ~/custom/config.json

# Output results in JSON format
secure-hulk-ts --json
```

## Security Approach

1. **Rule-Based Pattern Matching**: Detects common patterns associated with prompt injections, tool poisoning, and cross-origin escalations
2. **Tool Pinning**: Detects changes in tool descriptions to prevent MCP rug pull attacks
3. **Cross-Reference Detection**: Identifies potential cross-origin escalation attacks by detecting references to other servers or tools

## License

MIT
