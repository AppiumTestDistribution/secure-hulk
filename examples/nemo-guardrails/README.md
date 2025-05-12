# Using NVIDIA NeMo Guardrails with Secure Hulk

This directory contains example configuration files for using NVIDIA's NeMo Guardrails with Secure Hulk.

## What is NeMo Guardrails?

NeMo Guardrails is an open-source toolkit from NVIDIA for easily adding programmable guardrails to LLM-based conversational applications. Guardrails (or "rails") are specific ways of controlling the output of a large language model, such as:

- Not talking about certain topics
- Responding in a particular way to specific user requests
- Following a predefined dialog path
- Using a particular language style
- Extracting structured data

## Prerequisites

1. Install NeMo Guardrails:
   ```bash
   pip install nemoguardrails
   ```

2. Make sure you have Python 3.9, 3.10, 3.11, or 3.12 installed.

## Configuration

The `config.yml` file in this directory contains a basic configuration for NeMo Guardrails that:

- Uses OpenAI's GPT-3.5 Turbo model
- Enables content safety rails for both input and output
- Bans topics related to violence, hate, self-harm, sexual content, harassment, illegal activities, and deception
- Prevents jailbreak attempts, prompt injections, and sensitive information disclosure

You can customize this configuration to suit your needs by modifying the `config.yml` file.

## Using with Secure Hulk

To use NeMo Guardrails with Secure Hulk, run the following command:

```bash
node dist/index.js scan --use-nemo-guardrails --nemo-guardrails-config-path ./examples/nemo-guardrails /path/to/mcp/config.json
```

This will scan your MCP configuration using both OpenAI Moderation API (if enabled) and NeMo Guardrails to detect harmful content.

## Advanced Configuration

For more advanced configuration options, refer to the [NeMo Guardrails documentation](https://github.com/NVIDIA/NeMo-Guardrails).

You can create custom guardrails by:

1. Defining custom topics in the `config.yml` file
2. Creating topic detection models
3. Implementing custom rails using Python

## Troubleshooting

If you encounter issues with NeMo Guardrails:

1. Make sure you have the correct Python version installed
2. Verify that NeMo Guardrails is installed correctly
3. Check that the configuration path is correct
4. Look for error messages in the scan output

If NeMo Guardrails is enabled but no configuration path is provided, Secure Hulk will display a warning message.