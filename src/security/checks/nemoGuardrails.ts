/**
 * Check for harmful content using NVIDIA's NeMo Guardrails
 */

import { Entity, ScanResult, ScanOptions } from '../../models';
import { GuardrailsClient } from '../nemo/guardrailsClient';

/**
 * Check for harmful content using NVIDIA's NeMo Guardrails
 * @param entity The entity to check
 * @param results The scan results to update
 * @param options Scan options including NeMo Guardrails configuration
 */
export async function checkWithNemoGuardrails(
  entity: Entity,
  results: ScanResult,
  options?: ScanOptions
): Promise<void> {
  const description = entity.description || '';

  // Use NeMo Guardrails if enabled
  if (options?.useNemoGuardrails) {
    // Check if config path is provided
    if (!options?.nemoGuardrailsConfigPath) {
      console.warn('NeMo Guardrails is enabled but no configuration path is provided. Use --nemo-guardrails-config-path to specify the path.');
      
      // Add a warning to the results
      results.issues.push({
        type: 'warning',
        message: 'NeMo Guardrails is enabled but no configuration path is provided. Use --nemo-guardrails-config-path to specify the path.',
        severity: 'low',
      });
      
      return;
    }
    try {
      // Check for known compatibility issues with NeMo Guardrails
      if (options.pythonPath === 'python' && process.platform === 'darwin') {
        // Try to check Python version first
        try {
          const { spawn } = require('child_process');
          const pythonProcess = spawn(options.pythonPath || 'python', ['-V']);
          let pythonVersion = '';
          
          pythonProcess.stdout.on('data', (data: Buffer) => {
            pythonVersion += data.toString();
          });
          
          pythonProcess.stderr.on('data', (data: Buffer) => {
            pythonVersion += data.toString();
          });
          
          await new Promise((resolve) => {
            pythonProcess.on('close', resolve);
          });
          
          console.log(`Python version check: ${pythonVersion.trim()}`);
        } catch (e) {
          console.error(`Error checking Python version: ${e}`);
        }
      }
      
      // Ensure timeout is a number and use a higher default value
      const timeout = typeof options.nemoGuardrailsTimeout === 'string'
        ? parseInt(options.nemoGuardrailsTimeout, 10)
        : (options.nemoGuardrailsTimeout || 15000);
      
      console.log(`Using NeMo Guardrails timeout: ${timeout}ms`);
      
      const guardrailsClient = new GuardrailsClient({
        configPath: options.nemoGuardrailsConfigPath,
        timeout: timeout,
        pythonPath: options.pythonPath,
      });

      try {
        const guardrailsResult = await guardrailsClient.checkText(description);

        // Check if any guardrails were triggered
        if (guardrailsResult.flagged) {
          // Get the guardrails that were triggered
          const triggeredGuardrails = guardrailsResult.triggeredGuardrails;
          
          // Format the message to include the triggered guardrails
          const triggeredGuardrailsStr = triggeredGuardrails.join(', ');
          
          // Extract problematic content from the details if available
          let problematicContent = '';
          let contextInfo = '';
          
          if (guardrailsResult.details && typeof guardrailsResult.details === 'object') {
            // Try to extract problematic content from various possible detail formats
            if (guardrailsResult.details.matched_content) {
              problematicContent = guardrailsResult.details.matched_content;
            } else if (guardrailsResult.details.content) {
              problematicContent = guardrailsResult.details.content;
            } else if (guardrailsResult.details.text) {
              problematicContent = guardrailsResult.details.text;
            } else if (guardrailsResult.details.error) {
              problematicContent = guardrailsResult.details.error;
            }
            
            // Try to extract context information
            if (guardrailsResult.details.context) {
              contextInfo = ` (Context: ${guardrailsResult.details.context})`;
            }
          }
          
          // If we couldn't extract specific problematic content, use a portion of the original text
          if (!problematicContent && description.length > 0) {
            // Use the first 50 characters as a sample if the content is long
            problematicContent = description.length > 50
              ? description.substring(0, 50) + '...'
              : description;
          }
          
          // Create a message that includes the found content for the formatter to extract
          const message = `Content flagged by NeMo Guardrails: Content violates ${triggeredGuardrailsStr}${contextInfo} - Found "${problematicContent}"`;
          
          results.issues.push({
            type: 'nemo_guardrails_violation',
            message,
            severity: 'high',
            details: {
              triggeredGuardrails,
              problematicContent,
              originalDescription: description,
              details: guardrailsResult.details || {},
              modifiedContent: guardrailsResult.modifiedContent,
            },
          });
          
          // Mark as not verified if guardrails were triggered
          results.verified = false;
        }
      } catch (innerError: unknown) {
        // Handle specific NeMo Guardrails errors
        if (
          innerError instanceof Error &&
          innerError.message &&
          (innerError.message.includes("'str' object has no attribute 'colang_version'") ||
           innerError.message.includes("has no attribute 'from_path'"))
        ) {
          const message = `NeMo Guardrails compatibility issue: The installed version of NeMo Guardrails (likely 0.9.x) is not compatible with the current initialization method. This has been fixed in the latest version of Secure Hulk. Please rebuild the project with 'npm run build' and try again.`;
          
          console.warn(message);
          
          results.issues.push({
            type: 'warning',
            message,
            severity: 'medium',
          });
        } else {
          // Re-throw other errors to be caught by the outer catch block
          throw innerError;
        }
      }
    } catch (error) {
      // Log the error but continue with other checks
      console.error(
        `NeMo Guardrails check error: ${error instanceof Error ? error.message : String(error)}`
      );
      
      // Add a warning to the results
      results.issues.push({
        type: 'warning',
        message: `NeMo Guardrails check failed: ${error instanceof Error ? error.message : String(error)}.`,
        severity: 'low',
      });
    }
  }
}