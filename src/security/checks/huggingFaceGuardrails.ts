import { Entity, Tool, Resource, ScanResult, ScanOptions } from '../../models';
import { HuggingFaceSafetyClient, SafetyModel, HuggingFaceSafetyClientFactory } from '../huggingface/safetyClient';

export async function checkWithHuggingFaceGuardrails(
  entity: Entity,
  results: ScanResult,
  options?: ScanOptions
): Promise<void> {
  // Skip if Hugging Face guardrails are not explicitly enabled
  if (!options?.useHuggingFaceGuardrails) {
    return;
  }

  try {
    // Create client based on options or use default
    const client = createHuggingFaceClient(options);

    // Collect text content to analyze
    const textContent = collectEntityText(entity);
    
    if (!textContent || textContent.trim().length === 0) {
      return;
    }

    // Perform safety check
    const safetyResult = await client.checkText(textContent);

    if (safetyResult.flagged) {
      results.verified = false;
      results.issues.push({
        type: 'huggingface_safety_violation',
        severity: determineSeverity(safetyResult.score) as 'low' | 'medium' | 'high',
        message: `Content flagged by Hugging Face safety model (${safetyResult.model})`,
        details: {
          model: safetyResult.model,
          score: safetyResult.score,
          flaggedCategories: safetyResult.flaggedCategories,
          classifications: safetyResult.classifications,
          processingTime: safetyResult.processingTime,
          entityName: entity.name,
          entityDescription: entity.description
        }
      });
    }
  } catch (error) {
    // Log error but don't fail the entire scan
    console.warn(`Hugging Face guardrails check failed: ${error instanceof Error ? error.message : String(error)}`);
    
    // Optionally add a warning issue
    if (options?.reportGuardrailErrors !== false) {
      results.issues.push({
        type: 'huggingface_check_error',
        severity: 'low',
        message: 'Hugging Face safety check failed',
        details: {
          error: error instanceof Error ? error.message : String(error),
          entityName: entity.name
        }
      });
    }
  }
}

/**
 * Create a Hugging Face client based on scan options
 * @param options Scan options
 * @returns Configured Hugging Face client
 */
function createHuggingFaceClient(options?: ScanOptions): HuggingFaceSafetyClient {
  const apiToken = options?.huggingFaceApiToken || process.env.HUGGINGFACE_API_TOKEN;
  const model = options?.huggingFaceModel || SafetyModel.TOXIC_BERT;
  const threshold = options?.huggingFaceThreshold || 0.5;
  const timeout = options?.huggingFaceTimeout || 10000;

  // Use factory methods for common configurations
  if (options?.huggingFacePreset) {
    switch (options.huggingFacePreset) {
      case 'toxicity':
        return HuggingFaceSafetyClientFactory.createToxicityDetector(apiToken);
      case 'strict':
        return HuggingFaceSafetyClientFactory.createStrictModerator(apiToken);
    }
  }

  // Create custom client
  return new HuggingFaceSafetyClient({
    apiToken,
    model,
    threshold,
    timeout
  });
}

/**
 * Collect text content from an entity for analysis
 * @param entity The entity to extract text from
 * @returns Combined text content
 */
function collectEntityText(entity: Entity): string {
  const textParts: string[] = [];

  // Add entity name
  if (entity.name) {
    textParts.push(entity.name);
  }

  // Add entity description
  if (entity.description) {
    textParts.push(entity.description);
  }

  // Add tool-specific content
  const tool = entity as Tool;
  if (tool.inputSchema?.properties) {
    for (const [key, prop] of Object.entries(tool.inputSchema.properties)) {
      if (typeof prop === 'object' && prop !== null && 'description' in prop && prop.description) {
        textParts.push(`${key}: ${prop.description}`);
      }
    }
  }

  // Add resource-specific content
  const resource = entity as Resource;
  if (resource.uri) {
    textParts.push(resource.uri);
  }

  return textParts.join(' ').trim();
}

/**
 * Determine issue severity based on safety score
 * @param score Safety score (0-1)
 * @returns Severity level
 */
function determineSeverity(score: number): 'low' | 'medium' | 'high' {
  if (score >= 0.7) {
    return 'high';
  } else if (score >= 0.5) {
    return 'medium';
  } else {
    return 'low';
  }
}

/**
 * Extended scan options for Hugging Face integration
 */
declare module '../../models' {
  interface ScanOptions {
    /**
     * Whether to use Hugging Face guardrails
     * @default true
     */
    useHuggingFaceGuardrails?: boolean;

    /**
     * Hugging Face API token
     */
    huggingFaceApiToken?: string;

    /**
     * Hugging Face model to use
     * @default SafetyModel.TOXIC_BERT
     */
    huggingFaceModel?: SafetyModel | string;

    /**
     * Confidence threshold for flagging content (0-1)
     * @default 0.5
     */
    huggingFaceThreshold?: number;

    /**
     * Request timeout in milliseconds
     * @default 10000
     */
    huggingFaceTimeout?: number;

    /**
     * Preset configuration for common use cases
     */
    huggingFacePreset?: 'toxicity' | 'strict';

    /**
     * Whether to report guardrail check errors as issues
     * @default true
     */
    reportGuardrailErrors?: boolean;
  }
}