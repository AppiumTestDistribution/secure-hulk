/**
 * Hugging Face Safety Models client
 *
 * This module provides a client for various Hugging Face safety and toxicity detection models.
 * It supports both local inference and Hugging Face Inference API.
 *
 * @see https://huggingface.co/models?pipeline_tag=text-classification&search=toxicity
 * @see https://huggingface.co/unitary/toxic-bert
 * @see https://huggingface.co/martin-ha/toxic-comment-model
 */

import https from 'https';

/**
 * Available Hugging Face safety models
 */
export enum SafetyModel {
  TOXIC_BERT = 'unitary/toxic-bert',
  ROBERTA_TOXICITY = 's-nlp/roberta_toxicity_classifier',
  DETOXIFY_ORIGINAL = 'unitary/unbiased-toxic-roberta'
}

/**
 * Configuration options for the Hugging Face Safety client
 */
export interface HuggingFaceSafetyClientOptions {
  /**
   * Hugging Face API token (required for private models and higher rate limits)
   */
  apiToken?: string;

  /**
   * Model to use for safety classification
   * @default SafetyModel.TOXIC_BERT
   */
  model?: SafetyModel | string;

  /**
   * Timeout in milliseconds
   * @default 10000
   */
  timeout?: number;

  /**
   * Confidence threshold for flagging content (0-1)
   * @default 0.5
   */
  threshold?: number;

  /**
   * Whether to use local inference (requires transformers library)
   * @default false
   */
  useLocalInference?: boolean;

  /**
   * Maximum text length to process
   * @default 512
   */
  maxLength?: number;
}

/**
 * Safety classification result
 */
export interface SafetyClassification {
  /**
   * Classification label
   */
  label: string;

  /**
   * Confidence score (0-1)
   */
  score: number;
}

/**
 * Result of a safety check
 */
export interface HuggingFaceSafetyResult {
  /**
   * Whether the content violates safety policies
   */
  flagged: boolean;

  /**
   * Overall toxicity/safety score (0-1)
   */
  score: number;

  /**
   * Detailed classifications
   */
  classifications: SafetyClassification[];

  /**
   * Categories that were flagged
   */
  flaggedCategories: string[];

  /**
   * Model used for classification
   */
  model: string;

  /**
   * Processing time in milliseconds
   */
  processingTime: number;
}

/**
 * Hugging Face Inference API response
 */
interface HuggingFaceApiResponse {
  label: string;
  score: number;
}

/**
 * Client for Hugging Face safety models
 */
export class HuggingFaceSafetyClient {
  private readonly apiToken?: string;
  private readonly model: string;
  private readonly timeout: number;
  private readonly threshold: number;
  private readonly useLocalInference: boolean;
  private readonly maxLength: number;

  /**
   * Create a new Hugging Face Safety client
   * @param options Client configuration options
   */
  constructor(options: HuggingFaceSafetyClientOptions = {}) {
    this.apiToken = options.apiToken;
    this.model = options.model || SafetyModel.TOXIC_BERT;
    this.timeout = options.timeout || 10000;
    this.threshold = options.threshold || 0.5;
    this.useLocalInference = options.useLocalInference || false;
    this.maxLength = options.maxLength || 512;
  }

  /**
   * Check if text contains toxic or harmful content
   * @param text Text to check
   * @returns Safety result
   */
  async checkText(text: string): Promise<HuggingFaceSafetyResult> {
    const startTime = Date.now();

    try {
      // Truncate text if it's too long
      const processedText =
        text.length > this.maxLength ? text.substring(0, this.maxLength) : text;

      let classifications: SafetyClassification[];

      if (this.useLocalInference) {
        classifications = await this.runLocalInference(processedText);
      } else {
        classifications = await this.callHuggingFaceApi(processedText);
      }

      const processingTime = Date.now() - startTime;

      // Find the highest scoring classification and flagged categories
      const flaggedCategories: string[] = [];
      let maxScore = 0;

      for (const classification of classifications) {
        if (classification.score > this.threshold) {
          flaggedCategories.push(classification.label);
        }
        maxScore = Math.max(maxScore, classification.score);
      }

      const flagged = flaggedCategories.length > 0;

      return {
        flagged,
        score: maxScore,
        classifications,
        flaggedCategories,
        model: this.model,
        processingTime,
      };
    } catch (error) {
      throw new Error(
        `Hugging Face safety check failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Check multiple texts for toxic or harmful content
   * @param texts Array of texts to check
   * @returns Array of safety results
   */
  async checkTexts(texts: string[]): Promise<HuggingFaceSafetyResult[]> {
    const promises = texts.map((text) => this.checkText(text));
    return Promise.all(promises);
  }

  /**
   * Get model information and capabilities
   * @returns Model information
   */
  async getModelInfo(): Promise<any> {
    try {
      const response = await this.makeApiRequest(
        `https://huggingface.co/api/models/${this.model}`,
        'GET'
      );
      return JSON.parse(response);
    } catch (error) {
      throw new Error(
        `Failed to get model info: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Call the Hugging Face Inference API
   * @param text Text to classify
   * @returns Classification results
   * @private
   */
  private async callHuggingFaceApi(
    text: string
  ): Promise<SafetyClassification[]> {
    const url = `https://api-inference.huggingface.co/models/${this.model}`;
    const data = JSON.stringify({ inputs: text });

    try {
      const response = await this.makeApiRequest(url, 'POST', data);
      const results = JSON.parse(response) as
        | HuggingFaceApiResponse[]
        | HuggingFaceApiResponse[][];

      // Handle different response formats
      let classifications: HuggingFaceApiResponse[];
      if (Array.isArray(results[0])) {
        classifications = results[0] as HuggingFaceApiResponse[];
      } else {
        classifications = results as HuggingFaceApiResponse[];
      }

      return classifications.map((result) => ({
        label: result.label,
        score: result.score,
      }));
    } catch (error) {
      throw new Error(
        `Hugging Face API call failed: ${error instanceof Error ? error.message : String(error)}`
      );
    }
  }

  /**
   * Run local inference using Python transformers library
   * @param text Text to classify
   * @returns Classification results
   * @private
   */
  private async runLocalInference(
    text: string
  ): Promise<SafetyClassification[]> {
    // This would require a Python subprocess or a Node.js transformers library
    // For now, we'll throw an error indicating this feature needs implementation
    throw new Error(
      'Local inference not yet implemented. Please use API inference or implement Python subprocess integration.'
    );
  }

  /**
   * Make an HTTP request to the Hugging Face API
   * @param url Request URL
   * @param method HTTP method
   * @param data Request body (optional)
   * @returns Response body
   * @private
   */
  private makeApiRequest(
    url: string,
    method: string,
    data?: string
  ): Promise<string> {
    return new Promise((resolve, reject) => {
      const urlObj = new URL(url);
      const options = {
        hostname: urlObj.hostname,
        port: urlObj.port || 443,
        path: urlObj.pathname + urlObj.search,
        method,
        headers: {
          'Content-Type': 'application/json',
          'User-Agent': 'secure-hulk/1.0.0',
          ...(this.apiToken && { Authorization: `Bearer ${this.apiToken}` }),
          ...(data && { 'Content-Length': Buffer.byteLength(data) }),
        },
        timeout: this.timeout,
      };

      const req = https.request(options, (res) => {
        let responseData = '';

        res.on('data', (chunk) => {
          responseData += chunk;
        });

        res.on('end', () => {
          try {
            if (
              res.statusCode &&
              res.statusCode >= 200 &&
              res.statusCode < 300
            ) {
              resolve(responseData);
            } else {
              reject(
                new Error(
                  `API returned status code ${res.statusCode}: ${responseData}`
                )
              );
            }
          } catch (error) {
            reject(error);
          }
        });
      });

      req.on('error', (error) => {
        reject(error);
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Request timed out after ${this.timeout}ms`));
      });

      if (data) {
        req.write(data);
      }
      req.end();
    });
  }

  /**
   * Get available safety models
   * @returns List of available models
   */
  static getAvailableModels(): SafetyModel[] {
    return Object.values(SafetyModel);
  }

  /**
   * Get model recommendations based on use case
   * @param useCase The specific use case
   * @returns Recommended models
   */
  static getModelRecommendations(
    useCase: 'general' | 'toxicity'
  ): SafetyModel[] {
    switch (useCase) {
      case 'general':
        return [SafetyModel.TOXIC_BERT, SafetyModel.DETOXIFY_ORIGINAL];
      case 'toxicity':
        return [SafetyModel.ROBERTA_TOXICITY, SafetyModel.TOXIC_BERT];
      default:
        return [SafetyModel.TOXIC_BERT];
    }
  }
}

/**
 * Utility function to create a pre-configured client for common use cases
 */
export class HuggingFaceSafetyClientFactory {
  /**
   * Create a client optimized for general toxicity detection
   */
  static createToxicityDetector(apiToken?: string): HuggingFaceSafetyClient {
    return new HuggingFaceSafetyClient({
      apiToken,
      model: SafetyModel.TOXIC_BERT,
      threshold: 0.7,
      timeout: 10000,
    });
  }


  /**
   * Create a high-sensitivity client for strict moderation
   */
  static createStrictModerator(apiToken?: string): HuggingFaceSafetyClient {
    return new HuggingFaceSafetyClient({
      apiToken,
      model: SafetyModel.ROBERTA_TOXICITY,
      threshold: 0.3,
      timeout: 10000,
    });
  }
}
