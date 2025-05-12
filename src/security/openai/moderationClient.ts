/**
 * OpenAI Moderation API client
 * 
 * This module provides a client for the OpenAI Moderation API, which can be used
 * to detect harmful or prohibited content in text.
 * 
 * @see https://platform.openai.com/docs/guides/moderation
 * @see https://platform.openai.com/docs/models/omni-moderation-latest
 */

import https from 'https';

/**
 * Configuration options for the OpenAI Moderation API client
 */
export interface ModerationClientOptions {
  /**
   * OpenAI API key
   */
  apiKey: string;

  /**
   * Moderation model to use
   * @default 'omni-moderation-latest'
   */
  model?: string;

  /**
   * Timeout in milliseconds
   * @default 5000
   */
  timeout?: number;
}

/**
 * Response from the OpenAI Moderation API
 */
export interface ModerationResponse {
  /**
   * Unique identifier for the moderation request
   */
  id: string;

  /**
   * The model used for moderation
   */
  model: string;

  /**
   * Array of moderation results, one for each input
   */
  results: ModerationResult[];
}

/**
 * Result of a moderation check
 */
export interface ModerationResult {
  /**
   * Whether the content violates OpenAI's usage policies
   */
  flagged: boolean;

  /**
   * Categories that may be violated by the content
   */
  categories: {
    /**
     * Content that expresses, incites, or promotes hate based on race, gender, ethnicity, religion, nationality, sexual orientation, disability status, or caste
     */
    hate: boolean;

    /**
     * Hateful content that also includes violence or serious harm towards the targeted group
     */
    "hate/threatening": boolean;

    /**
     * Content that promotes, encourages, or depicts acts of self-harm, such as suicide, cutting, and eating disorders
     */
    "self-harm": boolean;

    /**
     * Content meant to arouse sexual excitement, such as the description of sexual activity, or that promotes sexual services (excluding sex education and wellness)
     */
    sexual: boolean;

    /**
     * Sexual content that includes an individual who is under 18 years old
     */
    "sexual/minors": boolean;

    /**
     * Content that promotes or glorifies violence or celebrates the suffering or humiliation of others
     */
    violence: boolean;

    /**
     * Violent content that depicts death, violence, or serious physical injury in extreme graphic detail
     */
    "violence/graphic": boolean;

    /**
     * Content that promotes, encourages, or depicts acts of harming others
     */
    harassment: boolean;

    /**
     * Content that promotes or facilitates illegal activities
     */
    illegal: boolean;

    /**
     * Content that deceives, misleads, or defrauds people
     */
    deception: boolean;
  };

  /**
   * Category scores from 0 to 1, representing the confidence level
   */
  category_scores: {
    hate: number;
    "hate/threatening": number;
    "self-harm": number;
    sexual: number;
    "sexual/minors": number;
    violence: number;
    "violence/graphic": number;
    harassment: number;
    illegal: number;
    deception: number;
  };
}

/**
 * Client for the OpenAI Moderation API
 */
export class ModerationClient {
  private readonly apiKey: string;
  private readonly model: string;
  private readonly timeout: number;

  /**
   * Create a new OpenAI Moderation API client
   * @param options Client configuration options
   */
  constructor(options: ModerationClientOptions) {
    this.apiKey = options.apiKey;
    this.model = options.model || 'omni-moderation-latest';
    this.timeout = options.timeout || 5000;
  }

  /**
   * Check if text contains harmful or prohibited content
   * @param text Text to check
   * @returns Moderation result
   */
  async moderateText(text: string): Promise<ModerationResult> {
    try {
      const response = await this.callModerationApi([text]);
      return response.results[0];
    } catch (error) {
      throw new Error(`OpenAI Moderation API error: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Check if multiple texts contain harmful or prohibited content
   * @param texts Array of texts to check
   * @returns Array of moderation results
   */
  async moderateTexts(texts: string[]): Promise<ModerationResult[]> {
    try {
      const response = await this.callModerationApi(texts);
      return response.results;
    } catch (error) {
      throw new Error(`OpenAI Moderation API error: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Call the OpenAI Moderation API
   * @param input Array of texts to moderate
   * @returns Moderation API response
   * @private
   */
  private callModerationApi(input: string[]): Promise<ModerationResponse> {
    return new Promise((resolve, reject) => {
      const data = JSON.stringify({
        input,
        model: this.model,
      });

      const options = {
        hostname: 'api.openai.com',
        port: 443,
        path: '/v1/moderations',
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${this.apiKey}`,
          'Content-Length': Buffer.byteLength(data),
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
            if (res.statusCode !== 200) {
              reject(new Error(`API returned status code ${res.statusCode}: ${responseData}`));
              return;
            }

            const parsedData = JSON.parse(responseData) as ModerationResponse;
            resolve(parsedData);
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

      req.write(data);
      req.end();
    });
  }
}