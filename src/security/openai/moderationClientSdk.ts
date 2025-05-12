/**
 * OpenAI Moderation API client using the official OpenAI SDK
 * 
 * This module provides a client for the OpenAI Moderation API using the official SDK,
 * which can be used to detect harmful or prohibited content in text.
 * 
 * @see https://platform.openai.com/docs/guides/moderation
 * @see https://platform.openai.com/docs/models/omni-moderation-latest
 */

import OpenAI from 'openai';
import { ModerationCreateParams } from 'openai/resources/moderations';
import { ModerationResult } from './moderationClient';

/**
 * Configuration options for the OpenAI Moderation API client
 */
export interface ModerationClientSdkOptions {
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
 * Client for the OpenAI Moderation API using the official SDK
 */
export class ModerationClientSdk {
  private readonly client: OpenAI;
  private readonly model: string;
  private readonly timeout: number;

  /**
   * Create a new OpenAI Moderation API client
   * @param options Client configuration options
   */
  constructor(options: ModerationClientSdkOptions) {
    this.client = new OpenAI({
      apiKey: options.apiKey,
      timeout: options.timeout || 5000,
    });
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
      const params: ModerationCreateParams = {
        input: text,
        model: this.model,
      };

      const response = await this.client.moderations.create(params);
      
      // Convert the SDK response to our ModerationResult interface
      return response.results[0] as unknown as ModerationResult;
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
      const params: ModerationCreateParams = {
        input: texts,
        model: this.model,
      };

      const response = await this.client.moderations.create(params);
      
      // Convert the SDK response to our ModerationResult interface
      return response.results as unknown as ModerationResult[];
    } catch (error) {
      throw new Error(`OpenAI Moderation API error: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}