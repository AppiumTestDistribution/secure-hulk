/**
 * Check for harmful content using OpenAI's Moderation API
 */

import { Entity, ScanResult, ScanOptions } from '../../models';
import { ModerationClient } from '../openai/moderationClient';
import { ModerationClientSdk } from '../openai/moderationClientSdk';

/**
 * Check for harmful content using OpenAI's Moderation API
 * @param entity The entity to check
 * @param results The scan results to update
 * @param options Scan options including OpenAI Moderation API configuration
 */
export async function checkForHarmfulContent(
  entity: Entity,
  results: ScanResult,
  options?: ScanOptions
): Promise<void> {
  const description = entity.description || '';

  // Use OpenAI Moderation API if enabled and API key is provided
  if (options?.useOpenaiModeration && options?.openaiApiKey) {
    try {
      let moderationResult;

      // Try using the SDK-based client first
      try {
        const sdkClient = new ModerationClientSdk({
          apiKey: options.openaiApiKey,
          model: options.openaiModerationModel || 'omni-moderation-latest',
        });

        moderationResult = await sdkClient.moderateText(description);
      } catch (sdkError) {
        // If SDK client fails, fall back to custom client
        console.warn(
          `OpenAI SDK client failed, falling back to custom client: ${sdkError instanceof Error ? sdkError.message : String(sdkError)}`
        );

        const customClient = new ModerationClient({
          apiKey: options.openaiApiKey,
          model: options.openaiModerationModel || 'omni-moderation-latest',
        });

        moderationResult = await customClient.moderateText(description);
      }

      // Check if the content was flagged by the moderation API
      if (moderationResult.flagged) {
        // Get the categories that were flagged
        const flaggedCategories = Object.entries(moderationResult.categories)
          .filter(([_, flagged]) => flagged)
          .map(([category]) => category);

        // Get the highest scoring category for more detailed reporting
        const highestCategory = Object.entries(
          moderationResult.category_scores
        ).sort(([_, scoreA], [__, scoreB]) => scoreB - scoreA)[0];

        // Format the message to include the flagged categories in a way that the formatter can extract them
        const flaggedCategoriesStr = flaggedCategories.join(', ');

        // Extract the highest scoring category for the message
        const highestCategoryName = highestCategory[0];
        const highestCategoryScore = highestCategory[1];

        // Create a message that includes the found content for the formatter to extract
        const message = `Harmful content detected by OpenAI Moderation API: Content flagged for ${flaggedCategoriesStr} - Found "${highestCategoryName} (score: ${highestCategoryScore.toFixed(2)})"`;

        results.issues.push({
          type: 'harmful_content',
          message,
          severity: 'high',
          details: {
            flaggedCategories,
            categoryScores: moderationResult.category_scores,
            highestCategory: {
              name: highestCategoryName,
              score: highestCategoryScore,
            },
          },
        });

        // Mark as not verified if harmful content was found
        results.verified = false;
      }
    } catch (error) {
      // Log the error but continue with other checks
      console.error(
        `OpenAI Moderation API error: ${error instanceof Error ? error.message : String(error)}`
      );

      // Add a warning to the results
      results.issues.push({
        type: 'warning',
        message: `OpenAI Moderation API check failed: ${error instanceof Error ? error.message : String(error)}.`,
        severity: 'low',
      });
    }
  }
}
