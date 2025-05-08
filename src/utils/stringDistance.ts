/**
 * Utility for calculating string distances
 */

import * as levenshtein from 'fast-levenshtein';

/**
 * Calculate the Levenshtein distance between two strings
 * @param a First string
 * @param b Second string
 * @returns The Levenshtein distance
 */
export function calculateLevenshteinDistance(a: string, b: string): number {
  return levenshtein.get(a, b);
}

/**
 * Calculate distances between a reference string and a list of responses
 * @param reference The reference string
 * @param responses The list of strings to compare against
 * @returns A sorted array of [string, distance] pairs, sorted by distance
 */
export function calculateDistance(
  reference: string,
  responses: string[]
): [string, number][] {
  return responses
    .map(
      (response) =>
        [response, calculateLevenshteinDistance(response, reference)] as [
          string,
          number,
        ]
    )
    .sort((a, b) => a[1] - b[1]);
}
