/**
 * Cross-reference detection for MCP entities
 */

import { ServerScanResult, CrossRefResult } from '../models';
import { calculateDistance } from '../utils/stringDistance';

/**
 * Check for cross-references between servers
 * @param servers Array of server scan results
 * @returns Cross-reference detection result
 */
export function checkCrossReferences(servers: ServerScanResult[]): CrossRefResult {
  const result: CrossRefResult = {
    found: false,
    sources: [],
  };

  for (const server of servers) {
    // Get names from other servers
    const otherServers = servers.filter(s => s !== server);
    const otherServerNames = otherServers.map(s => s.name).filter(Boolean) as string[];
    const otherEntityNames = otherServers.flatMap(s => 
      s.entities.map(e => e.name)
    );
    
    // Create a set of lowercase names to check against
    const flaggedNames = new Set(
      [...otherServerNames, ...otherEntityNames].map(name => 
        name.toLowerCase()
      )
    );

    // Check each entity in the current server
    for (const entity of server.entities) {
      const description = (entity.description || '').toLowerCase();
      const tokens = description.split(/\s+/);
      
      for (const token of tokens) {
        // Skip short tokens
        if (token.length < 5) continue;
        
        // Check exact matches
        if (flaggedNames.has(token)) {
          result.found = true;
          result.sources.push(`${entity.name}:${token}`);
          continue;
        }
        
        // Check similar matches
        const distances = calculateDistance(token, Array.from(flaggedNames));
        
        for (const [name, distance] of distances) {
          if (distance <= 2 && token.length >= 5) {
            result.found = true;
            result.sources.push(`${entity.name}:${token}`);
            break;
          }
        }
      }
    }
  }

  return result;
}