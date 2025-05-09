/**
 * HTML Report Generator for security scan results
 */

import { ScanResult, Entity, EntityScanResult as BaseEntityScanResult } from '../models';

// Extended interface for our HTML reporter
interface EntityScanResult extends BaseEntityScanResult {
  entity: Entity;
}
import * as fs from 'fs';
import * as path from 'path';

/**
 * Generate an HTML report for the scan results
 * @param serverName The name of the server
 * @param serverType The type of server (stdio, sse)
 * @param entities The entities in the server
 * @param results The scan results
 * @param outputPath The path to write the HTML report to
 */
export function generateHtmlReport(
  serverName: string,
  serverType: string,
  entities: Entity[],
  results: ScanResult[],
  outputPath: string
): void {
  // Count entities by type
  const prompts = entities.filter(e => !('inputSchema' in e) && !('uri' in e)).length;
  const resources = entities.filter(e => 'uri' in e).length;
  const tools = entities.filter(e => 'inputSchema' in e).length;

  // Count verified vs issues
  const verified = results.filter(r => r.verified).length;
  const withIssues = results.filter(r => !r.verified).length;

  // Create entity scan results
  const entityResults: EntityScanResult[] = [];
  for (let i = 0; i < entities.length; i++) {
    const entity = entities[i];
    const result = results[i];
    
    if (!result.verified) {
      entityResults.push({
        entity,
        messages: result.issues.map(issue => issue.message),
      });
    }
  }

  // Generate HTML content
  const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Scan Report - ${serverName}</title>
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <style>
    :root {
      --primary-color: #4a6cf7;
      --primary-dark: #3a56d4;
      --success-color: #10b981;
      --warning-color: #f59e0b;
      --danger-color: #ef4444;
      --info-color: #06b6d4;
      --dark-color: #1e293b;
      --light-color: #f9fafb;
      --prompt-color: #9333ea;
      --tool-color: #f97316;
      --cross-color: #ec4899;
      --data-color: #0ea5e9;
      --gray-100: #f3f4f6;
      --gray-200: #e5e7eb;
      --gray-300: #d1d5db;
      --gray-400: #9ca3af;
      --gray-500: #6b7280;
      --gray-600: #4b5563;
      --gray-700: #374151;
      --gray-800: #1f2937;
      --gray-900: #111827;
      --border-radius: 8px;
      --box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
      --transition: all 0.3s ease;
    }
    
    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }
    
    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, 'Open Sans', 'Helvetica Neue', sans-serif;
      line-height: 1.6;
      color: var(--gray-800);
      background-color: var(--gray-100);
      padding: 0;
      margin: 0;
    }
    
    .container {
      max-width: 1200px;
      margin: 0 auto;
      padding: 0 20px;
    }
    
    header {
      background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
      color: white;
      padding: 40px 0;
      margin-bottom: 40px;
      box-shadow: var(--box-shadow);
    }
    
    header .container {
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    
    h1 {
      font-size: 2.5rem;
      font-weight: 700;
      margin: 0;
      letter-spacing: -0.025em;
    }
    
    h2 {
      font-size: 1.875rem;
      font-weight: 600;
      margin: 40px 0 20px;
      color: var(--gray-800);
      position: relative;
      padding-bottom: 10px;
    }
    
    h2::after {
      content: '';
      position: absolute;
      bottom: 0;
      left: 0;
      width: 60px;
      height: 4px;
      background-color: var(--primary-color);
      border-radius: 2px;
    }
    
    h3 {
      font-size: 1.25rem;
      font-weight: 600;
      margin: 0 0 15px;
      color: var(--gray-700);
    }
    
    h4 {
      font-size: 1rem;
      font-weight: 600;
      margin: 0 0 10px;
      color: var(--gray-600);
    }
    
    p {
      margin-bottom: 1rem;
    }
    
    .summary-container {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
      gap: 24px;
      margin-bottom: 40px;
    }
    
    .summary-box {
      background-color: white;
      border-radius: var(--border-radius);
      padding: 24px;
      box-shadow: var(--box-shadow);
      transition: var(--transition);
    }
    
    .summary-box:hover {
      transform: translateY(-5px);
      box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
    }
    
    .summary-box h3 {
      margin-top: 0;
      border-bottom: 1px solid var(--gray-200);
      padding-bottom: 12px;
      color: var(--primary-color);
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .summary-box h3 i {
      font-size: 1.25rem;
    }
    
    .summary-box ul {
      list-style-type: none;
      padding: 0;
      margin: 15px 0;
    }
    
    .summary-box li {
      padding: 8px 0;
      display: flex;
      align-items: center;
      gap: 8px;
    }
    
    .summary-box li i {
      color: var(--primary-color);
    }
    
    .entity-list {
      list-style-type: none;
      padding: 0;
    }
    
    .entity-list li {
      padding: 10px 0;
      border-bottom: 1px solid var(--gray-200);
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    
    .entity-list li:last-child {
      border-bottom: none;
    }
    
    .entity-card {
      background-color: white;
      border-radius: var(--border-radius);
      margin-bottom: 24px;
      overflow: hidden;
      box-shadow: var(--box-shadow);
      transition: var(--transition);
    }
    
    .entity-card:hover {
      box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
    }
    
    .entity-header {
      background-color: var(--dark-color);
      color: white;
      padding: 16px 24px;
      font-weight: 600;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    
    .entity-type {
      background-color: var(--info-color);
      color: white;
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    
    .entity-body {
      padding: 24px;
    }
    
    .issue-group {
      margin-bottom: 24px;
      border-radius: var(--border-radius);
      background-color: var(--gray-100);
      overflow: hidden;
    }
    
    .issue-group:last-child {
      margin-bottom: 0;
    }
    
    .issue-type {
      font-weight: 600;
      padding: 12px 16px;
      display: flex;
      align-items: center;
      gap: 8px;
      cursor: pointer;
      transition: var(--transition);
    }
    
    .issue-type:hover {
      background-color: rgba(0, 0, 0, 0.03);
    }
    
    .issue-type.prompt-injection {
      background-color: rgba(147, 51, 234, 0.1);
      color: var(--prompt-color);
    }
    
    .issue-type.tool-poisoning {
      background-color: rgba(249, 115, 22, 0.1);
      color: var(--tool-color);
    }
    
    .issue-type.cross-origin {
      background-color: rgba(236, 72, 153, 0.1);
      color: var(--cross-color);
    }
    
    .issue-type.data-exfiltration {
      background-color: rgba(14, 165, 233, 0.1);
      color: var(--data-color);
    }
    
    .issue-icon {
      font-size: 1.25rem;
    }
    
    .issue-details {
      padding: 16px;
      background-color: white;
      border-top: 1px solid var(--gray-200);
    }
    
    .issue-category {
      font-weight: 600;
      margin-bottom: 12px;
      color: var(--gray-700);
    }
    
    .found-items {
      background-color: var(--gray-100);
      padding: 16px;
      border-radius: var(--border-radius);
      margin-bottom: 16px;
    }
    
    .found-items h4 {
      margin-top: 0;
      margin-bottom: 12px;
      font-size: 0.875rem;
      color: var(--gray-600);
      display: flex;
      align-items: center;
      gap: 6px;
    }
    
    .found-items ul {
      margin: 0;
      padding-left: 24px;
    }
    
    .found-items li {
      margin-bottom: 8px;
      position: relative;
      padding-left: 8px;
    }
    
    .found-items li:last-child {
      margin-bottom: 0;
    }
    
    .impact {
      font-style: italic;
      color: var(--gray-600);
      margin-bottom: 0;
      display: flex;
      align-items: flex-start;
      gap: 6px;
    }
    
    .impact i {
      margin-top: 4px;
      font-size: 0.875rem;
    }
    
    .timestamp {
      text-align: center;
      margin-top: 40px;
      padding: 20px 0;
      color: var(--gray-500);
      font-size: 0.875rem;
      border-top: 1px solid var(--gray-200);
    }
    
    .status-badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    
    .status-verified {
      background-color: rgba(16, 185, 129, 0.1);
      color: var(--success-color);
    }
    
    .status-issues {
      background-color: rgba(239, 68, 68, 0.1);
      color: var(--danger-color);
    }
    
    .collapsible {
      cursor: pointer;
    }
    
    .collapsible::after {
      content: '\\f078';
      font-family: 'Font Awesome 6 Free';
      font-weight: 900;
      margin-left: auto;
      transition: var(--transition);
    }
    
    .collapsible.active::after {
      transform: rotate(180deg);
    }
    
    .issue-content {
      max-height: 0;
      overflow: hidden;
      transition: max-height 0.3s ease;
    }
    
    .issue-content.active {
      max-height: 1000px;
    }
    
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
      gap: 16px;
      margin-bottom: 16px;
    }
    
    .stat-item {
      background-color: white;
      border-radius: var(--border-radius);
      padding: 16px;
      text-align: center;
      box-shadow: var(--box-shadow);
    }
    
    .stat-value {
      font-size: 2rem;
      font-weight: 700;
      color: var(--primary-color);
      margin-bottom: 8px;
    }
    
    .stat-label {
      font-size: 0.875rem;
      color: var(--gray-600);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    
    @media (max-width: 768px) {
      .summary-container {
        grid-template-columns: 1fr;
      }
      
      h1 {
        font-size: 2rem;
      }
      
      h2 {
        font-size: 1.5rem;
      }
    }
  </style>
</head>
<body>
  <header>
    <div class="container">
      <h1>Security Scan Report</h1>
      <p>Server: ${serverName} (${serverType})</p>
    </div>
  </header>
  
  <div class="container">
    <div class="summary-container">
      <div class="summary-box">
        <h3><i class="fas fa-chart-pie"></i> Scan Summary</h3>
        
        <div class="stats-grid">
          <div class="stat-item">
            <div class="stat-value">${entities.length}</div>
            <div class="stat-label">Total Entities</div>
          </div>
          <div class="stat-item">
            <div class="stat-value">${verified}</div>
            <div class="stat-label">Verified</div>
          </div>
          <div class="stat-item">
            <div class="stat-value">${withIssues}</div>
            <div class="stat-label">With Issues</div>
          </div>
        </div>
        
        <ul>
          <li><i class="fas fa-comment"></i> Prompts: ${prompts}</li>
          <li><i class="fas fa-database"></i> Resources: ${resources}</li>
          <li><i class="fas fa-tools"></i> Tools: ${tools}</li>
        </ul>
      </div>
      
      <div class="summary-box">
        <h3><i class="fas fa-list-check"></i> Entities</h3>
        <ul class="entity-list">
          ${entities.map(entity => {
            const result = results[entities.indexOf(entity)];
            const status = result.verified ?
              '<span class="status-badge status-verified"><i class="fas fa-check"></i> Verified</span>' :
              '<span class="status-badge status-issues"><i class="fas fa-exclamation-triangle"></i> Issues</span>';
            return `<li>${entity.name} ${status}</li>`;
          }).join('')}
        </ul>
      </div>
    </div>
    
    <h2>Security Issues</h2>
  
  ${entityResults.map(result => {
    // Determine entity type
    let type = 'unknown';
    if ('inputSchema' in result.entity) type = 'tool';
    if ('uri' in result.entity) type = 'resource';
    if (!('inputSchema' in result.entity) && !('uri' in result.entity)) type = 'prompt';
    
    // Group messages by issue type
    const groupedMessages = new Map();
    
    for (const message of result.messages || []) {
      let issueType = '';
      let issueCategory = '';
      let icon = '';
      let cssClass = '';
      let detailedExplanation = '';
      
      // Determine the issue type and category
      if (message.includes('Prompt Injection detected:')) {
        issueType = 'PROMPT INJECTION';
        icon = '🔒';
        cssClass = 'prompt-injection';
        
        const parts = message.split(': ');
        if (parts.length > 1) {
          const categoryParts = parts[1].split(' - ');
          issueCategory = categoryParts[0];
        }
        
        // Add detailed explanation based on the category
        if (issueCategory.includes('Hidden instructions')) {
          detailedExplanation = 'Hidden instructions in XML-like tags can manipulate the AI to perform unauthorized actions.';
        } else if (issueCategory.includes('Hidden secret')) {
          detailedExplanation = 'Secret instructions attempt to access sensitive files or perform privileged operations.';
        } else if (issueCategory.includes('Hidden system')) {
          detailedExplanation = 'System-level instructions attempt to modify AI behavior or bypass security controls.';
        } else if (issueCategory.includes('Instruction override')) {
          detailedExplanation = 'Attempts to override or ignore previous instructions to bypass security controls.';
        } else if (issueCategory.includes('Jailbreak')) {
          detailedExplanation = 'Uses known jailbreak techniques to bypass AI safety mechanisms.';
        }
      } else if (message.includes('Tool Poisoning detected:')) {
        issueType = 'TOOL POISONING';
        icon = '⚠️';
        cssClass = 'tool-poisoning';
        
        const parts = message.split(': ');
        if (parts.length > 1) {
          const categoryParts = parts[1].split(' - ');
          issueCategory = categoryParts[0];
        }
        
        // Add detailed explanation based on the category
        if (issueCategory.includes('Tool shadowing')) {
          detailedExplanation = 'Tool shadowing attempts to modify the behavior of other tools, potentially leading to unauthorized actions.';
        } else if (issueCategory.includes('Command execution')) {
          detailedExplanation = 'Attempts to execute arbitrary system commands that could compromise security.';
        } else if (issueCategory.includes('Code execution')) {
          detailedExplanation = 'Attempts to execute arbitrary code that could lead to system compromise.';
        } else if (issueCategory.includes('network request')) {
          detailedExplanation = 'Attempts to make unauthorized network requests to external servers.';
        } else if (issueCategory.includes('DOM manipulation')) {
          detailedExplanation = 'Attempts to manipulate the DOM which could lead to XSS attacks.';
        } else if (issueCategory.includes('File system')) {
          detailedExplanation = 'Attempts to access the file system which could lead to data theft or corruption.';
        } else if (issueCategory.includes('Environment')) {
          detailedExplanation = 'Attempts to access environment variables which could expose sensitive information.';
        }
      } else if (message.includes('Cross-Origin Escalation detected:')) {
        issueType = 'CROSS-ORIGIN ESCALATION';
        icon = '🌐';
        cssClass = 'cross-origin';
        
        const parts = message.split(': ');
        if (parts.length > 1) {
          const categoryParts = parts[1].split(' - ');
          issueCategory = categoryParts[0];
        }
        
        // Add detailed explanation based on the category
        if (issueCategory.includes('Reference to external')) {
          detailedExplanation = 'References to external services could lead to unauthorized data sharing.';
        } else if (issueCategory.includes('Unauthorized access')) {
          detailedExplanation = 'Attempts to access unauthorized services or resources.';
        } else if (issueCategory.includes('Data routing')) {
          detailedExplanation = 'Attempts to route data through external services which could lead to data exfiltration.';
        } else if (issueCategory.includes('cross-boundary')) {
          detailedExplanation = 'Explicit cross-boundary references could lead to privilege escalation.';
        } else if (issueCategory.includes('Tool chaining')) {
          detailedExplanation = 'Tool chaining attempts could bypass security controls by combining tools.';
        } else if (issueCategory.includes('weather service')) {
          detailedExplanation = 'References to weather services could lead to unauthorized data access or API key exposure.';
        } else if (issueCategory.includes('calendar service')) {
          detailedExplanation = 'References to calendar services could lead to unauthorized access to user schedule data.';
        } else if (issueCategory.includes('email service')) {
          detailedExplanation = 'References to email services could lead to unauthorized message sending or data exfiltration.';
        } else if (issueCategory.includes('search service')) {
          detailedExplanation = 'References to search services could lead to unauthorized data collection or tracking.';
        }
      } else if (message.includes('Data Exfiltration detected:')) {
        issueType = 'DATA EXFILTRATION';
        icon = '💼';
        cssClass = 'data-exfiltration';
        
        const parts = message.split(': ');
        if (parts.length > 1) {
          const categoryParts = parts[1].split(' - ');
          issueCategory = categoryParts[0];
        }
        
        // Add detailed explanation based on the category
        if (issueCategory.includes('Suspicious parameter')) {
          detailedExplanation = 'Suspicious parameters could be used to exfiltrate sensitive data to external systems.';
        } else if (issueCategory.includes('passthrough')) {
          detailedExplanation = 'Passthrough parameters allow arbitrary data to be sent, which could lead to data exfiltration.';
        } else {
          detailedExplanation = 'Data exfiltration attempts could lead to sensitive information being sent to unauthorized recipients.';
        }
      } else {
        issueType = 'ISSUE';
        icon = 'ℹ️';
        cssClass = '';
        issueCategory = message;
      }
      
      // Extract the found content
      let foundContent = '';
      if (message.includes(' - Found "')) {
        const parts = message.split(' - Found "');
        if (parts.length > 1) {
          const contentParts = parts[1].split('" in context "');
          if (contentParts.length > 1) {
            foundContent = contentParts[0];
          }
        }
      }
      
      // Group by issue type
      if (!groupedMessages.has(issueType)) {
        groupedMessages.set(issueType, {
          icon,
          cssClass,
          category: issueCategory,
          explanation: detailedExplanation,
          foundItems: []
        });
      }
      
      // Add found content to the group
      if (foundContent) {
        groupedMessages.get(issueType).foundItems.push(foundContent);
      }
    }
    
    // Generate HTML for the entity
    return `
    <div class="entity-card">
      <div class="entity-header">
        <span>${result.entity.name}</span>
        <span class="entity-type">${type}</span>
      </div>
      <div class="entity-body">
        ${Array.from(groupedMessages.entries()).map(([issueType, data]) => `
          <div class="issue-group">
            <div class="issue-type ${data.cssClass} collapsible">
              <span class="issue-icon">${data.icon}</span>
              <span>${issueType}: ${data.category}</span>
            </div>
            <div class="issue-details issue-content">
              ${data.foundItems.length > 0 ? `
                <div class="found-items">
                  <h4><i class="fas fa-search"></i> Found:</h4>
                  <ul>
                    ${data.foundItems.map((item: string) => `<li>${item}</li>`).join('')}
                  </ul>
                </div>
              ` : ''}
              ${data.explanation ? `<p class="impact"><i class="fas fa-exclamation-circle"></i> Impact: ${data.explanation}</p>` : ''}
            </div>
          </div>
        `).join('')}
      </div>
    </div>
    `;
  }).join('')}
  
  <div class="timestamp">
    <p><i class="fas fa-calendar-alt"></i> Report generated on ${new Date().toLocaleString()}</p>
    <p><i class="fas fa-shield-alt"></i> Secure-Hulk Security Scanner</p>
  </div>
  
  <script>
    // Add collapsible functionality
    document.addEventListener('DOMContentLoaded', function() {
      const collapsibles = document.querySelectorAll('.collapsible');
      
      // Initialize all issue details as hidden
      document.querySelectorAll('.issue-content').forEach(content => {
        content.style.maxHeight = '0';
      });
      
      collapsibles.forEach(item => {
        item.addEventListener('click', function() {
          this.classList.toggle('active');
          const content = this.nextElementSibling;
          
          if (content.classList.contains('active')) {
            content.classList.remove('active');
            content.style.maxHeight = '0';
          } else {
            content.classList.add('active');
            content.style.maxHeight = content.scrollHeight + 'px';
          }
        });
      });
      
      // Add icons to replace emoji for better visual consistency
      document.querySelectorAll('.issue-icon').forEach(icon => {
        const text = icon.textContent;
        if (text === '🔒') {
          icon.innerHTML = '<i class="fas fa-shield-alt"></i>';
        } else if (text === '⚠️') {
          icon.innerHTML = '<i class="fas fa-exclamation-triangle"></i>';
        } else if (text === '🌐') {
          icon.innerHTML = '<i class="fas fa-globe"></i>';
        } else if (text === '💼') {
          icon.innerHTML = '<i class="fas fa-briefcase"></i>';
        } else if (text === 'ℹ️') {
          icon.innerHTML = '<i class="fas fa-info-circle"></i>';
        }
      });
    });
  </script>
</body>
</html>
  `;

  // Write the HTML report to the output path
  fs.writeFileSync(outputPath, html);
  console.log(`HTML report generated at: ${outputPath}`);
}