/**
 * NVIDIA NeMo Guardrails client
 * 
 * This module provides a client for NVIDIA's NeMo Guardrails, which can be used
 * to add programmable guardrails to LLM-based conversational applications.
 * 
 * @see https://github.com/NVIDIA/NeMo-Guardrails
 */

import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

/**
 * Configuration options for the NeMo Guardrails client
 */
export interface GuardrailsClientOptions {
  /**
   * Path to the guardrails configuration directory
   * This should contain the config.yml and other guardrails configuration files
   */
  configPath: string;

  /**
   * Timeout in milliseconds
   * @default 5000
   */
  timeout?: number;

  /**
   * Python executable path
   * @default 'python' (system default)
   */
  pythonPath?: string;
}

/**
 * Result of a guardrails check
 */
export interface GuardrailsResult {
  /**
   * Whether the content violates any guardrails
   */
  flagged: boolean;

  /**
   * Guardrails that were triggered
   */
  triggeredGuardrails: string[];

  /**
   * Detailed information about the triggered guardrails
   */
  details?: Record<string, any>;

  /**
   * Modified content (if the guardrails modified the content)
   */
  modifiedContent?: string;
}

/**
 * Client for NVIDIA's NeMo Guardrails
 */
export class GuardrailsClient {
  private readonly configPath: string;
  private readonly timeout: number;
  private readonly pythonPath: string;
  private initialized: boolean = false;

  /**
   * Create a new NeMo Guardrails client
   * @param options Client configuration options
   */
  constructor(options: GuardrailsClientOptions) {
    this.configPath = options.configPath;
    this.timeout = options.timeout || 15000; // Increased default timeout from 5s to 15s
    this.pythonPath = options.pythonPath || 'python';
  }

  /**
   * Initialize the NeMo Guardrails client
   * This checks if NeMo Guardrails is installed and the configuration is valid
   */
  async initialize(): Promise<void> {
    if (this.initialized) {
      return;
    }

    try {
      // Check if the configuration directory exists
      if (!fs.existsSync(this.configPath)) {
        throw new Error(`Guardrails configuration directory not found: ${this.configPath}`);
      }

      // Check if the config.yml file exists
      const configFile = path.join(this.configPath, 'config.yml');
      if (!fs.existsSync(configFile)) {
        throw new Error(`Guardrails configuration file not found: ${configFile}`);
      }

      // Check if NeMo Guardrails is installed and get version info
      const versionInfo = await this.runPythonCommand([
        '-c',
        `
import sys
import traceback

try:
    import importlib.metadata
    import nemoguardrails
    
    # Get version information
    try:
        version = importlib.metadata.version('nemoguardrails')
    except:
        version = getattr(nemoguardrails, '__version__', 'unknown')
    
    # Get available modules and classes
    modules = dir(nemoguardrails)
    
    print(f"NeMo Guardrails version: {version}")
    print(f"Available modules and classes: {', '.join(modules)}")
    
    # Check if key classes are available
    if 'LLMRails' in modules:
        print("LLMRails class is available")
    elif 'Rails' in modules:
        print("Rails class is available")
    else:
        print("WARNING: Neither LLMRails nor Rails class found in the main module")
        
    # Check Python version
    print(f"Python version: {sys.version}")
except ImportError as e:
    print(f"Error: NeMo Guardrails not installed properly: {e}")
    print(f"Traceback: {traceback.format_exc()}")
    exit(1)
except Exception as e:
    print(f"Error checking NeMo Guardrails: {e}")
    print(f"Traceback: {traceback.format_exc()}")
    exit(1)
        `
      ]);
      
      console.log(`NeMo Guardrails check: ${versionInfo}`);
      this.initialized = true;
    } catch (error) {
      throw new Error(`Failed to initialize NeMo Guardrails client: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Check if text complies with the configured guardrails
   * @param text Text to check
   * @returns Guardrails result
   */
  async checkText(text: string): Promise<GuardrailsResult> {
    await this.initialize();

    try {
      // Create a temporary file to store the text
      const tempFile = path.join(os.tmpdir(), `guardrails-check-${Date.now()}.json`);
      fs.writeFileSync(tempFile, JSON.stringify({ text }));

      // Run the guardrails check
      const result = await this.runPythonCommand([
        '-c',
        `
import json
import sys
import re
import traceback
import importlib.metadata

try:
    # Get NeMo Guardrails version information
    try:
        nemo_version = importlib.metadata.version('nemoguardrails')
        print(f"DEBUG: NeMo Guardrails version: {nemo_version}", file=sys.stderr)
    except Exception as ve:
        print(f"DEBUG: Could not determine NeMo Guardrails version: {ve}", file=sys.stderr)
    
    # Load the configuration
    config_path = "${this.configPath.replace(/\\/g, '\\\\')}"
    print(f"DEBUG: Loading configuration from: {config_path}", file=sys.stderr)
    
    # Try different initialization methods based on NeMo Guardrails version
    try:
        # Import the module first to check what's available
        import nemoguardrails
        print(f"DEBUG: Available attributes in nemoguardrails: {dir(nemoguardrails)}", file=sys.stderr)
        
        # Try the most common initialization patterns
        if hasattr(nemoguardrails, 'LLMRails') and hasattr(nemoguardrails, 'RailsConfig'):
            from nemoguardrails import LLMRails, RailsConfig
            print("DEBUG: Using nemoguardrails.LLMRails with RailsConfig", file=sys.stderr)
            
            # Try the recommended initialization method for 0.9.x
            try:
                # Check if the config path exists and is a directory
                import os
                if not os.path.exists(config_path):
                    raise Exception(f"Config path does not exist: {config_path}")
                if not os.path.isdir(config_path):
                    raise Exception(f"Config path is not a directory: {config_path}")
                
                # Check if config.yml exists
                config_yml_path = os.path.join(config_path, "config.yml")
                if not os.path.exists(config_yml_path):
                    raise Exception(f"config.yml not found in config path: {config_yml_path}")
                
                print(f"DEBUG: Config path exists and contains config.yml: {config_yml_path}", file=sys.stderr)
                
                # Try to load the config
                try:
                    config = RailsConfig.from_path(config_path)
                    print("DEBUG: Successfully loaded config with RailsConfig.from_path", file=sys.stderr)
                    print(f"DEBUG: Config type: {type(config)}", file=sys.stderr)
                    print(f"DEBUG: Config attributes: {dir(config)}", file=sys.stderr)
                    
                    # Initialize LLMRails with the config
                    rails = LLMRails(config)
                    print("DEBUG: Successfully initialized with LLMRails(config)", file=sys.stderr)
                except Exception as e_config:
                    print(f"DEBUG: Error loading config: {e_config}", file=sys.stderr)
                    print(f"DEBUG: Traceback: {traceback.format_exc()}", file=sys.stderr)
                    raise e_config
            except Exception as e1:
                print(f"DEBUG: Error with RailsConfig/LLMRails initialization: {e1}", file=sys.stderr)
                print(f"DEBUG: Traceback: {traceback.format_exc()}", file=sys.stderr)
                
                # Fall back to older methods
                try:
                    rails = LLMRails(config_path)
                    print("DEBUG: Successfully initialized with LLMRails(config_path)", file=sys.stderr)
                except Exception as e2:
                    print(f"DEBUG: Error with LLMRails(config_path): {e2}", file=sys.stderr)
                    try:
                        rails = LLMRails.from_path(config_path)
                        print("DEBUG: Successfully initialized with LLMRails.from_path(config_path)", file=sys.stderr)
                    except Exception as e3:
                        print(f"DEBUG: Error with LLMRails.from_path(config_path): {e3}", file=sys.stderr)
                        raise Exception(f"Could not initialize LLMRails: {e1}, {e2}, {e3}")
        elif hasattr(nemoguardrails, 'LLMRails'):
            from nemoguardrails import LLMRails
            print("DEBUG: Using nemoguardrails.LLMRails", file=sys.stderr)
            
            # Try different initialization methods
            try:
                rails = LLMRails(config_path)
                print("DEBUG: Successfully initialized with LLMRails(config_path)", file=sys.stderr)
            except Exception as e1:
                print(f"DEBUG: Error with LLMRails(config_path): {e1}", file=sys.stderr)
                try:
                    rails = LLMRails.from_path(config_path)
                    print("DEBUG: Successfully initialized with LLMRails.from_path(config_path)", file=sys.stderr)
                except Exception as e2:
                    print(f"DEBUG: Error with LLMRails.from_path(config_path): {e2}", file=sys.stderr)
                    raise Exception(f"Could not initialize LLMRails: {e1}, {e2}")
        elif hasattr(nemoguardrails, 'Rails'):
            from nemoguardrails import Rails
            print("DEBUG: Using nemoguardrails.Rails", file=sys.stderr)
            rails = Rails(config_path)
            print("DEBUG: Successfully initialized with Rails(config_path)", file=sys.stderr)
        else:
            # Try another common pattern
            try:
                from nemoguardrails.rails.llm.rails import Rails
                print("DEBUG: Using nemoguardrails.rails.llm.rails.Rails", file=sys.stderr)
                rails = Rails(config_path)
                print("DEBUG: Successfully initialized with Rails(config_path)", file=sys.stderr)
            except ImportError:
                try:
                    from nemoguardrails.rails import LLMRails
                    print("DEBUG: Using nemoguardrails.rails.LLMRails", file=sys.stderr)
                    rails = LLMRails(config_path)
                    print("DEBUG: Successfully initialized with LLMRails(config_path)", file=sys.stderr)
                except ImportError as ie:
                    raise Exception(f"Could not import NeMo Guardrails classes: {ie}")
    except Exception as e:
        print(f"DEBUG: Error initializing NeMo Guardrails: {e}", file=sys.stderr)
        print(f"DEBUG: Traceback: {traceback.format_exc()}", file=sys.stderr)
        raise e

    # Load the input
    with open("${tempFile.replace(/\\/g, '\\\\')}") as f:
        data = json.load(f)

    input_text = data["text"]
    print(f"DEBUG: Input text length: {len(input_text)}", file=sys.stderr)
    
    # Check the text
    print("DEBUG: Checking text with NeMo Guardrails", file=sys.stderr)
    print(f"DEBUG: Input text length: {len(input_text)} characters", file=sys.stderr)
    print(f"DEBUG: Rails object type: {type(rails)}", file=sys.stderr)
    print(f"DEBUG: Available methods on rails: {dir(rails)}", file=sys.stderr)
    
    # Add timing information
    import time
    start_time = time.time()
    
    # Create a simple wrapper for the result
    class GuardrailsResult:
        def __init__(self, flagged=False, triggered_guardrails=None, details=None, modified_content=None):
            self.flagged = flagged
            self.triggered_guardrails = triggered_guardrails or []
            self.details = details or {}
            self.modified_content = modified_content
    
    # Try different method names based on NeMo Guardrails version
    # In 0.9.1.1, the method might be named differently
    try:
        # For NeMo Guardrails 0.9.1.1, we need to use the generate method
        # since it doesn't have check_text or other moderation methods
        if hasattr(rails, 'generate'):
            print("DEBUG: Using generate method for moderation", file=sys.stderr)
            
            # Format the messages properly for the generate method
            # NeMo Guardrails 0.9.1.1 expects a list of message dictionaries
            messages = [
                {"role": "system", "content": "You are a content moderation assistant. Check if the following text violates any content policies and respond with 'FLAGGED' or 'SAFE'."},
                {"role": "user", "content": input_text}
            ]
            
            print(f"DEBUG: Sending messages to generate: {messages}", file=sys.stderr)
            
            try:
                # Try with messages as a parameter
                response = rails.generate(messages=messages)
                print(f"DEBUG: Generate response with messages param: {response}", file=sys.stderr)
            except Exception as e1:
                print(f"DEBUG: Error with messages param: {e1}", file=sys.stderr)
                try:
                    # Try with direct parameter
                    response = rails.generate(messages)
                    print(f"DEBUG: Generate response with direct param: {response}", file=sys.stderr)
                except Exception as e2:
                    print(f"DEBUG: Error with direct param: {e2}", file=sys.stderr)
                    # Try with a single string - using triple quotes to avoid syntax errors
                    prompt = f'''System: You are a content moderation assistant. Check if the following text violates any content policies and respond with FLAGGED or SAFE.
User: {input_text}'''
                    response = rails.generate(prompt)
                    print(f"DEBUG: Generate response with string param: {response}", file=sys.stderr)
            
            # Extract the response content
            response_content = ""
            if isinstance(response, dict) and 'content' in response:
                response_content = response['content']
            elif isinstance(response, str):
                response_content = response
            
            print(f"DEBUG: Response content: {response_content}", file=sys.stderr)
            
            # Create a synthetic result
            is_flagged = 'FLAGGED' in response_content.upper()
            result = GuardrailsResult(
                flagged=is_flagged,
                triggered_guardrails=['content_moderation'] if is_flagged else [],
                details={'response': response_content},
                modified_content=None
            )
        else:
            # If no suitable method is found, create a dummy result
            available_methods = dir(rails)
            print(f"DEBUG: No suitable moderation method found. Available methods: {available_methods}", file=sys.stderr)
            result = GuardrailsResult(
                flagged=True,
                triggered_guardrails=['error'],
                details={'error': f"No suitable moderation method found in NeMo Guardrails 0.9.1.1. Available methods: {available_methods}"},
                modified_content=None
            )
    except Exception as e:
        print(f"DEBUG: Error calling moderation method: {e}", file=sys.stderr)
        print(f"DEBUG: Traceback: {traceback.format_exc()}", file=sys.stderr)
        raise e
        
    end_time = time.time()
    print(f"DEBUG: Moderation completed in {end_time - start_time:.2f} seconds", file=sys.stderr)
    print(f"DEBUG: Moderation result: {result}", file=sys.stderr)
    
    # Enhanced details extraction
    details = {}
    if hasattr(result, 'details') and result.details:
        details = result.details
        print(f"DEBUG: Result details: {details}", file=sys.stderr)
    
    # Format the result
    output = {
        "flagged": result.flagged if hasattr(result, 'flagged') else True,
        "triggeredGuardrails": result.triggered_guardrails if hasattr(result, 'triggered_guardrails') else ["unknown"],
        "details": details,
        "modifiedContent": result.modified_content if hasattr(result, 'modified_content') and result.modified_content else None
    }
    
    print(f"DEBUG: Final output: {output}", file=sys.stderr)

    # Output the result
    print(json.dumps(output))
except Exception as e:
    error_msg = str(e)
    traceback_str = traceback.format_exc()
    print(f"DEBUG: Exception in NeMo Guardrails check: {error_msg}", file=sys.stderr)
    print(f"DEBUG: Traceback: {traceback_str}", file=sys.stderr)
    
    print(json.dumps({
        "error": error_msg,
        "flagged": True,
        "triggeredGuardrails": ["error"],
        "details": {
            "exception": error_msg,
            "traceback": traceback_str,
            "error": error_msg
        },
        "modifiedContent": None
    }))
        `
      ]);

      // Clean up the temporary file
      fs.unlinkSync(tempFile);

      // Parse the result
      return JSON.parse(result) as GuardrailsResult;
    } catch (error) {
      throw new Error(`NeMo Guardrails check failed: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  /**
   * Run a Python command
   * @param args Command arguments
   * @returns Command output
   * @private
   */
  private runPythonCommand(args: string[]): Promise<string> {
    return new Promise((resolve, reject) => {
      const process = spawn(this.pythonPath, args);
      
      let stdout = '';
      let stderr = '';
      
      process.stdout.on('data', (data) => {
        stdout += data.toString();
      });
      
      process.stderr.on('data', (data) => {
        stderr += data.toString();
      });
      
      const timeout = setTimeout(() => {
        process.kill();
        reject(new Error(`Command timed out after ${this.timeout}ms`));
      }, this.timeout);
      
      process.on('close', (code) => {
        clearTimeout(timeout);
        
        if (code === 0) {
          resolve(stdout.trim());
        } else {
          reject(new Error(`Command failed with code ${code}: ${stderr}`));
        }
      });
      
      process.on('error', (error) => {
        clearTimeout(timeout);
        reject(error);
      });
    });
  }
}