/**
 * Tests for Hugging Face Guardrails integration
 */

import { checkWithHuggingFaceGuardrails } from '../src/security/checks/huggingFaceGuardrails';
import { HuggingFaceSafetyClient, SafetyModel } from '../src/security/huggingface/safetyClient';
import { Entity, ScanResult, ScanOptions } from '../src/models';

describe('Hugging Face Guardrails', () => {
  let mockEntity: Entity;
  let scanResult: ScanResult;
  let scanOptions: ScanOptions;

  beforeEach(() => {
    mockEntity = {
      name: 'test-entity',
      description: 'A test entity for safety checking'
    };

    scanResult = {
      verified: true,
      issues: []
    };

    scanOptions = {
      useHuggingFaceGuardrails: true,
      huggingFaceApiToken: process.env.HUGGINGFACE_API_TOKEN,
      huggingFaceModel: SafetyModel.TOXIC_BERT,
      huggingFaceThreshold: 0.5
    };
  });

  describe('checkWithHuggingFaceGuardrails', () => {
    it('should skip check when disabled', async () => {
      scanOptions.useHuggingFaceGuardrails = false;
      
      await checkWithHuggingFaceGuardrails(mockEntity, scanResult, scanOptions);
      
      expect(scanResult.verified).toBe(true);
      expect(scanResult.issues).toHaveLength(0);
    });

    it('should handle empty content gracefully', async () => {
      mockEntity.name = '';
      mockEntity.description = '';
      
      await checkWithHuggingFaceGuardrails(mockEntity, scanResult, scanOptions);
      
      expect(scanResult.verified).toBe(true);
      expect(scanResult.issues).toHaveLength(0);
    });

    it('should flag toxic content', async () => {
      mockEntity.description = 'This is a test of toxic content detection';
      
      // Mock the HuggingFaceSafetyClient
      const mockCheckText = jest.fn().mockResolvedValue({
        flagged: true,
        score: 0.8,
        classifications: [
          { label: 'TOXIC', score: 0.8 },
          { label: 'SAFE', score: 0.2 }
        ],
        flaggedCategories: ['TOXIC'],
        model: SafetyModel.TOXIC_BERT,
        processingTime: 150
      });

      jest.spyOn(HuggingFaceSafetyClient.prototype, 'checkText').mockImplementation(mockCheckText);
      
      await checkWithHuggingFaceGuardrails(mockEntity, scanResult, scanOptions);
      
      expect(scanResult.verified).toBe(false);
      expect(scanResult.issues).toHaveLength(1);
      expect(scanResult.issues[0].type).toBe('huggingface_safety_violation');
      expect(scanResult.issues[0].severity).toBe('high');
      expect(scanResult.issues[0].details.score).toBe(0.8);
      expect(scanResult.issues[0].details.flaggedCategories).toContain('TOXIC');
    });

    it('should not flag safe content', async () => {
      mockEntity.description = 'This is completely safe and helpful content';
      
      // Mock the HuggingFaceSafetyClient
      const mockCheckText = jest.fn().mockResolvedValue({
        flagged: false,
        score: 0.1,
        classifications: [
          { label: 'SAFE', score: 0.9 },
          { label: 'TOXIC', score: 0.1 }
        ],
        flaggedCategories: [],
        model: SafetyModel.TOXIC_BERT,
        processingTime: 120
      });

      jest.spyOn(HuggingFaceSafetyClient.prototype, 'checkText').mockImplementation(mockCheckText);
      
      await checkWithHuggingFaceGuardrails(mockEntity, scanResult, scanOptions);
      
      expect(scanResult.verified).toBe(true);
      expect(scanResult.issues).toHaveLength(0);
    });

    it('should handle API errors gracefully', async () => {
      mockEntity.description = 'Test content';
      
      // Mock the HuggingFaceSafetyClient to throw an error
      const mockCheckText = jest.fn().mockRejectedValue(new Error('API rate limit exceeded'));
      jest.spyOn(HuggingFaceSafetyClient.prototype, 'checkText').mockImplementation(mockCheckText);
      
      await checkWithHuggingFaceGuardrails(mockEntity, scanResult, scanOptions);
      
      expect(scanResult.verified).toBe(true); // Should not fail the entire scan
      expect(scanResult.issues).toHaveLength(1);
      expect(scanResult.issues[0].type).toBe('huggingface_check_error');
      expect(scanResult.issues[0].severity).toBe('low');
      expect(scanResult.issues[0].details.error).toContain('API rate limit exceeded');
    });

    it('should use different presets correctly', async () => {
      scanOptions.huggingFacePreset = 'toxicity';
      mockEntity.description = 'Test content for toxicity detection';
      
      const mockCheckText = jest.fn().mockResolvedValue({
        flagged: false,
        score: 0.3,
        classifications: [{ label: 'SAFE', score: 0.7 }],
        flaggedCategories: [],
        model: SafetyModel.ROBERTA_TOXICITY,
        processingTime: 100
      });

      jest.spyOn(HuggingFaceSafetyClient.prototype, 'checkText').mockImplementation(mockCheckText);
      
      await checkWithHuggingFaceGuardrails(mockEntity, scanResult, scanOptions);
      
      expect(mockCheckText).toHaveBeenCalledWith('test-entity Test content for toxicity detection');
      expect(scanResult.verified).toBe(true);
    });
  });

  describe('HuggingFaceSafetyClient', () => {
    let client: HuggingFaceSafetyClient;

    beforeEach(() => {
      client = new HuggingFaceSafetyClient({
        model: SafetyModel.TOXIC_BERT,
        threshold: 0.5,
        timeout: 5000
      });
    });

    it('should create client with default options', () => {
      const defaultClient = new HuggingFaceSafetyClient();
      expect(defaultClient).toBeInstanceOf(HuggingFaceSafetyClient);
    });

    it('should get available models', () => {
      const models = HuggingFaceSafetyClient.getAvailableModels();
      expect(models).toContain(SafetyModel.TOXIC_BERT);
      expect(models).toContain(SafetyModel.ROBERTA_TOXICITY);
      expect(models).toContain(SafetyModel.DETOXIFY_ORIGINAL);
    });

    it('should get model recommendations', () => {
      const toxicityModels = HuggingFaceSafetyClient.getModelRecommendations('toxicity');
      expect(toxicityModels).toContain(SafetyModel.ROBERTA_TOXICITY);
      
      const generalModels = HuggingFaceSafetyClient.getModelRecommendations('general');
      expect(generalModels).toContain(SafetyModel.TOXIC_BERT);
      expect(generalModels).toContain(SafetyModel.DETOXIFY_ORIGINAL);
    });

    // Integration test (requires actual API token)
    it.skip('should perform real API call', async () => {
      if (!process.env.HUGGINGFACE_API_TOKEN) {
        console.log('Skipping real API test - no token provided');
        return;
      }

      const realClient = new HuggingFaceSafetyClient({
        apiToken: process.env.HUGGINGFACE_API_TOKEN,
        model: SafetyModel.TOXIC_BERT,
        threshold: 0.5
      });

      const result = await realClient.checkText('This is a test message');
      
      expect(result).toHaveProperty('flagged');
      expect(result).toHaveProperty('score');
      expect(result).toHaveProperty('classifications');
      expect(result).toHaveProperty('model');
      expect(result.processingTime).toBeGreaterThan(0);
    });
  });
});