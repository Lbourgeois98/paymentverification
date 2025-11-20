import "https://deno.land/x/xhr@0.1.0/mod.ts";
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

interface AnalysisResult {
  authentic: boolean;
  confidence: number;
  findings: Array<{
    type: 'info' | 'warning' | 'critical';
    message: string;
  }>;
  metadata: {
    software?: string;
    editingDetected: boolean;
    compressionAnomalies: boolean;
    metadataInconsistencies: boolean;
  };
}

type AIFindingKey =
  | 'clonedRegions'
  | 'lightingInconsistencies'
  | 'pixelManipulation'
  | 'fontInconsistencies'
  | 'colorAnomalies'
  | 'artificialElements';

interface AggregatedAIFinding {
  description: string;
  models: string[];
}

type AIVisualAnalysis = Partial<Record<AIFindingKey, AggregatedAIFinding>>;

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { image, filename } = await req.json();
    
    if (!image) {
      throw new Error('No image provided');
    }

    console.log('Analyzing image:', filename);

    // Extract EXIF data and analyze the image
    const result = await analyzeImage(image);

    return new Response(
      JSON.stringify(result),
      { headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
    );
  } catch (error) {
    console.error('Analysis error:', error);
    return new Response(
      JSON.stringify({ error: error instanceof Error ? error.message : 'Unknown error' }),
      { 
        status: 500,
        headers: { ...corsHeaders, 'Content-Type': 'application/json' }
      }
    );
  }
});

async function analyzeImage(base64Image: string): Promise<AnalysisResult> {
  const findings: Array<{ type: 'info' | 'warning' | 'critical'; message: string }> = [];
  let confidence = 100;
  let editingSoftware: string | undefined;
  let editingDetected = false;
  let compressionAnomalies = false;
  let metadataInconsistencies = false;
  let jpegQualityInconsistent = false;

  try {
    // Convert base64 to binary for analysis
    const base64Data = base64Image.split(',')[1];
    const binaryData = Uint8Array.from(atob(base64Data), c => c.charCodeAt(0));

    // Identify the format early so heuristics can be tailored per type
    const format = detectImageFormat(binaryData);

    type EvidenceSeverity = 'warning' | 'critical';
    const evidenceByCategory = new Map<string, { warning: Set<string>; critical: Set<string> }>();

    // Track cumulative risk as signals are added so the final decision can
    // combine cross-category corroboration with weighted severity rather than
    // relying on a single heuristic.
    let riskScore = 0;

    const severityWeights: Record<string, { warning: number; critical: number }> = {
      metadata: { warning: 6, critical: 14 },
      compression: { warning: 10, critical: 18 },
      format: { warning: 8, critical: 16 },
      ai: { warning: 12, critical: 25 },
      default: { warning: 6, critical: 14 }
    };

    const addEvidence = (category: string, signal: string, severity: EvidenceSeverity) => {
      const entry = evidenceByCategory.get(category) || { warning: new Set<string>(), critical: new Set<string>() };
      entry[severity].add(signal);
      evidenceByCategory.set(category, entry);

      const categoryWeights = severityWeights[category] ?? severityWeights.default;
      riskScore += categoryWeights[severity];
    };

    const getCategoryCount = (severity?: EvidenceSeverity) => {
      let count = 0;
      for (const entry of evidenceByCategory.values()) {
        if (!severity && (entry.warning.size > 0 || entry.critical.size > 0)) {
          count++;
        } else if (severity === 'warning' && entry.warning.size > 0) {
          count++;
        } else if (severity === 'critical' && entry.critical.size > 0) {
          count++;
        }
      }
      return count;
    };

    const getEvidenceCount = (severity: EvidenceSeverity) => {
      let count = 0;
      for (const entry of evidenceByCategory.values()) {
        count += entry[severity].size;
      }
      return count;
    };

    // PHASE 1: Binary Forensic Analysis
    console.log('Starting binary forensic analysis...');

    // Check for EXIF data presence (only suspicious for JPEGs)
    const hasExif = checkExifPresence(binaryData);

    if (format === 'JPEG' && !hasExif) {
      findings.push({
        type: 'warning',
        message: 'No EXIF data found in JPEG. This can indicate metadata stripping from re-saving or editing.'
      });
      confidence -= 10;
      metadataInconsistencies = true;
    }

    // Analyze image header for editing software signatures
    const softwareSignatures = detectEditingSoftware(binaryData);
    const appSignatures = detectAppSignatures(binaryData);
    const strongMetadataEvidence = softwareSignatures.length + appSignatures.length > 1;

    if (softwareSignatures.length > 0) {
      editingSoftware = softwareSignatures.join(', ');
      const severity: 'warning' | 'critical' = strongMetadataEvidence ? 'critical' : 'warning';
      findings.push({
        type: severity,
        message: `Editing software detected in metadata: ${editingSoftware}.`
      });
      if (severity === 'critical') {
        editingDetected = true;
        confidence -= 30;
        addEvidence('metadata', 'editing-software', 'critical');
      } else {
        confidence -= 8;
        addEvidence('metadata', 'editing-software', 'warning');
      }
    }

    // Check for multiple save signatures (re-compression)
    const recompressionDetected = detectRecompression(binaryData);
    if (recompressionDetected) {
      compressionAnomalies = true;
      findings.push({
        type: 'warning',
        message: 'Multiple compression signatures detected. Image appears to have been saved multiple times, suggesting possible editing.'
      });
      confidence -= 15;
      addEvidence('compression', 'recompression', 'warning');
    }

    // Analyze PNG/JPEG specific markers
    if (format === 'PNG') {
      const pngAnalysis = analyzePNG(binaryData);
      if (pngAnalysis.suspicious) {
        findings.push({
          type: 'warning',
          message: 'PNG metadata suggests possible screenshot conversion or editing.'
        });
        confidence -= 10;
        addEvidence('format', 'png-metadata', 'warning');
      }
    } else if (format === 'JPEG') {
      const jpegAnalysis = analyzeJPEG(binaryData);
      if (jpegAnalysis.qualityInconsistent) {
        compressionAnomalies = true;
        jpegQualityInconsistent = true;
        findings.push({
          type: 'critical',
          message: 'JPEG quality levels are inconsistent across the image, indicating selective editing or manipulation.'
        });
        confidence -= 25;
        addEvidence('compression', 'quality', 'critical');
      }
    }

    if (format === 'JPEG' && recompressionDetected && jpegQualityInconsistent) {
      findings.push({
        type: 'critical',
        message: 'Multiple JPEG saves combined with shifting quality levels strongly suggest composite editing.'
      });
      confidence -= 18;
      addEvidence('compression', 'stacked-compression-signals', 'critical');
    }

    // Check for common editing app signatures in metadata
    if (appSignatures.length > 0) {
      const severity: 'warning' | 'critical' = strongMetadataEvidence ? 'critical' : 'warning';
      findings.push({
        type: severity,
        message: `Detected traces of editing apps in metadata: ${appSignatures.join(', ')}.`
      });
      if (severity === 'critical') {
        editingDetected = true;
        confidence -= 25;
        addEvidence('metadata', 'app-signature', 'critical');
      } else {
        confidence -= 6;
        addEvidence('metadata', 'app-signature', 'warning');
      }
    }

    // PHASE 2: AI-Powered Visual Analysis
    console.log('Starting AI-powered visual analysis...');
    const aiAnalysis = await performAIVisualAnalysis(base64Image);

    let highConfidenceAICritical = false;

    if (aiAnalysis) {
      const baseSeverity: Record<AIFindingKey, 'warning' | 'critical'> = {
        clonedRegions: 'critical',
        lightingInconsistencies: 'critical',
        pixelManipulation: 'critical',
        fontInconsistencies: 'warning',
        colorAnomalies: 'warning',
        artificialElements: 'warning'
      };

      const penaltyMap: Record<AIFindingKey, { warning: number; critical: number }> = {
        clonedRegions: { warning: 18, critical: 35 },
        lightingInconsistencies: { warning: 15, critical: 30 },
        pixelManipulation: { warning: 20, critical: 40 },
        fontInconsistencies: { warning: 12, critical: 18 },
        colorAnomalies: { warning: 10, critical: 16 },
        artificialElements: { warning: 6, critical: 12 }
      };

      for (const [key, detail] of Object.entries(aiAnalysis) as Array<[
        AIFindingKey,
        AggregatedAIFinding
      ]>) {
        const supportedModels = detail.models.length;
        const base = baseSeverity[key] ?? 'warning';
        const severity: 'warning' | 'critical' = supportedModels >= 2 ? base : 'warning';
        const penalties = penaltyMap[key];
        const penalty = severity === 'critical' ? penalties.critical : penalties.warning;
        const supportNote = detail.models.length > 0 ? ` (models: ${detail.models.join(', ')})` : '';

        const messages: Record<AIFindingKey, string> = {
          clonedRegions: `AI detected cloned/copied regions: ${detail.description}.${supportNote} This indicates copy-paste manipulation.`,
          lightingInconsistencies: `Lighting inconsistencies detected: ${detail.description}.${supportNote} Different parts of the image have inconsistent illumination.`,
          pixelManipulation: `Pixel-level manipulation detected: ${detail.description}.${supportNote} Text or numbers appear to have been altered.`,
          fontInconsistencies: `Font inconsistencies detected: ${detail.description}.${supportNote} Text rendering appears unnatural.`,
          colorAnomalies: `Color anomalies detected: ${detail.description}.${supportNote} Color distribution is inconsistent with authentic screenshots.`,
          artificialElements: `Possible artificial elements: ${detail.description}.${supportNote}`
        };

        findings.push({
          type: severity === 'critical' && base === 'critical' ? 'critical' : 'warning',
          message: messages[key]
        });

        confidence -= penalty;

        if (base === 'critical' && severity === 'critical') {
          editingDetected = true;
          addEvidence('ai', key, 'critical');

          // Treat critical findings with support from multiple models as high
          // confidence even if other categories are quiet, so clear visual
          // tampering is not missed.
          if (supportedModels >= 2) {
            highConfidenceAICritical = true;
          }
        } else {
          addEvidence('ai', key, 'warning');
        }
      }
    }

    // Evaluate evidence using categories and severities to require corroboration
    // across independent signals. Metadata-only warnings should not mark images
    // as modified without support from other categories.
    const totalCriticalEvidence = getEvidenceCount('critical');
    const totalWarningEvidence = getEvidenceCount('warning');
    const categoriesWithEvidence = getCategoryCount();
    const categoriesWithCritical = getCategoryCount('critical');
    const metadataCategoryPresent = evidenceByCategory.has('metadata');
    const nonMetadataCategoriesWithEvidence = metadataCategoryPresent
      ? Math.max(0, categoriesWithEvidence - 1)
      : categoriesWithEvidence;
    const aiCriticalPresent = (evidenceByCategory.get('ai')?.critical.size ?? 0) > 0;

    const multiCategorySupport = categoriesWithEvidence >= 2 && nonMetadataCategoriesWithEvidence >= 1;
    const multiCriticalCategories = categoriesWithCritical >= 2 && nonMetadataCategoriesWithEvidence >= 1;
    const aiRequiresSupport = aiCriticalPresent && (categoriesWithEvidence >= 2 || totalWarningEvidence >= 1);
    const criticalSupported =
      multiCriticalCategories ||
      (totalCriticalEvidence >= 2 && multiCategorySupport) ||
      (aiCriticalPresent && aiRequiresSupport) ||
      (totalCriticalEvidence >= 1 && totalWarningEvidence >= 2 && multiCategorySupport);

    const warningCluster =
      totalWarningEvidence >= 3 &&
      multiCategorySupport &&
      riskScore >= 35 &&
      nonMetadataCategoriesWithEvidence >= 1;

    const strongSingleCategoryCritical =
      categoriesWithCritical === 1 &&
      totalCriticalEvidence >= 2 &&
      riskScore >= 40;

    const riskAdjustedCritical = criticalSupported && riskScore >= 30;
    const editingLikely =
      riskAdjustedCritical ||
      strongSingleCategoryCritical ||
      (highConfidenceAICritical && riskScore >= 30) ||
      (warningCluster && riskScore >= 50);
    const authenticityThreshold = editingLikely ? 72 : 60;

    // Final confidence adjustment with guardrails to avoid false negatives when
    // only warning-level evidence exists. Cap the total penalty applied from
    // warnings so a clean screenshot with metadata quirks is not marked
    // inauthentic unless corroborating signals exist.
    confidence = Math.max(0, Math.min(100, confidence));
    const warningOnly = !aiCriticalPresent && totalCriticalEvidence === 0;
    if (!editingLikely && warningOnly) {
      const maxWarningPenalty = 35;
      const appliedPenalty = 100 - confidence;
      if (appliedPenalty > maxWarningPenalty) {
        confidence = 100 - maxWarningPenalty;
      }
    }

    // Re-evaluate authenticity after capping warning penalties to ensure
    // non-correlated warnings do not overpower the decision.
    const authentic = !editingLikely && confidence >= authenticityThreshold;

    // Align metadata flag with the final decision so warnings alone do not mark
    // the image as edited.
    editingDetected = editingLikely;

    if (authentic && findings.length === 0) {
      findings.push({
        type: 'info',
        message: 'No signs of manipulation detected through forensic or AI analysis. Image appears to be an original screenshot.'
      });
    }

    return {
      authentic,
      confidence,
      findings,
      metadata: {
        software: editingSoftware,
        editingDetected,
        compressionAnomalies,
        metadataInconsistencies
      }
    };
  } catch (error) {
    console.error('Image analysis error:', error);
    return {
      authentic: false,
      confidence: 0,
      findings: [{
        type: 'critical',
        message: 'Failed to analyze image properly. File may be corrupted or in an unsupported format.'
      }],
      metadata: {
        editingDetected: false,
        compressionAnomalies: false,
        metadataInconsistencies: true
      }
    };
  }
}

async function performAIVisualAnalysis(base64Image: string): Promise<AIVisualAnalysis | null> {
  try {
    const LOVABLE_API_KEY = Deno.env.get('LOVABLE_API_KEY');
    if (!LOVABLE_API_KEY) {
      console.error('LOVABLE_API_KEY not found');
      return null;
    }

    const prompt = `You are a forensic image analysis expert. Analyze this payment screenshot image for signs of manipulation or editing. Look for:

1. CLONED REGIONS: Areas that appear to be copied/pasted from other parts of the image
2. LIGHTING INCONSISTENCIES: Different areas with inconsistent shadows, highlights, or illumination that wouldn't occur naturally
3. PIXEL-LEVEL MANIPULATION: Text or numbers that show signs of editing (irregular edges, color fringing, misaligned pixels)
4. FONT INCONSISTENCIES: Text that uses different fonts, sizes, or rendering styles within what should be uniform UI elements
5. COLOR ANOMALIES: Unnatural color gradients, banding, or color shifts in supposedly uniform backgrounds
6. ARTIFICIAL ELEMENTS: Added overlays, digitally inserted content, or composite elements

Return your analysis in this EXACT JSON format (no markdown, no code blocks, just raw JSON):
{
  "clonedRegions": "description if found, or null",
  "lightingInconsistencies": "description if found, or null",
  "pixelManipulation": "description if found, or null",
  "fontInconsistencies": "description if found, or null",
  "colorAnomalies": "description if found, or null",
  "artificialElements": "description if found, or null"
}

If a category shows no issues, set it to null. Be specific about locations and what you observe. Only flag issues you're confident about.`;

    // Use multiple vision-capable models to reduce single-model bias.
    const configuredModels = Deno.env.get('AI_MODELS')?.split(',').map((m) => m.trim()).filter(Boolean);
    const models = configuredModels && configuredModels.length > 0
      ? configuredModels
      : ['openai/gpt-4o-mini', 'anthropic/claude-3.5-sonnet-20240620'];

    const modelAnalyses: Array<{ model: string; analysis: Record<string, string | null> }> = [];

    for (const model of models) {
      const response = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${LOVABLE_API_KEY}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          model,
          messages: [
            {
              role: 'user',
              content: [
                { type: 'text', text: prompt },
                { type: 'image_url', image_url: { url: base64Image } }
              ]
            }
          ],
          temperature: 0.3,
          max_tokens: 1000
        }),
      });

      if (!response.ok) {
        const errorText = await response.text();
        console.error(`AI API error for ${model}:`, response.status, errorText);
        continue;
      }

      const data = await response.json();
      const content = data.choices?.[0]?.message?.content;

      if (!content) {
        console.error(`No content in AI response for ${model}`);
        continue;
      }

      const jsonMatch = content.match(/\{[\s\S]*\}/);
      if (jsonMatch) {
        try {
          const analysis = JSON.parse(jsonMatch[0]);
          modelAnalyses.push({ model, analysis });
          console.log(`AI analysis result for ${model}:`, analysis);
        } catch (parseError) {
          console.error(`Could not parse AI response as JSON for ${model}:`, content, parseError);
        }
      } else {
        console.error(`Could not parse AI response as JSON for ${model}:`, content);
      }
    }

    if (modelAnalyses.length === 0) {
      return null;
    }

    const keys: AIFindingKey[] = [
      'clonedRegions',
      'lightingInconsistencies',
      'pixelManipulation',
      'fontInconsistencies',
      'colorAnomalies',
      'artificialElements'
    ];

    const aggregations: Record<AIFindingKey, { descriptions: Set<string>; models: Set<string> }> = {
      clonedRegions: { descriptions: new Set(), models: new Set() },
      lightingInconsistencies: { descriptions: new Set(), models: new Set() },
      pixelManipulation: { descriptions: new Set(), models: new Set() },
      fontInconsistencies: { descriptions: new Set(), models: new Set() },
      colorAnomalies: { descriptions: new Set(), models: new Set() },
      artificialElements: { descriptions: new Set(), models: new Set() }
    };

    for (const { model, analysis } of modelAnalyses) {
      for (const key of keys) {
        const value = analysis[key];
        if (value && typeof value === 'string' && value.trim().length > 0) {
          aggregations[key].descriptions.add(value.trim());
          aggregations[key].models.add(model);
        }
      }
    }

    const merged: AIVisualAnalysis = {};

    for (const key of keys) {
      const descriptionParts = Array.from(aggregations[key].descriptions);
      const modelsSupporting = Array.from(aggregations[key].models);

      if (descriptionParts.length > 0) {
        merged[key] = {
          description: descriptionParts.join(' | '),
          models: modelsSupporting
        };
      }
    }

    return Object.keys(merged).length > 0 ? merged : null;
  } catch (error) {
    console.error('AI analysis error:', error);
    return null;
  }
}

function checkExifPresence(data: Uint8Array): boolean {
  // Check for EXIF marker (0xFFE1 for JPEG)
  for (let i = 0; i < data.length - 4; i++) {
    if (data[i] === 0xFF && data[i + 1] === 0xE1) {
      // Check for "Exif" string
      if (data[i + 4] === 0x45 && data[i + 5] === 0x78 && 
          data[i + 6] === 0x69 && data[i + 7] === 0x66) {
        return true;
      }
    }
  }
  return false;
}

function extractMetadataStrings(data: Uint8Array, maxLength = 8192): string[] {
  // Collect readable ASCII sequences from the header/metadata region only
  const strings: string[] = [];
  const limit = Math.min(data.length, maxLength);
  let current: number[] = [];

  for (let i = 0; i < limit; i++) {
    const byte = data[i];
    if (byte >= 32 && byte <= 126) {
      current.push(byte);
    } else {
      if (current.length >= 4) {
        strings.push(String.fromCharCode(...current).trim());
      }
      current = [];
    }
  }

  if (current.length >= 4) {
    strings.push(String.fromCharCode(...current).trim());
  }

  return strings;
}

function extractHeaderTokens(data: Uint8Array, maxLength = 8192): string[] {
  return extractMetadataStrings(data, maxLength)
    .map((segment) => segment.replace(/\s+/g, ' ').toLowerCase())
    .filter((segment) => segment.length > 0);
}

function escapeRegExp(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function headerContainsPattern(tokens: string[], pattern: string): boolean {
  const normalizedPattern = pattern.toLowerCase();
  const boundaryRegex = new RegExp(`\\b${escapeRegExp(normalizedPattern)}\\b`, 'i');

  // Check each token for a whole-word match
  if (tokens.some((token) => boundaryRegex.test(token))) {
    return true;
  }

  // Allow multi-word patterns to span adjacent tokens
  if (normalizedPattern.includes(' ')) {
    const joined = tokens.join(' ');
    return boundaryRegex.test(joined);
  }

  return false;
}

function detectEditingSoftware(data: Uint8Array): string[] {
  const software: string[] = [];
  const headerTokens = extractHeaderTokens(data);

  // Only evaluate metadata-like tokens to avoid random binary matches
  const metadataTokens = headerTokens.filter((token) =>
    /(software|application|producer|creator|generator|rendered|modified)/i.test(token)
  );

  const signatures = [
    { name: 'Photoshop', patterns: ['adobe photoshop', 'photoshop', 'phoshop'] },
    { name: 'GIMP', patterns: ['gimp'] },
    { name: 'Canva', patterns: ['canva'] },
    { name: 'Pixlr', patterns: ['pixlr'] },
    { name: 'Paint.NET', patterns: ['paint.net'] },
    { name: 'Affinity', patterns: ['affinity photo', 'affinity'] },
    { name: 'Sketch', patterns: ['sketch'] }
  ];

  for (const sig of signatures) {
    for (const pattern of sig.patterns) {
      if (headerContainsPattern(metadataTokens, pattern)) {
        software.push(sig.name);
        break;
      }
    }
  }

  return [...new Set(software)];
}

function detectRecompression(data: Uint8Array): boolean {
  // Look for multiple JFIF or JPEG markers. Two markers can appear legitimately
  // when a file embeds a thumbnail preview, so require at least three distinct
  // start markers before flagging to reduce false positives on native captures.
  let jpegMarkerCount = 0;
  for (let i = 0; i < data.length - 1; i++) {
    if (data[i] === 0xFF && data[i + 1] === 0xD8) {
      jpegMarkerCount++;
    }
  }
  return jpegMarkerCount > 2;
}

function detectImageFormat(data: Uint8Array): string {
  // PNG signature
  if (data[0] === 0x89 && data[1] === 0x50 && data[2] === 0x4E && data[3] === 0x47) {
    return 'PNG';
  }
  // JPEG signature
  if (data[0] === 0xFF && data[1] === 0xD8) {
    return 'JPEG';
  }
  return 'UNKNOWN';
}

function analyzePNG(data: Uint8Array): { suspicious: boolean } {
  // Focus on text chunks near the header to avoid parsing entire binary payload
  const tokens = extractHeaderTokens(data, 16384);
  const metadataTokens = tokens.filter((token) => /(software|application|creator|producer)/i.test(token));

  const benignDeviceTokens = tokens.some((token) => /(iphone|ios|ipad|apple|screen capture|screenshot)/i.test(token));
  const editingHits = metadataTokens.some((token) => /(photoshop|gimp|canva|snapseed|instagram|picsart|lightroom|facetune)/i.test(token));

  // Treat PNGs that only contain device/screenshot markers as normal. Flag only
  // when explicit editing software appears.
  return { suspicious: editingHits && !benignDeviceTokens };
}

function analyzeJPEG(data: Uint8Array): { qualityInconsistent: boolean } {
  // Extract metadata-like tokens from the header region to look for explicit
  // quality tags instead of scanning arbitrary binary data, which can contain
  // random "quality" strings and cause false positives.
  const headerTokens = extractHeaderTokens(data, 16384);

  // Capture numerical quality values such as "Quality=92" or "quality 85".
  const qualityValues = headerTokens
    .map((token) => {
      const match = token.match(/\bquality[:=]?\s*(\d{1,3})/i);
      return match ? parseInt(match[1], 10) : null;
    })
    .filter((value): value is number => value !== null);

  // Flag only when multiple distinct quality levels are present, suggesting
  // the image was saved more than once with different compression settings.
  const distinctQualityValues = new Set(qualityValues);
  return { qualityInconsistent: distinctQualityValues.size > 1 && qualityValues.length > 1 };
}

function detectAppSignatures(data: Uint8Array): string[] {
  const apps: string[] = [];
  const headerTokens = extractHeaderTokens(data);
  const metadataTokens = headerTokens.filter((token) =>
    /(software|application|producer|creator|generator|rendered|modified|app)/i.test(token)
  );

  const appSignatures = [
    { name: 'Snapseed', pattern: 'snapseed' },
    { name: 'Instagram', pattern: 'instagram' },
    { name: 'PicsArt', pattern: 'picsart' },
    { name: 'Lightroom', pattern: 'lightroom' },
    { name: 'Facetune', pattern: 'facetune' }
  ];

  for (const app of appSignatures) {
    if (headerContainsPattern(metadataTokens, app.pattern)) {
      apps.push(app.name);
    }
  }

  return apps;
}

function detectWatermarks(data: Uint8Array): boolean {
  // Simplified watermark detection
  // In real implementation would use computer vision
  return false;
}
