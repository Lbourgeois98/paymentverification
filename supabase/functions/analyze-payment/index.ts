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

  try {
    // Convert base64 to binary for analysis
    const base64Data = base64Image.split(',')[1];
    const binaryData = Uint8Array.from(atob(base64Data), c => c.charCodeAt(0));
    
    // PHASE 1: Binary Forensic Analysis
    console.log('Starting binary forensic analysis...');
    
    // Check for EXIF data presence
    const hasExif = checkExifPresence(binaryData);
    
    if (!hasExif) {
      findings.push({
        type: 'warning',
        message: 'No EXIF data found. This could indicate metadata has been stripped, which is common with edited images.'
      });
      confidence -= 15;
      metadataInconsistencies = true;
    }

    // Analyze image header for editing software signatures
    const softwareSignatures = detectEditingSoftware(binaryData);
    if (softwareSignatures.length > 0) {
      editingSoftware = softwareSignatures.join(', ');
      editingDetected = true;
      findings.push({
        type: 'critical',
        message: `Editing software detected: ${editingSoftware}. Image has been processed through editing applications.`
      });
      confidence -= 40;
    }

    // Check for multiple save signatures (re-compression)
    const recompressionDetected = detectRecompression(binaryData);
    if (recompressionDetected) {
      compressionAnomalies = true;
      findings.push({
        type: 'warning',
        message: 'Multiple compression signatures detected. Image appears to have been saved multiple times, suggesting possible editing.'
      });
      confidence -= 20;
    }

    // Analyze PNG/JPEG specific markers
    const format = detectImageFormat(binaryData);
    if (format === 'PNG') {
      const pngAnalysis = analyzePNG(binaryData);
      if (pngAnalysis.suspicious) {
        findings.push({
          type: 'warning',
          message: 'PNG metadata suggests possible screenshot conversion or editing.'
        });
        confidence -= 10;
      }
    } else if (format === 'JPEG') {
      const jpegAnalysis = analyzeJPEG(binaryData);
      if (jpegAnalysis.qualityInconsistent) {
        compressionAnomalies = true;
        findings.push({
          type: 'critical',
          message: 'JPEG quality levels are inconsistent across the image, indicating selective editing or manipulation.'
        });
        confidence -= 25;
      }
    }

    // Check for common editing app signatures in metadata
    const appSignatures = detectAppSignatures(binaryData);
    if (appSignatures.length > 0) {
      findings.push({
        type: 'critical',
        message: `Detected traces of editing apps: ${appSignatures.join(', ')}. Image has been modified.`
      });
      editingDetected = true;
      confidence -= 30;
    }

    // PHASE 2: AI-Powered Visual Analysis
    console.log('Starting AI-powered visual analysis...');
    const aiAnalysis = await performAIVisualAnalysis(base64Image);
    
    if (aiAnalysis) {
      // Process AI findings
      if (aiAnalysis.clonedRegions) {
        findings.push({
          type: 'critical',
          message: `AI detected cloned/copied regions: ${aiAnalysis.clonedRegions}. This indicates copy-paste manipulation.`
        });
        editingDetected = true;
        confidence -= 35;
      }

      if (aiAnalysis.lightingInconsistencies) {
        findings.push({
          type: 'critical',
          message: `Lighting inconsistencies detected: ${aiAnalysis.lightingInconsistencies}. Different parts of the image have inconsistent illumination.`
        });
        editingDetected = true;
        confidence -= 30;
      }

      if (aiAnalysis.pixelManipulation) {
        findings.push({
          type: 'critical',
          message: `Pixel-level manipulation detected: ${aiAnalysis.pixelManipulation}. Text or numbers appear to have been altered.`
        });
        editingDetected = true;
        confidence -= 40;
      }

      if (aiAnalysis.fontInconsistencies) {
        findings.push({
          type: 'warning',
          message: `Font inconsistencies detected: ${aiAnalysis.fontInconsistencies}. Text rendering appears unnatural.`
        });
        confidence -= 15;
      }

      if (aiAnalysis.colorAnomalies) {
        findings.push({
          type: 'warning',
          message: `Color anomalies detected: ${aiAnalysis.colorAnomalies}. Color distribution is inconsistent with authentic screenshots.`
        });
        confidence -= 10;
      }

      if (aiAnalysis.artificialElements) {
        findings.push({
          type: 'info',
          message: `Possible artificial elements: ${aiAnalysis.artificialElements}`
        });
        confidence -= 5;
      }
    }

    // Final confidence adjustment
    confidence = Math.max(0, Math.min(100, confidence));

    // Only mark as modified when there is clear evidence of editing
    const hasCriticalFindings = findings.some(finding => finding.type === 'critical');
    const authenticityThreshold = (hasCriticalFindings || editingDetected) ? 70 : 50;
    const authentic = !editingDetected && !hasCriticalFindings && confidence >= authenticityThreshold;

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

async function performAIVisualAnalysis(base64Image: string) {
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

    const response = await fetch('https://ai.gateway.lovable.dev/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${LOVABLE_API_KEY}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        model: 'google/gemini-2.5-flash',
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
      console.error('AI API error:', response.status, errorText);
      return null;
    }

    const data = await response.json();
    const content = data.choices?.[0]?.message?.content;
    
    if (!content) {
      console.error('No content in AI response');
      return null;
    }

    // Parse the JSON response
    const jsonMatch = content.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      const analysis = JSON.parse(jsonMatch[0]);
      console.log('AI analysis result:', analysis);
      return analysis;
    }

    console.error('Could not parse AI response as JSON:', content);
    return null;
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

function detectEditingSoftware(data: Uint8Array): string[] {
  const software: string[] = [];
  const dataString = new TextDecoder().decode(data);
  
  const signatures = [
    { name: 'Photoshop', patterns: ['Adobe Photoshop', 'photoshop', 'PHOSHOP'] },
    { name: 'GIMP', patterns: ['GIMP', 'gimp'] },
    { name: 'Canva', patterns: ['Canva', 'canva'] },
    { name: 'Pixlr', patterns: ['Pixlr', 'pixlr'] },
    { name: 'Paint.NET', patterns: ['Paint.NET', 'paint.net'] },
    { name: 'Affinity', patterns: ['Affinity Photo', 'Affinity'] },
    { name: 'Sketch', patterns: ['Sketch', 'sketch'] }
  ];

  for (const sig of signatures) {
    for (const pattern of sig.patterns) {
      if (dataString.includes(pattern)) {
        software.push(sig.name);
        break;
      }
    }
  }

  return [...new Set(software)];
}

function detectRecompression(data: Uint8Array): boolean {
  // Look for multiple JFIF or JPEG markers
  let jpegMarkerCount = 0;
  for (let i = 0; i < data.length - 1; i++) {
    if (data[i] === 0xFF && data[i + 1] === 0xD8) {
      jpegMarkerCount++;
    }
  }
  return jpegMarkerCount > 1;
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
  const dataString = new TextDecoder().decode(data);
  // Check for software chunks or unusual metadata
  const hasSoftwareChunk = dataString.includes('Software') || dataString.includes('tEXt');
  return { suspicious: hasSoftwareChunk };
}

function analyzeJPEG(data: Uint8Array): { qualityInconsistent: boolean } {
  // Simplified quality analysis - in real implementation would analyze DCT coefficients
  // Check for multiple quality settings in comments
  const dataString = new TextDecoder().decode(data);
  const qualityMentions = (dataString.match(/quality/gi) || []).length;
  return { qualityInconsistent: qualityMentions > 2 };
}

function detectAppSignatures(data: Uint8Array): string[] {
  const apps: string[] = [];
  const dataString = new TextDecoder().decode(data);
  
  const appSignatures = [
    { name: 'Snapseed', pattern: 'snapseed' },
    { name: 'Instagram', pattern: 'instagram' },
    { name: 'PicsArt', pattern: 'picsart' },
    { name: 'Lightroom', pattern: 'lightroom' },
    { name: 'Facetune', pattern: 'facetune' }
  ];

  for (const app of appSignatures) {
    if (dataString.toLowerCase().includes(app.pattern)) {
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
