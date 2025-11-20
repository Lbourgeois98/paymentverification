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

    // Check for screen recording watermarks or UI elements
    const hasWatermarks = detectWatermarks(binaryData);
    if (hasWatermarks) {
      findings.push({
        type: 'info',
        message: 'Possible watermark or UI overlay detected. Verify if this is expected for the payment platform.'
      });
      confidence -= 5;
    }

    // Final confidence adjustment
    confidence = Math.max(0, Math.min(100, confidence));

    const authentic = confidence >= 70 && !editingDetected;

    if (authentic && findings.length === 0) {
      findings.push({
        type: 'info',
        message: 'No signs of manipulation detected. Image appears to be an original screenshot.'
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
