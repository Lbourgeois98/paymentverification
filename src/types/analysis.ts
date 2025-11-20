export type FindingType = 'info' | 'warning' | 'critical';

export interface AnalysisFinding {
  type: FindingType;
  message: string;
}

export interface AnalysisMetadata {
  software?: string;
  editingDetected: boolean;
  compressionAnomalies: boolean;
  metadataInconsistencies: boolean;
}

export interface AnalysisResult {
  authentic: boolean;
  confidence: number;
  findings: AnalysisFinding[];
  metadata: AnalysisMetadata;
}
