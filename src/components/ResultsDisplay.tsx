import { CheckCircle2, XCircle, AlertTriangle, Info } from 'lucide-react';
import { Card } from './ui/card';
import { Badge } from './ui/badge';

interface ResultsDisplayProps {
  result: {
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
  };
}

export const ResultsDisplay = ({ result }: ResultsDisplayProps) => {
  const getStatusIcon = () => {
    if (result.authentic) {
      return <CheckCircle2 className="w-16 h-16 text-primary animate-glow-pulse" />;
    }
    return <XCircle className="w-16 h-16 text-secondary animate-glow-pulse" />;
  };

  const getStatusText = () => {
    if (result.authentic) {
      return 'AUTHENTIC';
    }
    return 'MODIFIED';
  };

  const getConfidenceColor = () => {
    if (result.confidence >= 80) return 'text-primary';
    if (result.confidence >= 50) return 'text-yellow-400';
    return 'text-secondary';
  };

  return (
    <div className="w-full max-w-4xl mx-auto space-y-6 animate-in fade-in duration-500">
      {/* Status Card */}
      <Card className="p-8 cyber-border bg-card/50 backdrop-blur">
        <div className="flex flex-col items-center gap-4">
          {getStatusIcon()}
          <h2 className="text-4xl font-bold glow-text">{getStatusText()}</h2>
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground">Confidence:</span>
            <span className={`text-2xl font-bold ${getConfidenceColor()}`}>
              {result.confidence}%
            </span>
          </div>
        </div>
      </Card>

      {/* Findings Card */}
      {result.findings.length > 0 && (
        <Card className="p-6 cyber-border-purple bg-card/50 backdrop-blur">
          <h3 className="text-xl font-bold mb-4 text-secondary">Analysis Findings</h3>
          <div className="space-y-3">
            {result.findings.map((finding, index) => (
              <div
                key={index}
                className="flex items-start gap-3 p-3 rounded bg-muted/30"
              >
                {finding.type === 'critical' && (
                  <XCircle className="w-5 h-5 text-destructive flex-shrink-0 mt-0.5" />
                )}
                {finding.type === 'warning' && (
                  <AlertTriangle className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
                )}
                {finding.type === 'info' && (
                  <Info className="w-5 h-5 text-primary flex-shrink-0 mt-0.5" />
                )}
                <p className="text-sm text-foreground">{finding.message}</p>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Metadata Card */}
      <Card className="p-6 cyber-border bg-card/50 backdrop-blur">
        <h3 className="text-xl font-bold mb-4">Technical Details</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="flex items-center justify-between p-3 rounded bg-muted/30">
            <span className="text-sm text-muted-foreground">Editing Software</span>
            <Badge variant={result.metadata.software ? "destructive" : "outline"}>
              {result.metadata.software || 'None Detected'}
            </Badge>
          </div>
          <div className="flex items-center justify-between p-3 rounded bg-muted/30">
            <span className="text-sm text-muted-foreground">Editing Detected</span>
            <Badge variant={result.metadata.editingDetected ? "destructive" : "outline"}>
              {result.metadata.editingDetected ? 'Yes' : 'No'}
            </Badge>
          </div>
          <div className="flex items-center justify-between p-3 rounded bg-muted/30">
            <span className="text-sm text-muted-foreground">Compression Anomalies</span>
            <Badge variant={result.metadata.compressionAnomalies ? "destructive" : "outline"}>
              {result.metadata.compressionAnomalies ? 'Detected' : 'None'}
            </Badge>
          </div>
          <div className="flex items-center justify-between p-3 rounded bg-muted/30">
            <span className="text-sm text-muted-foreground">Metadata Issues</span>
            <Badge variant={result.metadata.metadataInconsistencies ? "destructive" : "outline"}>
              {result.metadata.metadataInconsistencies ? 'Found' : 'None'}
            </Badge>
          </div>
        </div>
      </Card>
    </div>
  );
};
