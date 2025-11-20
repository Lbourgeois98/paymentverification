import { useState, useEffect } from 'react';
import { Card } from './ui/card';

interface AnalysisProgressProps {
  isAnalyzing: boolean;
}

export const AnalysisProgress = ({ isAnalyzing }: AnalysisProgressProps) => {
  const [currentStep, setCurrentStep] = useState(0);

  const steps = [
    { label: 'Extracting EXIF metadata', duration: 1500 },
    { label: 'Scanning for editing software', duration: 1800 },
    { label: 'Analyzing compression artifacts', duration: 2000 },
    { label: 'AI visual analysis in progress', duration: 3000 },
    { label: 'Detecting cloned regions', duration: 2500 },
    { label: 'Checking lighting consistency', duration: 2200 },
    { label: 'Finalizing results', duration: 1000 },
  ];

  useEffect(() => {
    if (!isAnalyzing) {
      setCurrentStep(0);
      return;
    }

    let stepIndex = 0;
    const progressSteps = () => {
      if (stepIndex < steps.length - 1) {
        setTimeout(() => {
          stepIndex++;
          setCurrentStep(stepIndex);
          progressSteps();
        }, steps[stepIndex].duration);
      }
    };

    progressSteps();
  }, [isAnalyzing]);

  if (!isAnalyzing) return null;

  return (
    <Card className="mt-8 p-6 cyber-border bg-card/50 backdrop-blur max-w-2xl mx-auto">
      <div className="space-y-4">
        <h3 className="text-xl font-bold text-center text-primary glow-text">
          Analyzing Screenshot
        </h3>
        
        <div className="space-y-3">
          {steps.map((step, index) => (
            <div
              key={index}
              className={`flex items-center gap-3 p-3 rounded transition-all ${
                index === currentStep
                  ? 'bg-primary/20 cyber-border'
                  : index < currentStep
                  ? 'bg-muted/30'
                  : 'bg-muted/10 opacity-50'
              }`}
            >
              <div className={`flex-shrink-0 w-6 h-6 rounded-full flex items-center justify-center ${
                index === currentStep
                  ? 'bg-primary animate-glow-pulse'
                  : index < currentStep
                  ? 'bg-primary'
                  : 'bg-muted'
              }`}>
                {index < currentStep ? (
                  <svg className="w-4 h-4 text-cyber-dark" fill="currentColor" viewBox="0 0 20 20">
                    <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
                  </svg>
                ) : index === currentStep ? (
                  <div className="w-3 h-3 rounded-full bg-cyber-dark animate-pulse" />
                ) : (
                  <div className="w-2 h-2 rounded-full bg-muted-foreground" />
                )}
              </div>
              <span className={`text-sm ${
                index === currentStep
                  ? 'text-foreground font-semibold'
                  : 'text-muted-foreground'
              }`}>
                {step.label}
              </span>
            </div>
          ))}
        </div>

        <div className="pt-4 flex items-center justify-center gap-2 text-sm text-muted-foreground">
          <div className="w-2 h-2 rounded-full bg-primary animate-pulse" />
          <div className="w-2 h-2 rounded-full bg-primary animate-pulse" style={{ animationDelay: '0.2s' }} />
          <div className="w-2 h-2 rounded-full bg-primary animate-pulse" style={{ animationDelay: '0.4s' }} />
        </div>
      </div>
    </Card>
  );
};
