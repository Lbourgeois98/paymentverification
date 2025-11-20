import { useState } from 'react';
import { MatrixRain } from '@/components/MatrixRain';
import { UploadZone } from '@/components/UploadZone';
import { ResultsDisplay } from '@/components/ResultsDisplay';
import logo from '@/assets/logo.png';

const Index = () => {
  const [analysisResult, setAnalysisResult] = useState<any>(null);

  return (
    <div className="min-h-screen bg-cyber-darker relative overflow-hidden">
      <MatrixRain />
      
      <div className="relative z-10">
        {/* Header */}
        <header className="border-b border-primary/30 bg-cyber-dark/80 backdrop-blur">
          <div className="container mx-auto px-4 py-6">
            <div className="flex items-center justify-center gap-4">
              <img src={logo} alt="Tech Pimp" className="h-16 w-auto" />
              <h1 className="text-3xl font-bold text-primary glow-text">
                Payment Verification
              </h1>
            </div>
          </div>
        </header>

        {/* Main Content */}
        <main className="container mx-auto px-4 py-12">
          {!analysisResult ? (
            <div className="space-y-8">
              <div className="text-center space-y-4 mb-12">
                <h2 className="text-4xl md:text-5xl font-bold text-foreground">
                  Detect Payment Screenshot
                  <span className="block text-primary glow-text">Manipulation</span>
                </h2>
                <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
                  Advanced forensic analysis to verify the authenticity of payment screenshots
                  from Chime, CashApp, PayPal, Apple Pay, and Venmo.
                </p>
              </div>

              <UploadZone onAnalysisComplete={setAnalysisResult} />

              {/* Features */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mt-16">
                <div className="p-6 rounded-lg cyber-border bg-card/30 backdrop-blur">
                  <h3 className="text-xl font-bold text-primary mb-2">EXIF Analysis</h3>
                  <p className="text-sm text-muted-foreground">
                    Examines metadata for editing software signatures and inconsistencies
                  </p>
                </div>
                <div className="p-6 rounded-lg cyber-border-purple bg-card/30 backdrop-blur">
                  <h3 className="text-xl font-bold text-secondary mb-2">Error Level Analysis</h3>
                  <p className="text-sm text-muted-foreground">
                    Detects compression artifacts that indicate image manipulation
                  </p>
                </div>
                <div className="p-6 rounded-lg cyber-border bg-card/30 backdrop-blur">
                  <h3 className="text-xl font-bold text-primary mb-2">Clone Detection</h3>
                  <p className="text-sm text-muted-foreground">
                    Identifies copied or duplicated regions within the image
                  </p>
                </div>
              </div>
            </div>
          ) : (
            <div className="space-y-8">
              <div className="flex justify-center mb-8">
                <button
                  onClick={() => setAnalysisResult(null)}
                  className="text-primary hover:text-primary/80 underline"
                >
                  ← Analyze another screenshot
                </button>
              </div>
              <ResultsDisplay result={analysisResult} />
            </div>
          )}
        </main>

        {/* Footer */}
        <footer className="border-t border-primary/30 bg-cyber-dark/80 backdrop-blur mt-20">
          <div className="container mx-auto px-4 py-8 text-center">
            <p className="text-sm text-muted-foreground">
              Powered by advanced image forensics technology
            </p>
          </div>
        </footer>
      </div>
    </div>
  );
};

export default Index;
