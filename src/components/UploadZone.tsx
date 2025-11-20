import { useCallback, useState } from 'react';
import { Upload, Image } from 'lucide-react';
import { Button } from './ui/button';
import { useToast } from '@/hooks/use-toast';
import { supabase } from '@/integrations/supabase/client';

interface UploadZoneProps {
  onAnalysisStart: () => void;
  onAnalysisComplete: (result: any) => void;
}

export const UploadZone = ({ onAnalysisStart, onAnalysisComplete }: UploadZoneProps) => {
  const [isDragging, setIsDragging] = useState(false);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const { toast } = useToast();

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.type === "dragenter" || e.type === "dragover") {
      setIsDragging(true);
    } else if (e.type === "dragleave") {
      setIsDragging(false);
    }
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const files = Array.from(e.dataTransfer.files);
    if (files.length > 0) {
      handleFileSelect(files[0]);
    }
  }, []);

  const handleFileSelect = (file: File) => {
    if (!file.type.startsWith('image/')) {
      toast({
        title: "Invalid File",
        description: "Please upload an image file",
        variant: "destructive",
      });
      return;
    }

    setSelectedFile(file);
  };

  const handleAnalyze = async () => {
    if (!selectedFile) return;

    setIsAnalyzing(true);
    onAnalysisStart();
    
    try {
      // Convert file to base64
      const reader = new FileReader();
      reader.onload = async (e) => {
        const base64 = e.target?.result as string;

        const { data, error } = await supabase.functions.invoke('analyze-payment', {
          body: { 
            image: base64,
            filename: selectedFile.name 
          }
        });

        if (error) throw error;

        onAnalysisComplete(data);
        toast({
          title: "Analysis Complete",
          description: "Your payment screenshot has been analyzed",
        });
      };
      reader.readAsDataURL(selectedFile);
    } catch (error) {
      console.error('Analysis error:', error);
      toast({
        title: "Analysis Failed",
        description: "Failed to analyze the image. Please try again.",
        variant: "destructive",
      });
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      <div
        onDragEnter={handleDrag}
        onDragLeave={handleDrag}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        className={`relative border-2 border-dashed rounded-lg p-12 transition-all ${
          isDragging
            ? 'border-primary bg-primary/10 cyber-border'
            : 'border-muted hover:border-primary/50'
        }`}
      >
        <input
          type="file"
          accept="image/*"
          onChange={(e) => {
            const file = e.target.files?.[0];
            if (file) handleFileSelect(file);
          }}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
        />

        <div className="flex flex-col items-center justify-center gap-4">
          {selectedFile ? (
            <>
              <Image className="w-16 h-16 text-primary animate-glow-pulse" />
              <p className="text-xl font-bold text-primary glow-text">
                {selectedFile.name}
              </p>
              <p className="text-sm text-muted-foreground">
                {(selectedFile.size / 1024 / 1024).toFixed(2)} MB
              </p>
            </>
          ) : (
            <>
              <Upload className="w-16 h-16 text-muted-foreground" />
              <p className="text-xl font-semibold text-foreground">
                Drop your payment screenshot here
              </p>
              <p className="text-sm text-muted-foreground">
                or click to browse
              </p>
            </>
          )}

          <div className="flex gap-2 text-xs text-muted-foreground">
            <span className="px-2 py-1 rounded cyber-border">Chime</span>
            <span className="px-2 py-1 rounded cyber-border">CashApp</span>
            <span className="px-2 py-1 rounded cyber-border">PayPal</span>
            <span className="px-2 py-1 rounded cyber-border">Apple Pay</span>
            <span className="px-2 py-1 rounded cyber-border">Venmo</span>
          </div>
        </div>
      </div>

      {selectedFile && (
        <div className="mt-6 flex justify-center">
          <Button
            onClick={handleAnalyze}
            disabled={isAnalyzing}
            variant="cyber"
            size="lg"
            className="text-lg px-8 py-6"
          >
            {isAnalyzing ? (
              <>
                <div className="w-5 h-5 border-2 border-current border-t-transparent rounded-full animate-spin mr-2" />
                Analyzing...
              </>
            ) : (
              'Analyze Screenshot'
            )}
          </Button>
        </div>
      )}
    </div>
  );
};
