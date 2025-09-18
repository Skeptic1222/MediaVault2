import { useState, useCallback, useRef } from "react";
import { useMutation } from "@tanstack/react-query";
import { queryClient } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";
import { Upload, X, File, CheckCircle, AlertCircle } from "lucide-react";

interface FileUploadZoneProps {
  folderId?: string | null;
  onClose: () => void;
  onUploadComplete: () => void;
  className?: string;
  "data-testid"?: string;
}

interface UploadFile {
  file: File;
  id: string;
  status: "pending" | "uploading" | "success" | "error";
  progress: number;
  error?: string;
}

export default function FileUploadZone({
  folderId,
  onClose,
  onUploadComplete,
  className,
  "data-testid": dataTestId,
}: FileUploadZoneProps) {
  const { toast } = useToast();
  const [files, setFiles] = useState<UploadFile[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const uploadMutation = useMutation({
    mutationFn: async (uploadFile: UploadFile) => {
      const formData = new FormData();
      formData.append("file", uploadFile.file);
      if (folderId) {
        formData.append("folderId", folderId);
      }

      // Update status to uploading
      setFiles(prev => prev.map(f => 
        f.id === uploadFile.id ? { ...f, status: "uploading" as const } : f
      ));

      const xhr = new XMLHttpRequest();

      return new Promise((resolve, reject) => {
        xhr.upload.addEventListener("progress", (e) => {
          if (e.lengthComputable) {
            const progress = Math.round((e.loaded / e.total) * 100);
            setFiles(prev => prev.map(f => 
              f.id === uploadFile.id ? { ...f, progress } : f
            ));
          }
        });

        xhr.addEventListener("load", () => {
          if (xhr.status === 200) {
            setFiles(prev => prev.map(f => 
              f.id === uploadFile.id ? { ...f, status: "success" as const, progress: 100 } : f
            ));
            resolve(JSON.parse(xhr.responseText));
          } else {
            const error = "Upload failed";
            setFiles(prev => prev.map(f => 
              f.id === uploadFile.id ? { ...f, status: "error" as const, error } : f
            ));
            reject(new Error(error));
          }
        });

        xhr.addEventListener("error", () => {
          const error = "Network error";
          setFiles(prev => prev.map(f => 
            f.id === uploadFile.id ? { ...f, status: "error" as const, error } : f
          ));
          reject(new Error(error));
        });

        xhr.open("POST", "/api/upload");
        xhr.send(formData);
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/files"] });
      queryClient.invalidateQueries({ queryKey: ["/api/folders"] });
    },
  });

  const handleFiles = useCallback((fileList: FileList) => {
    const newFiles: UploadFile[] = Array.from(fileList).map(file => ({
      file,
      id: Math.random().toString(36).substr(2, 9),
      status: "pending" as const,
      progress: 0,
    }));

    setFiles(prev => [...prev, ...newFiles]);

    // Start uploading each file
    newFiles.forEach(uploadFile => {
      uploadMutation.mutate(uploadFile);
    });
  }, [uploadMutation]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    
    const droppedFiles = e.dataTransfer.files;
    if (droppedFiles.length > 0) {
      handleFiles(droppedFiles);
    }
  }, [handleFiles]);

  const handleFileSelect = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFiles(e.target.files);
    }
  }, [handleFiles]);

  const removeFile = useCallback((fileId: string) => {
    setFiles(prev => prev.filter(f => f.id !== fileId));
  }, []);

  const allComplete = files.length > 0 && files.every(f => f.status === "success" || f.status === "error");
  const hasErrors = files.some(f => f.status === "error");
  const successCount = files.filter(f => f.status === "success").length;

  const handleComplete = () => {
    if (successCount > 0) {
      onUploadComplete();
      toast({
        title: "Upload complete",
        description: `Successfully uploaded ${successCount} file(s)`,
      });
    }
    onClose();
  };

  return (
    <Dialog open onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="sm:max-w-2xl" data-testid={dataTestId}>
        <DialogHeader>
          <DialogTitle>Upload Files</DialogTitle>
          <DialogDescription>
            Drag and drop files here or click to browse
          </DialogDescription>
        </DialogHeader>

        <div className={cn("space-y-4", className)}>
          {/* Drop Zone */}
          <div
            className={cn(
              "border-2 border-dashed rounded-lg p-8 text-center transition-colors cursor-pointer",
              isDragging ? "border-primary bg-primary/5" : "border-muted-foreground/25 hover:border-muted-foreground/50"
            )}
            onDragOver={handleDragOver}
            onDragLeave={handleDragLeave}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
            data-testid="drop-zone"
          >
            <Upload className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              {isDragging ? "Drop files here" : "Drop files here or click to browse"}
            </p>
            <p className="text-xs text-muted-foreground mt-2">
              Support for images, videos, and documents
            </p>
            <input
              ref={fileInputRef}
              type="file"
              multiple
              className="hidden"
              onChange={handleFileSelect}
              data-testid="file-input"
            />
          </div>

          {/* File List */}
          {files.length > 0 && (
            <div className="space-y-2 max-h-64 overflow-y-auto">
              {files.map(uploadFile => (
                <div
                  key={uploadFile.id}
                  className="flex items-center space-x-3 p-2 rounded-lg bg-muted/50"
                  data-testid={`upload-file-${uploadFile.id}`}
                >
                  <File className="h-4 w-4 flex-shrink-0 text-muted-foreground" />
                  
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium truncate">{uploadFile.file.name}</p>
                    {uploadFile.status === "uploading" && (
                      <Progress value={uploadFile.progress} className="h-1 mt-1" />
                    )}
                    {uploadFile.error && (
                      <p className="text-xs text-destructive mt-1">{uploadFile.error}</p>
                    )}
                  </div>

                  <div className="flex-shrink-0">
                    {uploadFile.status === "pending" && (
                      <div className="h-4 w-4 border-2 border-muted-foreground rounded-full animate-pulse" />
                    )}
                    {uploadFile.status === "uploading" && (
                      <span className="text-xs text-muted-foreground">{uploadFile.progress}%</span>
                    )}
                    {uploadFile.status === "success" && (
                      <CheckCircle className="h-4 w-4 text-green-500" />
                    )}
                    {uploadFile.status === "error" && (
                      <AlertCircle className="h-4 w-4 text-destructive" />
                    )}
                  </div>

                  {(uploadFile.status === "pending" || uploadFile.status === "error") && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-6 w-6 p-0"
                      onClick={() => removeFile(uploadFile.id)}
                      data-testid={`button-remove-${uploadFile.id}`}
                    >
                      <X className="h-3 w-3" />
                    </Button>
                  )}
                </div>
              ))}
            </div>
          )}

          {/* Actions */}
          <div className="flex justify-end space-x-2">
            <Button variant="outline" onClick={onClose}>
              Cancel
            </Button>
            {allComplete && (
              <Button onClick={handleComplete} disabled={!successCount}>
                {hasErrors ? `Continue (${successCount} uploaded)` : "Done"}
              </Button>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}