import { useState } from "react";
import { apiRequest } from "@/lib/queryClient";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Progress } from "@/components/ui/progress";
import { Upload, Cloud, FolderOpen, X, CheckCircle, AlertCircle, FileText } from "lucide-react";

interface ImportModalProps {
  isOpen: boolean;
  onClose: () => void;
}

interface ImportProgress {
  total: number;
  processed: number;
  currentFile: string;
  status: 'idle' | 'connecting' | 'importing' | 'completed' | 'error';
  duplicatesFound: number;
  errors: string[];
}

export default function ImportModal({ isOpen, onClose }: ImportModalProps) {
  const [activeTab, setActiveTab] = useState('upload');
  const [importSettings, setImportSettings] = useState({
    removeDuplicates: true,
    generateThumbnails: true,
    autoCategorize: false,
    quality: 'original' as 'original' | 'high' | 'medium',
    fileTypes: 'all' as 'all' | 'images' | 'videos',
    encryptContent: false,
  });

  const [progress, setProgress] = useState<ImportProgress>({
    total: 0,
    processed: 0,
    currentFile: '',
    status: 'idle',
    duplicatesFound: 0,
    errors: [],
  });

  const handleClose = () => {
    if (progress.status === 'importing') {
      // In a real app, you'd show a confirmation dialog
      return;
    }
    setProgress({
      total: 0,
      processed: 0,
      currentFile: '',
      status: 'idle',
      duplicatesFound: 0,
      errors: [],
    });
    onClose();
  };

  const handleDirectoryUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (!files || files.length === 0) return;

    setProgress({
      total: files.length,
      processed: 0,
      currentFile: 'Preparing directory upload...',
      status: 'importing',
      duplicatesFound: 0,
      errors: [],
    });

    try {
      const formData = new FormData();
      
      // Add each file with its relative path from the directory structure
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        formData.append('files', file);
        // Store the webkitRelativePath for each file to preserve directory structure
        formData.append(`relativePath_${i}`, (file as any).webkitRelativePath || file.name);
      }

      // Add import settings
      // For directory uploads with createCategories=true, we don't need a specific categoryId
      // Categories will be created from the folder structure
      formData.append('encryptContent', importSettings.encryptContent ? 'true' : 'false');
      formData.append('preserveDirectoryStructure', 'true');
      formData.append('createCategories', 'true');

      const response = await fetch('/api/media/upload', {
        method: 'POST',
        body: formData,
        credentials: 'include',
      });
      
      if (response.ok) {
        const result = await response.json();
        setProgress({
          status: 'completed',
          total: files.length,
          processed: files.length,
          currentFile: 'Directory upload completed successfully!',
          duplicatesFound: result.duplicatesFound || 0,
          errors: result.errors || []
        });
      } else {
        const error = await response.json();
        setProgress(prev => ({
          ...prev,
          status: 'error',
          errors: [error.message || 'Upload failed'],
        }));
      }
    } catch (error) {
      console.error('Directory upload error:', error);
      setProgress(prev => ({
        ...prev,
        status: 'error',
        errors: ['Failed to upload directory. Please try again.'],
      }));
    }
  };

  // Import progress is now handled by the real API response

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files;
    if (!files || files.length === 0) return;

    setProgress({
      total: files.length,
      processed: 0,
      currentFile: 'Preparing upload...',
      status: 'importing',
      duplicatesFound: 0,
      errors: [],
    });

    try {
      const formData = new FormData();
      
      // Add each file to the form data
      for (let i = 0; i < files.length; i++) {
        formData.append('files', files[i]);
      }

      // Add import settings
      formData.append('encryptContent', importSettings.encryptContent ? 'true' : 'false');

      const response = await fetch('/api/media/upload', {
        method: 'POST',
        body: formData,
        credentials: 'include',
      });
      
      if (response.ok) {
        const result = await response.json();
        setProgress({
          status: 'completed',
          total: files.length,
          processed: files.length,
          currentFile: 'Upload completed successfully!',
          duplicatesFound: result.duplicatesFound || 0,
          errors: result.errors || []
        });
        
        // Refresh the gallery/file manager after successful upload
        window.location.reload();
      } else {
        const error = await response.json();
        setProgress(prev => ({
          ...prev,
          status: 'error',
          errors: [error.message || 'Upload failed'],
        }));
      }
    } catch (error) {
      console.error('File upload error:', error);
      setProgress(prev => ({
        ...prev,
        status: 'error',
        errors: ['Failed to upload files. Please try again.'],
      }));
    }
  };

  const getStatusIcon = () => {
    switch (progress.status) {
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-green-400" />;
      case 'error':
        return <AlertCircle className="w-5 h-5 text-red-400" />;
      case 'connecting':
      case 'importing':
        return <div className="w-5 h-5 border-2 border-primary border-t-transparent rounded-full animate-spin" />;
      default:
        return <Upload className="w-5 h-5 text-muted-foreground" />;
    }
  };

  const progressPercentage = progress.total > 0 ? (progress.processed / progress.total) * 100 : 0;

  return (
    <Dialog open={isOpen} onOpenChange={handleClose}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto" data-testid="import-modal">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-3">
            <Upload className="w-6 h-6 text-primary" />
            Import Media
          </DialogTitle>
        </DialogHeader>

        {progress.status === 'idle' ? (
          <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
            <TabsList className="grid w-full grid-cols-3">
              <TabsTrigger value="upload" data-testid="tab-upload-files">
                <Upload className="w-4 h-4 mr-2" />
                Upload Files
              </TabsTrigger>
              <TabsTrigger value="google" data-testid="tab-folder-import">
                <FolderOpen className="w-4 h-4 mr-2" />
                Folder Import
              </TabsTrigger>
              <TabsTrigger value="batch" data-testid="tab-batch-import">
                <FolderOpen className="w-4 h-4 mr-2" />
                Batch Import
              </TabsTrigger>
            </TabsList>

            <TabsContent value="google" className="space-y-6">
              {/* Folder Import */}
              <div className="p-6 border-2 border-dashed border-border rounded-lg">
                <div className="flex items-center justify-center mb-4">
                  <FolderOpen className="w-12 h-12 text-muted-foreground" />
                </div>
                <h3 className="text-lg font-semibold mb-2 text-center">Import from Folder</h3>
                <p className="text-muted-foreground mb-4 text-center">
                  Import all files from a folder. Supports all file types including images, videos, audio, documents, PDFs, and more. Subfolders will become categories.
                </p>
                
                <div className="space-y-4">
                  <div className="text-xs text-muted-foreground">
                    <strong>How it works:</strong><br/>
                    • Click the button below to select a folder from your computer<br/>
                    • All files will be uploaded preserving the folder structure<br/>
                    • Subfolders will automatically become categories in your gallery
                  </div>
                  
                  <div className="relative">
                    <input
                      type="file"
                      {...({ webkitdirectory: "" } as any)}
                      multiple
                      onChange={handleDirectoryUpload}
                      className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                      data-testid="directory-input"
                    />
                    <Button 
                      className="w-full bg-primary hover:bg-primary/90"
                      data-testid="select-folder-button"
                    >
                      <FolderOpen className="w-4 h-4 mr-2" />
                      Select Folder to Upload
                    </Button>
                  </div>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="upload" className="space-y-6">
              {/* File Upload */}
              <div className="text-center p-6 border-2 border-dashed border-border rounded-lg hover:border-primary/50 transition-colors">
                <Upload className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                <h3 className="text-lg font-semibold mb-2">Upload Files</h3>
                <p className="text-muted-foreground mb-4">
                  Select any files from your device (images, videos, audio, documents, PDFs, and more)
                </p>
                <div className="relative">
                  <input
                    type="file"
                    multiple
                    onChange={handleFileUpload}
                    className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                    data-testid="file-input"
                  />
                  <Button className="bg-primary hover:bg-primary/90">
                    <Upload className="w-4 h-4 mr-2" />
                    Choose Files
                  </Button>
                </div>
              </div>
            </TabsContent>

            <TabsContent value="batch" className="space-y-6">
              {/* Batch Import */}
              <div className="text-center p-6 border-2 border-dashed border-border rounded-lg">
                <FolderOpen className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                <h3 className="text-lg font-semibold mb-2">Batch Import</h3>
                <p className="text-muted-foreground mb-4">
                  Import from a folder or network location
                </p>
                <Button variant="outline" disabled>
                  <FolderOpen className="w-4 h-4 mr-2" />
                  Coming Soon
                </Button>
              </div>
            </TabsContent>

            {/* Import Settings */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 pt-6 border-t border-border">
              <div className="space-y-4">
                <h4 className="font-medium">Import Settings</h4>
                
                <div className="flex items-center space-x-3">
                  <Checkbox
                    id="remove-duplicates"
                    checked={importSettings.removeDuplicates}
                    onCheckedChange={(checked) => 
                      setImportSettings(prev => ({ ...prev, removeDuplicates: checked as boolean }))
                    }
                    data-testid="checkbox-remove-duplicates"
                  />
                  <Label htmlFor="remove-duplicates" className="text-sm">
                    Remove duplicates (SHA-256)
                  </Label>
                </div>

                <div className="flex items-center space-x-3">
                  <Checkbox
                    id="generate-thumbnails"
                    checked={importSettings.generateThumbnails}
                    onCheckedChange={(checked) => 
                      setImportSettings(prev => ({ ...prev, generateThumbnails: checked as boolean }))
                    }
                    data-testid="checkbox-generate-thumbnails"
                  />
                  <Label htmlFor="generate-thumbnails" className="text-sm">
                    Generate thumbnails
                  </Label>
                </div>

                <div className="flex items-center space-x-3">
                  <Checkbox
                    id="auto-categorize"
                    checked={importSettings.autoCategorize}
                    onCheckedChange={(checked) => 
                      setImportSettings(prev => ({ ...prev, autoCategorize: checked as boolean }))
                    }
                    data-testid="checkbox-auto-categorize"
                  />
                  <Label htmlFor="auto-categorize" className="text-sm">
                    Auto-categorize by metadata
                  </Label>
                </div>

                <div className="flex items-center space-x-3">
                  <Checkbox
                    id="encrypt-content"
                    checked={importSettings.encryptContent}
                    onCheckedChange={(checked) => 
                      setImportSettings(prev => ({ ...prev, encryptContent: checked as boolean }))
                    }
                    data-testid="checkbox-encrypt-content"
                  />
                  <Label htmlFor="encrypt-content" className="text-sm">
                    Encrypt content (add to vault)
                  </Label>
                </div>
              </div>

              <div className="space-y-4">
                <h4 className="font-medium">Quality & Type Settings</h4>

                <div className="space-y-2">
                  <Label htmlFor="quality-select" className="text-sm">Quality</Label>
                  <Select
                    value={importSettings.quality}
                    onValueChange={(value: 'original' | 'high' | 'medium') => 
                      setImportSettings(prev => ({ ...prev, quality: value }))
                    }
                  >
                    <SelectTrigger data-testid="quality-select">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="original">Original Quality</SelectItem>
                      <SelectItem value="high">High Quality (compressed)</SelectItem>
                      <SelectItem value="medium">Medium Quality</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="file-types-select" className="text-sm">File Types</Label>
                  <Select
                    value={importSettings.fileTypes}
                    onValueChange={(value: 'all' | 'images' | 'videos') => 
                      setImportSettings(prev => ({ ...prev, fileTypes: value }))
                    }
                  >
                    <SelectTrigger data-testid="file-types-select">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All file types</SelectItem>
                      <SelectItem value="images">Images only</SelectItem>
                      <SelectItem value="videos">Videos only</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </div>
          </Tabs>
        ) : (
          /* Import Progress */
          <div className="space-y-6" data-testid="import-progress">
            <div className="flex items-center gap-3">
              {getStatusIcon()}
              <div className="flex-1">
                <div className="font-medium">
                  {progress.status === 'connecting' && 'Connecting to Google Photos...'}
                  {progress.status === 'importing' && 'Importing Media Files'}
                  {progress.status === 'completed' && 'Import Completed Successfully!'}
                  {progress.status === 'error' && 'Import Failed'}
                </div>
                <div className="text-sm text-muted-foreground">
                  {progress.currentFile}
                </div>
              </div>
            </div>

            {progress.status === 'importing' && (
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>Progress</span>
                  <span>{progress.processed} / {progress.total}</span>
                </div>
                <Progress value={progressPercentage} className="w-full" />
              </div>
            )}

            {progress.status === 'completed' && (
              <div className="bg-green-50 dark:bg-green-950/20 border border-green-200 dark:border-green-800 rounded-lg p-4">
                <div className="flex items-center gap-2 text-green-700 dark:text-green-300 font-medium mb-2">
                  <CheckCircle className="w-5 h-5" />
                  Import Summary
                </div>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <div className="font-medium">Files Processed</div>
                    <div className="text-muted-foreground">{progress.processed.toLocaleString()}</div>
                  </div>
                  <div>
                    <div className="font-medium">Duplicates Removed</div>
                    <div className="text-muted-foreground">{progress.duplicatesFound}</div>
                  </div>
                </div>
              </div>
            )}

            {progress.status === 'error' && progress.errors.length > 0 && (
              <div className="bg-red-50 dark:bg-red-950/20 border border-red-200 dark:border-red-800 rounded-lg p-4">
                <div className="flex items-center gap-2 text-red-700 dark:text-red-300 font-medium mb-2">
                  <AlertCircle className="w-5 h-5" />
                  Import Errors
                </div>
                <ul className="space-y-1 text-sm">
                  {progress.errors.map((error, index) => (
                    <li key={index} className="text-red-600 dark:text-red-400">
                      • {error}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <div className="flex justify-end space-x-3">
              {progress.status === 'importing' ? (
                <Button variant="outline" onClick={handleClose}>
                  Cancel Import
                </Button>
              ) : (
                <Button onClick={handleClose}>
                  Close
                </Button>
              )}
            </div>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
