import { useState, useRef, useEffect } from 'react';
import { Button } from '@/components/ui/button';
import { Card } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Skeleton } from '@/components/ui/skeleton';
import { Alert, AlertDescription } from '@/components/ui/alert';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import {
  Download,
  Expand,
  Printer,
  X,
  FileText,
  ChevronLeft,
  ChevronRight,
  ZoomIn,
  ZoomOut,
  RotateCw,
  Copy,
  Maximize2,
  Minimize2
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { useToast } from '@/hooks/use-toast';
import { useMutation } from '@tanstack/react-query';
import { apiRequest } from '@/lib/queryClient';

interface DocumentViewerProps {
  fileId: string;
  fileName: string;
  fileType: string;
  mimeType?: string;
  fileUrl?: string;
  onClose?: () => void;
  isModal?: boolean;
  className?: string;
}

type DocumentType = 'pdf' | 'text' | 'office' | 'image' | 'code' | 'markdown' | 'unknown';

export default function DocumentViewer({
  fileId,
  fileName,
  fileType,
  mimeType,
  fileUrl,
  onClose,
  isModal = false,
  className
}: DocumentViewerProps) {
  const { toast } = useToast();
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [content, setContent] = useState<string>('');
  const [isFullscreen, setIsFullscreen] = useState(false);
  const [zoom, setZoom] = useState(100);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [accessToken, setAccessToken] = useState<string | null>(null);
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  
  // Determine document type
  const getDocumentType = (): DocumentType => {
    const ext = fileName.split('.').pop()?.toLowerCase() || '';
    const mime = mimeType?.toLowerCase() || '';
    
    if (mime.includes('pdf') || ext === 'pdf') return 'pdf';
    if (mime.includes('image') || ['jpg', 'jpeg', 'png', 'gif', 'svg', 'webp'].includes(ext)) return 'image';
    if (['txt', 'log', 'csv', 'tsv'].includes(ext) || mime.includes('text/plain')) return 'text';
    if (['js', 'jsx', 'ts', 'tsx', 'py', 'java', 'cpp', 'c', 'h', 'css', 'html', 'xml', 'json', 'yaml', 'yml', 'sh', 'bash'].includes(ext)) return 'code';
    if (['md', 'markdown'].includes(ext)) return 'markdown';
    if (['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'odt', 'ods', 'odp'].includes(ext) || 
        mime.includes('officedocument') || mime.includes('msword') || mime.includes('ms-excel') || 
        mime.includes('ms-powerpoint') || mime.includes('opendocument')) return 'office';
    
    return 'unknown';
  };

  const docType = getDocumentType();
  
  // Generate access token for direct media access
  const generateTokenMutation = useMutation({
    mutationFn: async (): Promise<{ token: string }> => {
      const response = await apiRequest(`/api/media/${fileId}/access-token`, {
        method: 'POST',
      });
      return response.json();
    },
    onSuccess: (data: { token: string }) => {
      setAccessToken(data.token);
    },
    onError: (error) => {
      console.error('Failed to generate access token:', error);
      setError('Failed to load document');
      setLoading(false);
    },
  });
  
  const documentUrl = fileUrl || (accessToken ? `/api/media/${fileId}?token=${accessToken}` : `/api/media/${fileId}`);

  // Generate access token when component mounts
  useEffect(() => {
    if (!fileUrl && !accessToken) {
      generateTokenMutation.mutate();
    }
  }, [fileId]);
  
  // Load text content for text-based documents
  useEffect(() => {
    if (docType === 'text' || docType === 'code' || docType === 'markdown') {
      if (!accessToken && !fileUrl) {
        return; // Wait for token
      }
      setLoading(true);
      fetch(documentUrl)
        .then(res => {
          if (!res.ok) throw new Error('Failed to load document');
          return res.text();
        })
        .then(text => {
          setContent(text);
          setLoading(false);
        })
        .catch(err => {
          setError(err.message);
          setLoading(false);
        });
    } else if (accessToken || fileUrl) {
      setLoading(false);
    }
  }, [documentUrl, docType, accessToken]);

  // Handle download
  const handleDownload = () => {
    const link = document.createElement('a');
    link.href = documentUrl;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    toast({
      title: 'Download started',
      description: `Downloading ${fileName}`,
    });
  };

  // Handle print
  const handlePrint = () => {
    if (docType === 'pdf' && iframeRef.current?.contentWindow) {
      iframeRef.current.contentWindow.print();
    } else if (docType === 'text' || docType === 'code' || docType === 'markdown') {
      const printWindow = window.open('', '_blank');
      if (printWindow) {
        printWindow.document.write(`
          <html>
            <head>
              <title>${fileName}</title>
              <style>
                body { font-family: monospace; white-space: pre-wrap; }
              </style>
            </head>
            <body>${content}</body>
          </html>
        `);
        printWindow.document.close();
        printWindow.print();
      }
    } else {
      toast({
        title: 'Print not available',
        description: 'Printing is not available for this document type',
        variant: 'destructive',
      });
    }
  };

  // Handle copy text
  const handleCopy = () => {
    if (content) {
      navigator.clipboard.writeText(content).then(() => {
        toast({
          title: 'Copied to clipboard',
          description: 'Document content has been copied',
        });
      });
    }
  };

  // Handle fullscreen
  const toggleFullscreen = () => {
    if (!document.fullscreenElement && containerRef.current) {
      containerRef.current.requestFullscreen();
      setIsFullscreen(true);
    } else if (document.fullscreenElement) {
      document.exitFullscreen();
      setIsFullscreen(false);
    }
  };

  // Handle zoom
  const handleZoomIn = () => setZoom(prev => Math.min(prev + 25, 200));
  const handleZoomOut = () => setZoom(prev => Math.max(prev - 25, 50));
  const handleResetZoom = () => setZoom(100);

  // Render viewer toolbar
  const renderToolbar = () => (
    <div className="flex items-center justify-between p-2 border-b bg-background/95 backdrop-blur">
      <div className="flex items-center gap-2">
        <FileText className="h-5 w-5 text-muted-foreground" />
        <span className="text-sm font-medium truncate max-w-[200px]" title={fileName}>
          {fileName}
        </span>
        {docType === 'pdf' && totalPages > 1 && (
          <span className="text-sm text-muted-foreground">
            Page {currentPage} of {totalPages}
          </span>
        )}
      </div>
      
      <div className="flex items-center gap-1">
        {/* Zoom controls for PDFs and images */}
        {(docType === 'pdf' || docType === 'image') && (
          <>
            <Button
              variant="ghost"
              size="icon"
              onClick={handleZoomOut}
              title="Zoom out"
              data-testid="button-zoom-out"
            >
              <ZoomOut className="h-4 w-4" />
            </Button>
            <span className="text-sm px-2">{zoom}%</span>
            <Button
              variant="ghost"
              size="icon"
              onClick={handleZoomIn}
              title="Zoom in"
              data-testid="button-zoom-in"
            >
              <ZoomIn className="h-4 w-4" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              onClick={handleResetZoom}
              title="Reset zoom"
              data-testid="button-reset-zoom"
            >
              <RotateCw className="h-4 w-4" />
            </Button>
            <div className="w-px h-4 bg-border mx-1" />
          </>
        )}

        {/* Copy button for text documents */}
        {(docType === 'text' || docType === 'code' || docType === 'markdown') && (
          <Button
            variant="ghost"
            size="icon"
            onClick={handleCopy}
            title="Copy to clipboard"
            data-testid="button-copy"
          >
            <Copy className="h-4 w-4" />
          </Button>
        )}

        {/* Print button */}
        {(docType === 'pdf' || docType === 'text' || docType === 'code' || docType === 'markdown') && (
          <Button
            variant="ghost"
            size="icon"
            onClick={handlePrint}
            title="Print"
            data-testid="button-print"
          >
            <Printer className="h-4 w-4" />
          </Button>
        )}

        {/* Download button */}
        <Button
          variant="ghost"
          size="icon"
          onClick={handleDownload}
          title="Download"
          data-testid="button-download"
        >
          <Download className="h-4 w-4" />
        </Button>

        {/* Fullscreen button */}
        <Button
          variant="ghost"
          size="icon"
          onClick={toggleFullscreen}
          title={isFullscreen ? "Exit fullscreen" : "Enter fullscreen"}
          data-testid="button-fullscreen"
        >
          {isFullscreen ? <Minimize2 className="h-4 w-4" /> : <Maximize2 className="h-4 w-4" />}
        </Button>

        {/* Close button for modals */}
        {isModal && onClose && (
          <>
            <div className="w-px h-4 bg-border mx-1" />
            <Button
              variant="ghost"
              size="icon"
              onClick={onClose}
              title="Close"
              data-testid="button-close"
            >
              <X className="h-4 w-4" />
            </Button>
          </>
        )}
      </div>
    </div>
  );

  // Render content based on document type
  const renderContent = () => {
    if (loading) {
      return (
        <div className="flex items-center justify-center h-full p-8">
          <div className="text-center">
            <Skeleton className="h-12 w-12 rounded-full mx-auto mb-4" />
            <Skeleton className="h-4 w-32 mx-auto mb-2" />
            <Skeleton className="h-3 w-24 mx-auto" />
          </div>
        </div>
      );
    }

    if (error) {
      return (
        <div className="flex items-center justify-center h-full p-8">
          <Alert className="max-w-md">
            <AlertDescription>
              <strong>Error loading document:</strong> {error}
            </AlertDescription>
          </Alert>
        </div>
      );
    }

    switch (docType) {
      case 'pdf':
        return (
          <div className="h-full w-full bg-gray-100 dark:bg-gray-900">
            <iframe
              ref={iframeRef}
              src={`${documentUrl}#toolbar=0&view=FitH&zoom=${zoom}`}
              className="w-full h-full border-0"
              style={{ transform: `scale(${zoom / 100})`, transformOrigin: 'top left' }}
              onLoad={() => setLoading(false)}
              title={fileName}
              data-testid="pdf-viewer"
            />
          </div>
        );

      case 'image':
        return (
          <div className="h-full w-full flex items-center justify-center bg-gray-100 dark:bg-gray-900 p-4">
            <img
              src={documentUrl}
              alt={fileName}
              className="max-w-full max-h-full object-contain"
              style={{ transform: `scale(${zoom / 100})` }}
              onLoad={() => setLoading(false)}
              onError={() => setError('Failed to load image')}
              data-testid="image-viewer"
            />
          </div>
        );

      case 'text':
      case 'code':
        return (
          <ScrollArea className="h-full w-full">
            <pre className="p-4 text-sm font-mono whitespace-pre-wrap break-words">
              <code data-testid="text-viewer">{content}</code>
            </pre>
          </ScrollArea>
        );

      case 'markdown':
        return (
          <ScrollArea className="h-full w-full">
            <div className="p-6 prose dark:prose-invert max-w-none" data-testid="markdown-viewer">
              <pre className="whitespace-pre-wrap">{content}</pre>
            </div>
          </ScrollArea>
        );

      case 'office':
        return (
          <div className="flex flex-col items-center justify-center h-full p-8">
            <FileText className="h-16 w-16 text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold mb-2">Office Document</h3>
            <p className="text-sm text-muted-foreground mb-6 text-center">
              This document cannot be viewed directly in the browser.
              <br />
              Please download it to view with appropriate software.
            </p>
            <Button onClick={handleDownload} data-testid="download-office">
              <Download className="h-4 w-4 mr-2" />
              Download {fileName}
            </Button>
          </div>
        );

      default:
        return (
          <div className="flex flex-col items-center justify-center h-full p-8">
            <FileText className="h-16 w-16 text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold mb-2">Unsupported Format</h3>
            <p className="text-sm text-muted-foreground mb-6">
              This file type cannot be previewed.
            </p>
            <Button onClick={handleDownload} data-testid="download-unsupported">
              <Download className="h-4 w-4 mr-2" />
              Download File
            </Button>
          </div>
        );
    }
  };

  const viewerContent = (
    <div
      ref={containerRef}
      className={cn(
        "flex flex-col h-full bg-background",
        isFullscreen && "fixed inset-0 z-50",
        className
      )}
      data-testid="document-viewer"
    >
      {renderToolbar()}
      <div className="flex-1 overflow-hidden">
        {renderContent()}
      </div>
    </div>
  );

  if (isModal) {
    return (
      <Dialog open={true} onOpenChange={(open) => !open && onClose?.()}>
        <DialogContent className="max-w-4xl h-[80vh] p-0">
          {viewerContent}
        </DialogContent>
      </Dialog>
    );
  }

  return viewerContent;
}