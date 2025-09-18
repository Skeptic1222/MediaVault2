import { X, Download, Share2, Trash2, Move, Copy, Tag, Lock, Unlock, Calendar, HardDrive, Camera, MapPin, Eye, AlertCircle, FileText } from 'lucide-react';
import { Sheet, SheetContent, SheetHeader, SheetTitle, SheetDescription } from '@/components/ui/sheet';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Skeleton } from '@/components/ui/skeleton';
import { Alert, AlertDescription } from '@/components/ui/alert';
import { useState } from 'react';
import DocumentViewer from '@/components/DocumentViewer';
import { useMutation, useQuery } from '@tanstack/react-query';
import { apiRequest, queryClient } from '@/lib/queryClient';
import { useToast } from '@/hooks/use-toast';
import { format } from 'date-fns';

// Type definitions
interface FileItem {
  id: string;
  name: string;
  type: 'file' | 'folder';
  size?: number;
  mimeType?: string;
  path?: string;
  thumbnailUrl?: string;
  isEncrypted?: boolean;
  createdAt: string | Date;
  updatedAt: string | Date;
  hash?: string;
}

interface Tag {
  id: string;
  name: string;
  color?: string;
}

interface ExifData {
  camera?: string;
  lens?: string;
  iso?: number;
  aperture?: number;
  shutterSpeed?: string;
  focalLength?: number;
  dateTaken?: string;
  gps?: {
    lat: number;
    lng: number;
  };
}

interface Metadata {
  exif?: ExifData;
  dimensions?: {
    width: number;
    height: number;
    aspectRatio: string;
  };
  colorSpace?: string;
  bitDepth?: number;
}

interface FileDetailsPanelProps {
  file: FileItem | null;
  isOpen: boolean;
  onClose: () => void;
  onDelete?: (fileId: string) => void;
  onMove?: (fileId: string) => void;
  onShare?: (fileId: string) => void;
  onDownload?: (fileId: string) => void;
  onCopy?: (fileId: string) => void;
}

export function FileDetailsPanel({ file, isOpen, onClose, onDelete, onMove, onShare, onDownload, onCopy }: FileDetailsPanelProps) {
  const { toast } = useToast();
  const [newTag, setNewTag] = useState('');
  const [showDocumentViewer, setShowDocumentViewer] = useState(false);

  // Fetch file tags
  const { data: tags = [], isLoading: tagsLoading, isError: tagsError } = useQuery<Tag[]>({
    queryKey: ['/api/files', file?.id, 'tags'],
    enabled: !!file?.id && file?.type === 'file',
  });

  // Fetch file metadata with EXIF
  const { data: metadata, isLoading: metadataLoading, isError: metadataError } = useQuery<Metadata>({
    queryKey: ['/api/files', file?.id, 'metadata'],
    enabled: !!file?.id && file?.type === 'file',
  });

  // Add tag mutation
  const addTagMutation = useMutation({
    mutationFn: async (tagName: string) => {
      const tagResponse = await apiRequest('/api/tags', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: tagName, color: generateRandomColor() }),
      });
      const tagData = await tagResponse.json();
      
      await apiRequest(`/api/files/${file!.id}/tags`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tagId: tagData.id }),
      });
      
      return tagData;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/files', file?.id, 'tags'] });
      setNewTag('');
      toast({
        title: 'Tag added',
        description: 'The tag has been added to the file.',
      });
    },
    onError: () => {
      toast({
        title: 'Error',
        description: 'Failed to add tag.',
        variant: 'destructive',
      });
    },
  });

  // Remove tag mutation
  const removeTagMutation = useMutation({
    mutationFn: async (tagId: string) => {
      const response = await apiRequest(`/api/files/${file!.id}/tags/${tagId}`, {
        method: 'DELETE',
      });
      return response;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['/api/files', file?.id, 'tags'] });
      toast({
        title: 'Tag removed',
        description: 'The tag has been removed from the file.',
      });
    },
  });

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const generateRandomColor = () => {
    const colors = ['red', 'blue', 'green', 'yellow', 'purple', 'pink', 'orange', 'cyan'];
    return colors[Math.floor(Math.random() * colors.length)];
  };

  const getFileIcon = () => {
    if (!file) return null;
    if (file.type === 'folder') return '📁';
    
    const mimeType = file.mimeType || '';
    if (mimeType.startsWith('image/')) return '🖼️';
    if (mimeType.startsWith('video/')) return '🎬';
    if (mimeType.startsWith('audio/')) return '🎵';
    if (mimeType.includes('pdf')) return '📄';
    if (mimeType.includes('document') || mimeType.includes('text')) return '📝';
    if (mimeType.includes('spreadsheet')) return '📊';
    if (mimeType.includes('presentation')) return '📈';
    if (mimeType.includes('zip') || mimeType.includes('archive')) return '📦';
    return '📎';
  };

  const isDocument = () => {
    if (!file) return false;
    const ext = file.name?.split('.').pop()?.toLowerCase() || '';
    const mime = file.mimeType?.toLowerCase() || '';
    
    const documentExts = ['pdf', 'txt', 'md', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'csv', 'json', 'xml', 'log'];
    const documentMimes = ['pdf', 'text', 'document', 'spreadsheet', 'presentation', 'json', 'xml'];
    
    return documentExts.includes(ext) || documentMimes.some(m => mime.includes(m));
  };

  if (!file) return null;

  // Show DocumentViewer when requested
  if (showDocumentViewer && isDocument()) {
    return (
      <DocumentViewer
        fileId={file.id}
        fileName={file.name}
        fileType={file.type}
        mimeType={file.mimeType}
        isModal={true}
        onClose={() => {
          setShowDocumentViewer(false);
          onClose();
        }}
      />
    );
  }

  return (
    <Sheet open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <SheetContent className="w-[400px] sm:w-[540px]" data-testid="file-details-panel">
        <SheetHeader>
          <div className="flex items-center justify-between">
            <SheetTitle className="flex items-center gap-2">
              <span className="text-2xl">{getFileIcon()}</span>
              <span className="truncate">{file.name}</span>
            </SheetTitle>
            <Button variant="ghost" size="icon" onClick={onClose} data-testid="details-panel-close">
              <X className="h-4 w-4" />
            </Button>
          </div>
          <SheetDescription>
            {file.type === 'folder' ? 'Folder' : file.mimeType || 'File'}
          </SheetDescription>
        </SheetHeader>

        <Tabs defaultValue="details" className="mt-6">
          <TabsList className="grid w-full grid-cols-3">
            <TabsTrigger value="details">Details</TabsTrigger>
            <TabsTrigger value="metadata">Metadata</TabsTrigger>
            <TabsTrigger value="sharing">Sharing</TabsTrigger>
          </TabsList>

          <TabsContent value="details">
            <ScrollArea className="h-[calc(100vh-250px)]">
              {/* Preview */}
              {file.type === 'file' && isDocument() && (
                <Card 
                  className="mb-4 bg-muted/10 flex flex-col items-center justify-center p-8 cursor-pointer hover:bg-muted/20 transition-colors"
                  onClick={() => setShowDocumentViewer(true)}
                  data-testid="preview-document"
                >
                  <FileText className="h-12 w-12 text-muted-foreground mb-2" />
                  <p className="text-sm text-muted-foreground">Click to preview document</p>
                </Card>
              )}
              {file.type === 'file' && !isDocument() && file.thumbnailUrl && (
                <Card className="mb-4">
                  <CardContent className="p-4">
                    <img
                      src={file.thumbnailUrl}
                      alt={file.name}
                      className="w-full h-48 object-cover rounded"
                    />
                  </CardContent>
                </Card>
              )}

              {/* Basic Info */}
              <Card className="mb-4">
                <CardHeader>
                  <CardTitle className="text-sm">Information</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div className="flex justify-between">
                    <span className="text-sm text-muted-foreground">Type</span>
                    <span className="text-sm">{file.type === 'folder' ? 'Folder' : file.mimeType}</span>
                  </div>
                  {file.size !== undefined && (
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Size</span>
                      <span className="text-sm">{formatFileSize(file.size)}</span>
                    </div>
                  )}
                  <div className="flex justify-between">
                    <span className="text-sm text-muted-foreground">Created</span>
                    <span className="text-sm">{format(new Date(file.createdAt), 'PPp')}</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-sm text-muted-foreground">Modified</span>
                    <span className="text-sm">{format(new Date(file.updatedAt), 'PPp')}</span>
                  </div>
                  {file.path && (
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Path</span>
                      <span className="text-sm truncate">{file.path}</span>
                    </div>
                  )}
                  {file.isEncrypted && (
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Security</span>
                      <Badge variant="secondary" className="gap-1">
                        <Lock className="h-3 w-3" />
                        Encrypted
                      </Badge>
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Tags */}
              {file.type === 'file' && (
                <Card className="mb-4">
                  <CardHeader>
                    <CardTitle className="text-sm">Tags</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {tagsLoading ? (
                      <div className="space-y-2">
                        <div className="flex gap-2">
                          <Skeleton className="h-6 w-16" />
                          <Skeleton className="h-6 w-20" />
                          <Skeleton className="h-6 w-18" />
                        </div>
                        <Skeleton className="h-10 w-full" />
                      </div>
                    ) : tagsError ? (
                      <Alert variant="destructive">
                        <AlertCircle className="h-4 w-4" />
                        <AlertDescription>
                          Failed to load tags. Please try again.
                        </AlertDescription>
                      </Alert>
                    ) : (
                      <>
                        <div className="flex flex-wrap gap-2 mb-3">
                          {tags.map((tag) => (
                            <Badge
                              key={tag.id}
                              variant="secondary"
                              className="gap-1"
                              data-testid={`tag-${tag.id}`}
                            >
                              {tag.name}
                              <button
                                onClick={() => removeTagMutation.mutate(tag.id)}
                                className="ml-1 hover:text-destructive"
                                data-testid={`remove-tag-${tag.id}`}
                              >
                                <X className="h-3 w-3" />
                              </button>
                            </Badge>
                          ))}
                        </div>
                        <div className="flex gap-2">
                          <Input
                            placeholder="Add a tag..."
                            value={newTag}
                            onChange={(e) => setNewTag(e.target.value)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' && newTag.trim()) {
                                addTagMutation.mutate(newTag.trim());
                              }
                            }}
                            data-testid="add-tag-input"
                          />
                          <Button
                            size="sm"
                            onClick={() => newTag.trim() && addTagMutation.mutate(newTag.trim())}
                            disabled={!newTag.trim()}
                            data-testid="add-tag-button"
                          >
                            <Tag className="h-4 w-4" />
                          </Button>
                        </div>
                      </>
                    )}
                  </CardContent>
                </Card>
              )}

              {/* Actions */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Actions</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-2">
                    {file.type === 'file' && (
                      <Button 
                        variant="outline" 
                        size="sm" 
                        onClick={() => onDownload?.(file.id)}
                        data-testid="download-file"
                      >
                        <Download className="h-4 w-4 mr-2" />
                        Download
                      </Button>
                    )}
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => onShare?.(file.id)}
                      data-testid="share-file"
                    >
                      <Share2 className="h-4 w-4 mr-2" />
                      Share
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => onMove?.(file.id)}
                      data-testid="move-file"
                    >
                      <Move className="h-4 w-4 mr-2" />
                      Move
                    </Button>
                    {file.type === 'file' && (
                      <Button 
                        variant="outline" 
                        size="sm" 
                        onClick={() => onCopy?.(file.id)}
                        data-testid="copy-file"
                      >
                        <Copy className="h-4 w-4 mr-2" />
                        Copy
                      </Button>
                    )}
                    <Button
                      variant="outline"
                      size="sm"
                      className="text-destructive col-span-2"
                      onClick={() => onDelete?.(file.id)}
                      data-testid="delete-file"
                    >
                      <Trash2 className="h-4 w-4 mr-2" />
                      Delete
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </ScrollArea>
          </TabsContent>

          <TabsContent value="metadata">
            <ScrollArea className="h-[calc(100vh-250px)]">
              {metadataLoading ? (
                <Card className="mb-4">
                  <CardHeader>
                    <CardTitle className="text-sm">Loading Metadata...</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      <Skeleton className="h-4 w-full" />
                      <Skeleton className="h-4 w-3/4" />
                      <Skeleton className="h-4 w-5/6" />
                      <Skeleton className="h-4 w-2/3" />
                    </div>
                  </CardContent>
                </Card>
              ) : metadataError ? (
                <Alert variant="destructive">
                  <AlertCircle className="h-4 w-4" />
                  <AlertDescription>
                    Failed to load metadata. Please try again.
                  </AlertDescription>
                </Alert>
              ) : (
                <>
                  {metadata?.exif && (
                    <Card className="mb-4">
                      <CardHeader>
                        <CardTitle className="text-sm">EXIF Data</CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-2">
                        {metadata.exif?.camera && (
                          <div className="flex justify-between">
                            <span className="text-sm text-muted-foreground flex items-center gap-1">
                              <Camera className="h-3 w-3" />
                              Camera
                            </span>
                            <span className="text-sm">{metadata.exif.camera}</span>
                          </div>
                        )}
                        {metadata.exif?.lens && (
                          <div className="flex justify-between">
                            <span className="text-sm text-muted-foreground">Lens</span>
                            <span className="text-sm">{metadata.exif.lens}</span>
                          </div>
                        )}
                        {metadata.exif?.iso && (
                          <div className="flex justify-between">
                            <span className="text-sm text-muted-foreground">ISO</span>
                            <span className="text-sm">{metadata.exif.iso}</span>
                          </div>
                        )}
                        {metadata.exif?.aperture && (
                          <div className="flex justify-between">
                            <span className="text-sm text-muted-foreground">Aperture</span>
                            <span className="text-sm">f/{metadata.exif.aperture}</span>
                          </div>
                        )}
                        {metadata.exif?.shutterSpeed && (
                          <div className="flex justify-between">
                            <span className="text-sm text-muted-foreground">Shutter Speed</span>
                            <span className="text-sm">{metadata.exif.shutterSpeed}</span>
                          </div>
                        )}
                        {metadata.exif?.focalLength && (
                          <div className="flex justify-between">
                            <span className="text-sm text-muted-foreground">Focal Length</span>
                            <span className="text-sm">{metadata.exif.focalLength}mm</span>
                          </div>
                        )}
                        {metadata.exif?.dateTaken && (
                          <div className="flex justify-between">
                            <span className="text-sm text-muted-foreground flex items-center gap-1">
                              <Calendar className="h-3 w-3" />
                              Date Taken
                            </span>
                            <span className="text-sm">{format(new Date(metadata.exif.dateTaken), 'PPp')}</span>
                          </div>
                        )}
                        {metadata.exif?.gps && (
                          <div className="flex justify-between">
                            <span className="text-sm text-muted-foreground flex items-center gap-1">
                              <MapPin className="h-3 w-3" />
                              Location
                            </span>
                            <span className="text-sm">
                              {metadata.exif.gps.lat}, {metadata.exif.gps.lng}
                            </span>
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  )}
                </>
              )}

              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Technical Details</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  {metadata?.dimensions && (
                    <>
                      <div className="flex justify-between">
                        <span className="text-sm text-muted-foreground">Dimensions</span>
                        <span className="text-sm">{metadata.dimensions.width} × {metadata.dimensions.height}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-sm text-muted-foreground">Aspect Ratio</span>
                        <span className="text-sm">{metadata.dimensions.aspectRatio}</span>
                      </div>
                    </>
                  )}
                  {metadata?.colorSpace && (
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Color Space</span>
                      <span className="text-sm">{metadata.colorSpace}</span>
                    </div>
                  )}
                  {metadata?.bitDepth && (
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">Bit Depth</span>
                      <span className="text-sm">{metadata.bitDepth} bits</span>
                    </div>
                  )}
                  {file.hash && (
                    <div className="flex justify-between">
                      <span className="text-sm text-muted-foreground">SHA-256 Hash</span>
                      <span className="text-sm font-mono truncate">{file.hash}</span>
                    </div>
                  )}
                </CardContent>
              </Card>
            </ScrollArea>
          </TabsContent>

          <TabsContent value="sharing">
            <ScrollArea className="h-[calc(100vh-250px)]">
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Sharing & Permissions</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Eye className="h-4 w-4 text-muted-foreground" />
                        <span className="text-sm">Visibility</span>
                      </div>
                      <Badge variant="outline">Private</Badge>
                    </div>
                    
                    <Separator />
                    
                    <div className="space-y-2">
                      <p className="text-sm text-muted-foreground">Share with others</p>
                      <Input placeholder="Enter email address..." data-testid="share-email-input" />
                      <Button className="w-full" size="sm" data-testid="send-share-invite">
                        Send Invite
                      </Button>
                    </div>

                    <Separator />

                    <div className="space-y-2">
                      <p className="text-sm text-muted-foreground">Create shareable link</p>
                      <div className="flex gap-2">
                        <Button variant="outline" size="sm" className="flex-1" data-testid="create-share-link">
                          Generate Link
                        </Button>
                        <Button variant="outline" size="sm" data-testid="copy-share-link">
                          <Copy className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </ScrollArea>
          </TabsContent>
        </Tabs>
      </SheetContent>
    </Sheet>
  );
}