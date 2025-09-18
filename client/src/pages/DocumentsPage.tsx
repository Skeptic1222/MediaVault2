import { useState, useEffect, useRef } from 'react';
import { useQuery, useMutation } from '@tanstack/react-query';
import { queryClient, apiRequest } from '@/lib/queryClient';
import { useToast } from '@/hooks/use-toast';
import Navbar from '@/components/ui/navbar';
import DocumentViewer from '@/components/DocumentViewer';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select';
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu';
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Skeleton } from '@/components/ui/skeleton';
import {
  Grid3X3,
  List,
  Search,
  Upload,
  FileText,
  FileSpreadsheet,
  FileImage,
  FileCode,
  File,
  Download,
  Trash2,
  Eye,
  MoreVertical,
  FolderPlus,
  Filter,
  Calendar,
  HardDrive,
  SortAsc,
  SortDesc
} from 'lucide-react';
import { cn } from '@/lib/utils';
import { format } from 'date-fns';

interface Document {
  id: string;
  name: string;
  type: string;
  size: number;
  mimeType?: string;
  createdAt: string | Date;
  updatedAt: string | Date;
  category?: string;
  tags?: string[];
}

type ViewMode = 'grid' | 'list';
type DocumentType = 'all' | 'pdf' | 'text' | 'spreadsheet' | 'presentation' | 'other';
type SortOption = 'name' | 'date' | 'size' | 'type';

export default function DocumentsPage() {
  const { toast } = useToast();
  const [viewMode, setViewMode] = useState<ViewMode>('grid');
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState<DocumentType>('all');
  const [sortBy, setSortBy] = useState<SortOption>('date');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [selectedDocument, setSelectedDocument] = useState<Document | null>(null);
  const [isViewerOpen, setIsViewerOpen] = useState(false);
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Listen to navbar search changes
  useEffect(() => {
    const handleNavbarSearchChange = (event: CustomEvent) => {
      setSearchQuery(event.detail.query || '');
    };

    window.addEventListener('navbarSearchChange' as any, handleNavbarSearchChange as any);
    return () => {
      window.removeEventListener('navbarSearchChange' as any, handleNavbarSearchChange as any);
    };
  }, []);

  // Fetch documents
  const { data: documents = [], isLoading, refetch } = useQuery<Document[]>({
    queryKey: ['/api/documents', searchQuery, filterType, sortBy, sortOrder, selectedCategory],
    queryFn: async () => {
      const params = new URLSearchParams({
        ...(searchQuery && { search: searchQuery }),
        ...(filterType !== 'all' && { type: filterType }),
        ...(selectedCategory && { category: selectedCategory }),
        sortBy,
        sortOrder,
      });
      const response = await fetch(`/api/documents?${params}`);
      if (!response.ok) throw new Error('Failed to fetch documents');
      return response.json();
    },
    retry: false,
  });

  // Fetch categories
  const { data: categories = [] } = useQuery<string[]>({
    queryKey: ['/api/document-categories'],
    queryFn: async () => {
      const response = await fetch('/api/document-categories');
      if (!response.ok) return [];
      return response.json();
    },
    retry: false,
  });

  // Upload document mutation
  const uploadMutation = useMutation({
    mutationFn: async (files: FileList) => {
      const formData = new FormData();
      Array.from(files).forEach(file => {
        formData.append('files', file);
      });
      if (selectedCategory) {
        formData.append('category', selectedCategory);
      }

      const response = await fetch('/api/media/upload', {
        method: 'POST',
        body: formData,
        credentials: 'include'
      });
      
      if (!response.ok) throw new Error('Failed to upload documents');
      return response.json();
    },
    onSuccess: () => {
      refetch();
      toast({
        title: 'Success',
        description: 'Documents uploaded successfully',
      });
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: error.message || 'Failed to upload documents',
        variant: 'destructive',
      });
    },
  });

  // Delete document mutation
  const deleteMutation = useMutation({
    mutationFn: async (documentId: string) => {
      const response = await apiRequest(`/api/documents/${documentId}`, {
        method: 'DELETE',
      });
      return response;
    },
    onSuccess: () => {
      refetch();
      toast({
        title: 'Success',
        description: 'Document deleted successfully',
      });
    },
    onError: (error: Error) => {
      toast({
        title: 'Error',
        description: error.message || 'Failed to delete document',
        variant: 'destructive',
      });
    },
  });

  // Get document icon based on type
  const getDocumentIcon = (mimeType?: string, fileName?: string) => {
    const ext = fileName?.split('.').pop()?.toLowerCase() || '';
    const mime = mimeType?.toLowerCase() || '';
    
    if (mime.includes('pdf') || ext === 'pdf') {
      return <FileText className="h-8 w-8 text-red-500" />;
    }
    if (mime.includes('spreadsheet') || ['xls', 'xlsx', 'csv', 'ods'].includes(ext)) {
      return <FileSpreadsheet className="h-8 w-8 text-green-500" />;
    }
    if (mime.includes('presentation') || ['ppt', 'pptx', 'odp'].includes(ext)) {
      return <FileImage className="h-8 w-8 text-orange-500" />;
    }
    if (['js', 'ts', 'jsx', 'tsx', 'json', 'xml', 'html', 'css', 'py', 'java', 'cpp'].includes(ext)) {
      return <FileCode className="h-8 w-8 text-blue-500" />;
    }
    return <File className="h-8 w-8 text-gray-500" />;
  };

  // Format file size
  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  // Handle file upload
  const handleUpload = () => {
    fileInputRef.current?.click();
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      uploadMutation.mutate(e.target.files);
    }
  };

  // Handle document view
  const handleViewDocument = (doc: Document) => {
    setSelectedDocument(doc);
    setIsViewerOpen(true);
  };

  // Handle document download
  const handleDownload = (doc: Document) => {
    const link = document.createElement('a');
    link.href = `/api/media/${doc.id}`;
    link.download = doc.name;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    
    toast({
      title: 'Download started',
      description: `Downloading ${doc.name}`,
    });
  };

  // Filter documents based on type
  const filteredDocuments = documents.filter(doc => {
    if (filterType === 'all') return true;
    
    const ext = doc.name.split('.').pop()?.toLowerCase() || '';
    const mime = doc.mimeType?.toLowerCase() || '';
    
    switch (filterType) {
      case 'pdf':
        return mime.includes('pdf') || ext === 'pdf';
      case 'text':
        return ['txt', 'md', 'log', 'csv'].includes(ext) || mime.includes('text');
      case 'spreadsheet':
        return ['xls', 'xlsx', 'csv', 'ods'].includes(ext) || mime.includes('spreadsheet');
      case 'presentation':
        return ['ppt', 'pptx', 'odp'].includes(ext) || mime.includes('presentation');
      default:
        return true;
    }
  });

  // Stats calculation
  const stats = {
    total: documents.length,
    pdf: documents.filter(d => d.mimeType?.includes('pdf') || d.name.endsWith('.pdf')).length,
    text: documents.filter(d => ['txt', 'md', 'log', 'csv'].some(ext => d.name.endsWith(`.${ext}`))).length,
    office: documents.filter(d => ['doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'].some(ext => d.name.endsWith(`.${ext}`))).length,
    totalSize: documents.reduce((acc, d) => acc + (d.size || 0), 0),
  };

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      
      <div className="pt-16 px-4 sm:px-6 lg:px-8 max-w-7xl mx-auto">
        {/* Header */}
        <div className="py-6 border-b">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h1 className="text-3xl font-bold">Documents</h1>
              <p className="text-muted-foreground mt-1">
                Manage and view your documents
              </p>
            </div>
            
            <Button onClick={handleUpload} data-testid="button-upload-document">
              <Upload className="h-4 w-4 mr-2" />
              Upload Documents
            </Button>
            
            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept=".pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.txt,.md,.csv,.json,.xml"
              onChange={handleFileSelect}
              className="hidden"
            />
          </div>

          {/* Stats */}
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mt-6">
            <Card>
              <CardContent className="p-4">
                <div className="text-2xl font-bold">{stats.total}</div>
                <div className="text-xs text-muted-foreground">Total Documents</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="text-2xl font-bold">{stats.pdf}</div>
                <div className="text-xs text-muted-foreground">PDFs</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="text-2xl font-bold">{stats.text}</div>
                <div className="text-xs text-muted-foreground">Text Files</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="text-2xl font-bold">{stats.office}</div>
                <div className="text-xs text-muted-foreground">Office Documents</div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="p-4">
                <div className="text-2xl font-bold">{formatFileSize(stats.totalSize)}</div>
                <div className="text-xs text-muted-foreground">Total Size</div>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Filters and Controls */}
        <div className="py-4 flex items-center justify-between">
          <div className="flex items-center gap-4">
            {/* Search */}
            <div className="relative">
              <Input
                type="search"
                placeholder="Search documents..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-64 pl-10"
                data-testid="input-search-documents"
              />
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
            </div>

            {/* Filter by type */}
            <Select value={filterType} onValueChange={(value) => setFilterType(value as DocumentType)}>
              <SelectTrigger className="w-40" data-testid="select-document-type">
                <SelectValue placeholder="All Types" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Types</SelectItem>
                <SelectItem value="pdf">PDF</SelectItem>
                <SelectItem value="text">Text</SelectItem>
                <SelectItem value="spreadsheet">Spreadsheet</SelectItem>
                <SelectItem value="presentation">Presentation</SelectItem>
                <SelectItem value="other">Other</SelectItem>
              </SelectContent>
            </Select>

            {/* Category filter */}
            {categories.length > 0 && (
              <Select value={selectedCategory || ''} onValueChange={(value) => setSelectedCategory(value || null)}>
                <SelectTrigger className="w-40" data-testid="select-category">
                  <SelectValue placeholder="All Categories" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="">All Categories</SelectItem>
                  {categories.map(cat => (
                    <SelectItem key={cat} value={cat}>{cat}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}

            {/* Sort */}
            <Select value={`${sortBy}-${sortOrder}`} onValueChange={(value) => {
              const [newSortBy, newSortOrder] = value.split('-');
              setSortBy(newSortBy as SortOption);
              setSortOrder(newSortOrder as 'asc' | 'desc');
            }}>
              <SelectTrigger className="w-40" data-testid="select-sort">
                <SelectValue placeholder="Sort by" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="name-asc">Name (A-Z)</SelectItem>
                <SelectItem value="name-desc">Name (Z-A)</SelectItem>
                <SelectItem value="date-desc">Newest First</SelectItem>
                <SelectItem value="date-asc">Oldest First</SelectItem>
                <SelectItem value="size-desc">Largest First</SelectItem>
                <SelectItem value="size-asc">Smallest First</SelectItem>
                <SelectItem value="type-asc">Type</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* View mode toggle */}
          <div className="flex items-center border rounded-lg">
            <Button
              variant={viewMode === 'grid' ? 'default' : 'ghost'}
              size="sm"
              onClick={() => setViewMode('grid')}
              className="rounded-none rounded-l-lg"
              data-testid="button-view-grid"
            >
              <Grid3X3 className="h-4 w-4" />
            </Button>
            <Button
              variant={viewMode === 'list' ? 'default' : 'ghost'}
              size="sm"
              onClick={() => setViewMode('list')}
              className="rounded-none rounded-r-lg"
              data-testid="button-view-list"
            >
              <List className="h-4 w-4" />
            </Button>
          </div>
        </div>

        {/* Documents Display */}
        <ScrollArea className="h-[calc(100vh-380px)]">
          {isLoading ? (
            <div className={cn(
              viewMode === 'grid' 
                ? "grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-4"
                : "space-y-2"
            )}>
              {[...Array(8)].map((_, i) => (
                <Skeleton key={i} className={viewMode === 'grid' ? "h-48" : "h-16"} />
              ))}
            </div>
          ) : filteredDocuments.length === 0 ? (
            <div className="text-center py-12">
              <FileText className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
              <h3 className="text-lg font-medium mb-1">No documents found</h3>
              <p className="text-sm text-muted-foreground">
                {searchQuery ? 'Try adjusting your search or filters' : 'Upload some documents to get started'}
              </p>
            </div>
          ) : viewMode === 'grid' ? (
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-5 gap-4">
              {filteredDocuments.map(doc => (
                <Card
                  key={doc.id}
                  className="group hover:shadow-lg transition-shadow cursor-pointer"
                  onClick={() => handleViewDocument(doc)}
                  data-testid={`document-card-${doc.id}`}
                >
                  <CardContent className="p-4">
                    <div className="flex flex-col items-center">
                      <div className="mb-3">
                        {getDocumentIcon(doc.mimeType, doc.name)}
                      </div>
                      <h3 className="font-medium text-sm text-center mb-2 line-clamp-2" title={doc.name}>
                        {doc.name}
                      </h3>
                      <div className="text-xs text-muted-foreground text-center">
                        {formatFileSize(doc.size)}
                      </div>
                      <div className="text-xs text-muted-foreground text-center mt-1">
                        {format(new Date(doc.updatedAt), 'MMM d, yyyy')}
                      </div>
                      
                      <div className="mt-3 flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleViewDocument(doc);
                          }}
                          data-testid={`button-view-${doc.id}`}
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8"
                          onClick={(e) => {
                            e.stopPropagation();
                            handleDownload(doc);
                          }}
                          data-testid={`button-download-${doc.id}`}
                        >
                          <Download className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-8 w-8"
                          onClick={(e) => {
                            e.stopPropagation();
                            if (confirm('Delete this document?')) {
                              deleteMutation.mutate(doc.id);
                            }
                          }}
                          data-testid={`button-delete-${doc.id}`}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <div className="space-y-2">
              {filteredDocuments.map(doc => (
                <Card
                  key={doc.id}
                  className="hover:shadow-md transition-shadow"
                  data-testid={`document-row-${doc.id}`}
                >
                  <CardContent className="p-4 flex items-center justify-between">
                    <div className="flex items-center gap-4">
                      {getDocumentIcon(doc.mimeType, doc.name)}
                      <div>
                        <h3 className="font-medium">{doc.name}</h3>
                        <div className="text-sm text-muted-foreground">
                          {formatFileSize(doc.size)} • {format(new Date(doc.updatedAt), 'MMM d, yyyy h:mm a')}
                        </div>
                      </div>
                    </div>
                    
                    <div className="flex items-center gap-2">
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => handleViewDocument(doc)}
                        data-testid={`button-view-${doc.id}`}
                      >
                        <Eye className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={() => handleDownload(doc)}
                        data-testid={`button-download-${doc.id}`}
                      >
                        <Download className="h-4 w-4" />
                      </Button>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon" data-testid={`button-menu-${doc.id}`}>
                            <MoreVertical className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem onClick={() => handleViewDocument(doc)}>
                            <Eye className="h-4 w-4 mr-2" />
                            View
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleDownload(doc)}>
                            <Download className="h-4 w-4 mr-2" />
                            Download
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            onClick={() => {
                              if (confirm('Delete this document?')) {
                                deleteMutation.mutate(doc.id);
                              }
                            }}
                            className="text-destructive"
                          >
                            <Trash2 className="h-4 w-4 mr-2" />
                            Delete
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </ScrollArea>

        {/* Document Viewer Modal */}
        {selectedDocument && (
          <DocumentViewer
            fileId={selectedDocument.id}
            fileName={selectedDocument.name}
            fileType={selectedDocument.type}
            mimeType={selectedDocument.mimeType}
            isModal={isViewerOpen}
            onClose={() => {
              setIsViewerOpen(false);
              setSelectedDocument(null);
            }}
          />
        )}
      </div>
    </div>
  );
}