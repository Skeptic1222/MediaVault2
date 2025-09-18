import { useState, useEffect, useCallback, useRef } from "react";
import { useQuery, useMutation, useInfiniteQuery } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import { useLocation } from "wouter";
import Navbar from "@/components/ui/navbar";
import StatsBar from "@/components/gallery/StatsBar";
import FilterControls from "@/components/gallery/FilterControls";
import CategoryHierarchy from "@/components/gallery/CategoryHierarchy";
import MediaGrid from "@/components/gallery/MediaGrid";
import MediaListView from "@/components/gallery/MediaListView";
import MediaLightbox from "@/components/gallery/MediaLightbox";
import KeyboardNavigation from "@/components/gallery/KeyboardNavigation";
import ImportModal from "@/components/import/ImportModal";
import { useKeyboardNavigation } from "@/hooks/useKeyboardNavigation";
import { Trash2, Download, Folder, X, CheckSquare } from "lucide-react";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { useToast } from "@/hooks/use-toast";
import type { MediaFile, Category } from "@shared/schema";

// Type definitions for API responses
type MediaResponse = {
  files: MediaFile[];
  total: number;
};

type StatsResponse = {
  totalItems: number;
  images: number;
  videos: number;
  vaultItems: number;
  storageUsed: number;
  duplicatesFound: number;
};

export default function Gallery() {
  const [location, navigate] = useLocation();
  const { toast } = useToast();
  const [view, setView] = useState<'grid' | 'list'>('grid');
  const [selectedItems, setSelectedItems] = useState<Set<string>>(new Set());
  const [focusedIndex, setFocusedIndex] = useState<number>(0);
  
  const [filters, setFilters] = useState({
    categoryId: undefined as string | undefined,
    isVault: false,
    search: '',
    sortBy: 'created_at' as 'created_at' | 'filename' | 'file_size',
    sortOrder: 'desc' as 'asc' | 'desc',
    mimeType: undefined as 'images' | 'videos' | undefined,
  });

  const sentinelRef = useRef<HTMLDivElement>(null);
  const ITEMS_PER_PAGE = 20;

  const [selectedMediaId, setSelectedMediaId] = useState<string | null>(null);
  const [showImportModal, setShowImportModal] = useState(false);
  
  // File operation dialogs
  const [deleteDialog, setDeleteDialog] = useState<{ open: boolean; mediaId: string; filename: string } | null>(null);
  const [renameDialog, setRenameDialog] = useState<{ open: boolean; mediaId: string; filename: string } | null>(null);
  const [moveDialog, setMoveDialog] = useState<{ open: boolean; mediaId: string; filename: string } | null>(null);
  const [bulkMoveDialog, setBulkMoveDialog] = useState<{ open: boolean; mediaIds: string[] } | null>(null);
  const [newFilename, setNewFilename] = useState('');

  const {
    data,
    fetchNextPage,
    hasNextPage,
    isFetchingNextPage,
    isLoading,
  } = useInfiniteQuery<MediaResponse>({
    queryKey: ["/api/media", filters],
    queryFn: async ({ pageParam }) => {
      const params = new URLSearchParams({
        limit: String(ITEMS_PER_PAGE),
        offset: String(pageParam),
        ...Object.entries(filters).reduce((acc, [key, value]) => {
          if (value !== undefined && value !== null && value !== '') {
            acc[key] = String(value);
          }
          return acc;
        }, {} as Record<string, string>),
      });
      const response = await fetch(`/api/media?${params}`);
      if (!response.ok) throw new Error('Failed to fetch media');
      return response.json();
    },
    initialPageParam: 0,
    getNextPageParam: (lastPage, pages) => {
      const totalLoaded = pages.reduce((acc, page) => acc + page.files.length, 0);
      if (totalLoaded < lastPage.total) {
        return totalLoaded;
      }
      return undefined;
    },
    retry: false,
  });

  // Flatten all pages of media files
  const mediaFiles = data?.pages.flatMap(page => page.files) || [];
  const totalItems = data?.pages[0]?.total || 0;

  const { data: categories } = useQuery<Category[]>({
    queryKey: ["/api/categories"],
    retry: false,
  });

  const { data: stats } = useQuery<StatsResponse>({
    queryKey: ["/api/stats"],
    retry: false,
  });

  const {
    selectedIndex,
    isLightboxOpen,
    openLightbox,
    closeLightbox,
    navigateNext,
    navigatePrevious,
  } = useKeyboardNavigation(mediaFiles);

  const handleFilterChange = (newFilters: Partial<{
    categoryId?: string | undefined;
    isVault: boolean;
    search: string;
    sortBy: 'created_at' | 'filename' | 'file_size';
    sortOrder: 'asc' | 'desc';
    mimeType?: 'images' | 'videos' | undefined;
  }>) => {
    setFilters(prev => ({ ...prev, ...newFilters }));
  };

  // Intersection observer for infinite scroll
  useEffect(() => {
    if (!sentinelRef.current) return;

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting && hasNextPage && !isFetchingNextPage) {
          fetchNextPage();
        }
      },
      { threshold: 0.1, rootMargin: '100px' }
    );

    observer.observe(sentinelRef.current);

    return () => {
      if (sentinelRef.current) {
        observer.unobserve(sentinelRef.current);
      }
    };
  }, [hasNextPage, isFetchingNextPage, fetchNextPage]);

  const handleMediaSelect = (mediaId: string, index: number) => {
    setSelectedMediaId(mediaId);
    setFocusedIndex(index);
    openLightbox(index);
  };

  // File operation mutations
  const deleteMutation = useMutation({
    mutationFn: async (mediaId: string) => {
      return await apiRequest(`/api/media/${mediaId}`, {
        method: 'DELETE',
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/media"] });
      queryClient.invalidateQueries({ queryKey: ["/api/stats"] });
      toast({
        title: "Success",
        description: "File deleted successfully",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to delete file",
        variant: "destructive",
      });
    },
  });

  // Bulk delete mutation
  const bulkDeleteMutation = useMutation({
    mutationFn: async (mediaIds: string[]) => {
      const results = await Promise.all(
        mediaIds.map(id => 
          apiRequest(`/api/media/${id}`, { method: 'DELETE' })
            .catch(err => ({ error: err, id }))
        )
      );
      return results;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/media"] });
      queryClient.invalidateQueries({ queryKey: ["/api/stats"] });
      setSelectedItems(new Set());
      toast({
        title: "Success",
        description: `${selectedItems.size} files deleted successfully`,
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to delete some files",
        variant: "destructive",
      });
    },
  });

  const renameMutation = useMutation({
    mutationFn: async ({ mediaId, newName }: { mediaId: string; newName: string }) => {
      return await apiRequest(`/api/media/${mediaId}`, {
        method: 'PATCH',
        body: JSON.stringify({ originalName: newName }),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/media"] });
      toast({
        title: "Success",
        description: "File renamed successfully",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to rename file",
        variant: "destructive",
      });
    },
  });

  const toggleFavoriteMutation = useMutation({
    mutationFn: async ({ mediaId, isFavorite }: { mediaId: string; isFavorite: boolean }) => {
      return await apiRequest(`/api/media/${mediaId}`, {
        method: 'PATCH',
        body: JSON.stringify({ isFavorite }),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/media"] });
      toast({
        title: "Success",
        description: "Favorite status updated",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to update favorite status",
        variant: "destructive",
      });
    },
  });

  const moveMutation = useMutation({
    mutationFn: async ({ mediaId, categoryId }: { mediaId: string; categoryId: string | null }) => {
      return await apiRequest(`/api/media/${mediaId}`, {
        method: 'PATCH',
        body: JSON.stringify({ categoryId }),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/media"] });
      toast({
        title: "Success",
        description: "File moved successfully",
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to move file",
        variant: "destructive",
      });
    },
  });

  // Bulk move mutation
  const bulkMoveMutation = useMutation({
    mutationFn: async ({ mediaIds, categoryId }: { mediaIds: string[]; categoryId: string | null }) => {
      const results = await Promise.all(
        mediaIds.map(id => 
          apiRequest(`/api/media/${id}`, {
            method: 'PATCH',
            body: JSON.stringify({ categoryId }),
          }).catch(err => ({ error: err, id }))
        )
      );
      return results;
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/media"] });
      setSelectedItems(new Set());
      toast({
        title: "Success",
        description: `Files moved successfully`,
      });
    },
    onError: () => {
      toast({
        title: "Error",
        description: "Failed to move some files",
        variant: "destructive",
      });
    },
  });

  // File operation handlers
  const handleDelete = (mediaId: string, filename: string) => {
    setDeleteDialog({ open: true, mediaId, filename });
  };

  const handleRename = (mediaId: string, filename: string) => {
    setNewFilename(filename);
    setRenameDialog({ open: true, mediaId, filename });
  };

  const handleMove = (mediaId: string, filename: string) => {
    setMoveDialog({ open: true, mediaId, filename });
  };

  const handleDownload = (mediaId: string, filename: string) => {
    const link = document.createElement('a');
    link.href = `/api/media/${mediaId}/download`;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleToggleFavorite = (mediaId: string, isFavorite: boolean) => {
    toggleFavoriteMutation.mutate({ mediaId, isFavorite });
  };

  const confirmDelete = () => {
    if (deleteDialog) {
      deleteMutation.mutate(deleteDialog.mediaId);
      setDeleteDialog(null);
    }
  };

  const confirmRename = () => {
    if (renameDialog && newFilename.trim()) {
      renameMutation.mutate({ mediaId: renameDialog.mediaId, newName: newFilename });
      setRenameDialog(null);
      setNewFilename('');
    }
  };

  const confirmMove = (categoryId: string | null) => {
    if (moveDialog) {
      moveMutation.mutate({ mediaId: moveDialog.mediaId, categoryId });
      setMoveDialog(null);
    }
  };

  const handleItemSelect = (itemId: string, selected: boolean) => {
    setSelectedItems(prev => {
      const next = new Set(prev);
      if (selected) {
        next.add(itemId);
      } else {
        next.delete(itemId);
      }
      return next;
    });
  };

  const handleSelectAll = () => {
    if (mediaFiles.length > 0) {
      if (selectedItems.size === mediaFiles.length) {
        setSelectedItems(new Set());
      } else {
        setSelectedItems(new Set(mediaFiles.map(f => f.id)));
      }
    }
  };

  // Listen for upload modal trigger from navbar
  useEffect(() => {
    const handleOpenUploadModal = () => {
      setShowImportModal(true);
    };

    window.addEventListener('openUploadModal', handleOpenUploadModal);
    return () => {
      window.removeEventListener('openUploadModal', handleOpenUploadModal);
    };
  }, []);

  // Listen for navbar search changes
  useEffect(() => {
    const handleSearchChange = (event: CustomEvent) => {
      setFilters(prev => ({ ...prev, search: event.detail.query }));
    };

    window.addEventListener('navbarSearchChange' as any, handleSearchChange as any);
    return () => {
      window.removeEventListener('navbarSearchChange' as any, handleSearchChange as any);
    };
  }, []);

  // Get number of columns based on viewport width
  const getGridColumns = useCallback(() => {
    const width = window.innerWidth;
    if (width >= 1280) return 5; // xl:grid-cols-5
    if (width >= 1024) return 4; // lg:grid-cols-4
    if (width >= 768) return 3; // md:grid-cols-3
    return 2; // grid-cols-2
  }, []);

  // Keyboard navigation for thumbnail grid
  useEffect(() => {
    if (view !== 'grid' || !mediaFiles.length || isLightboxOpen) return;

    const handleKeyDown = (e: KeyboardEvent) => {
      const totalItems = mediaFiles.length;
      if (totalItems === 0) return;

      const columns = getGridColumns();
      let newIndex = focusedIndex;

      switch (e.key) {
        case 'ArrowLeft':
          e.preventDefault();
          newIndex = Math.max(0, focusedIndex - 1);
          break;
        case 'ArrowRight':
          e.preventDefault();
          newIndex = Math.min(totalItems - 1, focusedIndex + 1);
          break;
        case 'ArrowUp':
          e.preventDefault();
          newIndex = Math.max(0, focusedIndex - columns);
          break;
        case 'ArrowDown':
          e.preventDefault();
          newIndex = Math.min(totalItems - 1, focusedIndex + columns);
          break;
        case 'Enter':
        case ' ':
          e.preventDefault();
          if (mediaFiles[focusedIndex]) {
            handleMediaSelect(mediaFiles[focusedIndex].id, focusedIndex);
          }
          break;
      }

      if (newIndex !== focusedIndex) {
        setFocusedIndex(newIndex);
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [view, focusedIndex, mediaFiles, isLightboxOpen, getGridColumns]);

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navbar />
      
      <main className="pt-16">
        {/* Stats Bar */}
        <StatsBar stats={stats} />

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {/* Filter Controls */}
          <FilterControls
            filters={filters}
            onFilterChange={handleFilterChange}
            onUploadClick={() => setShowImportModal(true)}
            view={view}
            onViewChange={setView}
            data-testid="filter-controls"
          />

          {/* Category Hierarchy */}
          <CategoryHierarchy
            categories={categories || []}
            selectedCategoryId={filters.categoryId}
            onCategorySelect={(categoryId) => handleFilterChange({ categoryId })}
            data-testid="category-hierarchy"
          />

          {/* Bulk Actions Toolbar - Shown when items are selected */}
          {selectedItems.size > 0 && (
            <div className="bg-card border border-border rounded-lg p-4 mb-6 flex items-center justify-between animate-in slide-in-from-top-2">
              <div className="flex items-center gap-4">
                <button
                  onClick={handleSelectAll}
                  className="p-2 hover:bg-secondary rounded-lg transition-colors"
                  data-testid="button-select-all-toggle"
                >
                  <CheckSquare className="w-5 h-5" />
                </button>
                <span className="text-sm font-medium">
                  {selectedItems.size} item{selectedItems.size > 1 ? 's' : ''} selected
                </span>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    // Download all selected items
                    selectedItems.forEach(itemId => {
                      const file = mediaFiles.find(f => f.id === itemId);
                      if (file) {
                        handleDownload(itemId, file.originalName);
                      }
                    });
                  }}
                  data-testid="button-bulk-download"
                >
                  <Download className="w-4 h-4 mr-1" />
                  Download
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    // Move all selected items
                    if (selectedItems.size === 1) {
                      const itemId = Array.from(selectedItems)[0];
                      const file = mediaFiles.find(f => f.id === itemId);
                      if (file) {
                        handleMove(itemId, file.originalName);
                      }
                    } else {
                      // Open bulk move dialog for multiple items
                      setBulkMoveDialog({ open: true, mediaIds: Array.from(selectedItems) });
                    }
                  }}
                  data-testid="button-bulk-move"
                >
                  <Folder className="w-4 h-4 mr-1" />
                  Move
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  className="text-destructive hover:bg-destructive hover:text-destructive-foreground"
                  onClick={() => {
                    // Delete all selected items
                    if (selectedItems.size === 1) {
                      const itemId = Array.from(selectedItems)[0];
                      const file = mediaFiles.find(f => f.id === itemId);
                      if (file) {
                        handleDelete(itemId, file.originalName);
                      }
                    } else {
                      // Confirm bulk delete
                      if (window.confirm(`Are you sure you want to delete ${selectedItems.size} items? This action cannot be undone.`)) {
                        bulkDeleteMutation.mutate(Array.from(selectedItems));
                      }
                    }
                  }}
                  data-testid="button-bulk-delete"
                >
                  <Trash2 className="w-4 h-4 mr-1" />
                  Delete
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => setSelectedItems(new Set())}
                  data-testid="button-clear-selection"
                >
                  <X className="w-4 h-4" />
                </Button>
              </div>
            </div>
          )}

          {/* Media Grid or List View */}
          {view === 'grid' ? (
            <MediaGrid
              mediaFiles={mediaFiles}
              isLoading={isLoading}
              selectedIndex={selectedIndex}
              focusedIndex={focusedIndex}
              onMediaSelect={handleMediaSelect}
              selectedItems={selectedItems}
              onItemSelect={handleItemSelect}
              onSelectAll={handleSelectAll}
              isFetchingMore={isFetchingNextPage}
              sentinelRef={sentinelRef}
              data-testid="media-grid"
            />
          ) : (
            <MediaListView
              mediaFiles={mediaFiles}
              isLoading={isLoading}
              selectedItems={selectedItems}
              onMediaSelect={handleMediaSelect}
              onItemSelect={handleItemSelect}
              onSelectAll={handleSelectAll}
              onDelete={handleDelete}
              onRename={handleRename}
              onMove={handleMove}
              onDownload={handleDownload}
              onToggleFavorite={handleToggleFavorite}
              data-testid="media-list"
            />
          )}

          {/* Infinite scroll loading indicator */}
          {isFetchingNextPage && (
            <div className="flex justify-center py-8" data-testid="infinite-scroll-loading">
              <div className="flex items-center gap-3">
                <div className="animate-spin w-5 h-5 border-2 border-primary border-t-transparent rounded-full"></div>
                <span className="text-muted-foreground">Loading more...</span>
              </div>
            </div>
          )}

          {/* Show total count */}
          {totalItems > 0 && (
            <div className="text-center mt-8 text-sm text-muted-foreground">
              Showing {mediaFiles.length} of {totalItems} items
            </div>
          )}
        </div>
      </main>

      {/* Media Lightbox */}
      <MediaLightbox
        mediaFiles={mediaFiles}
        selectedIndex={selectedIndex}
        isOpen={isLightboxOpen}
        onClose={closeLightbox}
        onNext={navigateNext}
        onPrevious={navigatePrevious}
        data-testid="media-lightbox"
      />

      {/* Import Modal */}
      <ImportModal
        isOpen={showImportModal}
        onClose={() => setShowImportModal(false)}
        data-testid="import-modal"
      />

      {/* Keyboard Navigation Component */}
      <KeyboardNavigation />

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={deleteDialog?.open} onOpenChange={(open) => !open && setDeleteDialog(null)}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete File</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete "{deleteDialog?.filename}"? This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={confirmDelete}
              className="bg-destructive hover:bg-destructive/90"
            >
              Delete
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      {/* Rename Dialog */}
      <Dialog open={renameDialog?.open} onOpenChange={(open) => !open && setRenameDialog(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rename File</DialogTitle>
            <DialogDescription>
              Enter a new name for "{renameDialog?.filename}"
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="grid grid-cols-4 items-center gap-4">
              <Label htmlFor="new-name" className="text-right">
                New Name
              </Label>
              <Input
                id="new-name"
                value={newFilename}
                onChange={(e) => setNewFilename(e.target.value)}
                className="col-span-3"
                data-testid="input-new-filename"
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setRenameDialog(null)}
            >
              Cancel
            </Button>
            <Button
              onClick={confirmRename}
              disabled={!newFilename.trim()}
              data-testid="button-confirm-rename"
            >
              Rename
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Move Dialog */}
      <Dialog open={moveDialog?.open} onOpenChange={(open) => !open && setMoveDialog(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Move File</DialogTitle>
            <DialogDescription>
              Select a category to move "{moveDialog?.filename}" to:
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 py-4">
            <div className="space-y-2">
              <Button
                variant="outline"
                className="w-full justify-start"
                onClick={() => confirmMove(null)}
                data-testid="button-move-uncategorized"
              >
                📁 Uncategorized
              </Button>
              {categories?.map((category) => (
                <Button
                  key={category.id}
                  variant="outline"
                  className="w-full justify-start"
                  onClick={() => confirmMove(category.id)}
                  data-testid={`button-move-${category.id}`}
                >
                  {category.icon} {category.name}
                </Button>
              ))}
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => setMoveDialog(null)}
            >
              Cancel
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Bulk Move Dialog */}
      {bulkMoveDialog?.open && (
        <Dialog open={true} onOpenChange={(open) => !open && setBulkMoveDialog(null)}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Move {bulkMoveDialog.mediaIds.length} Files</DialogTitle>
              <DialogDescription>
                Select a category to move the selected files to:
              </DialogDescription>
            </DialogHeader>
            <div className="grid gap-4 py-4">
              <div className="space-y-2">
                <Button
                  variant="outline"
                  className="w-full justify-start"
                  onClick={() => {
                    bulkMoveMutation.mutate({ 
                      mediaIds: bulkMoveDialog.mediaIds, 
                      categoryId: null 
                    });
                    setBulkMoveDialog(null);
                  }}
                  data-testid="button-bulk-move-uncategorized"
                >
                  📁 Uncategorized
                </Button>
                {categories?.map((category) => (
                  <Button
                    key={category.id}
                    variant="outline"
                    className="w-full justify-start"
                    onClick={() => {
                      bulkMoveMutation.mutate({ 
                        mediaIds: bulkMoveDialog.mediaIds, 
                        categoryId: category.id 
                      });
                      setBulkMoveDialog(null);
                    }}
                    data-testid={`button-bulk-move-${category.id}`}
                  >
                    {category.icon} {category.name}
                  </Button>
                ))}
              </div>
            </div>
            <DialogFooter>
              <Button
                variant="outline"
                onClick={() => setBulkMoveDialog(null)}
              >
                Cancel
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
    </div>
  );
}