import { useState, useCallback, useEffect } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { queryClient } from "@/lib/queryClient";
import { apiRequest } from "@/lib/queryClient";
import { useToast } from "@/hooks/use-toast";
import Navbar from "@/components/ui/navbar";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Grid3X3,
  List,
  FolderTree,
  Calendar,
  Search,
  Upload,
  MoreVertical,
  FolderPlus,
  Filter,
} from "lucide-react";
import { cn } from "@/lib/utils";

// Import view mode components
import GridView from "@/components/fileManager/GridView";
import ListView from "@/components/fileManager/ListView";
import TreeView from "@/components/fileManager/TreeView";
import TimelineView from "@/components/fileManager/TimelineView";

// Import reusable components
import FolderTreeSidebar from "@/components/fileManager/FolderTree";
import BreadcrumbNav from "@/components/fileManager/BreadcrumbNav";
import FileUploadZone from "@/components/fileManager/FileUploadZone";
import BulkActions from "@/components/fileManager/BulkActions";
import { FileDetailsPanel } from "@/components/fileManager/FileDetailsPanel";

// Types
export type ViewMode = "grid" | "list" | "tree" | "timeline";
export type FileItem = {
  id: string;
  name: string;
  type: "file" | "folder";
  size?: number;
  mimeType?: string;
  createdAt: string;
  updatedAt: string;
  parentId?: string;
  path: string;
  thumbnailUrl?: string;
  isEncrypted?: boolean;
  tags?: string[];
};

export type Folder = {
  id: string;
  name: string;
  parentId?: string;
  path: string;
  childrenCount: number;
  createdAt: string;
  updatedAt: string;
};

export default function FileManager() {
  const { toast } = useToast();
  const [viewMode, setViewMode] = useState<ViewMode>("grid");
  const [currentFolderId, setCurrentFolderId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedItems, setSelectedItems] = useState<Set<string>>(new Set());
  const [showSidebar, setShowSidebar] = useState(true);
  const [showUploadZone, setShowUploadZone] = useState(false);
  const [sortBy, setSortBy] = useState<"name" | "date" | "size" | "type">("name");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("asc");
  const [selectedFile, setSelectedFile] = useState<FileItem | null>(null);
  const [isPanelOpen, setIsPanelOpen] = useState(false);

  // Fetch folders
  const { data: folders, isLoading: foldersLoading } = useQuery<Folder[]>({
    queryKey: ["/api/folders"],
    retry: false,
  });

  // Fetch files and folders for current folder
  const { data: items, isLoading: itemsLoading, refetch: refetchItems } = useQuery<FileItem[]>({
    queryKey: ["/api/files", {
      folderId: currentFolderId,
      search: searchQuery,
      sortBy: sortBy === "name" ? "filename" : sortBy === "date" ? "created_at" : sortBy === "size" ? "file_size" : "filename",
      sortOrder: sortOrder
    }],
    retry: false,
  });

  // Create folder mutation
  const createFolderMutation = useMutation({
    mutationFn: async (data: { name: string; parentId?: string }) => {
      return apiRequest("/api/folders", {
        method: "POST",
        body: JSON.stringify(data),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/folders"] });
      queryClient.invalidateQueries({ queryKey: ["/api/files"] });
      toast({
        title: "Success",
        description: "Folder created successfully",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Error",
        description: error.message || "Failed to create folder",
        variant: "destructive",
      });
    },
  });

  // Delete items mutation
  const deleteItemsMutation = useMutation({
    mutationFn: async (itemIds: string[]) => {
      return apiRequest("/api/files/bulk-delete", {
        method: "DELETE",
        body: JSON.stringify({ ids: itemIds }),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/files"] });
      queryClient.invalidateQueries({ queryKey: ["/api/folders"] });
      setSelectedItems(new Set());
      toast({
        title: "Success",
        description: "Items deleted successfully",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Error",
        description: error.message || "Failed to delete items",
        variant: "destructive",
      });
    },
  });

  // Move items mutation
  const moveItemsMutation = useMutation({
    mutationFn: async (data: { itemIds: string[]; targetFolderId: string }) => {
      return apiRequest("/api/files/bulk-move", {
        method: "POST",
        body: JSON.stringify(data),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/files"] });
      queryClient.invalidateQueries({ queryKey: ["/api/folders"] });
      setSelectedItems(new Set());
      toast({
        title: "Success",
        description: "Items moved successfully",
      });
    },
    onError: (error: Error) => {
      toast({
        title: "Error",
        description: error.message || "Failed to move items",
        variant: "destructive",
      });
    },
  });

  // Handle file selection for details panel
  const handleSelectFile = useCallback((file: FileItem) => {
    setSelectedFile(file);
    setIsPanelOpen(true);
  }, []);

  const handleItemClick = useCallback((item: FileItem) => {
    if (item.type === "folder") {
      // For folders, just navigate without opening details panel
      setCurrentFolderId(item.id);
      setSelectedItems(new Set());
    } else {
      // For files, open the details panel
      handleSelectFile(item);
    }
  }, [handleSelectFile]);

  // Handle file download
  const handleDownload = useCallback((fileId: string) => {
    const link = document.createElement('a');
    link.href = `/api/media/${fileId}`;
    link.download = '';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }, []);

  // Handle file deletion from details panel
  const handleDeleteFile = useCallback((fileId: string) => {
    if (confirm('Are you sure you want to delete this file?')) {
      deleteItemsMutation.mutate([fileId]);
      setIsPanelOpen(false);
    }
  }, [deleteItemsMutation]);

  // Handle file move from details panel
  const handleMoveFile = useCallback((fileId: string) => {
    // This would typically open a folder selection dialog
    const targetFolderId = prompt('Enter target folder ID:');
    if (targetFolderId) {
      moveItemsMutation.mutate({ itemIds: [fileId], targetFolderId });
      setIsPanelOpen(false);
    }
  }, [moveItemsMutation]);

  // Handle file share from details panel
  const handleShareFile = useCallback((fileId: string) => {
    // Copy share link to clipboard
    const shareUrl = `${window.location.origin}/api/media/${fileId}`;
    navigator.clipboard.writeText(shareUrl).then(() => {
      toast({
        title: "Link copied",
        description: "Share link copied to clipboard",
      });
    });
  }, [toast]);

  // Handle file copy from details panel
  const handleCopyFile = useCallback((fileId: string) => {
    // Create a copy of the file
    apiRequest(`/api/files/${fileId}/copy`, {
      method: 'POST',
    })
      .then(() => {
        queryClient.invalidateQueries({ queryKey: ["/api/files"] });
        toast({
          title: "Success",
          description: "File copied successfully",
        });
      })
      .catch((error: Error) => {
        toast({
          title: "Error",
          description: error.message || "Failed to copy file",
          variant: "destructive",
        });
      });
  }, [toast]);

  const handleItemSelect = useCallback((itemId: string, selected: boolean) => {
    setSelectedItems(prev => {
      const newSet = new Set(prev);
      if (selected) {
        newSet.add(itemId);
      } else {
        newSet.delete(itemId);
      }
      return newSet;
    });
  }, []);

  const handleSelectAll = useCallback(() => {
    if (items) {
      if (selectedItems.size === items.length) {
        setSelectedItems(new Set());
      } else {
        setSelectedItems(new Set(items.map(item => item.id)));
      }
    }
  }, [items, selectedItems]);

  const handleCreateFolder = useCallback(() => {
    const name = prompt("Enter folder name:");
    if (name) {
      createFolderMutation.mutate({ name, parentId: currentFolderId || undefined });
    }
  }, [currentFolderId, createFolderMutation]);

  const handleDeleteSelected = useCallback(() => {
    if (selectedItems.size > 0 && confirm(`Delete ${selectedItems.size} item(s)?`)) {
      deleteItemsMutation.mutate(Array.from(selectedItems));
    }
  }, [selectedItems, deleteItemsMutation]);

  const handleUploadComplete = useCallback(() => {
    refetchItems();
    setShowUploadZone(false);
    toast({
      title: "Success",
      description: "Files uploaded successfully",
    });
  }, [refetchItems, toast]);

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

  const handleDrop = useCallback((targetFolderId: string, draggedItemIds: string[]) => {
    if (draggedItemIds.length > 0) {
      moveItemsMutation.mutate({ itemIds: draggedItemIds, targetFolderId });
    }
  }, [moveItemsMutation]);

  const viewModeButtons = [
    { mode: "grid" as ViewMode, icon: Grid3X3, label: "Grid View" },
    { mode: "list" as ViewMode, icon: List, label: "List View" },
    { mode: "tree" as ViewMode, icon: FolderTree, label: "Tree View" },
    { mode: "timeline" as ViewMode, icon: Calendar, label: "Timeline View" },
  ];

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navbar />
      
      <div className="flex h-[calc(100vh-64px)] pt-16">
        {/* Sidebar */}
        {showSidebar && (
          <div className="w-64 border-r bg-muted/10 p-4 overflow-y-auto">
            <div className="mb-4">
              <Button
                onClick={() => setShowUploadZone(true)}
                className="w-full"
                variant="default"
                data-testid="button-upload"
              >
                <Upload className="mr-2 h-4 w-4" />
                Upload Files
              </Button>
            </div>
            
            <div className="mb-4">
              <Button
                onClick={handleCreateFolder}
                className="w-full"
                variant="outline"
                data-testid="button-create-folder"
              >
                <FolderPlus className="mr-2 h-4 w-4" />
                New Folder
              </Button>
            </div>

            <div className="mt-6">
              <h3 className="text-sm font-semibold mb-2 text-muted-foreground">Folders</h3>
              <FolderTreeSidebar
                folders={folders || []}
                currentFolderId={currentFolderId}
                onFolderSelect={setCurrentFolderId}
                onDrop={handleDrop}
                data-testid="folder-tree"
              />
            </div>
          </div>
        )}

        {/* Main Content */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Header */}
          <div className="border-b px-6 py-4">
            <div className="flex items-center justify-between mb-4">
              <BreadcrumbNav
                currentFolderId={currentFolderId}
                folders={folders || []}
                onNavigate={setCurrentFolderId}
                data-testid="breadcrumb-nav"
              />
              
              <div className="flex items-center space-x-2">
                {/* View Mode Switcher */}
                <div className="flex items-center border rounded-lg">
                  {viewModeButtons.map(({ mode, icon: Icon, label }) => (
                    <Button
                      key={mode}
                      variant={viewMode === mode ? "default" : "ghost"}
                      size="sm"
                      onClick={() => setViewMode(mode)}
                      className={cn(
                        "rounded-none",
                        mode === "grid" && "rounded-l-lg",
                        mode === "timeline" && "rounded-r-lg"
                      )}
                      title={label}
                      data-testid={`button-view-${mode}`}
                    >
                      <Icon className="h-4 w-4" />
                    </Button>
                  ))}
                </div>

                {/* Sort Options */}
                <Select
                  value={`${sortBy}-${sortOrder}`}
                  onValueChange={(value) => {
                    const [newSortBy, newSortOrder] = value.split("-");
                    setSortBy(newSortBy as "name" | "date" | "size" | "type");
                    setSortOrder(newSortOrder as "asc" | "desc");
                  }}
                >
                  <SelectTrigger className="w-40" data-testid="select-sort">
                    <SelectValue placeholder="Sort by" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="name-asc">Name (A-Z)</SelectItem>
                    <SelectItem value="name-desc">Name (Z-A)</SelectItem>
                    <SelectItem value="date-desc">Date (Newest)</SelectItem>
                    <SelectItem value="date-asc">Date (Oldest)</SelectItem>
                    <SelectItem value="size-desc">Size (Largest)</SelectItem>
                    <SelectItem value="size-asc">Size (Smallest)</SelectItem>
                    <SelectItem value="type-asc">Type</SelectItem>
                  </SelectContent>
                </Select>

                {/* More Options */}
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button variant="ghost" size="sm" data-testid="button-more-options">
                      <MoreVertical className="h-4 w-4" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem onClick={() => setShowSidebar(!showSidebar)}>
                      {showSidebar ? "Hide" : "Show"} Sidebar
                    </DropdownMenuItem>
                    <DropdownMenuItem onClick={handleSelectAll}>
                      {selectedItems.size === items?.length ? "Deselect All" : "Select All"}
                    </DropdownMenuItem>
                    <DropdownMenuSeparator />
                    <DropdownMenuItem onClick={() => refetchItems()}>
                      Refresh
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              </div>
            </div>

            {/* Search Bar */}
            <div className="relative max-w-md">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                type="text"
                placeholder="Search files and folders..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-10"
                data-testid="input-search"
              />
            </div>
          </div>

          {/* Bulk Actions */}
          {selectedItems.size > 0 && (
            <BulkActions
              selectedCount={selectedItems.size}
              onDelete={handleDeleteSelected}
              onMove={(targetFolderId: string) => 
                moveItemsMutation.mutate({ 
                  itemIds: Array.from(selectedItems), 
                  targetFolderId 
                })
              }
              onDownload={() => {
                // Download selected items
                Array.from(selectedItems).forEach(id => {
                  window.open(`/api/media/${id}`, "_blank");
                });
              }}
              onClearSelection={() => setSelectedItems(new Set())}
              data-testid="bulk-actions"
            />
          )}

          {/* Content Area */}
          <div className="flex-1 overflow-auto p-6">
            {itemsLoading || foldersLoading ? (
              <div className="flex items-center justify-center h-full">
                <div className="text-muted-foreground">Loading...</div>
              </div>
            ) : (
              <>
                {viewMode === "grid" && (
                  <GridView
                    items={items || []}
                    selectedItems={selectedItems}
                    onItemClick={handleItemClick}
                    onItemSelect={handleItemSelect}
                    onSelectFile={handleSelectFile}
                    onDrop={handleDrop}
                    data-testid="grid-view"
                  />
                )}
                
                {viewMode === "list" && (
                  <ListView
                    items={items || []}
                    selectedItems={selectedItems}
                    onItemClick={handleItemClick}
                    onItemSelect={handleItemSelect}
                    onSelectFile={handleSelectFile}
                    onDrop={handleDrop}
                    data-testid="list-view"
                  />
                )}
                
                {viewMode === "tree" && (
                  <TreeView
                    folders={folders || []}
                    items={items || []}
                    selectedItems={selectedItems}
                    onItemClick={handleItemClick}
                    onItemSelect={handleItemSelect}
                    onSelectFile={handleSelectFile}
                    onDrop={handleDrop}
                    data-testid="tree-view"
                  />
                )}
                
                {viewMode === "timeline" && (
                  <TimelineView
                    items={items || []}
                    selectedItems={selectedItems}
                    onItemClick={handleItemClick}
                    onItemSelect={handleItemSelect}
                    onSelectFile={handleSelectFile}
                    data-testid="timeline-view"
                  />
                )}
              </>
            )}
          </div>
        </div>
      </div>

      {/* Upload Zone Modal */}
      {showUploadZone && (
        <FileUploadZone
          folderId={currentFolderId}
          onClose={() => setShowUploadZone(false)}
          onUploadComplete={handleUploadComplete}
          data-testid="file-upload-zone"
        />
      )}

      {/* File Details Panel */}
      <FileDetailsPanel
        file={selectedFile}
        isOpen={isPanelOpen}
        onClose={() => setIsPanelOpen(false)}
        onDelete={handleDeleteFile}
        onMove={handleMoveFile}
        onShare={handleShareFile}
        onDownload={handleDownload}
        onCopy={handleCopyFile}
      />
    </div>
  );
}