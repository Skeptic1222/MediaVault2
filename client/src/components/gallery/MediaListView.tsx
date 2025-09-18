import { useState } from "react";
import { 
  Table, 
  TableBody, 
  TableCell, 
  TableHead, 
  TableHeader, 
  TableRow 
} from "@/components/ui/table";
import { 
  DropdownMenu, 
  DropdownMenuContent, 
  DropdownMenuItem, 
  DropdownMenuSeparator, 
  DropdownMenuTrigger 
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { 
  MoreHorizontal, 
  Download, 
  Edit2, 
  FolderInput, 
  Trash2, 
  Lock, 
  Image, 
  Video, 
  Heart,
  Star
} from "lucide-react";
import type { MediaFile } from "@shared/schema";

interface MediaListViewProps {
  mediaFiles: MediaFile[];
  isLoading: boolean;
  selectedItems: Set<string>;
  onMediaSelect: (mediaId: string, index: number) => void;
  onItemSelect: (itemId: string, selected: boolean) => void;
  onSelectAll: () => void;
  onDelete: (mediaId: string, filename: string) => void;
  onRename: (mediaId: string, currentName: string) => void;
  onMove: (mediaId: string, filename: string) => void;
  onDownload: (mediaId: string, filename: string) => void;
  onToggleFavorite: (mediaId: string, isFavorite: boolean) => void;
  isVaultMode?: boolean;
}

export default function MediaListView({
  mediaFiles,
  isLoading,
  selectedItems,
  onMediaSelect,
  onItemSelect,
  onSelectAll,
  onDelete,
  onRename,
  onMove,
  onDownload,
  onToggleFavorite,
  isVaultMode = false,
}: MediaListViewProps) {
  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  const formatDate = (date: Date | string | null): string => {
    if (!date) return '-';
    const d = new Date(date);
    return d.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    });
  };

  const formatDuration = (seconds: number | null): string => {
    if (!seconds) return '-';
    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`;
  };

  const getMediaType = (mimeType: string) => {
    if (mimeType.startsWith('image/')) {
      return { icon: Image, label: 'Image', color: 'text-blue-500' };
    } else if (mimeType.startsWith('video/')) {
      return { icon: Video, label: 'Video', color: 'text-purple-500' };
    }
    return { icon: Image, label: 'File', color: 'text-gray-500' };
  };

  if (isLoading) {
    return (
      <div className="space-y-2" data-testid="media-list-loading">
        {Array.from({ length: 10 }).map((_, i) => (
          <div key={i} className="h-12 bg-card rounded-lg border border-border animate-pulse" />
        ))}
      </div>
    );
  }

  if (mediaFiles.length === 0) {
    return (
      <div className="text-center py-12" data-testid="media-list-empty">
        <div className="w-16 h-16 bg-muted rounded-full flex items-center justify-center mx-auto mb-4">
          <Image className="w-8 h-8 text-muted-foreground" />
        </div>
        <h3 className="text-lg font-semibold mb-2">No Media Found</h3>
        <p className="text-muted-foreground">
          {isVaultMode ? "No encrypted content in your vault" : "Upload some photos and videos to get started"}
        </p>
      </div>
    );
  }

  return (
    <div className="bg-card rounded-lg border border-border overflow-hidden" data-testid="media-list">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-12">
              <Checkbox
                checked={mediaFiles.length > 0 && selectedItems.size === mediaFiles.length}
                onCheckedChange={onSelectAll}
                aria-label="Select all"
                data-testid="checkbox-select-all"
              />
            </TableHead>
            <TableHead className="w-12"></TableHead>
            <TableHead>Name</TableHead>
            <TableHead className="w-24">Type</TableHead>
            <TableHead className="w-32">Size</TableHead>
            <TableHead className="w-24">Duration</TableHead>
            <TableHead className="w-48">Modified</TableHead>
            <TableHead className="w-20 text-center">Actions</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {mediaFiles.map((file, index) => {
            const mediaType = getMediaType(file.mimeType);
            const MediaIcon = mediaType.icon;
            const isSelected = selectedItems.has(file.id);
            
            return (
              <TableRow 
                key={file.id} 
                className="cursor-pointer hover:bg-muted/50 transition-colors"
                data-testid={`media-row-${index}`}
              >
                <TableCell onClick={(e) => e.stopPropagation()}>
                  <Checkbox
                    checked={isSelected}
                    onCheckedChange={(checked) => onItemSelect(file.id, checked as boolean)}
                    aria-label={`Select ${file.originalName}`}
                    data-testid={`checkbox-${file.id}`}
                  />
                </TableCell>
                <TableCell onClick={() => onMediaSelect(file.id, index)}>
                  <div className="flex items-center gap-1">
                    <MediaIcon className={`w-4 h-4 ${mediaType.color}`} />
                    {file.isEncrypted && <Lock className="w-3 h-3 text-accent" />}
                    {file.isFavorite && <Heart className="w-3 h-3 text-red-500 fill-current" />}
                  </div>
                </TableCell>
                <TableCell 
                  className="font-medium max-w-xs truncate" 
                  title={file.originalName}
                  onClick={() => onMediaSelect(file.id, index)}
                  data-testid={`media-name-${index}`}
                >
                  {file.originalName}
                </TableCell>
                <TableCell onClick={() => onMediaSelect(file.id, index)}>
                  <span className={`text-xs ${mediaType.color}`}>{mediaType.label}</span>
                </TableCell>
                <TableCell onClick={() => onMediaSelect(file.id, index)}>
                  {formatFileSize(file.fileSize)}
                </TableCell>
                <TableCell onClick={() => onMediaSelect(file.id, index)}>
                  {formatDuration(file.duration || null)}
                </TableCell>
                <TableCell onClick={() => onMediaSelect(file.id, index)}>
                  {formatDate(file.createdAt)}
                </TableCell>
                <TableCell>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button 
                        variant="ghost" 
                        size="sm" 
                        className="h-8 w-8 p-0"
                        onClick={(e) => e.stopPropagation()}
                        data-testid={`action-menu-${index}`}
                      >
                        <MoreHorizontal className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end" className="w-48">
                      <DropdownMenuItem 
                        onClick={(e) => {
                          e.stopPropagation();
                          onDownload(file.id, file.originalName);
                        }}
                        data-testid={`action-download-${index}`}
                      >
                        <Download className="w-4 h-4 mr-2" />
                        Download
                      </DropdownMenuItem>
                      <DropdownMenuItem 
                        onClick={(e) => {
                          e.stopPropagation();
                          onToggleFavorite(file.id, !file.isFavorite);
                        }}
                        data-testid={`action-favorite-${index}`}
                      >
                        <Star className={`w-4 h-4 mr-2 ${file.isFavorite ? 'fill-current' : ''}`} />
                        {file.isFavorite ? 'Remove from Favorites' : 'Add to Favorites'}
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem 
                        onClick={(e) => {
                          e.stopPropagation();
                          onRename(file.id, file.originalName);
                        }}
                        data-testid={`action-rename-${index}`}
                      >
                        <Edit2 className="w-4 h-4 mr-2" />
                        Rename
                      </DropdownMenuItem>
                      <DropdownMenuItem 
                        onClick={(e) => {
                          e.stopPropagation();
                          onMove(file.id, file.originalName);
                        }}
                        data-testid={`action-move-${index}`}
                      >
                        <FolderInput className="w-4 h-4 mr-2" />
                        Move to...
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem 
                        className="text-destructive hover:bg-destructive/10"
                        onClick={(e) => {
                          e.stopPropagation();
                          onDelete(file.id, file.originalName);
                        }}
                        data-testid={`action-delete-${index}`}
                      >
                        <Trash2 className="w-4 h-4 mr-2" />
                        Delete
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}