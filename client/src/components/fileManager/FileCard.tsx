import { useState, useEffect } from "react";
import { cn } from "@/lib/utils";
import { Checkbox } from "@/components/ui/checkbox";
import {
  ContextMenu,
  ContextMenuContent,
  ContextMenuItem,
  ContextMenuSeparator,
  ContextMenuTrigger,
} from "@/components/ui/context-menu";
import {
  File,
  FileText,
  FileVideo,
  FileImage,
  FileAudio,
  FileArchive,
  Folder,
  Download,
  Trash2,
  Edit,
  Copy,
  Move,
  Share2,
  Info,
  Lock,
  Play,
  Pause,
} from "lucide-react";
import type { FileItem } from "@/pages/FileManager";

interface FileCardProps {
  item: FileItem;
  isSelected: boolean;
  onClick: () => void;
  onSelect: (selected: boolean) => void;
  onDragStart?: (e: React.DragEvent) => void;
  onDragOver?: (e: React.DragEvent) => void;
  onDrop?: (e: React.DragEvent) => void;
  draggable?: boolean;
  showDate?: boolean;
  className?: string;
  "data-testid"?: string;
}

export default function FileCard({
  item,
  isSelected,
  onClick,
  onSelect,
  onDragStart,
  onDragOver,
  onDrop,
  draggable,
  showDate,
  className,
  "data-testid": dataTestId,
}: FileCardProps) {
  const [showCheckbox, setShowCheckbox] = useState(false);
  const [isCurrentlyPlaying, setIsCurrentlyPlaying] = useState(false);
  
  const isAudioFile = item.type === 'file' && item.mimeType?.startsWith('audio/');
  
  // Check if this file is currently playing
  useEffect(() => {
    const checkPlayingStatus = () => {
      if ((window as any).audioPlayer) {
        const audioPlayer = (window as any).audioPlayer;
        const isPlaying = audioPlayer.getCurrentTrack()?.id === item.id && audioPlayer.isPlaying();
        setIsCurrentlyPlaying(isPlaying);
      }
    };
    
    // Check status initially and set up an interval to keep it updated
    checkPlayingStatus();
    const interval = setInterval(checkPlayingStatus, 500);
    
    return () => clearInterval(interval);
  }, [item.id]);

  const getFileIcon = () => {
    if (item.type === "folder") return Folder;
    
    if (item.mimeType?.startsWith("image/")) return FileImage;
    if (item.mimeType?.startsWith("video/")) return FileVideo;
    if (item.mimeType?.startsWith("audio/")) return FileAudio;
    if (item.mimeType?.includes("pdf")) return FileText;
    if (item.mimeType?.includes("zip") || item.mimeType?.includes("rar")) return FileArchive;
    
    return File;
  };

  const Icon = getFileIcon();

  const formatFileSize = (bytes?: number) => {
    if (!bytes) return "";
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
  };

  const getThumbnail = () => {
    if (item.thumbnailUrl) {
      return (
        <img
          src={item.thumbnailUrl}
          alt={item.name}
          className="w-full h-full object-cover"
          loading="lazy"
        />
      );
    }
    
    return (
      <div className="w-full h-full flex items-center justify-center bg-muted">
        <Icon className="h-12 w-12 text-muted-foreground" />
      </div>
    );
  };

  return (
    <ContextMenu>
      <ContextMenuTrigger>
        <div
          className={cn(
            "group relative flex flex-col rounded-lg border bg-card hover:shadow-md transition-all cursor-pointer",
            isSelected && "ring-2 ring-primary",
            className
          )}
          onMouseEnter={() => setShowCheckbox(true)}
          onMouseLeave={() => !isSelected && setShowCheckbox(false)}
          onClick={onClick}
          onDragStart={onDragStart}
          onDragOver={onDragOver}
          onDrop={onDrop}
          draggable={draggable}
          data-testid={dataTestId}
        >
          {/* Checkbox */}
          <div
            className={cn(
              "absolute top-2 left-2 z-10 transition-opacity",
              (showCheckbox || isSelected) ? "opacity-100" : "opacity-0"
            )}
          >
            <Checkbox
              checked={isSelected}
              onCheckedChange={onSelect}
              onClick={(e) => e.stopPropagation()}
              className="bg-background"
              data-testid={`checkbox-select-${item.id}`}
            />
          </div>

          {/* Lock icon for encrypted files */}
          {item.isEncrypted && (
            <div className="absolute top-2 right-2 z-10">
              <Lock className="h-4 w-4 text-yellow-500" />
            </div>
          )}

          {/* Thumbnail */}
          <div className="aspect-square rounded-t-lg overflow-hidden bg-muted relative">
            {getThumbnail()}
            
            {/* Play button overlay for audio files */}
            {isAudioFile && (
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  if ((window as any).audioPlayer) {
                    const audioPlayer = (window as any).audioPlayer;
                    const track = {
                      id: item.id,
                      originalName: item.name,
                      filename: item.name,
                      thumbnailData: null,
                      duration: 0,
                      fileSize: item.size,
                      mimeType: item.mimeType,
                      createdAt: item.createdAt,
                      isDeleted: false,
                      categoryId: null,
                      isFavorite: false,
                      isEncrypted: item.isEncrypted || false,
                      artistName: 'Unknown Artist',
                      albumName: 'Unknown Album'
                    };
                    
                    if (isCurrentlyPlaying) {
                      // Since we don't have a toggle method, we'll just add a note
                      // The user can control playback via the audio player bar
                      audioPlayer.playTrack(track, 0);
                    } else {
                      audioPlayer.playTrack(track, 0);
                    }
                  }
                }}
                className="absolute inset-0 flex items-center justify-center bg-black/40 opacity-0 hover:opacity-100 transition-opacity"
                data-testid={`button-play-audio-${item.id}`}
              >
                <div className="rounded-full bg-primary p-3 shadow-lg">
                  {isCurrentlyPlaying ? (
                    <Pause className="h-6 w-6 text-white" />
                  ) : (
                    <Play className="h-6 w-6 text-white ml-0.5" />
                  )}
                </div>
              </button>
            )}
          </div>

          {/* Info */}
          <div className="p-2 space-y-1">
            <p className="text-sm font-medium truncate" title={item.name}>
              {item.name}
            </p>
            <div className="flex items-center justify-between text-xs text-muted-foreground">
              {item.type === "folder" ? (
                <span>Folder</span>
              ) : (
                <span>{formatFileSize(item.size)}</span>
              )}
              {item.tags && item.tags.length > 0 && (
                <span className="text-xs px-1 py-0.5 bg-muted rounded">
                  {item.tags[0]}
                </span>
              )}
            </div>
          </div>
        </div>
      </ContextMenuTrigger>
      
      <ContextMenuContent className="w-48">
        <ContextMenuItem onClick={(e) => {
          e.stopPropagation();
          onClick();
        }}>
          <Info className="mr-2 h-4 w-4" />
          Open
        </ContextMenuItem>
        
        {item.type === "file" && (
          <ContextMenuItem onClick={(e) => {
            e.stopPropagation();
            window.open(`/api/media/${item.id}`, "_blank");
          }}>
            <Download className="mr-2 h-4 w-4" />
            Download
          </ContextMenuItem>
        )}
        
        <ContextMenuItem onClick={(e) => {
          e.stopPropagation();
          const newName = prompt("Rename:", item.name);
          if (newName) {
            // Handle rename
          }
        }}>
          <Edit className="mr-2 h-4 w-4" />
          Rename
        </ContextMenuItem>
        
        <ContextMenuItem onClick={(e) => {
          e.stopPropagation();
          // Handle copy
        }}>
          <Copy className="mr-2 h-4 w-4" />
          Copy
        </ContextMenuItem>
        
        <ContextMenuItem onClick={(e) => {
          e.stopPropagation();
          // Handle move
        }}>
          <Move className="mr-2 h-4 w-4" />
          Move
        </ContextMenuItem>
        
        <ContextMenuItem onClick={(e) => {
          e.stopPropagation();
          // Handle share
        }}>
          <Share2 className="mr-2 h-4 w-4" />
          Share
        </ContextMenuItem>
        
        <ContextMenuSeparator />
        
        <ContextMenuItem
          className="text-destructive"
          onClick={(e) => {
            e.stopPropagation();
            if (confirm(`Delete "${item.name}"?`)) {
              // Handle delete
            }
          }}
        >
          <Trash2 className="mr-2 h-4 w-4" />
          Delete
        </ContextMenuItem>
      </ContextMenuContent>
    </ContextMenu>
  );
}