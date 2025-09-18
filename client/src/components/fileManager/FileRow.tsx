import { cn } from "@/lib/utils";
import { format } from "date-fns";
import { Checkbox } from "@/components/ui/checkbox";
import { TableCell, TableRow } from "@/components/ui/table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Button } from "@/components/ui/button";
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
  MoreVertical,
  Lock,
  Play,
} from "lucide-react";
import type { FileItem } from "@/pages/FileManager";

interface FileRowProps {
  item: FileItem;
  isSelected: boolean;
  isDragOver?: boolean;
  onClick: () => void;
  onSelect: (selected: boolean) => void;
  onDragStart?: (e: React.DragEvent) => void;
  onDragOver?: (e: React.DragEvent) => void;
  onDragLeave?: () => void;
  onDrop?: (e: React.DragEvent) => void;
  draggable?: boolean;
  className?: string;
  "data-testid"?: string;
}

export default function FileRow({
  item,
  isSelected,
  isDragOver,
  onClick,
  onSelect,
  onDragStart,
  onDragOver,
  onDragLeave,
  onDrop,
  draggable,
  className,
  "data-testid": dataTestId,
}: FileRowProps) {
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
    if (!bytes) return "—";
    const sizes = ["B", "KB", "MB", "GB"];
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
  };

  const getFileType = () => {
    if (item.type === "folder") return "Folder";
    
    if (item.mimeType?.startsWith("image/")) return "Image";
    if (item.mimeType?.startsWith("video/")) return "Video";
    if (item.mimeType?.startsWith("audio/")) return "Audio";
    if (item.mimeType?.includes("pdf")) return "PDF";
    if (item.mimeType?.includes("zip") || item.mimeType?.includes("rar")) return "Archive";
    
    return "File";
  };

  return (
    <TableRow
      className={cn(
        "hover:bg-accent cursor-pointer transition-colors",
        isSelected && "bg-accent/50",
        isDragOver && "bg-primary/10 border-l-2 border-primary",
        className
      )}
      onClick={onClick}
      onDragStart={onDragStart}
      onDragOver={onDragOver}
      onDragLeave={onDragLeave}
      onDrop={onDrop}
      draggable={draggable}
      data-testid={dataTestId}
    >
      <TableCell className="w-12">
        <Checkbox
          checked={isSelected}
          onCheckedChange={onSelect}
          onClick={(e) => e.stopPropagation()}
          aria-label={`Select ${item.name}`}
          data-testid={`checkbox-row-${item.id}`}
        />
      </TableCell>
      
      <TableCell>
        <div className="flex items-center space-x-2">
          <Icon className="h-4 w-4 flex-shrink-0 text-muted-foreground" />
          <span className="truncate font-medium">{item.name}</span>
          {item.isEncrypted && (
            <Lock className="h-3 w-3 text-yellow-500" />
          )}
        </div>
      </TableCell>
      
      <TableCell className="w-32">
        <span className="text-sm text-muted-foreground">{getFileType()}</span>
      </TableCell>
      
      <TableCell className="w-32">
        <span className="text-sm text-muted-foreground">
          {formatFileSize(item.size)}
        </span>
      </TableCell>
      
      <TableCell className="w-48">
        <span className="text-sm text-muted-foreground">
          {format(new Date(item.updatedAt), "MMM d, yyyy h:mm a")}
        </span>
      </TableCell>
      
      <TableCell className="w-16">
        <DropdownMenu>
          <DropdownMenuTrigger asChild onClick={(e) => e.stopPropagation()}>
            <Button variant="ghost" size="sm" className="h-8 w-8 p-0">
              <MoreVertical className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-48">
            {item.type === "file" && item.mimeType?.startsWith("audio/") && (
              <DropdownMenuItem onClick={(e) => {
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
                  audioPlayer.playTrack(track, 0);
                }
              }}>
                <Play className="mr-2 h-4 w-4" />
                Play
              </DropdownMenuItem>
            )}
            
            {item.type === "file" && (
              <DropdownMenuItem onClick={(e) => {
                e.stopPropagation();
                window.open(`/api/media/${item.id}`, "_blank");
              }}>
                <Download className="mr-2 h-4 w-4" />
                Download
              </DropdownMenuItem>
            )}
            
            <DropdownMenuItem onClick={(e) => {
              e.stopPropagation();
              const newName = prompt("Rename:", item.name);
              if (newName) {
                // Handle rename
              }
            }}>
              <Edit className="mr-2 h-4 w-4" />
              Rename
            </DropdownMenuItem>
            
            <DropdownMenuItem onClick={(e) => {
              e.stopPropagation();
              // Handle copy
            }}>
              <Copy className="mr-2 h-4 w-4" />
              Copy
            </DropdownMenuItem>
            
            <DropdownMenuItem onClick={(e) => {
              e.stopPropagation();
              // Handle move
            }}>
              <Move className="mr-2 h-4 w-4" />
              Move
            </DropdownMenuItem>
            
            <DropdownMenuItem onClick={(e) => {
              e.stopPropagation();
              // Handle share
            }}>
              <Share2 className="mr-2 h-4 w-4" />
              Share
            </DropdownMenuItem>
            
            <DropdownMenuSeparator />
            
            <DropdownMenuItem
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
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </TableCell>
    </TableRow>
  );
}