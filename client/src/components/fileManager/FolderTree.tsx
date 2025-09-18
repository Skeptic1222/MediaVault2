import { useState, useCallback } from "react";
import { cn } from "@/lib/utils";
import { ChevronRight, ChevronDown, Folder as FolderIcon, FolderOpen } from "lucide-react";
import type { Folder } from "@/pages/FileManager";

interface FolderTreeProps {
  folders: Folder[];
  currentFolderId: string | null;
  onFolderSelect: (folderId: string | null) => void;
  onDrop?: (targetFolderId: string, draggedItemIds: string[]) => void;
  className?: string;
  "data-testid"?: string;
}

interface FolderNodeProps {
  folder: Folder;
  folders: Folder[];
  depth: number;
  currentFolderId: string | null;
  expandedFolders: Set<string>;
  onToggleExpand: (folderId: string) => void;
  onFolderSelect: (folderId: string | null) => void;
  onDrop?: (targetFolderId: string, draggedItemIds: string[]) => void;
}

function FolderNode({
  folder,
  folders,
  depth,
  currentFolderId,
  expandedFolders,
  onToggleExpand,
  onFolderSelect,
  onDrop,
}: FolderNodeProps) {
  const [isDragOver, setIsDragOver] = useState(false);
  const isExpanded = expandedFolders.has(folder.id);
  const isSelected = currentFolderId === folder.id;
  const childFolders = folders.filter(f => f.parentId === folder.id);
  const hasChildren = childFolders.length > 0;

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    e.dataTransfer.dropEffect = "move";
    setIsDragOver(true);
  }, []);

  const handleDragLeave = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
    
    if (!onDrop) return;
    
    try {
      const draggedItemIds = JSON.parse(e.dataTransfer.getData("application/json"));
      if (draggedItemIds.includes(folder.id)) return;
      onDrop(folder.id, draggedItemIds);
    } catch (err) {
      console.error("Failed to handle drop:", err);
    }
  }, [folder.id, onDrop]);

  return (
    <div>
      <div
        className={cn(
          "flex items-center h-8 px-2 hover:bg-accent rounded-sm cursor-pointer select-none transition-colors",
          isSelected && "bg-accent",
          isDragOver && "bg-primary/10 border-l-2 border-primary"
        )}
        style={{ paddingLeft: `${depth * 12 + 8}px` }}
        onClick={() => onFolderSelect(folder.id)}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        data-testid={`folder-node-${folder.id}`}
      >
        {hasChildren && (
          <button
            className="p-0.5 hover:bg-accent-foreground/10 rounded"
            onClick={(e) => {
              e.stopPropagation();
              onToggleExpand(folder.id);
            }}
            data-testid={`button-expand-folder-${folder.id}`}
          >
            {isExpanded ? (
              <ChevronDown className="h-3 w-3" />
            ) : (
              <ChevronRight className="h-3 w-3" />
            )}
          </button>
        )}
        
        {!hasChildren && <div className="w-4" />}
        
        {isExpanded || isSelected ? (
          <FolderOpen className="h-4 w-4 mr-2 text-blue-500" />
        ) : (
          <FolderIcon className="h-4 w-4 mr-2 text-blue-500" />
        )}
        
        <span className="text-sm truncate">{folder.name}</span>
        {folder.childrenCount > 0 && (
          <span className="ml-auto text-xs text-muted-foreground">
            {folder.childrenCount}
          </span>
        )}
      </div>
      
      {isExpanded && hasChildren && (
        <div>
          {childFolders.map((childFolder) => (
            <FolderNode
              key={childFolder.id}
              folder={childFolder}
              folders={folders}
              depth={depth + 1}
              currentFolderId={currentFolderId}
              expandedFolders={expandedFolders}
              onToggleExpand={onToggleExpand}
              onFolderSelect={onFolderSelect}
              onDrop={onDrop}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default function FolderTree({
  folders,
  currentFolderId,
  onFolderSelect,
  onDrop,
  className,
  "data-testid": dataTestId,
}: FolderTreeProps) {
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(
    new Set(folders.filter(f => f.parentId === null).map(f => f.id))
  );

  const handleToggleExpand = useCallback((folderId: string) => {
    setExpandedFolders(prev => {
      const newSet = new Set(prev);
      if (newSet.has(folderId)) {
        newSet.delete(folderId);
      } else {
        newSet.add(folderId);
      }
      return newSet;
    });
  }, []);

  const rootFolders = folders.filter(f => !f.parentId);

  return (
    <div className={cn("space-y-1", className)} data-testid={dataTestId}>
      {/* All Files */}
      <div
        className={cn(
          "flex items-center h-8 px-2 hover:bg-accent rounded-sm cursor-pointer select-none",
          currentFolderId === null && "bg-accent"
        )}
        onClick={() => onFolderSelect(null)}
        data-testid="folder-all-files"
      >
        <FolderIcon className="h-4 w-4 mr-2 text-gray-500" />
        <span className="text-sm font-medium">All Files</span>
      </div>

      {/* Folder Tree */}
      {rootFolders.map((folder) => (
        <FolderNode
          key={folder.id}
          folder={folder}
          folders={folders}
          depth={0}
          currentFolderId={currentFolderId}
          expandedFolders={expandedFolders}
          onToggleExpand={handleToggleExpand}
          onFolderSelect={onFolderSelect}
          onDrop={onDrop}
        />
      ))}
    </div>
  );
}