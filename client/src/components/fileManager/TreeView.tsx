import { useState, useCallback } from "react";
import { cn } from "@/lib/utils";
import { ChevronRight, ChevronDown, Folder, File } from "lucide-react";
import { Checkbox } from "@/components/ui/checkbox";
import type { FileItem, Folder as FolderType } from "@/pages/FileManager";

interface TreeViewProps {
  folders: FolderType[];
  items: FileItem[];
  selectedItems: Set<string>;
  onItemClick: (item: FileItem) => void;
  onItemSelect: (itemId: string, selected: boolean) => void;
  onSelectFile?: (item: FileItem) => void;
  onDrop?: (targetFolderId: string, draggedItemIds: string[]) => void;
  className?: string;
  "data-testid"?: string;
}

interface TreeNodeProps {
  item: FileItem | FolderType;
  items: FileItem[];
  folders: FolderType[];
  depth: number;
  selectedItems: Set<string>;
  expandedFolders: Set<string>;
  onToggleExpand: (folderId: string) => void;
  onItemClick: (item: FileItem) => void;
  onItemSelect: (itemId: string, selected: boolean) => void;
  onSelectFile?: (item: FileItem) => void;
  onDrop?: (targetFolderId: string, draggedItemIds: string[]) => void;
}

function TreeNode({
  item,
  items,
  folders,
  depth,
  selectedItems,
  expandedFolders,
  onToggleExpand,
  onItemClick,
  onItemSelect,
  onSelectFile,
  onDrop,
}: TreeNodeProps) {
  const isFolder = "childrenCount" in item;
  const isExpanded = isFolder && expandedFolders.has(item.id);
  
  const childFolders = isFolder 
    ? folders.filter(f => f.parentId === item.id) 
    : [];
  const childFiles = isFolder
    ? items.filter(i => i.parentId === item.id)
    : [];

  const handleDragStart = useCallback((e: React.DragEvent) => {
    const selected = selectedItems.has(item.id) 
      ? Array.from(selectedItems) 
      : [item.id];
    e.dataTransfer.setData("application/json", JSON.stringify(selected));
    e.dataTransfer.effectAllowed = "move";
  }, [item.id, selectedItems]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    if (isFolder) {
      e.preventDefault();
      e.dataTransfer.dropEffect = "move";
    }
  }, [isFolder]);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    
    if (!isFolder || !onDrop) return;
    
    try {
      const draggedItemIds = JSON.parse(e.dataTransfer.getData("application/json"));
      if (draggedItemIds.includes(item.id)) return;
      onDrop(item.id, draggedItemIds);
    } catch (err) {
      console.error("Failed to handle drop:", err);
    }
  }, [isFolder, item.id, onDrop]);

  const fileItem = isFolder ? {
    ...item,
    type: "folder" as const,
    size: 0,
    mimeType: "folder",
    path: "",
  } : item as FileItem;

  return (
    <div>
      <div
        className={cn(
          "flex items-center h-8 px-2 hover:bg-accent rounded-sm cursor-pointer select-none",
          selectedItems.has(item.id) && "bg-accent"
        )}
        style={{ paddingLeft: `${depth * 16 + 8}px` }}
        onClick={() => {
          if (isFolder) {
            onToggleExpand(item.id);
          } else {
            onItemClick(fileItem);
          }
        }}
        onDragStart={handleDragStart}
        onDragOver={handleDragOver}
        onDrop={handleDrop}
        draggable
        data-testid={`tree-node-${item.id}`}
      >
        {isFolder && (
          <button
            className="p-0.5 hover:bg-accent-foreground/10 rounded"
            onClick={(e) => {
              e.stopPropagation();
              onToggleExpand(item.id);
            }}
            data-testid={`button-expand-${item.id}`}
          >
            {isExpanded ? (
              <ChevronDown className="h-4 w-4" />
            ) : (
              <ChevronRight className="h-4 w-4" />
            )}
          </button>
        )}
        
        {!isFolder && <div className="w-5" />}
        
        <Checkbox
          checked={selectedItems.has(item.id)}
          onCheckedChange={(checked) => {
            onItemSelect(item.id, checked as boolean);
          }}
          onClick={(e) => e.stopPropagation()}
          className="mr-2"
          data-testid={`checkbox-${item.id}`}
        />
        
        {isFolder ? (
          <Folder className="h-4 w-4 mr-2 text-blue-500" />
        ) : (
          <File className="h-4 w-4 mr-2 text-gray-500" />
        )}
        
        <span className="text-sm">{item.name}</span>
      </div>
      
      {isExpanded && (
        <div>
          {childFolders.map((folder) => (
            <TreeNode
              key={folder.id}
              item={folder}
              items={items}
              folders={folders}
              depth={depth + 1}
              selectedItems={selectedItems}
              expandedFolders={expandedFolders}
              onToggleExpand={onToggleExpand}
              onItemClick={onItemClick}
              onItemSelect={onItemSelect}
              onSelectFile={onSelectFile}
              onDrop={onDrop}
            />
          ))}
          {childFiles.map((file) => (
            <TreeNode
              key={file.id}
              item={file}
              items={items}
              folders={folders}
              depth={depth + 1}
              selectedItems={selectedItems}
              expandedFolders={expandedFolders}
              onToggleExpand={onToggleExpand}
              onItemClick={onItemClick}
              onItemSelect={onItemSelect}
              onSelectFile={onSelectFile}
              onDrop={onDrop}
            />
          ))}
        </div>
      )}
    </div>
  );
}

export default function TreeView({
  folders,
  items,
  selectedItems,
  onItemClick,
  onItemSelect,
  onSelectFile,
  onDrop,
  className,
  "data-testid": dataTestId,
}: TreeViewProps) {
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(new Set());

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
  const rootFiles = items.filter(i => !i.parentId);

  if (rootFolders.length === 0 && rootFiles.length === 0) {
    return (
      <div className="flex items-center justify-center h-64 text-muted-foreground">
        <div className="text-center">
          <p className="text-lg mb-2">No files or folders</p>
          <p className="text-sm">Upload files or create a folder to get started</p>
        </div>
      </div>
    );
  }

  return (
    <div className={cn("w-full", className)} data-testid={dataTestId}>
      {rootFolders.map((folder) => (
        <TreeNode
          key={folder.id}
          item={folder}
          items={items}
          folders={folders}
          depth={0}
          selectedItems={selectedItems}
          expandedFolders={expandedFolders}
          onToggleExpand={handleToggleExpand}
          onItemClick={onItemClick}
          onItemSelect={onItemSelect}
          onSelectFile={onSelectFile}
          onDrop={onDrop}
        />
      ))}
      {rootFiles.map((file) => (
        <TreeNode
          key={file.id}
          item={file}
          items={items}
          folders={folders}
          depth={0}
          selectedItems={selectedItems}
          expandedFolders={expandedFolders}
          onToggleExpand={handleToggleExpand}
          onItemClick={onItemClick}
          onItemSelect={onItemSelect}
          onSelectFile={onSelectFile}
          onDrop={onDrop}
        />
      ))}
    </div>
  );
}