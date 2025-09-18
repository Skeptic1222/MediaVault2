import { useCallback } from "react";
import { cn } from "@/lib/utils";
import FileCard from "./FileCard";
import type { FileItem } from "@/pages/FileManager";

interface GridViewProps {
  items: FileItem[];
  selectedItems: Set<string>;
  onItemClick: (item: FileItem) => void;
  onItemSelect: (itemId: string, selected: boolean) => void;
  onSelectFile?: (item: FileItem) => void;
  onDrop?: (targetFolderId: string, draggedItemIds: string[]) => void;
  className?: string;
  "data-testid"?: string;
}

export default function GridView({
  items,
  selectedItems,
  onItemClick,
  onItemSelect,
  onSelectFile,
  onDrop,
  className,
  "data-testid": dataTestId,
}: GridViewProps) {
  const handleDragStart = useCallback((e: React.DragEvent, item: FileItem) => {
    const selected = selectedItems.has(item.id) 
      ? Array.from(selectedItems) 
      : [item.id];
    e.dataTransfer.setData("application/json", JSON.stringify(selected));
    e.dataTransfer.effectAllowed = "move";
  }, [selectedItems]);

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
  }, []);

  const handleDrop = useCallback((e: React.DragEvent, targetItem: FileItem) => {
    e.preventDefault();
    e.stopPropagation();
    
    if (targetItem.type !== "folder" || !onDrop) return;
    
    try {
      const draggedItemIds = JSON.parse(e.dataTransfer.getData("application/json"));
      if (draggedItemIds.includes(targetItem.id)) return; // Can't drop on itself
      onDrop(targetItem.id, draggedItemIds);
    } catch (err) {
      console.error("Failed to handle drop:", err);
    }
  }, [onDrop]);

  if (items.length === 0) {
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
    <div 
      className={cn(
        "grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 gap-4",
        className
      )}
      data-testid={dataTestId}
    >
      {items.map((item) => (
        <FileCard
          key={item.id}
          item={item}
          isSelected={selectedItems.has(item.id)}
          onClick={() => onItemClick(item)}
          onSelect={(selected: boolean) => onItemSelect(item.id, selected)}
          onDragStart={(e: React.DragEvent) => handleDragStart(e, item)}
          onDragOver={handleDragOver}
          onDrop={(e: React.DragEvent) => handleDrop(e, item)}
          draggable
          data-testid={`file-card-${item.id}`}
        />
      ))}
    </div>
  );
}