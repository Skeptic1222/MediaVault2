import { useCallback, useState } from "react";
import { cn } from "@/lib/utils";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import FileRow from "./FileRow";
import type { FileItem } from "@/pages/FileManager";

interface ListViewProps {
  items: FileItem[];
  selectedItems: Set<string>;
  onItemClick: (item: FileItem) => void;
  onItemSelect: (itemId: string, selected: boolean) => void;
  onSelectFile?: (item: FileItem) => void;
  onDrop?: (targetFolderId: string, draggedItemIds: string[]) => void;
  className?: string;
  "data-testid"?: string;
}

export default function ListView({
  items,
  selectedItems,
  onItemClick,
  onItemSelect,
  onSelectFile,
  onDrop,
  className,
  "data-testid": dataTestId,
}: ListViewProps) {
  const [dragOverId, setDragOverId] = useState<string | null>(null);

  const handleDragStart = useCallback((e: React.DragEvent, item: FileItem) => {
    const selected = selectedItems.has(item.id) 
      ? Array.from(selectedItems) 
      : [item.id];
    e.dataTransfer.setData("application/json", JSON.stringify(selected));
    e.dataTransfer.effectAllowed = "move";
  }, [selectedItems]);

  const handleDragOver = useCallback((e: React.DragEvent, itemId: string) => {
    e.preventDefault();
    e.dataTransfer.dropEffect = "move";
    setDragOverId(itemId);
  }, []);

  const handleDragLeave = useCallback(() => {
    setDragOverId(null);
  }, []);

  const handleDrop = useCallback((e: React.DragEvent, targetItem: FileItem) => {
    e.preventDefault();
    e.stopPropagation();
    setDragOverId(null);
    
    if (targetItem.type !== "folder" || !onDrop) return;
    
    try {
      const draggedItemIds = JSON.parse(e.dataTransfer.getData("application/json"));
      if (draggedItemIds.includes(targetItem.id)) return;
      onDrop(targetItem.id, draggedItemIds);
    } catch (err) {
      console.error("Failed to handle drop:", err);
    }
  }, [onDrop]);

  const handleSelectAll = useCallback(() => {
    const allSelected = items.every(item => selectedItems.has(item.id));
    items.forEach(item => {
      onItemSelect(item.id, !allSelected);
    });
  }, [items, selectedItems, onItemSelect]);

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
    <div className={cn("w-full", className)} data-testid={dataTestId}>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-12">
              <Checkbox
                checked={items.length > 0 && items.every(item => selectedItems.has(item.id))}
                onCheckedChange={handleSelectAll}
                aria-label="Select all"
                data-testid="checkbox-select-all"
              />
            </TableHead>
            <TableHead>Name</TableHead>
            <TableHead className="w-32">Type</TableHead>
            <TableHead className="w-32">Size</TableHead>
            <TableHead className="w-48">Modified</TableHead>
            <TableHead className="w-16"></TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.map((item) => (
            <FileRow
              key={item.id}
              item={item}
              isSelected={selectedItems.has(item.id)}
              isDragOver={dragOverId === item.id}
              onClick={() => onItemClick(item)}
              onSelect={(selected: boolean) => onItemSelect(item.id, selected)}
              onDragStart={(e: React.DragEvent) => handleDragStart(e, item)}
              onDragOver={(e: React.DragEvent) => handleDragOver(e, item.id)}
              onDragLeave={handleDragLeave}
              onDrop={(e: React.DragEvent) => handleDrop(e, item)}
              draggable
              data-testid={`file-row-${item.id}`}
            />
          ))}
        </TableBody>
      </Table>
    </div>
  );
}