import { useState } from "react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";
import { Trash2, Download, Move, Copy, Share2, X } from "lucide-react";

interface BulkActionsProps {
  selectedCount: number;
  onDelete: () => void;
  onMove: (targetFolderId: string) => void;
  onCopy?: (targetFolderId: string) => void;
  onDownload: () => void;
  onShare?: () => void;
  onClearSelection: () => void;
  folders?: Array<{ id: string; name: string; path: string }>;
  className?: string;
  "data-testid"?: string;
}

export default function BulkActions({
  selectedCount,
  onDelete,
  onMove,
  onCopy,
  onDownload,
  onShare,
  onClearSelection,
  folders = [],
  className,
  "data-testid": dataTestId,
}: BulkActionsProps) {
  const [showMoveDialog, setShowMoveDialog] = useState(false);
  const [showCopyDialog, setShowCopyDialog] = useState(false);
  const [selectedFolderId, setSelectedFolderId] = useState<string>("");

  const handleMove = () => {
    if (selectedFolderId) {
      onMove(selectedFolderId);
      setShowMoveDialog(false);
      setSelectedFolderId("");
    }
  };

  const handleCopy = () => {
    if (selectedFolderId && onCopy) {
      onCopy(selectedFolderId);
      setShowCopyDialog(false);
      setSelectedFolderId("");
    }
  };

  return (
    <>
      <div
        className={cn(
          "flex items-center justify-between px-6 py-3 bg-primary/5 border-b animate-in slide-in-from-top-2",
          className
        )}
        data-testid={dataTestId}
      >
        <div className="flex items-center space-x-2">
          <span className="text-sm font-medium">
            {selectedCount} {selectedCount === 1 ? "item" : "items"} selected
          </span>
          <Button
            variant="ghost"
            size="sm"
            onClick={onClearSelection}
            className="h-7 px-2"
            data-testid="button-clear-selection"
          >
            <X className="h-3 w-3" />
          </Button>
        </div>

        <div className="flex items-center space-x-2">
          <Button
            variant="outline"
            size="sm"
            onClick={onDownload}
            data-testid="button-bulk-download"
          >
            <Download className="h-4 w-4 mr-2" />
            Download
          </Button>

          {folders.length > 0 && (
            <>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowMoveDialog(true)}
                data-testid="button-bulk-move"
              >
                <Move className="h-4 w-4 mr-2" />
                Move
              </Button>

              {onCopy && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setShowCopyDialog(true)}
                  data-testid="button-bulk-copy"
                >
                  <Copy className="h-4 w-4 mr-2" />
                  Copy
                </Button>
              )}
            </>
          )}

          {onShare && (
            <Button
              variant="outline"
              size="sm"
              onClick={onShare}
              data-testid="button-bulk-share"
            >
              <Share2 className="h-4 w-4 mr-2" />
              Share
            </Button>
          )}

          <Button
            variant="outline"
            size="sm"
            onClick={onDelete}
            className="text-destructive hover:text-destructive"
            data-testid="button-bulk-delete"
          >
            <Trash2 className="h-4 w-4 mr-2" />
            Delete
          </Button>
        </div>
      </div>

      {/* Move Dialog */}
      <Dialog open={showMoveDialog} onOpenChange={setShowMoveDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Move {selectedCount} items</DialogTitle>
            <DialogDescription>
              Select a folder to move the selected items to.
            </DialogDescription>
          </DialogHeader>

          <Select value={selectedFolderId} onValueChange={setSelectedFolderId}>
            <SelectTrigger data-testid="select-move-folder">
              <SelectValue placeholder="Select a folder" />
            </SelectTrigger>
            <SelectContent>
              {folders.map(folder => (
                <SelectItem key={folder.id} value={folder.id}>
                  {folder.path || folder.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowMoveDialog(false)}>
              Cancel
            </Button>
            <Button onClick={handleMove} disabled={!selectedFolderId}>
              Move
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Copy Dialog */}
      {onCopy && (
        <Dialog open={showCopyDialog} onOpenChange={setShowCopyDialog}>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Copy {selectedCount} items</DialogTitle>
              <DialogDescription>
                Select a folder to copy the selected items to.
              </DialogDescription>
            </DialogHeader>

            <Select value={selectedFolderId} onValueChange={setSelectedFolderId}>
              <SelectTrigger data-testid="select-copy-folder">
                <SelectValue placeholder="Select a folder" />
              </SelectTrigger>
              <SelectContent>
                {folders.map(folder => (
                  <SelectItem key={folder.id} value={folder.id}>
                    {folder.path || folder.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>

            <DialogFooter>
              <Button variant="outline" onClick={() => setShowCopyDialog(false)}>
                Cancel
              </Button>
              <Button onClick={handleCopy} disabled={!selectedFolderId}>
                Copy
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      )}
    </>
  );
}