import { useMemo } from "react";
import { cn } from "@/lib/utils";
import { format, isToday, isYesterday, isThisWeek, isThisMonth, isThisYear } from "date-fns";
import FileCard from "./FileCard";
import type { FileItem } from "@/pages/FileManager";

interface TimelineViewProps {
  items: FileItem[];
  selectedItems: Set<string>;
  onItemClick: (item: FileItem) => void;
  onItemSelect: (itemId: string, selected: boolean) => void;
  onSelectFile?: (item: FileItem) => void;
  className?: string;
  "data-testid"?: string;
}

interface TimelineGroup {
  label: string;
  items: FileItem[];
}

export default function TimelineView({
  items,
  selectedItems,
  onItemClick,
  onItemSelect,
  onSelectFile,
  className,
  "data-testid": dataTestId,
}: TimelineViewProps) {
  const timelineGroups = useMemo(() => {
    const groups: TimelineGroup[] = [];
    const sortedItems = [...items].sort((a, b) => 
      new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    );

    const today: FileItem[] = [];
    const yesterday: FileItem[] = [];
    const thisWeek: FileItem[] = [];
    const thisMonth: FileItem[] = [];
    const thisYear: FileItem[] = [];
    const older: FileItem[] = [];

    sortedItems.forEach(item => {
      const date = new Date(item.createdAt);
      
      if (isToday(date)) {
        today.push(item);
      } else if (isYesterday(date)) {
        yesterday.push(item);
      } else if (isThisWeek(date)) {
        thisWeek.push(item);
      } else if (isThisMonth(date)) {
        thisMonth.push(item);
      } else if (isThisYear(date)) {
        thisYear.push(item);
      } else {
        older.push(item);
      }
    });

    if (today.length > 0) groups.push({ label: "Today", items: today });
    if (yesterday.length > 0) groups.push({ label: "Yesterday", items: yesterday });
    if (thisWeek.length > 0) groups.push({ label: "This Week", items: thisWeek });
    if (thisMonth.length > 0) groups.push({ label: "This Month", items: thisMonth });
    if (thisYear.length > 0) groups.push({ label: "This Year", items: thisYear });
    if (older.length > 0) groups.push({ label: "Older", items: older });

    return groups;
  }, [items]);

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
    <div className={cn("space-y-8", className)} data-testid={dataTestId}>
      {timelineGroups.map((group) => (
        <div key={group.label}>
          <div className="sticky top-0 bg-background z-10 pb-2 mb-4">
            <h3 className="text-lg font-semibold flex items-center">
              <span className="mr-2">{group.label}</span>
              <span className="text-sm text-muted-foreground font-normal">
                ({group.items.length} items)
              </span>
            </h3>
            <div className="h-px bg-border mt-2" />
          </div>
          
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 gap-4">
            {group.items.map((item) => (
              <div key={item.id} className="relative">
                <FileCard
                  item={item}
                  isSelected={selectedItems.has(item.id)}
                  onClick={() => onItemClick(item)}
                  onSelect={(selected: boolean) => onItemSelect(item.id, selected)}
                  showDate
                  data-testid={`timeline-card-${item.id}`}
                />
                <div className="text-xs text-muted-foreground mt-1 text-center">
                  {format(new Date(item.createdAt), "MMM d, h:mm a")}
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  );
}