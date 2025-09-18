import { useMemo } from "react";
import { ChevronRight, Home } from "lucide-react";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { Folder } from "@/pages/FileManager";

interface BreadcrumbNavProps {
  currentFolderId: string | null;
  folders: Folder[];
  onNavigate: (folderId: string | null) => void;
  className?: string;
  "data-testid"?: string;
}

export default function BreadcrumbNav({
  currentFolderId,
  folders,
  onNavigate,
  className,
  "data-testid": dataTestId,
}: BreadcrumbNavProps) {
  const breadcrumbs = useMemo(() => {
    if (!currentFolderId) return [];
    
    const path: Folder[] = [];
    let current = folders.find(f => f.id === currentFolderId);
    
    while (current) {
      path.unshift(current);
      current = current.parentId 
        ? folders.find(f => f.id === current!.parentId)
        : undefined;
    }
    
    return path;
  }, [currentFolderId, folders]);

  return (
    <nav 
      className={cn("flex items-center space-x-1 text-sm", className)}
      aria-label="Breadcrumb"
      data-testid={dataTestId}
    >
      <Button
        variant="ghost"
        size="sm"
        className="h-7 px-2"
        onClick={() => onNavigate(null)}
        data-testid="breadcrumb-home"
      >
        <Home className="h-4 w-4" />
      </Button>

      {breadcrumbs.map((folder, index) => (
        <div key={folder.id} className="flex items-center">
          <ChevronRight className="h-4 w-4 text-muted-foreground" />
          <Button
            variant="ghost"
            size="sm"
            className={cn(
              "h-7 px-2",
              index === breadcrumbs.length - 1 && "font-semibold"
            )}
            onClick={() => onNavigate(folder.id)}
            data-testid={`breadcrumb-${folder.id}`}
          >
            {folder.name}
          </Button>
        </div>
      ))}
    </nav>
  );
}