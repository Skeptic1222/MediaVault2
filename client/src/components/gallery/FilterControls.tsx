import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Upload, Search, Grid, List, Filter } from "lucide-react";

interface FilterControlsProps {
  filters: {
    categoryId?: string;
    isVault: boolean;
    search: string;
    sortBy: 'created_at' | 'filename' | 'file_size';
    sortOrder: 'asc' | 'desc';
    mimeType?: 'images' | 'videos';
  };
  onFilterChange: (filters: Partial<FilterControlsProps['filters']>) => void;
  onUploadClick: () => void;
  view: 'grid' | 'list';
  onViewChange: (view: 'grid' | 'list') => void;
}

export default function FilterControls({ filters, onFilterChange, onUploadClick, view, onViewChange }: FilterControlsProps) {
  const filterButtons = [
    { key: 'all', label: 'All Media', active: !filters.isVault && !filters.categoryId && !filters.mimeType },
    { key: 'images', label: '🖼️ Images', active: filters.mimeType === 'images' },
    { key: 'videos', label: '🎬 Videos', active: filters.mimeType === 'videos' },
    { key: 'recent', label: 'Recent', active: false },
    { key: 'favorites', label: '⭐ Favorites', active: false },
    { key: 'vault', label: '🔒 Vault Access', active: filters.isVault, vault: true },
  ];

  const handleFilterClick = (key: string) => {
    switch (key) {
      case 'all':
        onFilterChange({ isVault: false, categoryId: undefined, mimeType: undefined });
        break;
      case 'images':
        onFilterChange({ mimeType: 'images', isVault: false, categoryId: undefined });
        break;
      case 'videos':
        onFilterChange({ mimeType: 'videos', isVault: false, categoryId: undefined });
        break;
      case 'vault':
        onFilterChange({ isVault: true, mimeType: undefined });
        break;
      case 'recent':
        onFilterChange({ sortBy: 'created_at', sortOrder: 'desc' });
        break;
      // Add more filter logic as needed
      default:
        break;
    }
  };

  return (
    <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-6 mb-8" data-testid="filter-controls">
      {/* Category Filters */}
      <div className="flex flex-wrap gap-2">
        {filterButtons.map((button) => (
          <Button
            key={button.key}
            variant={button.active ? "default" : "secondary"}
            onClick={() => handleFilterClick(button.key)}
            className={`transition-colors ${
              button.vault 
                ? 'hover:bg-accent/80 data-[state=active]:bg-accent' 
                : ''
            }`}
            data-testid={`filter-${button.key}`}
          >
            {button.label}
          </Button>
        ))}
      </div>
      
      {/* View Controls */}
      <div className="flex items-center gap-4">
        {/* Search */}
        <div className="relative">
          <Input
            type="search"
            placeholder="Search media..."
            value={filters.search}
            onChange={(e) => onFilterChange({ search: e.target.value })}
            className="w-64 pr-10"
            data-testid="search-media"
          />
          <div className="absolute right-3 top-2.5 text-muted-foreground">
            <Search className="w-4 h-4" />
          </div>
        </div>

        {/* View Mode Toggle */}
        <div className="flex bg-secondary rounded-lg p-1">
          <Button
            variant="ghost"
            size="sm"
            className={view === 'grid' ? "bg-primary text-primary-foreground rounded-md" : "text-muted-foreground hover:text-foreground"}
            title="Grid View"
            onClick={() => onViewChange('grid')}
            data-testid="view-grid"
          >
            <Grid className="w-4 h-4" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className={view === 'list' ? "bg-primary text-primary-foreground rounded-md" : "text-muted-foreground hover:text-foreground"}
            title="List View"
            onClick={() => onViewChange('list')}
            data-testid="view-list"
          >
            <List className="w-4 h-4" />
          </Button>
        </div>
        
        {/* Sort Dropdown */}
        <Select
          value={`${filters.sortBy}-${filters.sortOrder}`}
          onValueChange={(value) => {
            const [sortBy, sortOrder] = value.split('-') as [typeof filters.sortBy, typeof filters.sortOrder];
            onFilterChange({ sortBy, sortOrder });
          }}
        >
          <SelectTrigger className="w-40" data-testid="sort-select">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="created_at-desc">Newest First</SelectItem>
            <SelectItem value="created_at-asc">Oldest First</SelectItem>
            <SelectItem value="filename-asc">Name A-Z</SelectItem>
            <SelectItem value="filename-desc">Name Z-A</SelectItem>
            <SelectItem value="file_size-desc">Largest First</SelectItem>
            <SelectItem value="file_size-asc">Smallest First</SelectItem>
          </SelectContent>
        </Select>

        {/* Upload Button */}
        <Button 
          onClick={onUploadClick}
          className="bg-primary hover:bg-primary/90"
          data-testid="upload-media"
        >
          <Upload className="w-4 h-4 mr-2" />
          Upload
        </Button>
      </div>
    </div>
  );
}
