interface StatsBarProps {
  stats?: {
    totalItems: number;
    images: number;
    videos: number;
    vaultItems: number;
    storageUsed: number;
    duplicatesFound: number;
  };
}

export default function StatsBar({ stats }: StatsBarProps) {
  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  };

  return (
    <div className="bg-card border-b border-border" data-testid="stats-bar">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-6">
          <div className="text-center" data-testid="stat-total-items">
            <div className="text-2xl font-bold text-primary">
              {stats?.totalItems?.toLocaleString() || '0'}
            </div>
            <div className="text-sm text-muted-foreground">Total Items</div>
          </div>
          
          <div className="text-center" data-testid="stat-images">
            <div className="text-2xl font-bold text-green-400">
              {stats?.images?.toLocaleString() || '0'}
            </div>
            <div className="text-sm text-muted-foreground">Images</div>
          </div>
          
          <div className="text-center" data-testid="stat-videos">
            <div className="text-2xl font-bold text-blue-400">
              {stats?.videos?.toLocaleString() || '0'}
            </div>
            <div className="text-sm text-muted-foreground">Videos</div>
          </div>
          
          <div className="text-center" data-testid="stat-vault-items">
            <div className="text-2xl font-bold text-accent">
              {stats?.vaultItems?.toLocaleString() || '0'}
            </div>
            <div className="text-sm text-muted-foreground">Vault Items</div>
          </div>
          
          <div className="text-center" data-testid="stat-storage-used">
            <div className="text-2xl font-bold text-yellow-400">
              {formatBytes(stats?.storageUsed || 0)}
            </div>
            <div className="text-sm text-muted-foreground">Storage Used</div>
          </div>
          
          <div className="text-center" data-testid="stat-duplicates-found">
            <div className="text-2xl font-bold text-purple-400">
              {stats?.duplicatesFound?.toLocaleString() || '0'}
            </div>
            <div className="text-sm text-muted-foreground">Duplicates Found</div>
          </div>
        </div>
      </div>
    </div>
  );
}
