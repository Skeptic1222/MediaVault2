import { useEffect } from "react";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { useQuery } from "@tanstack/react-query";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import { 
  GalleryThumbnails, 
  Shield, 
  Database, 
  Upload, 
  Activity,
  TrendingUp,
  Files,
  Lock
} from "lucide-react";
import Navbar from "@/components/ui/navbar";

export default function Home() {
  const { toast } = useToast();
  const { isAuthenticated, isLoading, user } = useAuth();

  // Redirect to login if not authenticated
  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      toast({
        title: "Unauthorized",
        description: "You are logged out. Logging in again...",
        variant: "destructive",
      });
      setTimeout(() => {
        window.location.href = "/api/login";
      }, 500);
      return;
    }
  }, [isAuthenticated, isLoading, toast]);

  const { data: stats, isLoading: statsLoading } = useQuery({
    queryKey: ["/api/stats"],
    retry: false,
  });

  const { data: recentActivity } = useQuery({
    queryKey: ["/api/activity"],
    retry: false,
  });

  if (!isAuthenticated) {
    return null; // Will redirect via useEffect
  }

  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navbar />
      
      <main className="pt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {/* Welcome Section */}
          <div className="mb-8">
            <h1 className="text-4xl font-bold mb-2" data-testid="text-welcome">
              Welcome back, {user?.firstName || user?.email || 'User'}
            </h1>
            <p className="text-muted-foreground text-lg">
              Manage your secure media collection with enterprise-grade tools
            </p>
          </div>

          {/* Stats Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4 mb-8">
            <Card data-testid="card-total-items">
              <CardContent className="p-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-primary" data-testid="text-total-items">
                    {statsLoading ? '...' : (stats?.totalItems?.toLocaleString() || '0')}
                  </div>
                  <div className="text-sm text-muted-foreground">Total Items</div>
                </div>
              </CardContent>
            </Card>

            <Card data-testid="card-images">
              <CardContent className="p-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-green-400" data-testid="text-images">
                    {statsLoading ? '...' : (stats?.images?.toLocaleString() || '0')}
                  </div>
                  <div className="text-sm text-muted-foreground">Images</div>
                </div>
              </CardContent>
            </Card>

            <Card data-testid="card-videos">
              <CardContent className="p-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-blue-400" data-testid="text-videos">
                    {statsLoading ? '...' : (stats?.videos?.toLocaleString() || '0')}
                  </div>
                  <div className="text-sm text-muted-foreground">Videos</div>
                </div>
              </CardContent>
            </Card>

            <Card data-testid="card-vault-items">
              <CardContent className="p-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-accent" data-testid="text-vault-items">
                    {statsLoading ? '...' : (stats?.vaultItems?.toLocaleString() || '0')}
                  </div>
                  <div className="text-sm text-muted-foreground">Vault Items</div>
                </div>
              </CardContent>
            </Card>

            <Card data-testid="card-storage-used">
              <CardContent className="p-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-yellow-400" data-testid="text-storage-used">
                    {statsLoading ? '...' : formatBytes(stats?.storageUsed || 0)}
                  </div>
                  <div className="text-sm text-muted-foreground">Storage Used</div>
                </div>
              </CardContent>
            </Card>

            <Card data-testid="card-duplicates">
              <CardContent className="p-4">
                <div className="text-center">
                  <div className="text-2xl font-bold text-purple-400" data-testid="text-duplicates">
                    {statsLoading ? '...' : (stats?.duplicatesFound?.toLocaleString() || '0')}
                  </div>
                  <div className="text-sm text-muted-foreground">Duplicates</div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Quick Actions */}
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <Card className="hover:shadow-lg transition-shadow cursor-pointer" data-testid="card-browse-gallery">
              <Link href="/gallery">
                <CardHeader className="pb-3">
                  <CardTitle className="flex items-center gap-3 text-lg">
                    <GalleryThumbnails className="w-6 h-6 text-primary" />
                    Browse GalleryThumbnails
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-muted-foreground text-sm">
                    Explore your media collection with advanced filtering and search
                  </p>
                </CardContent>
              </Link>
            </Card>

            <Card className="hover:shadow-lg transition-shadow cursor-pointer" data-testid="card-vault-access">
              <Link href="/vault">
                <CardHeader className="pb-3">
                  <CardTitle className="flex items-center gap-3 text-lg">
                    <Lock className="w-6 h-6 text-accent" />
                    Vault Access
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-muted-foreground text-sm">
                    Access your encrypted vault with secure authentication
                  </p>
                </CardContent>
              </Link>
            </Card>

            <Card className="hover:shadow-lg transition-shadow cursor-pointer" data-testid="card-upload-media">
              <CardHeader className="pb-3">
                <CardTitle className="flex items-center gap-3 text-lg">
                  <Upload className="w-6 h-6 text-primary" />
                  Upload Media
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground text-sm">
                  Add new photos and videos with automatic processing
                </p>
              </CardContent>
            </Card>

            <Card className="hover:shadow-lg transition-shadow cursor-pointer" data-testid="card-activity-logs">
              <Link href="/admin/activity">
                <CardHeader className="pb-3">
                  <CardTitle className="flex items-center gap-3 text-lg">
                    <Activity className="w-6 h-6 text-primary" />
                    Activity Logs
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <p className="text-muted-foreground text-sm">
                    Review security logs and system activity
                  </p>
                </CardContent>
              </Link>
            </Card>
          </div>

          {/* Recent Activity & System Status */}
          <div className="grid lg:grid-cols-2 gap-6">
            {/* Recent Activity */}
            <Card data-testid="card-recent-activity">
              <CardHeader>
                <CardTitle className="flex items-center gap-3">
                  <TrendingUp className="w-5 h-5" />
                  Recent Activity
                </CardTitle>
              </CardHeader>
              <CardContent>
                {recentActivity && recentActivity.length > 0 ? (
                  <div className="space-y-3">
                    {recentActivity.slice(0, 5).map((log: any, index: number) => (
                      <div key={log.id} className="flex items-center justify-between py-2 border-b border-border last:border-0" data-testid={`activity-item-${index}`}>
                        <div>
                          <div className="font-medium text-sm">{formatAction(log.action)}</div>
                          <div className="text-xs text-muted-foreground">
                            {new Date(log.createdAt).toLocaleString()}
                          </div>
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {log.resource}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-muted-foreground text-center py-8" data-testid="text-no-activity">
                    No recent activity to display
                  </p>
                )}
              </CardContent>
            </Card>

            {/* System Status */}
            <Card data-testid="card-system-status">
              <CardHeader>
                <CardTitle className="flex items-center gap-3">
                  <Database className="w-5 h-5" />
                  System Status
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  <div className="flex items-center justify-between" data-testid="status-database">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                      <span className="text-sm">Database Connection</span>
                    </div>
                    <span className="text-xs text-green-400">Connected</span>
                  </div>
                  
                  <div className="flex items-center justify-between" data-testid="status-auth">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                      <span className="text-sm">Authentication Service</span>
                    </div>
                    <span className="text-xs text-green-400">Active</span>
                  </div>
                  
                  <div className="flex items-center justify-between" data-testid="status-encryption">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 bg-green-400 rounded-full"></div>
                      <span className="text-sm">Encryption Module</span>
                    </div>
                    <span className="text-xs text-green-400">Operational</span>
                  </div>
                  
                  <div className="flex items-center justify-between" data-testid="status-storage">
                    <div className="flex items-center gap-2">
                      <div className="w-2 h-2 bg-yellow-400 rounded-full"></div>
                      <span className="text-sm">Storage Capacity</span>
                    </div>
                    <span className="text-xs text-yellow-400">
                      {stats ? `${Math.round((stats.storageUsed / (200 * 1024 * 1024 * 1024)) * 100)}%` : '0%'}
                    </span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </main>
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatAction(action: string): string {
  return action.split('_').map(word => 
    word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()
  ).join(' ');
}
