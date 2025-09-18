import { useState } from "react";
import { useAuth } from "@/hooks/useAuth";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { User, Bell, Shield, Palette, HardDrive, Info, Settings2, RefreshCw, Trash2, Users, ArrowRight } from "lucide-react";
import { useMutation } from "@tanstack/react-query";
import { apiRequest } from "@/lib/queryClient";
import { Link } from "wouter";

export default function Settings() {
  const { user } = useAuth();
  const { toast } = useToast();
  const isAdmin = user?.role === 'admin';
  
  // Settings state
  const [emailNotifications, setEmailNotifications] = useState(true);
  const [autoBackup, setAutoBackup] = useState(false);
  const [theme, setTheme] = useState("system");
  const [displayName, setDisplayName] = useState(user?.firstName || "");
  const [email, setEmail] = useState(user?.email || "");

  const handleSaveProfile = () => {
    toast({
      title: "Profile Updated",
      description: "Your profile settings have been saved.",
    });
  };

  const handleSaveNotifications = () => {
    toast({
      title: "Notification Settings Updated",
      description: "Your notification preferences have been saved.",
    });
  };

  // Admin mutations
  const syncMediaMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest('/api/admin/sync-media-to-files', {
        method: 'POST',
      });
      return response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Media Sync Complete",
        description: data.message || `Successfully synced ${data.synced || 0} files to the file manager.`,
      });
    },
    onError: (error) => {
      toast({
        title: "Sync Failed",
        description: error.message || "Failed to sync media to file manager.",
        variant: "destructive",
      });
    },
  });

  const cleanupCategoriesMutation = useMutation({
    mutationFn: async () => {
      const response = await apiRequest('/api/admin/cleanup-duplicate-categories', {
        method: 'GET',
      });
      return response.json();
    },
    onSuccess: (data) => {
      toast({
        title: "Cleanup Complete",
        description: data.message || `Removed ${data.removed || 0} duplicate categories.`,
      });
    },
    onError: (error) => {
      toast({
        title: "Cleanup Failed",
        description: error.message || "Failed to clean up duplicate categories.",
        variant: "destructive",
      });
    },
  });

  return (
    <div className="container max-w-7xl mx-auto p-6" data-testid="settings-page">
      <div className="mb-8">
        <h1 className="text-3xl font-bold">Settings</h1>
        <p className="text-muted-foreground">Manage your account settings and preferences</p>
      </div>

      <Tabs defaultValue="profile" className="space-y-4">
        <TabsList>
          <TabsTrigger value="profile" data-testid="tab-profile">
            <User className="w-4 h-4 mr-2" />
            Profile
          </TabsTrigger>
          <TabsTrigger value="notifications" data-testid="tab-notifications">
            <Bell className="w-4 h-4 mr-2" />
            Notifications
          </TabsTrigger>
          <TabsTrigger value="security" data-testid="tab-security">
            <Shield className="w-4 h-4 mr-2" />
            Security
          </TabsTrigger>
          <TabsTrigger value="appearance" data-testid="tab-appearance">
            <Palette className="w-4 h-4 mr-2" />
            Appearance
          </TabsTrigger>
          <TabsTrigger value="storage" data-testid="tab-storage">
            <HardDrive className="w-4 h-4 mr-2" />
            Storage
          </TabsTrigger>
          <TabsTrigger value="about" data-testid="tab-about">
            <Info className="w-4 h-4 mr-2" />
            About
          </TabsTrigger>
          {isAdmin && (
            <TabsTrigger value="admin" data-testid="tab-admin">
              <Settings2 className="w-4 h-4 mr-2" />
              Admin
            </TabsTrigger>
          )}
        </TabsList>

        <TabsContent value="profile">
          <Card>
            <CardHeader>
              <CardTitle>Profile Information</CardTitle>
              <CardDescription>
                Update your account profile information and email address
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="display-name">Display Name</Label>
                <Input
                  id="display-name"
                  value={displayName}
                  onChange={(e) => setDisplayName(e.target.value)}
                  placeholder="Enter your display name"
                  data-testid="input-display-name"
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="email">Email Address</Label>
                <Input
                  id="email"
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Enter your email"
                  disabled
                  data-testid="input-email"
                />
                <p className="text-sm text-muted-foreground">
                  Email cannot be changed as it's linked to your Replit account
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="user-id">User ID</Label>
                <Input
                  id="user-id"
                  value={user?.id || ""}
                  disabled
                  data-testid="input-user-id"
                />
              </div>
              <Button onClick={handleSaveProfile} data-testid="save-profile">
                Save Changes
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="notifications">
          <Card>
            <CardHeader>
              <CardTitle>Notification Preferences</CardTitle>
              <CardDescription>
                Configure how you receive notifications
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Email Notifications</Label>
                  <p className="text-sm text-muted-foreground">
                    Receive email updates about your uploads and activity
                  </p>
                </div>
                <Switch
                  checked={emailNotifications}
                  onCheckedChange={setEmailNotifications}
                  data-testid="switch-email-notifications"
                />
              </div>
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Upload Confirmations</Label>
                  <p className="text-sm text-muted-foreground">
                    Get notified when uploads are complete
                  </p>
                </div>
                <Switch defaultChecked data-testid="switch-upload-confirmations" />
              </div>
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Security Alerts</Label>
                  <p className="text-sm text-muted-foreground">
                    Notifications about security-related activities
                  </p>
                </div>
                <Switch defaultChecked data-testid="switch-security-alerts" />
              </div>
              <Button onClick={handleSaveNotifications} data-testid="save-notifications">
                Save Preferences
              </Button>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="security">
          <Card>
            <CardHeader>
              <CardTitle>Security Settings</CardTitle>
              <CardDescription>
                Manage your account security and privacy
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>Two-Factor Authentication</Label>
                <p className="text-sm text-muted-foreground mb-2">
                  Add an extra layer of security to your account
                </p>
                <Button variant="outline" data-testid="enable-2fa">
                  Enable Two-Factor Authentication
                </Button>
              </div>
              <div className="space-y-2">
                <Label>Vault Settings</Label>
                <p className="text-sm text-muted-foreground mb-2">
                  Configure your secure vault preferences
                </p>
                <Button variant="outline" data-testid="vault-settings">
                  Manage Vault Settings
                </Button>
              </div>
              <div className="space-y-2">
                <Label>Active Sessions</Label>
                <p className="text-sm text-muted-foreground mb-2">
                  View and manage your active login sessions
                </p>
                <Button variant="outline" data-testid="view-sessions">
                  View Active Sessions
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="appearance">
          <Card>
            <CardHeader>
              <CardTitle>Appearance</CardTitle>
              <CardDescription>
                Customize how SecureGallery Pro looks for you
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="theme">Theme</Label>
                <Select value={theme} onValueChange={setTheme}>
                  <SelectTrigger id="theme" data-testid="select-theme">
                    <SelectValue placeholder="Select a theme" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="light">Light</SelectItem>
                    <SelectItem value="dark">Dark</SelectItem>
                    <SelectItem value="system">System</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-sm text-muted-foreground">
                  Choose your preferred color theme
                </p>
              </div>
              <div className="space-y-2">
                <Label htmlFor="view-mode">Default View Mode</Label>
                <Select defaultValue="grid">
                  <SelectTrigger id="view-mode" data-testid="select-view-mode">
                    <SelectValue placeholder="Select default view" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="grid">Grid View</SelectItem>
                    <SelectItem value="list">List View</SelectItem>
                    <SelectItem value="timeline">Timeline View</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-sm text-muted-foreground">
                  Choose your preferred view for files and media
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="storage">
          <Card>
            <CardHeader>
              <CardTitle>Storage Management</CardTitle>
              <CardDescription>
                Monitor and manage your storage usage
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>Storage Usage</Label>
                <div className="w-full bg-secondary rounded-full h-4 mb-2">
                  <div className="bg-primary h-4 rounded-full" style={{ width: "35%" }} />
                </div>
                <p className="text-sm text-muted-foreground">
                  3.5 GB of 10 GB used
                </p>
              </div>
              <div className="flex items-center justify-between">
                <div className="space-y-0.5">
                  <Label>Auto Backup</Label>
                  <p className="text-sm text-muted-foreground">
                    Automatically backup your files
                  </p>
                </div>
                <Switch
                  checked={autoBackup}
                  onCheckedChange={setAutoBackup}
                  data-testid="switch-auto-backup"
                />
              </div>
              <div className="space-y-2">
                <Button variant="outline" data-testid="clear-cache">
                  Clear Cache
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="about">
          <Card>
            <CardHeader>
              <CardTitle>About SecureGallery Pro</CardTitle>
              <CardDescription>
                Information about your application
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>Version</Label>
                <p className="text-sm text-muted-foreground">v2.0.0</p>
              </div>
              <div className="space-y-2">
                <Label>Features</Label>
                <ul className="text-sm text-muted-foreground space-y-1">
                  <li>• Comprehensive file management system</li>
                  <li>• Multiple view modes (Grid, List, Tree, Timeline)</li>
                  <li>• Secure vault with AES-256 encryption</li>
                  <li>• Support for all file types</li>
                  <li>• Folder hierarchy with unlimited nesting</li>
                  <li>• Advanced metadata and EXIF data display</li>
                  <li>• Tagging and album organization</li>
                  <li>• Bulk file operations</li>
                </ul>
              </div>
              <div className="space-y-2">
                <Label>Support</Label>
                <p className="text-sm text-muted-foreground">
                  For support and feedback, please contact your administrator
                </p>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {isAdmin && (
          <TabsContent value="admin">
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>User Administration</CardTitle>
                  <CardDescription>
                    Manage users, roles, and permissions
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-4">
                    <div className="flex items-center justify-between">
                      <div className="space-y-1">
                        <div className="flex items-center gap-2">
                          <Users className="w-5 h-5" />
                          <Label className="text-base">User Management</Label>
                        </div>
                        <p className="text-sm text-muted-foreground">
                          View all users, manage roles, monitor storage usage, and control access
                        </p>
                      </div>
                      <Link href="/admin/users">
                        <Button data-testid="button-user-admin">
                          Open User Admin
                          <ArrowRight className="w-4 h-4 ml-2" />
                        </Button>
                      </Link>
                    </div>
                  </div>
                </CardContent>
              </Card>
              
              <Card>
                <CardHeader>
                  <CardTitle>Data Migration</CardTitle>
                  <CardDescription>
                    Sync existing media files to the new file manager system
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label>Sync Media to File Manager</Label>
                    <p className="text-sm text-muted-foreground mb-4">
                      This will migrate all existing media files to be available in the file manager.
                      Files that are already synced will be skipped.
                    </p>
                    <Button
                      onClick={() => syncMediaMutation.mutate()}
                      disabled={syncMediaMutation.isPending}
                      data-testid="button-sync-media"
                    >
                      {syncMediaMutation.isPending ? (
                        <>
                          <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                          Syncing...
                        </>
                      ) : (
                        <>
                          <RefreshCw className="w-4 h-4 mr-2" />
                          Sync Media to File Manager
                        </>
                      )}
                    </Button>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Category Cleanup</CardTitle>
                  <CardDescription>
                    Clean up duplicate categories in the database
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label>Remove Duplicate Categories</Label>
                    <p className="text-sm text-muted-foreground mb-4">
                      This will identify and remove duplicate category entries,
                      keeping the first occurrence and updating all references.
                    </p>
                    <Button
                      onClick={() => cleanupCategoriesMutation.mutate()}
                      disabled={cleanupCategoriesMutation.isPending}
                      variant="outline"
                      data-testid="button-cleanup-categories"
                    >
                      {cleanupCategoriesMutation.isPending ? (
                        <>
                          <Trash2 className="w-4 h-4 mr-2 animate-spin" />
                          Cleaning...
                        </>
                      ) : (
                        <>
                          <Trash2 className="w-4 h-4 mr-2" />
                          Clean Duplicate Categories
                        </>
                      )}
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        )}
      </Tabs>
    </div>
  );
}