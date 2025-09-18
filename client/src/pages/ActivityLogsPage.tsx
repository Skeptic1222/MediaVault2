import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { useAuth } from "@/hooks/useAuth";
import { useToast } from "@/hooks/use-toast";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import Navbar from "@/components/ui/navbar";
import { 
  Search, 
  Filter, 
  Calendar, 
  Activity,
  Download,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  Shield,
  AlertCircle
} from "lucide-react";
import { format } from "date-fns";

interface ActivityLog {
  id: string;
  userId: string;
  action: string;
  resource?: string;
  resourceId?: string;
  ipAddress?: string;
  userAgent?: string;
  metadata?: any;
  createdAt: string;
}

const ACTION_TYPES = [
  { value: "all", label: "All Actions" },
  { value: "LOGIN", label: "Login" },
  { value: "LOGOUT", label: "Logout" },
  { value: "VIEW_MEDIA", label: "View Media" },
  { value: "UPLOAD_MEDIA", label: "Upload Media" },
  { value: "DELETE_MEDIA", label: "Delete Media" },
  { value: "DOWNLOAD_MEDIA", label: "Download Media" },
  { value: "CREATE_CATEGORY", label: "Create Category" },
  { value: "DELETE_CATEGORY", label: "Delete Category" },
  { value: "VAULT_ACCESS", label: "Vault Access" },
  { value: "VAULT_SETUP", label: "Vault Setup" },
  { value: "IMPORT_START", label: "Import Start" },
  { value: "FILE_CREATE", label: "File Create" },
  { value: "FILE_DELETE", label: "File Delete" },
  { value: "FOLDER_CREATE", label: "Folder Create" },
  { value: "USER_UPDATE", label: "User Update" },
];

export default function ActivityLogsPage() {
  const { toast } = useToast();
  const { user } = useAuth();
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState("");
  const [actionFilter, setActionFilter] = useState("all");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [debouncedSearch, setDebouncedSearch] = useState("");

  const limit = 50;

  // Check if user is admin
  const isAdmin = user?.role === 'admin';

  // Redirect if not admin
  useEffect(() => {
    if (user && !isAdmin) {
      toast({
        title: "Access Denied",
        description: "You need administrator privileges to access this page",
        variant: "destructive",
      });
      window.location.href = "/";
    }
  }, [user, isAdmin, toast]);

  // Debounce search input
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedSearch(search);
      setPage(0); // Reset to first page on search
    }, 300);
    return () => clearTimeout(timer);
  }, [search]);

  const { data, isLoading, error, refetch } = useQuery({
    queryKey: [
      "/api/activity",
      page,
      debouncedSearch,
      actionFilter,
      dateFrom,
      dateTo,
      "admin"
    ],
    queryFn: async () => {
      const params = new URLSearchParams({
        adminView: "true",
        limit: limit.toString(),
        offset: (page * limit).toString(),
        ...(debouncedSearch && { search: debouncedSearch }),
        ...(actionFilter !== "all" && { action: actionFilter }),
        ...(dateFrom && { dateFrom }),
        ...(dateTo && { dateTo }),
      });

      const response = await fetch(`/api/activity?${params}`);
      if (!response.ok) {
        throw new Error("Failed to fetch activity logs");
      }
      return response.json();
    },
    enabled: isAdmin,
    retry: false,
  });

  const handleExport = () => {
    // Create CSV content
    const headers = ["Timestamp", "User ID", "Action", "Resource", "Resource ID", "IP Address"];
    const rows = data?.logs?.map((log: ActivityLog) => [
      format(new Date(log.createdAt), "yyyy-MM-dd HH:mm:ss"),
      log.userId,
      log.action,
      log.resource || "-",
      log.resourceId || "-",
      log.ipAddress || "-",
    ]);

    const csvContent = [
      headers.join(","),
      ...(rows || []).map((row: string[]) => row.join(","))
    ].join("\n");

    // Download CSV
    const blob = new Blob([csvContent], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `activity-logs-${format(new Date(), "yyyy-MM-dd")}.csv`;
    a.click();
    URL.revokeObjectURL(url);

    toast({
      title: "Export Complete",
      description: "Activity logs have been exported to CSV",
    });
  };

  const handleReset = () => {
    setSearch("");
    setActionFilter("all");
    setDateFrom("");
    setDateTo("");
    setPage(0);
  };

  const getActionBadgeVariant = (action: string): "default" | "secondary" | "destructive" | "outline" => {
    if (action.includes("DELETE")) return "destructive";
    if (action.includes("CREATE") || action.includes("UPLOAD")) return "default";
    if (action.includes("VIEW") || action.includes("DOWNLOAD")) return "secondary";
    return "outline";
  };

  if (!isAdmin) {
    return null; // Will redirect via useEffect
  }

  return (
    <div className="min-h-screen bg-background">
      <Navbar />
      
      <main className="pt-16">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {/* Header */}
          <div className="mb-8">
            <div className="flex items-center gap-3 mb-4">
              <Shield className="w-8 h-8 text-primary" />
              <h1 className="text-3xl font-bold" data-testid="text-title">
                System Activity Logs
              </h1>
            </div>
            <p className="text-muted-foreground">
              Monitor all system activity and user actions for security auditing
            </p>
          </div>

          {/* Filters */}
          <Card className="mb-6">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Filter className="w-5 h-5" />
                Filters & Search
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {/* Search */}
                <div className="space-y-2">
                  <Label htmlFor="search">Search</Label>
                  <div className="relative">
                    <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                    <Input
                      id="search"
                      type="text"
                      placeholder="Search in logs..."
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                      className="pl-10"
                      data-testid="input-search"
                    />
                  </div>
                </div>

                {/* Action Filter */}
                <div className="space-y-2">
                  <Label htmlFor="action-filter">Action Type</Label>
                  <Select value={actionFilter} onValueChange={setActionFilter}>
                    <SelectTrigger id="action-filter" data-testid="select-action">
                      <SelectValue placeholder="Filter by action" />
                    </SelectTrigger>
                    <SelectContent>
                      {ACTION_TYPES.map((type) => (
                        <SelectItem key={type.value} value={type.value}>
                          {type.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                {/* Date From */}
                <div className="space-y-2">
                  <Label htmlFor="date-from">From Date</Label>
                  <Input
                    id="date-from"
                    type="date"
                    value={dateFrom}
                    onChange={(e) => setDateFrom(e.target.value)}
                    data-testid="input-date-from"
                  />
                </div>

                {/* Date To */}
                <div className="space-y-2">
                  <Label htmlFor="date-to">To Date</Label>
                  <Input
                    id="date-to"
                    type="date"
                    value={dateTo}
                    onChange={(e) => setDateTo(e.target.value)}
                    data-testid="input-date-to"
                  />
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex gap-2 mt-4">
                <Button
                  variant="outline"
                  onClick={handleReset}
                  className="gap-2"
                  data-testid="button-reset"
                >
                  <RefreshCw className="w-4 h-4" />
                  Reset Filters
                </Button>
                <Button
                  variant="outline"
                  onClick={() => refetch()}
                  className="gap-2"
                  data-testid="button-refresh"
                >
                  <RefreshCw className="w-4 h-4" />
                  Refresh
                </Button>
                {data?.logs && data.logs.length > 0 && (
                  <Button
                    variant="outline"
                    onClick={handleExport}
                    className="gap-2"
                    data-testid="button-export"
                  >
                    <Download className="w-4 h-4" />
                    Export CSV
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Logs Table */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Activity className="w-5 h-5" />
                  Activity Logs
                </div>
                {data?.total && (
                  <span className="text-sm font-normal text-muted-foreground">
                    Total: {data.total.toLocaleString()} logs
                  </span>
                )}
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              {error ? (
                <div className="flex items-center justify-center py-12 text-muted-foreground">
                  <AlertCircle className="w-5 h-5 mr-2" />
                  Failed to load activity logs
                </div>
              ) : isLoading ? (
                <div className="p-6 space-y-3">
                  {[...Array(5)].map((_, i) => (
                    <Skeleton key={i} className="h-12 w-full" />
                  ))}
                </div>
              ) : data?.logs && data.logs.length > 0 ? (
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Timestamp</TableHead>
                        <TableHead>User ID</TableHead>
                        <TableHead>Action</TableHead>
                        <TableHead>Resource</TableHead>
                        <TableHead>Details</TableHead>
                        <TableHead>IP Address</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.logs.map((log: ActivityLog) => (
                        <TableRow key={log.id} data-testid={`log-row-${log.id}`}>
                          <TableCell className="text-sm">
                            {format(new Date(log.createdAt), "MMM dd, yyyy HH:mm:ss")}
                          </TableCell>
                          <TableCell className="font-mono text-xs">
                            {log.userId.slice(0, 8)}...
                          </TableCell>
                          <TableCell>
                            <Badge variant={getActionBadgeVariant(log.action)}>
                              {log.action}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-sm">
                            {log.resource || "-"}
                          </TableCell>
                          <TableCell className="text-sm">
                            {log.resourceId ? (
                              <span className="font-mono text-xs">{log.resourceId.slice(0, 12)}...</span>
                            ) : (
                              "-"
                            )}
                          </TableCell>
                          <TableCell className="text-sm">
                            {log.ipAddress || "-"}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              ) : (
                <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                  <Activity className="w-12 h-12 mb-3 opacity-50" />
                  <p>No activity logs found</p>
                  <p className="text-sm mt-1">Try adjusting your filters</p>
                </div>
              )}

              {/* Pagination */}
              {data?.total && data.total > limit && (
                <div className="flex items-center justify-between px-6 py-4 border-t">
                  <div className="text-sm text-muted-foreground">
                    Showing {page * limit + 1} to {Math.min((page + 1) * limit, data.total)} of {data.total} logs
                  </div>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setPage(Math.max(0, page - 1))}
                      disabled={page === 0}
                      data-testid="button-prev-page"
                    >
                      <ChevronLeft className="w-4 h-4" />
                      Previous
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setPage(page + 1)}
                      disabled={(page + 1) * limit >= data.total}
                      data-testid="button-next-page"
                    >
                      Next
                      <ChevronRight className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  );
}