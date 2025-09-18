import { useState, useEffect } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { queryClient, apiRequest } from "@/lib/queryClient";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { useToast } from "@/hooks/use-toast";
import { Plus, Edit2, Trash2, Folder, FolderOpen, Loader2, AlertCircle } from "lucide-react";
import type { Category } from "@shared/schema";

interface ManageCategoriesDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

interface CategoryWithStats extends Category {
  fileCount: number;
}

interface CategoryTreeNode extends CategoryWithStats {
  children: CategoryTreeNode[];
  level: number;
}

export default function ManageCategoriesDialog({ open, onOpenChange }: ManageCategoriesDialogProps) {
  const { toast } = useToast();
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingName, setEditingName] = useState("");
  const [newCategoryName, setNewCategoryName] = useState("");
  const [newCategoryParentId, setNewCategoryParentId] = useState<string | null>(null);
  const [showNewCategoryForm, setShowNewCategoryForm] = useState(false);
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false);
  const [categoryToDelete, setCategoryToDelete] = useState<{ id: string; name: string; fileCount: number } | null>(null);

  // Fetch categories
  const { data: categories, isLoading: categoriesLoading } = useQuery<Category[]>({
    queryKey: ["/api/categories"],
    enabled: open,
  });

  // Fetch category stats
  const { data: categoryStats, isLoading: statsLoading } = useQuery<Record<string, number>>({
    queryKey: ["/api/stats/categories"],
    enabled: open,
  });

  // Combine categories with their file counts
  const categoriesWithStats: CategoryWithStats[] = categories?.map(cat => ({
    ...cat,
    fileCount: categoryStats?.[cat.id] || 0
  })) || [];

  // Create category mutation
  const createMutation = useMutation({
    mutationFn: async (data: { name: string; parentId?: string | null }) => {
      return await apiRequest('/api/categories', {
        method: 'POST',
        body: JSON.stringify(data),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/categories"] });
      queryClient.invalidateQueries({ queryKey: ["/api/stats/categories"] });
      toast({
        title: "Success",
        description: "Category created successfully",
      });
      setShowNewCategoryForm(false);
      setNewCategoryName("");
      setNewCategoryParentId(null);
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to create category",
        variant: "destructive",
      });
    },
  });

  // Update category mutation
  const updateMutation = useMutation({
    mutationFn: async ({ id, name }: { id: string; name: string }) => {
      return await apiRequest(`/api/categories/${id}`, {
        method: 'PUT',
        body: JSON.stringify({ name }),
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/categories"] });
      toast({
        title: "Success",
        description: "Category updated successfully",
      });
      setEditingId(null);
      setEditingName("");
    },
    onError: (error: any) => {
      toast({
        title: "Error",
        description: error.message || "Failed to update category",
        variant: "destructive",
      });
    },
  });

  // Delete category mutation
  const deleteMutation = useMutation({
    mutationFn: async (id: string) => {
      return await apiRequest(`/api/categories/${id}`, {
        method: 'DELETE',
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["/api/categories"] });
      queryClient.invalidateQueries({ queryKey: ["/api/stats/categories"] });
      queryClient.invalidateQueries({ queryKey: ["/api/media"] });
      toast({
        title: "Success",
        description: "Category deleted successfully",
      });
      setCategoryToDelete(null);
      setDeleteDialogOpen(false);
    },
    onError: (error: any) => {
      const errorMessage = error.message || "Failed to delete category";
      const fileCount = error.fileCount;
      
      toast({
        title: "Error",
        description: fileCount 
          ? `Cannot delete category with ${fileCount} file(s). Please move or delete all files first.`
          : errorMessage,
        variant: "destructive",
      });
      setDeleteDialogOpen(false);
    },
  });

  // Build category tree for display
  const buildCategoryTree = (cats: CategoryWithStats[]): CategoryTreeNode[] => {
    const categoryMap = new Map<string, CategoryTreeNode>();
    const rootCategories: CategoryTreeNode[] = [];

    // Initialize category map
    cats.forEach(cat => {
      categoryMap.set(cat.id, { ...cat, children: [], level: 0 });
    });

    // Build tree structure
    cats.forEach(cat => {
      const category = categoryMap.get(cat.id)!;
      if (cat.parentId) {
        const parent = categoryMap.get(cat.parentId);
        if (parent) {
          parent.children.push(category);
          category.level = parent.level + 1;
        } else {
          rootCategories.push(category);
        }
      } else {
        rootCategories.push(category);
      }
    });

    // Sort categories by sortOrder and name
    const sortCategories = (nodes: CategoryTreeNode[]): CategoryTreeNode[] => {
      return nodes.sort((a, b) => {
        if (a.sortOrder !== b.sortOrder) {
          return (a.sortOrder || 0) - (b.sortOrder || 0);
        }
        return a.name.localeCompare(b.name);
      }).map(node => ({
        ...node,
        children: sortCategories(node.children)
      }));
    };

    return sortCategories(rootCategories);
  };

  const categoryTree = buildCategoryTree(categoriesWithStats);

  // Flatten tree for display with proper indentation
  const flattenTree = (tree: CategoryTreeNode[]): CategoryTreeNode[] => {
    const result: CategoryTreeNode[] = [];
    
    const traverse = (nodes: CategoryTreeNode[]) => {
      nodes.forEach(node => {
        result.push(node);
        if (node.children.length > 0) {
          traverse(node.children);
        }
      });
    };
    
    traverse(tree);
    return result;
  };

  const flatCategories = flattenTree(categoryTree);

  const handleStartEdit = (category: CategoryWithStats) => {
    setEditingId(category.id);
    setEditingName(category.name);
  };

  const handleSaveEdit = () => {
    if (editingId && editingName.trim()) {
      updateMutation.mutate({ id: editingId, name: editingName.trim() });
    }
  };

  const handleCancelEdit = () => {
    setEditingId(null);
    setEditingName("");
  };

  const handleCreateCategory = () => {
    if (newCategoryName.trim()) {
      createMutation.mutate({
        name: newCategoryName.trim(),
        parentId: newCategoryParentId,
      });
    }
  };

  const handleDeleteClick = (category: CategoryWithStats) => {
    setCategoryToDelete({
      id: category.id,
      name: category.name,
      fileCount: category.fileCount,
    });
    setDeleteDialogOpen(true);
  };

  const confirmDelete = () => {
    if (categoryToDelete) {
      deleteMutation.mutate(categoryToDelete.id);
    }
  };

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="max-w-2xl max-h-[80vh] flex flex-col" data-testid="manage-categories-dialog">
          <DialogHeader>
            <DialogTitle>Manage Categories</DialogTitle>
            <DialogDescription>
              Create, edit, or delete categories to organize your media collection.
            </DialogDescription>
          </DialogHeader>

          <div className="flex-1 flex flex-col min-h-0">
            {/* Add New Category Form */}
            {showNewCategoryForm ? (
              <div className="border rounded-lg p-4 mb-4 bg-secondary/20" data-testid="new-category-form">
                <div className="space-y-3">
                  <div>
                    <Label htmlFor="new-category-name">Category Name</Label>
                    <Input
                      id="new-category-name"
                      value={newCategoryName}
                      onChange={(e) => setNewCategoryName(e.target.value)}
                      placeholder="Enter category name"
                      autoFocus
                      data-testid="input-new-category-name"
                    />
                  </div>
                  
                  <div>
                    <Label htmlFor="parent-category">Parent Category (Optional)</Label>
                    <select
                      id="parent-category"
                      className="w-full px-3 py-2 border rounded-md bg-background"
                      value={newCategoryParentId || ""}
                      onChange={(e) => setNewCategoryParentId(e.target.value || null)}
                      data-testid="select-parent-category"
                    >
                      <option value="">None (Root Category)</option>
                      {flatCategories.map(cat => (
                        <option key={cat.id} value={cat.id}>
                          {"  ".repeat(cat.level)}{cat.name}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div className="flex justify-end space-x-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setShowNewCategoryForm(false);
                        setNewCategoryName("");
                        setNewCategoryParentId(null);
                      }}
                      data-testid="button-cancel-new-category"
                    >
                      Cancel
                    </Button>
                    <Button
                      size="sm"
                      onClick={handleCreateCategory}
                      disabled={!newCategoryName.trim() || createMutation.isPending}
                      data-testid="button-save-new-category"
                    >
                      {createMutation.isPending ? (
                        <>
                          <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                          Creating...
                        </>
                      ) : (
                        <>
                          <Plus className="w-4 h-4 mr-2" />
                          Create Category
                        </>
                      )}
                    </Button>
                  </div>
                </div>
              </div>
            ) : (
              <div className="mb-4">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setShowNewCategoryForm(true)}
                  data-testid="button-add-category"
                >
                  <Plus className="w-4 h-4 mr-2" />
                  Add New Category
                </Button>
              </div>
            )}

            {/* Categories List */}
            <ScrollArea className="flex-1 pr-4">
              {categoriesLoading || statsLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
                </div>
              ) : flatCategories.length === 0 ? (
                <div className="text-center py-8">
                  <Folder className="w-12 h-12 mx-auto mb-4 text-muted-foreground" />
                  <p className="text-muted-foreground">No categories yet. Create your first category to get started.</p>
                </div>
              ) : (
                <div className="space-y-1">
                  {flatCategories.map(category => (
                    <div
                      key={category.id}
                      className="flex items-center space-x-2 p-2 rounded-lg hover:bg-secondary/50 transition-colors"
                      style={{ paddingLeft: `${category.level * 1.5 + 0.5}rem` }}
                      data-testid={`category-item-${category.id}`}
                    >
                      <div className="flex items-center flex-1 min-w-0">
                        {category.fileCount > 0 ? (
                          <FolderOpen className="w-4 h-4 mr-2 text-primary shrink-0" />
                        ) : (
                          <Folder className="w-4 h-4 mr-2 text-muted-foreground shrink-0" />
                        )}
                        
                        {editingId === category.id ? (
                          <div className="flex items-center space-x-2 flex-1">
                            <Input
                              value={editingName}
                              onChange={(e) => setEditingName(e.target.value)}
                              onKeyDown={(e) => {
                                if (e.key === 'Enter') handleSaveEdit();
                                if (e.key === 'Escape') handleCancelEdit();
                              }}
                              className="h-8"
                              autoFocus
                              data-testid={`input-edit-category-${category.id}`}
                            />
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={handleSaveEdit}
                              disabled={!editingName.trim() || updateMutation.isPending}
                              data-testid={`button-save-edit-${category.id}`}
                            >
                              Save
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={handleCancelEdit}
                              data-testid={`button-cancel-edit-${category.id}`}
                            >
                              Cancel
                            </Button>
                          </div>
                        ) : (
                          <>
                            <span className="font-medium truncate">{category.name}</span>
                            <span className="text-sm text-muted-foreground ml-2">
                              ({category.fileCount} {category.fileCount === 1 ? 'file' : 'files'})
                            </span>
                          </>
                        )}
                      </div>

                      {editingId !== category.id && (
                        <div className="flex items-center space-x-1 shrink-0">
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => handleStartEdit(category)}
                            data-testid={`button-edit-${category.id}`}
                          >
                            <Edit2 className="w-4 h-4" />
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => handleDeleteClick(category)}
                            className={category.fileCount > 0 ? "text-muted-foreground" : "hover:text-destructive"}
                            title={category.fileCount > 0 ? "Cannot delete category with files" : "Delete category"}
                            data-testid={`button-delete-${category.id}`}
                          >
                            <Trash2 className="w-4 h-4" />
                          </Button>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </ScrollArea>

            {/* Info message */}
            {flatCategories.some(cat => cat.fileCount > 0) && (
              <div className="mt-4 p-3 bg-muted rounded-lg flex items-start space-x-2">
                <AlertCircle className="w-4 h-4 text-muted-foreground shrink-0 mt-0.5" />
                <p className="text-sm text-muted-foreground">
                  Categories with files cannot be deleted. Move or delete the files first.
                </p>
              </div>
            )}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <AlertDialog open={deleteDialogOpen} onOpenChange={setDeleteDialogOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Category</AlertDialogTitle>
            <AlertDialogDescription>
              {categoryToDelete && categoryToDelete.fileCount > 0 ? (
                <>
                  Cannot delete "{categoryToDelete.name}" because it contains {categoryToDelete.fileCount} file(s).
                  Please move or delete all files first.
                </>
              ) : (
                <>
                  Are you sure you want to delete the category "{categoryToDelete?.name}"?
                  This action cannot be undone.
                </>
              )}
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            {categoryToDelete && categoryToDelete.fileCount === 0 && (
              <AlertDialogAction
                onClick={confirmDelete}
                className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
              >
                Delete
              </AlertDialogAction>
            )}
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}