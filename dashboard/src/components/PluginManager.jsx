import { useEffect, useState } from "react";
import { Edit, Package, Plus, Search, Shield, Trash2 } from "lucide-react";
import EditPluginDialog from "./EditPluginDialog.jsx";
import DynamicPackageInputs from "./DynamicPackageInputs.jsx";
import EncryptionModal from "./EncryptionModal.jsx";
import { Button } from "@/components/ui/button.jsx";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.jsx";
import { Badge } from "@/components/ui/badge.jsx";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table.jsx";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog.jsx";
import { Input } from "@/components/ui/input.jsx";
import { Label } from "@/components/ui/label.jsx";
import { Textarea } from "@/components/ui/textarea.jsx";
import { Alert, AlertDescription } from "@/components/ui/alert.jsx";
import { useAuth } from "@/contexts/AuthContext.jsx";
import { API_BASE_URL } from "@/lib/config.js";

export default function PluginManager() {
  const { getAuthHeaders } = useAuth();
  const [plugins, setPlugins] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [showRegisterDialog, setShowRegisterDialog] = useState(false);
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [showEncryptionModal, setShowEncryptionModal] = useState(false);
  const [editingPlugin, setEditingPlugin] = useState(null);
  const [selectedPlugin, setSelectedPlugin] = useState(null);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const [newPlugin, setNewPlugin] = useState({
    pluginId: "",
    name: "",
    version: "",
    description: "",
    originalMainClass: "",
    targetPackages: [""],
    ownerId: "admin",
    jarHash: "",
    jarFile: null,
  });

  useEffect(() => {
    loadPlugins();
  }, []);

  const loadPlugins = async () => {
    try {
      setLoading(true);
      const response = await fetch(`${API_BASE_URL}/plugins`, {
        headers: getAuthHeaders(),
      });
      if (response.ok) {
        const data = await response.json();
        if (data.success) {
          setPlugins(data.plugins || []);
        } else {
          setError("Failed to load plugins: " + data.error);
        }
      } else {
        setError("Failed to connect to backend");
      }
    } catch (err) {
      setError("Error loading plugins: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  const registerPlugin = async () => {
    try {
      setError("");
      setSuccess("");

      if (
        !newPlugin.pluginId ||
        !newPlugin.name ||
        !newPlugin.originalMainClass
      ) {
        setError(
          "Please fill in all required fields (Plugin ID, Name, and Original Main Class)",
        );
        return;
      }

      const validPackages = newPlugin.targetPackages.filter((pkg) =>
        pkg.trim(),
      );
      if (validPackages.length === 0) {
        setError("At least one target package must be specified");
        return;
      }

      const formData = new FormData();

      const pluginData = {
        pluginId: newPlugin.pluginId,
        name: newPlugin.name,
        version: newPlugin.version,
        description: newPlugin.description,
        originalMainClass: newPlugin.originalMainClass,
        targetPackages: validPackages,
        ownerId: newPlugin.ownerId,
        jarHash: newPlugin.jarHash,
      };

      formData.append("pluginData", JSON.stringify(pluginData));

      if (newPlugin.jarFile) {
        formData.append("jarFile", newPlugin.jarFile);
      }

      const response = await fetch(`${API_BASE_URL}/plugins`, {
        method: "POST",
        headers: getAuthHeaders(),
        body: formData,
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setSuccess(
          "Plugin registered successfully!" +
            (newPlugin.jarFile ? " JAR file uploaded." : ""),
        );
        setNewPlugin({
          pluginId: "",
          name: "",
          version: "",
          description: "",
          originalMainClass: "",
          targetPackages: [""],
          ownerId: "admin",
          jarHash: "",
          jarFile: null,
        });
        setShowRegisterDialog(false);
        loadPlugins();
      } else {
        setError(data.error || "Failed to register plugin");
      }
    } catch (err) {
      setError("Error registering plugin: " + err.message);
    }
  };

  const handleEncryptPlugin = (plugin) => {
    setSelectedPlugin(plugin);
    setShowEncryptionModal(true);
  };

  const deletePlugin = async (pluginId) => {
    try {
      setError("");
      setSuccess("");

      const response = await fetch(`${API_BASE_URL}/plugins/${pluginId}`, {
        method: "DELETE",
        headers: getAuthHeaders(),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setSuccess("Plugin deleted successfully!");
        loadPlugins();
      } else {
        setError(data.error || "Failed to delete plugin");
      }
    } catch (err) {
      setError("Error deleting plugin: " + err.message);
    }
  };

  const updatePlugin = async (pluginId, updatedData) => {
    try {
      setError("");
      setSuccess("");

      const response = await fetch(`${API_BASE_URL}/plugins/${pluginId}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          ...getAuthHeaders(),
        },
        body: JSON.stringify(updatedData),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setSuccess("Plugin updated successfully!");
        setShowEditDialog(false);
        setEditingPlugin(null);
        loadPlugins();
      } else {
        setError(data.error || "Failed to update plugin");
      }
    } catch (err) {
      setError("Error updating plugin: " + err.message);
    }
  };

  const handleEditPlugin = (plugin) => {
    setEditingPlugin(plugin);
    setShowEditDialog(true);
  };

  const filteredPlugins = plugins.filter(
    (plugin) =>
      plugin.pluginId?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      plugin.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      plugin.description?.toLowerCase().includes(searchTerm.toLowerCase()),
  );

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-lg">Loading plugins...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">
            Plugin Management
          </h2>
          <p className="text-muted-foreground">
            Register and manage plugins for license creation
          </p>
        </div>
        <Dialog open={showRegisterDialog} onOpenChange={setShowRegisterDialog}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Register Plugin
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>Register New Plugin</DialogTitle>
              <DialogDescription>
                Add a new plugin to the system. This information will be used
                for license creation.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="pluginId">Plugin ID *</Label>
                <Input
                  id="pluginId"
                  placeholder="e.g., alcachofa-v1.0"
                  value={newPlugin.pluginId}
                  onChange={(e) =>
                    setNewPlugin({ ...newPlugin, pluginId: e.target.value })
                  }
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="name">Plugin Name *</Label>
                <Input
                  id="name"
                  placeholder="e.g., Alcachofa Plugin"
                  value={newPlugin.name}
                  onChange={(e) =>
                    setNewPlugin({ ...newPlugin, name: e.target.value })
                  }
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="version">Version</Label>
                <Input
                  id="version"
                  placeholder="e.g., 1.0.0"
                  value={newPlugin.version}
                  onChange={(e) =>
                    setNewPlugin({ ...newPlugin, version: e.target.value })
                  }
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="description">Description</Label>
                <Textarea
                  id="description"
                  placeholder="Brief description of the plugin"
                  value={newPlugin.description}
                  onChange={(e) =>
                    setNewPlugin({ ...newPlugin, description: e.target.value })
                  }
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="originalMainClass">Original Main Class *</Label>
                <Input
                  id="originalMainClass"
                  placeholder="e.g., net.kerfu.alcachofa.Meetup"
                  value={newPlugin.originalMainClass}
                  onChange={(e) =>
                    setNewPlugin({
                      ...newPlugin,
                      originalMainClass: e.target.value,
                    })
                  }
                />
              </div>
              <DynamicPackageInputs
                packages={newPlugin.targetPackages}
                onChange={(packages) =>
                  setNewPlugin({ ...newPlugin, targetPackages: packages })
                }
                label="Target Packages for Encryption *"
              />
              <div className="space-y-2">
                <Label htmlFor="jarHash">JAR Hash (SHA-256)</Label>
                <Input
                  id="jarHash"
                  placeholder="Optional: SHA-256 hash of the original JAR"
                  value={newPlugin.jarHash}
                  onChange={(e) =>
                    setNewPlugin({ ...newPlugin, jarHash: e.target.value })
                  }
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="jarFile">Upload JAR File</Label>
                <Input
                  id="jarFile"
                  type="file"
                  accept=".jar"
                  onChange={(e) => {
                    const file = e.target.files[0];
                    setNewPlugin({ ...newPlugin, jarFile: file });
                  }}
                />
                <p className="text-xs text-muted-foreground">
                  Optional: Upload the original JAR file for automatic
                  encryption
                </p>
              </div>
              <div className="flex justify-end space-x-2">
                <Button
                  variant="outline"
                  onClick={() => setShowRegisterDialog(false)}
                >
                  Cancel
                </Button>
                <Button onClick={registerPlugin}>Register Plugin</Button>
              </div>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {success && (
        <Alert>
          <AlertDescription>{success}</AlertDescription>
        </Alert>
      )}

      <div className="flex items-center space-x-2">
        <Search className="h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search plugins..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="max-w-sm"
        />
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Package className="mr-2 h-5 w-5" />
            Registered Plugins ({filteredPlugins.length})
          </CardTitle>
          <CardDescription>
            Plugins available for license creation
          </CardDescription>
        </CardHeader>
        <CardContent>
          {filteredPlugins.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              {plugins.length === 0
                ? "No plugins registered yet"
                : "No plugins match your search"}
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Plugin ID</TableHead>
                  <TableHead>Name</TableHead>
                  <TableHead>Version</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredPlugins.map((plugin) => (
                  <TableRow key={plugin.pluginId}>
                    <TableCell className="font-mono text-sm">
                      {plugin.pluginId}
                    </TableCell>
                    <TableCell>
                      <div>
                        <div className="font-medium">{plugin.name}</div>
                        {plugin.description && (
                          <div className="text-sm text-muted-foreground truncate max-w-xs">
                            {plugin.description}
                          </div>
                        )}
                      </div>
                    </TableCell>
                    <TableCell>{plugin.version || "N/A"}</TableCell>
                    <TableCell>
                      <Badge variant={plugin.active ? "default" : "secondary"}>
                        {plugin.active ? "Active" : "Inactive"}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {plugin.createdAt
                        ? new Date(plugin.createdAt).toLocaleDateString()
                        : "N/A"}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center space-x-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleEncryptPlugin(plugin)}
                          title="Encrypt plugin with custom packages"
                          className="text-blue-600"
                        >
                          <Shield className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleEditPlugin(plugin)}
                          title="Editar plugin"
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-destructive"
                          onClick={() => {
                            if (
                              window.confirm(
                                `Are you sure you want to delete the plugin "${plugin.name}"?`,
                              )
                            ) {
                              deletePlugin(plugin.pluginId);
                            }
                          }}
                          title="Eliminar plugin"
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <EditPluginDialog
        plugin={editingPlugin}
        isOpen={showEditDialog}
        onClose={() => {
          setShowEditDialog(false);
          setEditingPlugin(null);
        }}
        onSave={(updatedData) =>
          updatePlugin(editingPlugin.pluginId, updatedData)
        }
      />

      <EncryptionModal
        isOpen={showEncryptionModal}
        onClose={() => {
          setShowEncryptionModal(false);
          setSelectedPlugin(null);
        }}
        plugin={selectedPlugin}
        userToken={localStorage.getItem("authToken")}
      />
    </div>
  );
}
