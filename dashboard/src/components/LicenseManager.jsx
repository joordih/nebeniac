import { Alert, AlertDescription } from "@/components/ui/alert.jsx";
import { Badge } from "@/components/ui/badge.jsx";
import { Button } from "@/components/ui/button.jsx";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.jsx";
import { Checkbox } from "@/components/ui/checkbox.jsx";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select.jsx";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table.jsx";
import { Textarea } from "@/components/ui/textarea.jsx";
import {
  Download,
  Edit,
  Eye,
  Key,
  Package,
  Plus,
  Search,
  Trash2,
} from "lucide-react";
import { useEffect, useState } from "react";
import { useAuth } from "@/contexts/AuthContext.jsx";
import BlurredLicenseKey from "./BlurredLicenseKey.jsx";
import EditLicenseDialog from "./EditLicenseDialog.jsx";
import UserCombobox from "./UserCombobox.jsx";
import ViewLicenseDialog from "./ViewLicenseDialog.jsx";
import {API_BASE_URL} from "@/lib/config.js";

const DEFAULT_NEW_LICENSE = {
  customerEmail: "",
  customerName: "",
  licenseType: "STANDARD",
  maxActivations: 5,
  features: ["BASIC_PROTECTION", "HEARTBEAT_VERIFICATION"],
  notes: "",
  pluginId: "",
};

const AVAILABLE_FEATURES = [
  "BASIC_PROTECTION",
  "HEARTBEAT_VERIFICATION",
  "ADVANCED_ENCRYPTION",
  "CUSTOM_BRANDING",
  "PRIORITY_SUPPORT",
];

export default function LicenseManager() {
  const { getAuthHeaders } = useAuth();
  const [licenses, setLicenses] = useState([]);
  const [plugins, setPlugins] = useState([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState("");
  const [filterType, setFilterType] = useState("all");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [showEditDialog, setShowEditDialog] = useState(false);
  const [showViewDialog, setShowViewDialog] = useState(false);
  const [editingLicense, setEditingLicense] = useState(null);
  const [viewingLicense, setViewingLicense] = useState(null);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");

  const [newLicense, setNewLicense] = useState(DEFAULT_NEW_LICENSE);
  const [selectedUser, setSelectedUser] = useState(null);

  useEffect(() => {
    loadLicenses();
    loadPlugins();
  }, []);

  const loadLicenses = async () => {
    try {
      setLoading(true);
      const response = await fetch(`${API_BASE_URL}/licenses`, {
        headers: getAuthHeaders(),
      });
      if (response.ok) {
        const data = await response.json();
        if (data.success) {
          const licensesWithDates = data.licenses.map((license) => ({
            ...license,
            createdAt: license.createdAt
              ? new Date(license.createdAt).toISOString()
              : null,
            updatedAt: license.updatedAt
              ? new Date(license.updatedAt).toISOString()
              : null,
            expiresAt: license.expiresAt
              ? new Date(license.expiresAt).toISOString()
              : null,
          }));
          setLicenses(licensesWithDates);
        } else {
          setError("Error loading licenses: " + data.error);
        }
      } else {
        setError("Failed to fetch licenses from server");
      }
    } catch (err) {
      setError("Error loading licenses: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  const loadPlugins = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/plugins`, {
        headers: getAuthHeaders(),
      });
      if (response.ok) {
        const data = await response.json();
        if (data.success) {
          setPlugins(data.plugins || []);
        }
      }
    } catch (err) {
      console.error("Error loading plugins:", err);
    }
  };

  const createLicense = async () => {
    try {
      setError("");
      setSuccess("");

      if (!selectedUser) {
        setError("Por favor selecciona un usuario");
        return;
      }

      if (!newLicense.pluginId) {
        setError("Por favor selecciona un plugin");
        return;
      }

      const licenseData = {
        ...newLicense,
        customerEmail: selectedUser.email,
        customerName:
          selectedUser.fullName ||
          `${selectedUser.firstName} ${selectedUser.lastName}`,
        userId: selectedUser.id,
        active: true,
      };

      const response = await fetch(`${API_BASE_URL}/licenses`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          ...getAuthHeaders(),
        },
        body: JSON.stringify(licenseData),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setSuccess(`License created successfully! License Key: ${data.license.licenseKey}`);
        setNewLicense(DEFAULT_NEW_LICENSE);
        setSelectedUser(null);
        setShowCreateDialog(false);
        loadLicenses();
      } else {
        setError(data.error || "Failed to create license");
      }
    } catch (err) {
      setError("Error creating license: " + err.message);
    }
  };

  const toggleFeature = (feature) => {
    setNewLicense((prev) => ({
      ...prev,
      features: prev.features.includes(feature)
        ? prev.features.filter((f) => f !== feature)
        : [...prev.features, feature],
    }));
  };

  const editLicense = async (licenseKey, updatedData) => {
    try {
      setError("");
      setSuccess("");

      const response = await fetch(`${API_BASE_URL}/licenses/${licenseKey}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          ...getAuthHeaders(),
        },
        body: JSON.stringify(updatedData),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setSuccess("License updated successfully!");
        setShowEditDialog(false);
        setEditingLicense(null);
        loadLicenses();
      } else {
        setError(data.error || "Failed to update license");
      }
    } catch (err) {
      setError("Error updating license: " + err.message);
    }
  };

  const handleEditLicense = (license) => {
    setEditingLicense(license);
    setShowEditDialog(true);
  };

  const viewLicense = (license) => {
    setViewingLicense(license);
    setShowViewDialog(true);
  };

  const downloadLicense = (license) => {
    const licenseData = {
      licenseKey: license.licenseKey,
      pluginId: license.pluginId,
      customerName: license.customerName,
      customerEmail: license.customerEmail,
      licenseType: license.licenseType,
      maxActivations: license.maxActivations,
      features: license.features,
      active: license.active,
      createdAt: license.createdAt,
      notes: license.notes,
    };

    const dataStr = JSON.stringify(licenseData, null, 2);
    const dataUri =
      "data:application/json;charset=utf-8," + encodeURIComponent(dataStr);

    const exportFileDefaultName = `license_${license.licenseKey}.json`;

    const linkElement = document.createElement("a");
    linkElement.setAttribute("href", dataUri);
    linkElement.setAttribute("download", exportFileDefaultName);
    linkElement.click();
  };

  const deleteLicense = async (licenseKey) => {
    if (
      !window.confirm(
        `Are you sure you want to delete the license "${licenseKey}"?`,
      )
    ) {
      return;
    }

    try {
      setError("");
      setSuccess("");

      const response = await fetch(`${API_BASE_URL}/licenses/${licenseKey}`, {
        method: "DELETE",
        headers: getAuthHeaders(),
      });

      const data = await response.json();

      if (response.ok && data.success) {
        setSuccess("License deleted successfully!");
        loadLicenses();
      } else {
        setError(data.error || "Failed to delete license");
      }
    } catch (err) {
      setError("Error deleting license: " + err.message);
    }
  };

  const filteredLicenses = licenses.filter((license) => {
    const matchesSearch =
      license.licenseKey?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      license.customerEmail?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      license.customerName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      license.pluginId?.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesFilter =
      filterType === "all" ||
      (filterType === "active" && license.active) ||
      (filterType === "inactive" && !license.active) ||
      filterType === license.licenseType?.toLowerCase();

    return matchesSearch && matchesFilter;
  });

  const getPluginName = (pluginId) => {
    const plugin = plugins.find((p) => p.pluginId === pluginId);
    return plugin ? plugin.name : pluginId;
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-lg">Loading licenses...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-3xl font-bold tracking-tight">
            License Management
          </h2>
          <p className="text-muted-foreground">
            Create and manage plugin licenses
          </p>
        </div>
        <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
          <DialogTrigger asChild>
            <Button>
              <Plus className="mr-2 h-4 w-4" />
              Create License
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-md">
            <DialogHeader>
              <DialogTitle>Create New License</DialogTitle>
              <DialogDescription>
                Create a new license for a registered plugin
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="pluginId">Plugin *</Label>
                <Select
                  value={newLicense.pluginId}
                  onValueChange={(value) =>
                    setNewLicense({ ...newLicense, pluginId: value })
                  }
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Select a plugin" />
                  </SelectTrigger>
                  <SelectContent>
                    {plugins
                      .filter((p) => p.active)
                      .map((plugin) => (
                        <SelectItem
                          key={plugin.pluginId}
                          value={plugin.pluginId}
                        >
                          <div className="flex items-center">
                            <Package className="mr-2 h-4 w-4" />
                            {plugin.name} ({plugin.pluginId})
                          </div>
                        </SelectItem>
                      ))}
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label>Usuario *</Label>
                <UserCombobox
                  selectedUser={selectedUser}
                  onUserSelect={setSelectedUser}
                  placeholder="Seleccionar usuario..."
                />
                {selectedUser && (
                  <div className="text-sm text-muted-foreground">
                    License will be created for:{" "}
                    <strong>{selectedUser.email}</strong>
                  </div>
                )}
              </div>
              <div className="space-y-2">
                <Label htmlFor="licenseType">License Type</Label>
                <Select
                  value={newLicense.licenseType}
                  onValueChange={(value) =>
                    setNewLicense({ ...newLicense, licenseType: value })
                  }
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="STANDARD">Standard</SelectItem>
                    <SelectItem value="PREMIUM">Premium</SelectItem>
                    <SelectItem value="ENTERPRISE">Enterprise</SelectItem>
                    <SelectItem value="DEVELOPER">Developer</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="maxActivations">Max Activations</Label>
                <Input
                  id="maxActivations"
                  type="number"
                  min="1"
                  value={newLicense.maxActivations}
                  onChange={(e) =>
                    setNewLicense({
                      ...newLicense,
                      maxActivations: parseInt(e.target.value) || 1,
                    })
                  }
                />
              </div>
              <div className="space-y-2">
                <Label>Features</Label>
                <div className="space-y-2">
                  {AVAILABLE_FEATURES.map((feature) => (
                    <div key={feature} className="flex items-center space-x-2">
                      <Checkbox
                        id={feature}
                        checked={newLicense.features.includes(feature)}
                        onCheckedChange={() => toggleFeature(feature)}
                      />
                      <Label htmlFor={feature} className="text-sm">
                        {feature
                          .replace(/_/g, " ")
                          .toLowerCase()
                          .replace(/\b\w/g, (l) => l.toUpperCase())}
                      </Label>
                    </div>
                  ))}
                </div>
              </div>
              <div className="space-y-2">
                <Label htmlFor="notes">Notes</Label>
                <Textarea
                  id="notes"
                  placeholder="Optional notes about this license"
                  value={newLicense.notes}
                  onChange={(e) =>
                    setNewLicense({ ...newLicense, notes: e.target.value })
                  }
                />
              </div>
              <div className="flex justify-end space-x-2">
                <Button
                  variant="outline"
                  onClick={() => setShowCreateDialog(false)}
                >
                  Cancel
                </Button>
                <Button onClick={createLicense}>Create License</Button>
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

      <div className="flex items-center space-x-4">
        <div className="flex items-center space-x-2">
          <Search className="h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search licenses..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="max-w-sm"
          />
        </div>
        <Select value={filterType} onValueChange={setFilterType}>
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Licenses</SelectItem>
            <SelectItem value="active">Active</SelectItem>
            <SelectItem value="inactive">Inactive</SelectItem>
            <SelectItem value="standard">Standard</SelectItem>
            <SelectItem value="premium">Premium</SelectItem>
            <SelectItem value="enterprise">Enterprise</SelectItem>
          </SelectContent>
        </Select>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center">
            <Key className="mr-2 h-5 w-5" />
            Licenses ({filteredLicenses.length})
          </CardTitle>
          <CardDescription>
            Manage plugin licenses and their associated metadata
          </CardDescription>
        </CardHeader>
        <CardContent>
          {filteredLicenses.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              {licenses.length === 0
                ? "No licenses created yet"
                : "No licenses match your search"}
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>License Key</TableHead>
                  <TableHead>Plugin</TableHead>
                  <TableHead>Customer</TableHead>
                  <TableHead>Type</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Activations</TableHead>
                  <TableHead>Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredLicenses.map((license) => (
                  <TableRow key={license.id}>
                    <TableCell>
                      <BlurredLicenseKey licenseKey={license.licenseKey} />
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center">
                        <Package className="mr-2 h-4 w-4 text-muted-foreground" />
                        <div>
                          <div className="font-medium">
                            {getPluginName(license.pluginId)}
                          </div>
                          <div className="text-sm text-muted-foreground">
                            {license.pluginId}
                          </div>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <div>
                        <div className="font-medium">
                          {license.customerName}
                        </div>
                        <div className="text-sm text-muted-foreground">
                          {license.customerEmail}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{license.licenseType}</Badge>
                    </TableCell>
                    <TableCell>
                      <Badge variant={license.active ? "default" : "secondary"}>
                        {license.active ? "Active" : "Inactive"}
                      </Badge>
                    </TableCell>
                    <TableCell>0 / {license.maxActivations}</TableCell>
                    <TableCell>
                      <div className="flex items-center space-x-2">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => viewLicense(license)}
                          title="Ver detalles"
                        >
                          <Eye className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => handleEditLicense(license)}
                          title="Editar licencia"
                        >
                          <Edit className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => downloadLicense(license)}
                          title="Descargar licencia"
                        >
                          <Download className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-destructive"
                          onClick={() => deleteLicense(license.licenseKey)}
                          title="Eliminar licencia"
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

      <EditLicenseDialog
        license={editingLicense}
        isOpen={showEditDialog}
        onClose={() => {
          setShowEditDialog(false);
          setEditingLicense(null);
        }}
        onSave={(updatedData) =>
          editLicense(editingLicense.licenseKey, updatedData)
        }
      />

      <ViewLicenseDialog
        license={viewingLicense}
        isOpen={showViewDialog}
        onClose={() => {
          setShowViewDialog(false);
          setViewingLicense(null);
        }}
        pluginName={getPluginName(viewingLicense?.pluginId)}
      />
    </div>
  );
}
