import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  ArrowLeft,
  Download,
  Key,
  LogOut,
  Moon,
  Package,
  Shield,
  Sun,
  User,
} from "lucide-react";
import { useAuth } from "../contexts/AuthContext.jsx";
import PluginList from "./PluginList.jsx";
import UserLicenseManager from "./UserLicenseManager.jsx";
import { Button } from "@/components/ui/button.jsx";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.jsx";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/ui/tabs.jsx";
import { Alert, AlertDescription } from "@/components/ui/alert.jsx";
import { ERR_SERVER_CONNECTION } from "@/lib/utils.js";

const API_BASE_URL = "http://localhost:8080/api/v1";

export default function UserDashboard({ user }) {
  const { logout, getAuthHeaders, isAdmin } = useAuth();
  const [userStats, setUserStats] = useState({
    totalLicenses: 0,
    activeLicenses: 0,
    totalDownloads: 0,
    availablePlugins: 0,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem("darkMode");
    if (saved !== null) {
      return JSON.parse(saved);
    }
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  });

  useEffect(() => {
    if (user?.id) {
      loadUserStats();
    }
  }, [user?.id]);

  useEffect(() => {
    localStorage.setItem("darkMode", JSON.stringify(darkMode));
    if (darkMode) {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }
  }, [darkMode]);

  const toggleDarkMode = () => {
    setDarkMode(!darkMode);
  };

  const loadUserStats = async () => {
    try {
      setLoading(true);
      setError("");

      const headers = getAuthHeaders();

      const [licensesResponse, pluginsResponse] = await Promise.all([
        fetch(`${API_BASE_URL}/licenses/user/${user.id}`, { headers }),
        fetch(`${API_BASE_URL}/plugins/available`, { headers }),
      ]);

      if (licensesResponse.ok) {
        const licensesData = await licensesResponse.json();
        if (licensesData.success) {
          const licenses = licensesData.licenses || [];
          setUserStats((prev) => ({
            ...prev,
            totalLicenses: licenses.length,
            activeLicenses: licenses.filter((l) => l.license?.active).length,
          }));
        }
      }

      if (pluginsResponse.ok) {
        const pluginsData = await pluginsResponse.json();
        if (pluginsData.success) {
          setUserStats((prev) => ({
            ...prev,
            availablePlugins: pluginsData.total || 0,
          }));
        }
      } else {
        console.error(
          "Error loading plugins:",
          pluginsResponse.status,
          pluginsResponse.statusText,
        );
        setError("Error cargando plugins disponibles");
      }
    } catch (err) {
      console.error("Error loading user stats:", err);
      setError(ERR_SERVER_CONNECTION);
    } finally {
      setLoading(false);
    }
  };

  const StatCard = ({
    title,
    value,
    description,
    icon: Icon,
    color = "blue",
  }) => (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium">{title}</CardTitle>
        <Icon className={`h-4 w-4 text-${color}-600`} />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold">{value}</div>
        <p className="text-xs text-muted-foreground">{description}</p>
      </CardContent>
    </Card>
  );

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b bg-card">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-primary" />
              <div>
                <h1 className="text-2xl font-bold text-foreground">
                  Nebeniac User
                </h1>
                <p className="text-sm text-muted-foreground">
                  Panel de Usuario
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              {isAdmin() && (
                <Link to="/admin">
                  <Button variant="outline" size="sm">
                    <ArrowLeft className="h-4 w-4 mr-2" />
                    Volver al Admin
                  </Button>
                </Link>
              )}
              <Button
                variant="ghost"
                size="sm"
                onClick={toggleDarkMode}
                className="p-2"
              >
                {darkMode ? (
                  <Sun className="h-4 w-4" />
                ) : (
                  <Moon className="h-4 w-4" />
                )}
              </Button>
              <div className="flex items-center space-x-2 px-3 py-1 bg-muted rounded-md">
                <User className="h-4 w-4" />
                <span className="text-sm font-medium">
                  {user?.fullName || user?.email}
                </span>
              </div>
              <Button variant="ghost" size="sm" onClick={logout}>
                <LogOut className="h-4 w-4" />
              </Button>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto p-6 space-y-6">
        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          <StatCard
            title="Total Licenses"
            value={userStats.totalLicenses}
            icon={Key}
            description="Licenses generated"
            color="blue"
          />
          <StatCard
            title="Active Licenses"
            value={userStats.activeLicenses}
            icon={Shield}
            description="Valid licenses"
            color="green"
          />
          <StatCard
            title="Available Plugins"
            value={userStats.availablePlugins}
            icon={Package}
            description="Available to download"
            color="purple"
          />
          <StatCard
            title="Downloads"
            value={userStats.totalDownloads}
            icon={Download}
            description="Plugins downloaded"
            color="orange"
          />
        </div>

        <Tabs defaultValue="plugins" className="space-y-4">
          <TabsList>
            <TabsTrigger value="plugins">
              <Package className="w-4 h-4 mr-2" />
              Available Plugins
            </TabsTrigger>
            <TabsTrigger value="licenses">
              <Key className="w-4 h-4 mr-2" />
              My Licenses
            </TabsTrigger>
          </TabsList>

          <TabsContent value="plugins" className="space-y-4">
            <PluginList userId={user?.id} onStatsUpdate={loadUserStats} />
          </TabsContent>

          <TabsContent value="licenses" className="space-y-4">
            <UserLicenseManager userId={user?.id} />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}
