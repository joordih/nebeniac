import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  Activity,
  Key,
  LogOut,
  Moon,
  Package,
  Shield,
  Sun,
  User,
  Users,
} from "lucide-react";
import { useAuth } from "./contexts/AuthContext.jsx";
import PluginManager from "./components/PluginManager.jsx";
import LicenseManager from "./components/LicenseManager.jsx";
import UserManagement from "./components/admin/UserManagement.jsx";
import { Button } from "@/components/ui/button.jsx";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card.jsx";
import { Badge } from "@/components/ui/badge.jsx";

const API_BASE_URL = "http://localhost:8080/api/v1";

export default function AdminDashboard() {
  const { user, logout, getAuthHeaders } = useAuth();
  const navigate = useNavigate();
  const [activeTab, setActiveTab] = useState("dashboard");
  const [stats, setStats] = useState({
    totalLicenses: 0,
    activeLicenses: 0,
    totalActivations: 0,
    totalSessions: 0,
    totalPlugins: 0,
    activePlugins: 0,
    totalUsers: 0,
    activeUsers: 0,
  });
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem("darkMode");
    if (saved !== null) {
      return JSON.parse(saved);
    }
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  });

  useEffect(() => {
    loadStatistics();
  }, []);

  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }
  }, [darkMode]);

  const loadStatistics = async () => {
    try {
      const response = await fetch(`${API_BASE_URL}/statistics`, {
        headers: getAuthHeaders(),
      });

      if (response.ok) {
        const data = await response.json();
        if (data.success) {
          setStats(data.statistics || {});
        }
      }
    } catch (err) {
      console.error("Error loading statistics:", err);
    }
  };

  const toggleDarkMode = () => {
    const newMode = !darkMode;
    setDarkMode(newMode);
    localStorage.setItem("darkMode", JSON.stringify(newMode));

    if (newMode) {
      document.documentElement.classList.add("dark");
    } else {
      document.documentElement.classList.remove("dark");
    }
  };

  const handleLogout = async () => {
    await logout();
    navigate("/login");
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

  return (
    <div className="min-h-screen bg-background">
      {}
      <header className="border-b bg-card">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Shield className="h-8 w-8 text-primary" />
              <div>
                <h1 className="text-2xl font-bold text-foreground">
                  Nebeniac Admin
                </h1>
                <p className="text-sm text-muted-foreground">
                  Administration Panel
                </p>
              </div>
            </div>
            <div className="flex items-center space-x-2">
              <Link to="/user">
                <Button variant="outline" size="sm">
                  <User className="h-4 w-4 mr-2" />
                  User Panel
                </Button>
              </Link>
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
              <Button variant="ghost" size="sm" onClick={handleLogout}>
                <LogOut className="h-4 w-4" />
              </Button>
              <Badge variant="outline" className="text-green-600">
                <Activity className="h-3 w-3 mr-1" />
                Sistema Local
              </Badge>
            </div>
          </div>
        </div>
      </header>

      <div className="container mx-auto px-6 py-8">
        {}
        <div className="flex space-x-1 mb-8 bg-muted p-1 rounded-lg">
          <button
            onClick={() => setActiveTab("dashboard")}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === "dashboard"
                ? "bg-background text-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <Activity className="w-4 h-4 mr-2 inline" />
            Dashboard
          </button>
          <button
            onClick={() => setActiveTab("users")}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === "users"
                ? "bg-background text-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <Users className="w-4 h-4 mr-2 inline" />
            Usuarios
          </button>
          <button
            onClick={() => setActiveTab("plugins")}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === "plugins"
                ? "bg-background text-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <Package className="w-4 h-4 mr-2 inline" />
            Plugins
          </button>
          <button
            onClick={() => setActiveTab("licenses")}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === "licenses"
                ? "bg-background text-foreground shadow-sm"
                : "text-muted-foreground hover:text-foreground"
            }`}
          >
            <Key className="w-4 h-4 mr-2 inline" />
            Licencias
          </button>
        </div>

        {}
        {activeTab === "dashboard" && (
          <div className="space-y-6">
            <div>
              <h2 className="text-3xl font-bold tracking-tight">Dashboard</h2>
              <p className="text-muted-foreground">
                Overview of the plugin protection system
              </p>
            </div>

            {}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
              <StatCard
                title="Total Users"
                value={stats.totalUsers || 0}
                description={`${stats.activeUsers || 0} active`}
                icon={Users}
                color="blue"
              />
              <StatCard
                title="Total Licenses"
                value={stats.totalLicenses || 0}
                description={`${stats.activeLicenses || 0} active`}
                icon={Key}
                color="green"
              />
              <StatCard
                title="Total Plugins"
                value={stats.totalPlugins || 0}
                description={`${stats.activePlugins || 0} active`}
                icon={Package}
                color="purple"
              />
              <StatCard
                title="Activations"
                value={stats.totalActivations || 0}
                description="Total activations"
                icon={Activity}
                color="orange"
              />
            </div>

            {}
            <Card>
              <CardHeader>
                <CardTitle>Quick Actions</CardTitle>
                <CardDescription>
                  Common administration actions
                </CardDescription>
              </CardHeader>
              <CardContent className="grid gap-4 md:grid-cols-3">
                <Button
                  onClick={() => setActiveTab("users")}
                  className="h-20 flex-col space-y-2"
                >
                  <Users className="h-6 w-6" />
                  <span>Manage Users</span>
                </Button>
                <Button
                  onClick={() => setActiveTab("plugins")}
                  variant="outline"
                  className="h-20 flex-col space-y-2"
                >
                  <Package className="h-6 w-6" />
                  <span>Manage Plugins</span>
                </Button>
                <Button
                  onClick={() => setActiveTab("licenses")}
                  variant="outline"
                  className="h-20 flex-col space-y-2"
                >
                  <Key className="h-6 w-6" />
                  <span>Manage Licenses</span>
                </Button>
              </CardContent>
            </Card>
          </div>
        )}

        {activeTab === "users" && <UserManagement />}
        {activeTab === "plugins" && <PluginManager />}
        {activeTab === "licenses" && <LicenseManager />}
      </div>
    </div>
  );
}
