import { useState, useEffect } from "react";
import {
  Shield,
  Lock,
  Unlock,
  Key,
  Activity,
  AlertTriangle,
  RefreshCw,
  ChevronDown,
  ChevronUp,
  CheckCircle,
  XCircle,
  Clock,
  Database,
  TrendingUp,
} from "lucide-react";
import { useE2EE } from "../hooks/useE2EE";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Separator } from "@/components/ui/separator";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const E2EEStatus = ({ apiBaseUrl, authToken, isAdmin = false }) => {
  const {
    isInitialized,
    isEnabled,
    isReady,
    error,
    stats,
    fetchStats,
    rotateKeys,
    reinitialize,
  } = useE2EE(apiBaseUrl);

  const [isRotating, setIsRotating] = useState(false);
  const [rotationMessage, setRotationMessage] = useState("");
  const [activeTab, setActiveTab] = useState("overview");

  useEffect(() => {
    if (isReady) {
      fetchStats();
      const interval = setInterval(fetchStats, 30000);
      return () => clearInterval(interval);
    }
  }, [isReady, fetchStats]);

  const handleRotateKeys = async () => {
    if (!authToken || !isAdmin) {
      setRotationMessage("Admin privileges required");
      return;
    }

    setIsRotating(true);
    setRotationMessage("Rotating keys...");

    try {
      const success = await rotateKeys(authToken);
      if (success) {
        setRotationMessage("Keys rotated successfully!");
        await fetchStats();
      } else {
        setRotationMessage("Key rotation failed");
      }
    } catch (err) {
      setRotationMessage("Error: " + err.message);
    } finally {
      setIsRotating(false);
      setTimeout(() => setRotationMessage(""), 5000);
    }
  };

  const handleReinitialize = async () => {
    const success = await reinitialize();
    if (success) {
      await fetchStats();
    }
  };

  const getStatusBadge = () => {
    if (!isEnabled) {
      return (
        <Badge variant="destructive" className="gap-1">
          <Unlock className="h-3 w-3" /> Disabled
        </Badge>
      );
    }
    if (!isInitialized) {
      return (
        <Badge variant="secondary" className="gap-1">
          <Clock className="h-3 w-3" /> Initializing
        </Badge>
      );
    }
    if (error) {
      return (
        <Badge variant="destructive" className="gap-1">
          <XCircle className="h-3 w-3" /> Error
        </Badge>
      );
    }
    return (
      <Badge variant="default" className="gap-1 bg-green-600">
        <Lock className="h-3 w-3" /> Active
      </Badge>
    );
  };

  if (!isReady && !error) {
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5" />
            End-to-End Encryption
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-center py-8">
            <RefreshCw className="h-6 w-6 animate-spin text-muted-foreground" />
            <span className="ml-2 text-muted-foreground">
              Initializing E2EE service...
            </span>
          </div>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              End-to-End Encryption Status
            </CardTitle>
            <CardDescription className="mt-1">
              Monitor and manage encryption system status
            </CardDescription>
          </div>
          {getStatusBadge()}
        </div>
      </CardHeader>

      <CardContent className="space-y-6">
        {error && (
          <Alert variant="destructive">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription className="flex items-center justify-between">
              <span>{error}</span>
              <Button onClick={handleReinitialize} variant="outline" size="sm">
                <RefreshCw className="h-4 w-4 mr-1" />
                Retry
              </Button>
            </AlertDescription>
          </Alert>
        )}

        {rotationMessage && (
          <Alert
            variant={
              rotationMessage.includes("successfully")
                ? "default"
                : "destructive"
            }
          >
            <AlertDescription>{rotationMessage}</AlertDescription>
          </Alert>
        )}

        {isReady && stats && (
          <Tabs
            value={activeTab}
            onValueChange={setActiveTab}
            className="w-full"
          >
            <TabsList className="grid w-full grid-cols-4">
              <TabsTrigger value="overview">Overview</TabsTrigger>
              <TabsTrigger value="rotation">Key Rotation</TabsTrigger>
              <TabsTrigger value="security">Security</TabsTrigger>
              <TabsTrigger value="advanced">Advanced</TabsTrigger>
            </TabsList>

            <TabsContent value="overview" className="space-y-4">
              <div className="grid gap-4 md:grid-cols-2">
                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium flex items-center gap-2">
                      <Lock className="h-4 w-4" />
                      Encryption Status
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">
                          Request Encryption
                        </span>
                        {stats.enabled ? (
                          <Badge variant="default" className="bg-green-600">
                            <CheckCircle className="h-3 w-3 mr-1" />
                            Enabled
                          </Badge>
                        ) : (
                          <Badge variant="destructive">
                            <XCircle className="h-3 w-3 mr-1" />
                            Disabled
                          </Badge>
                        )}
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">
                          Response Encryption
                        </span>
                        {stats.responseEncryption?.enabled ? (
                          <Badge variant="default" className="bg-green-600">
                            <CheckCircle className="h-3 w-3 mr-1" />
                            Enabled
                          </Badge>
                        ) : (
                          <Badge variant="secondary">
                            <XCircle className="h-3 w-3 mr-1" />
                            Disabled
                          </Badge>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader className="pb-3">
                    <CardTitle className="text-sm font-medium flex items-center gap-2">
                      <Activity className="h-4 w-4" />
                      Decryption Service
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">
                          Tracked Nonces
                        </span>
                        <span className="font-semibold">
                          {stats.decryption?.trackedNonces || 0}
                        </span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">
                          Service Status
                        </span>
                        {stats.decryption?.isReady ? (
                          <Badge variant="default" className="bg-green-600">
                            Ready
                          </Badge>
                        ) : (
                          <Badge variant="destructive">Not Ready</Badge>
                        )}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>
            </TabsContent>

            <TabsContent value="rotation" className="space-y-4">
              {stats.keyRotation ? (
                <>
                  <Card>
                    <CardHeader>
                      <CardTitle className="text-sm font-medium flex items-center gap-2">
                        <Key className="h-4 w-4" />
                        Rotation Schedule
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="grid gap-3">
                        <div className="flex justify-between items-center">
                          <span className="text-sm text-muted-foreground">
                            Auto Rotation
                          </span>
                          {stats.keyRotation.enabled ? (
                            <Badge variant="default" className="bg-green-600">
                              Enabled
                            </Badge>
                          ) : (
                            <Badge variant="secondary">Disabled</Badge>
                          )}
                        </div>
                        <Separator />
                        <div className="flex justify-between items-center">
                          <span className="text-sm text-muted-foreground">
                            Rotation Period
                          </span>
                          <span className="font-semibold">
                            {stats.keyRotation.rotationDays || "N/A"} days
                          </span>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-sm text-muted-foreground">
                            Last Rotation
                          </span>
                          <span className="text-sm font-mono">
                            {stats.keyRotation.lastRotation || "N/A"}
                          </span>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-sm text-muted-foreground">
                            Next Rotation
                          </span>
                          <div className="flex items-center gap-2">
                            <span className="text-sm font-mono">
                              {stats.keyRotation.nextRotation || "N/A"}
                            </span>
                            {stats.keyRotation.overdue && (
                              <Badge variant="destructive">OVERDUE</Badge>
                            )}
                          </div>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-sm text-muted-foreground">
                            Archived Keys
                          </span>
                          <Badge variant="outline">
                            {stats.keyRotation.archivedKeys || 0}
                          </Badge>
                        </div>
                      </div>

                      {isAdmin && (
                        <>
                          <Separator />
                          <div className="flex items-center gap-2">
                            <Button
                              onClick={handleRotateKeys}
                              disabled={isRotating}
                              className="w-full"
                            >
                              {isRotating ? (
                                <>
                                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                                  Rotating...
                                </>
                              ) : (
                                <>
                                  <Key className="h-4 w-4 mr-2" />
                                  Rotate Keys Now
                                </>
                              )}
                            </Button>
                          </div>
                        </>
                      )}
                    </CardContent>
                  </Card>
                </>
              ) : (
                <Alert>
                  <AlertDescription>
                    Key rotation information not available
                  </AlertDescription>
                </Alert>
              )}
            </TabsContent>

            <TabsContent value="security" className="space-y-4">
              {stats.rateLimiter ? (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm font-medium flex items-center gap-2">
                      <Shield className="h-4 w-4" />
                      Rate Limiting & Security
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="grid gap-3">
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">
                          Rate Limiter
                        </span>
                        {stats.rateLimiter.enabled ? (
                          <Badge variant="default" className="bg-green-600">
                            Active
                          </Badge>
                        ) : (
                          <Badge variant="secondary">Inactive</Badge>
                        )}
                      </div>
                      <Separator />
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">
                          Rate Limit
                        </span>
                        <span className="font-semibold">
                          {stats.rateLimiter.requestsPerMinute || "N/A"} req/min
                        </span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">
                          Total Requests
                        </span>
                        <span className="font-semibold">
                          {stats.rateLimiter.totalRequests || 0}
                        </span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">
                          Blocked Requests
                        </span>
                        <div className="flex items-center gap-2">
                          <span className="font-semibold text-red-600">
                            {stats.rateLimiter.blockedRequests || 0}
                          </span>
                          <Badge variant="outline">
                            {(stats.rateLimiter.blockedPercentage || 0).toFixed(
                              2,
                            )}
                            %
                          </Badge>
                        </div>
                      </div>
                      {stats.rateLimiter.blockedRequests > 0 && (
                        <Progress
                          value={stats.rateLimiter.blockedPercentage || 0}
                          className="h-2"
                        />
                      )}
                      <Separator />
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">
                          Suspicious Activity
                        </span>
                        <Badge
                          variant={
                            stats.rateLimiter.suspiciousActivity > 0
                              ? "destructive"
                              : "outline"
                          }
                        >
                          {stats.rateLimiter.suspiciousActivity || 0}
                        </Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">
                          Tracked IPs
                        </span>
                        <Badge variant="outline">
                          {stats.rateLimiter.trackedIPs || 0}
                        </Badge>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ) : (
                <Alert>
                  <AlertDescription>
                    Rate limiting information not available
                  </AlertDescription>
                </Alert>
              )}
            </TabsContent>

            <TabsContent value="advanced" className="space-y-4">
              {stats.responseEncryption && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm font-medium flex items-center gap-2">
                      <Database className="h-4 w-4" />
                      Response Encryption Details
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">
                          Cached Session Keys
                        </span>
                        <span className="font-semibold">
                          {stats.responseEncryption.cachedSessionKeys || 0}
                        </span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">
                          Encryption Version
                        </span>
                        <Badge variant="outline">
                          {stats.responseEncryption.encryptionVersion || "N/A"}
                        </Badge>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">
                          Cache Max Size
                        </span>
                        <span className="font-semibold">
                          {stats.responseEncryption.cacheMaxSize || "N/A"}
                        </span>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

              {stats.decryption && (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm font-medium flex items-center gap-2">
                      <TrendingUp className="h-4 w-4" />
                      Decryption Details
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">
                          Max Timestamp Diff
                        </span>
                        <span className="text-sm font-mono">
                          {stats.decryption.maxTimestampDiffMs || "N/A"} ms
                        </span>
                      </div>
                      <div className="flex justify-between items-center">
                        <span className="text-sm text-muted-foreground">
                          Nonce Expiry
                        </span>
                        <span className="text-sm font-mono">
                          {stats.decryption.nonceExpiryMs || "N/A"} ms
                        </span>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}
            </TabsContent>
          </Tabs>
        )}
      </CardContent>
    </Card>
  );
};

export default E2EEStatus;
