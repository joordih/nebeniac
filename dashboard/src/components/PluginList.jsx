import {useEffect, useState} from 'react'
import {Clock, Info, Package, Shield, User} from 'lucide-react'
import {useAuth} from '../contexts/AuthContext.jsx'
import {ERR_SERVER_CONNECTION} from '@/lib/utils.js'
import {Button} from '@/components/ui/button.jsx'
import {Input} from '@/components/ui/input.jsx'
import {Card, CardContent, CardDescription, CardHeader, CardTitle} from '@/components/ui/card.jsx'
import {Badge} from '@/components/ui/badge.jsx'
import {Alert, AlertDescription} from '@/components/ui/alert.jsx'
import {Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle} from '@/components/ui/dialog.jsx'
import DownloadButton from './DownloadButton.jsx'

const API_BASE_URL = 'http://localhost:8080/api/v1'
export default function PluginList({userId, onStatsUpdate}) {
    const {getAuthHeaders} = useAuth()
    const [plugins, setPlugins] = useState([])
    const [loading, setLoading] = useState(true)
    const [searchTerm, setSearchTerm] = useState('')
    const [error, setError] = useState('')
    const [selectedPlugin, setSelectedPlugin] = useState(null)
    const [showDetailsDialog, setShowDetailsDialog] = useState(false)

    useEffect(() => {
        loadAvailablePlugins()
    }, [])

    const loadAvailablePlugins = async () => {
        try {
            setLoading(true)
            setError('')

            const headers = getAuthHeaders()
            const response = await fetch(`${API_BASE_URL}/plugins/available`, {
                headers
            })

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`)
            }

            const data = await response.json()

            if (data.success) {
                setPlugins(data.plugins || [])
            } else {
                setError(data.error || 'Error cargando plugins')
            }
        } catch (err) {
            console.error('Error loading plugins:', err)
            setError(ERR_SERVER_CONNECTION)
        } finally {
            setLoading(false)
        }
    }

    const filteredPlugins = plugins.filter(plugin =>
        plugin.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        plugin.pluginId?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        plugin.description?.toLowerCase().includes(searchTerm.toLowerCase())
    )

    const handleDownloadSuccess = () => {
        if (onStatsUpdate) {
            onStatsUpdate()
        }
    }

    const showPluginDetails = (plugin) => {
        setSelectedPlugin(plugin)
        setShowDetailsDialog(true)
    }

    const formatDate = (dateString) => {
        if (!dateString) return 'N/A'
        return new Date(dateString).toLocaleDateString('es-ES', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        })
    }

    if (loading) {
        return (
            <Card>
                <CardContent className="flex items-center justify-center h-64">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                </CardContent>
            </Card>
        )
    }

    return (
        <div className="space-y-4">
            {}
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold">Plugins Disponibles</h2>
                    <p className="text-muted-foreground">
                        Download protected plugins with automatic licenses
                    </p>
                </div>
                <Badge variant="secondary">
                    {filteredPlugins.length} plugins
                </Badge>
            </div>

            {error && (
                <Alert variant="destructive">
                    <AlertDescription>{error}</AlertDescription>
                </Alert>
            )}

            {}
            <div className="flex items-center space-x-2">
                <Input
                    placeholder="Buscar plugins..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="max-w-sm"
                />
            </div>

            {}
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {filteredPlugins.map((plugin) => (
                    <Card key={plugin.pluginId} className="hover:shadow-lg transition-shadow">
                        <CardHeader>
                            <div className="flex items-start justify-between">
                                <div className="flex items-center space-x-2">
                                    <Package className="h-5 w-5 text-blue-600"/>
                                    <CardTitle className="text-lg">{plugin.name || plugin.pluginId}</CardTitle>
                                </div>
                                <Badge variant="outline">{plugin.version || 'v1.0'}</Badge>
                            </div>
                            <CardDescription className="line-clamp-2">
                                {plugin.description || 'Plugin de Minecraft protegido'}
                            </CardDescription>
                        </CardHeader>

                        <CardContent className="space-y-4">
                            {}
                            <div className="space-y-2 text-sm text-muted-foreground">
                                <div className="flex items-center space-x-2">
                                    <User className="h-4 w-4"/>
                                    <span>Autor: {plugin.ownerId || 'Nebeniac'}</span>
                                </div>
                                <div className="flex items-center space-x-2">
                                    <Clock className="h-4 w-4"/>
                                    <span>Actualizado: {formatDate(plugin.updatedAt)}</span>
                                </div>
                                <div className="flex items-center space-x-2">
                                    <Shield className="h-4 w-4"/>
                                    <span>License: {plugin.licenseType || 'Valid'}</span>
                                </div>
                                {plugin.targetPackages && plugin.targetPackages.length > 0 && (
                                    <div className="flex items-center space-x-2">
                                        <Package className="h-4 w-4"/>
                                        <span>Paquetes: {plugin.targetPackages.slice(0, 2).join(', ')}{plugin.targetPackages.length > 2 ? '...' : ''}</span>
                                    </div>
                                )}
                                {plugin.encrypted && (
                                    <div className="flex items-center space-x-2">
                                        <Shield className="h-4 w-4 text-green-600"/>
                                        <span className="text-green-600">Encriptado</span>
                                    </div>
                                )}
                                {plugin.expiresAt && (
                                    <div className="flex items-center space-x-2">
                                        <Clock className="h-4 w-4"/>
                                        <span>Expira: {formatDate(plugin.expiresAt)}</span>
                                    </div>
                                )}
                            </div>

                            {}
                            <div className="flex items-center space-x-2">
                                <DownloadButton
                                    pluginId={plugin.pluginId}
                                    pluginName={plugin.name || plugin.pluginId}
                                    userId={userId}
                                    onSuccess={handleDownloadSuccess}
                                    className="flex-1"
                                />

                                <Button
                                    variant="outline"
                                    size="sm"
                                    onClick={() => showPluginDetails(plugin)}
                                >
                                    <Info className="h-4 w-4"/>
                                </Button>
                            </div>
                        </CardContent>
                    </Card>
                ))}
            </div>

            {filteredPlugins.length === 0 && !loading && (
                <Card>
                    <CardContent className="flex flex-col items-center justify-center h-64 text-center">
                        <Package className="h-12 w-12 text-muted-foreground mb-4"/>
                        <h3 className="text-lg font-medium mb-2">No hay plugins disponibles</h3>
                        <p className="text-muted-foreground">
                            {searchTerm ? 'No plugins match your search.' : 'No plugins available for download.'}
                        </p>
                    </CardContent>
                </Card>
            )}

            {}
            <Dialog open={showDetailsDialog} onOpenChange={setShowDetailsDialog}>
                <DialogContent className="max-w-2xl">
                    <DialogHeader>
                        <DialogTitle className="flex items-center space-x-2">
                            <Package className="h-5 w-5"/>
                            <span>{selectedPlugin?.name || selectedPlugin?.pluginId}</span>
                        </DialogTitle>
                        <DialogDescription>
                            Plugin details
                        </DialogDescription>
                    </DialogHeader>

                    {selectedPlugin && (
                        <div className="space-y-4">
                            <div className="grid grid-cols-2 gap-4">
                                <div>
                                    <label className="text-sm font-medium">ID del Plugin</label>
                                    <p className="text-sm text-muted-foreground">{selectedPlugin.pluginId}</p>
                                </div>
                                <div>
                                    <label className="text-sm font-medium">Version</label>
                                    <p className="text-sm text-muted-foreground">{selectedPlugin.version || 'v1.0'}</p>
                                </div>
                                <div>
                                    <label className="text-sm font-medium">Autor</label>
                                    <p className="text-sm text-muted-foreground">{selectedPlugin.ownerId || 'Nebeniac'}</p>
                                </div>
                                <div>
                                    <label className="text-sm font-medium">Creado</label>
                                    <p className="text-sm text-muted-foreground">{formatDate(selectedPlugin.createdAt)}</p>
                                </div>
                            </div>

                            <div>
                                <label className="text-sm font-medium">Description</label>
                                <p className="text-sm text-muted-foreground mt-1">
                                    {selectedPlugin.description || 'Plugin de Minecraft protegido con sistema de licencias avanzado.'}
                                </p>
                            </div>

                            {selectedPlugin.targetPackages && selectedPlugin.targetPackages.length > 0 && (
                                <div>
                                    <label className="text-sm font-medium">Encryption Packages</label>
                                    <div className="mt-1 flex flex-wrap gap-1">
                                        {selectedPlugin.targetPackages.map((pkg, index) => (
                                            <Badge key={index} variant="secondary" className="text-xs">
                                                {pkg}
                                            </Badge>
                                        ))}
                                    </div>
                                </div>
                            )}

                            <div className="flex items-center space-x-2 pt-4">
                                <DownloadButton
                                    pluginId={selectedPlugin.pluginId}
                                    pluginName={selectedPlugin.name || selectedPlugin.pluginId}
                                    userId={userId}
                                    onSuccess={handleDownloadSuccess}
                                />
                                <Button variant="outline" onClick={() => setShowDetailsDialog(false)}>
                                    Cerrar
                                </Button>
                            </div>
                        </div>
                    )}
                </DialogContent>
            </Dialog>
        </div>
    )
}
