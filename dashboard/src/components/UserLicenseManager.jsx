import {Alert, AlertDescription} from '@/components/ui/alert.jsx'
import {Badge} from '@/components/ui/badge.jsx'
import {Button} from '@/components/ui/button.jsx'
import {Card, CardContent, CardDescription, CardHeader, CardTitle} from '@/components/ui/card.jsx'
import {Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle} from '@/components/ui/dialog.jsx'
import {Input} from '@/components/ui/input.jsx'
import {Table, TableBody, TableCell, TableHead, TableHeader, TableRow} from '@/components/ui/table.jsx'
import {CheckCircle, Clock, Copy, Eye, Key, Shield, XCircle} from 'lucide-react'
import {useEffect, useState} from 'react'
import {useAuth} from '../contexts/AuthContext.jsx'
import {ERR_SERVER_CONNECTION} from '@/lib/utils.js'
import {API_BASE_URL} from '@/lib/config.js'

export default function UserLicenseManager({userId}) {
    const {getAuthHeaders} = useAuth()
    const [licenses, setLicenses] = useState([])
    const [loading, setLoading] = useState(true)
    const [searchTerm, setSearchTerm] = useState('')
    const [error, setError] = useState('')
    const [selectedLicense, setSelectedLicense] = useState(null)
    const [showDetailsDialog, setShowDetailsDialog] = useState(false)

    useEffect(() => {
        loadUserLicenses()
    }, [userId])

    const loadUserLicenses = async () => {
        try {
            setLoading(true)
            setError('')

            const headers = getAuthHeaders()
            const response = await fetch(`${API_BASE_URL}/licenses/user/${userId}`, {
                headers
            })

            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`)
            }

            const data = await response.json()

            if (data.success) {
                setLicenses(data.licenses || [])
            } else {
                setError(data.error || 'Error cargando licencias')
            }
        } catch (err) {
            console.error('Error loading user licenses:', err)
            setError(ERR_SERVER_CONNECTION)
        } finally {
            setLoading(false)
        }
    }

    const filteredLicenses = licenses.filter(licenseData => {
        const license = licenseData.license
        return (
            license?.licenseKey?.toLowerCase().includes(searchTerm.toLowerCase()) ||
            license?.licenseType?.toLowerCase().includes(searchTerm.toLowerCase())
        )
    })

    const showLicenseDetails = (licenseData) => {
        setSelectedLicense(licenseData)
        setShowDetailsDialog(true)
    }

    const copyLicenseKey = (licenseKey) => {
        navigator.clipboard.writeText(licenseKey)
    }

    const formatDate = (dateString) => {
        if (!dateString) return 'N/A'
        return new Date(dateString).toLocaleDateString('es-ES', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
        })
    }

    const maskLicenseKey = (licenseKey) => {
        if (!licenseKey || licenseKey.length < 8) return '***'
        return licenseKey.substring(0, 4) + '***' + licenseKey.substring(licenseKey.length - 4)
    }

    const getLicenseStatus = (license) => {
        if (!license.active) return {status: 'inactive', color: 'destructive', text: 'Inactiva'}

        const now = new Date()
        const expiresAt = new Date(license.expiresAt)

        if (expiresAt < now) return {status: 'expired', color: 'destructive', text: 'Expirada'}

        const daysUntilExpiry = Math.ceil((expiresAt - now) / (1000 * 60 * 60 * 24))
        if (daysUntilExpiry <= 7) return {status: 'expiring', color: 'warning', text: 'Por expirar'}

        return {status: 'active', color: 'success', text: 'Activa'}
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
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-2xl font-bold">Mis Licencias</h2>
                    <p className="text-muted-foreground">
                        Gestiona tus licencias de plugins descargados
                    </p>
                </div>
                <Badge variant="secondary">
                    {filteredLicenses.length} licencias
                </Badge>
            </div>

            {error && (
                <Alert variant="destructive">
                    <AlertDescription>{error}</AlertDescription>
                </Alert>
            )}

            <div className="flex items-center space-x-2">
                <Input
                    placeholder="Buscar licencias..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="max-w-sm"
                />
            </div>

            <Card>
                <CardHeader>
                    <CardTitle>Licencias Generadas</CardTitle>
                    <CardDescription>
                        Todas las licencias generadas para tus descargas de plugins
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    {filteredLicenses.length > 0 ? (
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>Clave de Licencia</TableHead>
                                    <TableHead>Tipo</TableHead>
                                    <TableHead>Estado</TableHead>
                                    <TableHead>Activaciones</TableHead>
                                    <TableHead>Expira</TableHead>
                                    <TableHead>Acciones</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {filteredLicenses.map((licenseData) => {
                                    const license = licenseData.license
                                    const status = getLicenseStatus(license)

                                    return (
                                        <TableRow key={license.licenseKey}>
                                            <TableCell>
                                                <div className="flex items-center space-x-2">
                                                    <Key className="h-4 w-4 text-muted-foreground"/>
                                                    <code
                                                        className="text-sm">{maskLicenseKey(license.licenseKey)}</code>
                                                    <Button
                                                        variant="ghost"
                                                        size="sm"
                                                        onClick={() => copyLicenseKey(license.licenseKey)}
                                                    >
                                                        <Copy className="h-3 w-3"/>
                                                    </Button>
                                                </div>
                                            </TableCell>

                                            <TableCell>
                                                <Badge variant="outline">
                                                    {license.licenseType || 'PLUGIN_DOWNLOAD'}
                                                </Badge>
                                            </TableCell>

                                            <TableCell>
                                                <Badge variant={status.color === 'success' ? 'default' : 'destructive'}>
                                                    {status.status === 'active' &&
                                                        <CheckCircle className="w-3 h-3 mr-1"/>}
                                                    {status.status !== 'active' && <XCircle className="w-3 h-3 mr-1"/>}
                                                    {status.text}
                                                </Badge>
                                            </TableCell>

                                            <TableCell>
                                                <div className="flex items-center space-x-1">
                                                    <Shield className="h-4 w-4 text-muted-foreground"/>
                                                    <span>{licenseData.activeActivations || 0}/{license.maxActivations || 1}</span>
                                                </div>
                                            </TableCell>

                                            <TableCell>
                                                <div className="flex items-center space-x-1">
                                                    <Clock className="h-4 w-4 text-muted-foreground"/>
                                                    <span className="text-sm">{formatDate(license.expiresAt)}</span>
                                                </div>
                                            </TableCell>

                                            <TableCell>
                                                <Button
                                                    variant="ghost"
                                                    size="sm"
                                                    onClick={() => showLicenseDetails(licenseData)}
                                                >
                                                    <Eye className="h-4 w-4"/>
                                                </Button>
                                            </TableCell>
                                        </TableRow>
                                    )
                                })}
                            </TableBody>
                        </Table>
                    ) : (
                        <div className="text-center py-8">
                            <Key className="h-12 w-12 text-muted-foreground mx-auto mb-4"/>
                            <h3 className="text-lg font-medium mb-2">No licenses</h3>
                            <p className="text-muted-foreground">
                                {searchTerm ? 'No licenses match your search.' : "You haven't downloaded any plugins yet."}
                            </p>
                        </div>
                    )}
                </CardContent>
            </Card>

            <Dialog open={showDetailsDialog} onOpenChange={setShowDetailsDialog}>
                <DialogContent className="max-w-2xl">
                    <DialogHeader>
                        <DialogTitle className="flex items-center space-x-2">
                            <Key className="h-5 w-5"/>
                            <span>License Details</span>
                        </DialogTitle>
                        <DialogDescription>
                            Full details of the selected license
                        </DialogDescription>
                    </DialogHeader>

                    {selectedLicense && (
                        <div className="space-y-4">
                            <Card>
                                <CardHeader>
                                    <CardTitle className="text-lg">License Information</CardTitle>
                                </CardHeader>
                                <CardContent className="space-y-3">
                                    <div className="grid grid-cols-2 gap-4">
                                        <div>
                                            <label className="text-sm font-medium">License Key</label>
                                            <div className="flex items-center space-x-2 mt-1">
                                                <code className="flex-1 p-2 bg-muted rounded text-sm font-mono">
                                                    {selectedLicense.license.licenseKey}
                                                </code>
                                                <Button
                                                    variant="outline"
                                                    size="sm"
                                                    onClick={() => copyLicenseKey(selectedLicense.license.licenseKey)}
                                                >
                                                    <Copy className="h-3 w-3"/>
                                                </Button>
                                            </div>
                                        </div>
                                        <div>
                                            <label className="text-sm font-medium">Type</label>
                                            <p className="text-sm text-muted-foreground mt-1">
                                                {selectedLicense.license.licenseType || 'PLUGIN_DOWNLOAD'}
                                            </p>
                                        </div>
                                        <div>
                                            <label className="text-sm font-medium">Created</label>
                                            <p className="text-sm text-muted-foreground">
                                                {formatDate(selectedLicense.license.createdAt)}
                                            </p>
                                        </div>
                                        <div>
                                            <label className="text-sm font-medium">Expires</label>
                                            <p className="text-sm text-muted-foreground">
                                                {formatDate(selectedLicense.license.expiresAt)}
                                            </p>
                                        </div>
                                    </div>

                                    <div>
                                        <label className="text-sm font-medium">Features</label>
                                        <div className="flex flex-wrap gap-1 mt-1">
                                            {selectedLicense.license.features?.map((feature) => (
                                                <Badge key={feature} variant="secondary" className="text-xs">
                                                    {feature}
                                                </Badge>
                                            ))}
                                        </div>
                                    </div>
                                </CardContent>
                            </Card>

                            <Card>
                                <CardHeader>
                                    <CardTitle className="text-lg">Activations</CardTitle>
                                </CardHeader>
                                <CardContent>
                                    <div className="space-y-2">
                                        <div className="flex items-center justify-between">
                                            <span className="text-sm">Activations Used</span>
                                            <Badge variant="outline">
                                                {selectedLicense.activeActivations || 0} / {selectedLicense.license.maxActivations || 1}
                                            </Badge>
                                        </div>

                                        {selectedLicense.activations && selectedLicense.activations.length > 0 ? (
                                            <div className="space-y-2">
                                                <label className="text-sm font-medium">Activated Servers</label>
                                                {selectedLicense.activations.map((activation, index) => (
                                                    <div key={index} className="p-2 bg-muted rounded text-sm">
                                                        <div className="flex items-center justify-between">
                                                            <span>{activation.serverName || 'Unknown server'}</span>
                                                            <span className="text-xs text-muted-foreground">
                                {formatDate(activation.activatedAt)}
                              </span>
                                                        </div>
                                                    </div>
                                                ))}
                                            </div>
                                        ) : (
                                            <p className="text-sm text-muted-foreground">
                                                This license has not been activated on any server yet.
                                            </p>
                                        )}
                                    </div>
                                </CardContent>
                            </Card>

                            <div className="flex justify-end">
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
