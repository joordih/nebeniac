import {Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle} from '@/components/ui/dialog.jsx'
import {Button} from '@/components/ui/button.jsx'
import {Badge} from '@/components/ui/badge.jsx'
import {Card, CardContent, CardHeader, CardTitle} from '@/components/ui/card.jsx'
import {Calendar, FileText, Key, Package, Settings, User} from 'lucide-react'
import BlurredLicenseKey from './BlurredLicenseKey.jsx'

export default function ViewLicenseDialog({
                                              license,
                                              isOpen,
                                              onClose,
                                              pluginName = null
                                          }) {
    if (!license) return null

    const formatDate = (dateString) => {
        if (!dateString) return 'N/A'
        try {
            return new Date(dateString).toLocaleDateString('es-ES', {
                year: 'numeric',
                month: 'long',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            })
        } catch {
            return 'Invalid Date'
        }
    }

    const getLicenseTypeColor = (type) => {
        switch (type) {
            case 'PREMIUM':
                return 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-300'
            case 'ENTERPRISE':
                return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300'
            case 'DEVELOPER':
                return 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300'
            case 'STANDARD':
                return 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300'
            default:
                return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-300'
        }
    }

    const getStatusColor = (active) => {
        return active
            ? 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300'
            : 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300'
    }

    return (
        <Dialog open={isOpen} onOpenChange={onClose}>
            <DialogContent className="max-w-2xl">
                <DialogHeader>
                    <DialogTitle className="flex items-center">
                        <Key className="mr-2 h-5 w-5"/>
                        License Details
                    </DialogTitle>
                    <DialogDescription>
                        Complete information for license {license.licenseKey}
                    </DialogDescription>
                </DialogHeader>

                <div className="space-y-6">
                    {}
                    <Card>
                        <CardHeader>
                            <CardTitle className="text-lg flex items-center">
                                <Key className="mr-2 h-4 w-4"/>
                                License Key
                            </CardTitle>
                        </CardHeader>
                        <CardContent>
                            <BlurredLicenseKey licenseKey={license.licenseKey} className="text-lg"/>
                        </CardContent>
                    </Card>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {}
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-lg flex items-center">
                                    <User className="mr-2 h-4 w-4"/>
                                    Customer
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="space-y-2">
                                <div>
                                    <p className="text-sm text-muted-foreground">Name</p>
                                    <p className="font-medium">{license.customerName || 'N/A'}</p>
                                </div>
                                <div>
                                    <p className="text-sm text-muted-foreground">Email</p>
                                    <p className="font-medium">{license.customerEmail || 'N/A'}</p>
                                </div>
                            </CardContent>
                        </Card>

                        {}
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-lg flex items-center">
                                    <Package className="mr-2 h-4 w-4"/>
                                    Plugin
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="space-y-2">
                                <div>
                                    <p className="text-sm text-muted-foreground">Plugin Name</p>
                                    <p className="font-medium">{pluginName || license.pluginId || 'N/A'}</p>
                                </div>
                                <div>
                                    <p className="text-sm text-muted-foreground">Plugin ID</p>
                                    <p className="font-mono text-sm">{license.pluginId || 'N/A'}</p>
                                </div>
                            </CardContent>
                        </Card>

                        {}
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-lg flex items-center">
                                    <Settings className="mr-2 h-4 w-4"/>
                                    Settings
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="space-y-3">
                                <div className="flex items-center justify-between">
                                    <span className="text-sm text-muted-foreground">Type</span>
                                    <Badge className={getLicenseTypeColor(license.licenseType)}>
                                        {license.licenseType}
                                    </Badge>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span className="text-sm text-muted-foreground">Status</span>
                                    <Badge className={getStatusColor(license.active)}>
                                        {license.active ? 'Active' : 'Inactive'}
                                    </Badge>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span className="text-sm text-muted-foreground">Max Activations</span>
                                    <span className="font-medium">{license.maxActivations || 'N/A'}</span>
                                </div>
                                <div className="flex items-center justify-between">
                                    <span className="text-sm text-muted-foreground">Current Activations</span>
                                    <span className="font-medium">0 / {license.maxActivations || 'N/A'}</span>
                                </div>
                            </CardContent>
                        </Card>

                        {}
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-lg flex items-center">
                                    <Calendar className="mr-2 h-4 w-4"/>
                                    Dates
                                </CardTitle>
                            </CardHeader>
                            <CardContent className="space-y-2">
                                <div>
                                    <p className="text-sm text-muted-foreground">Created</p>
                                    <p className="font-medium">{formatDate(license.createdAt)}</p>
                                </div>
                                <div>
                                    <p className="text-sm text-muted-foreground">Updated</p>
                                    <p className="font-medium">{formatDate(license.updatedAt)}</p>
                                </div>
                                {license.expiresAt && (
                                    <div>
                                        <p className="text-sm text-muted-foreground">Expires</p>
                                        <p className="font-medium">{formatDate(license.expiresAt)}</p>
                                    </div>
                                )}
                            </CardContent>
                        </Card>
                    </div>

                    {}
                    {license.features && license.features.length > 0 && (
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-lg">Features</CardTitle>
                            </CardHeader>
                            <CardContent>
                                <div className="flex flex-wrap gap-2">
                                    {license.features.map((feature) => (
                                        <Badge key={feature} variant="outline">
                                            {feature.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, l => l.toUpperCase())}
                                        </Badge>
                                    ))}
                                </div>
                            </CardContent>
                        </Card>
                    )}

                    {}
                    {license.notes && (
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-lg flex items-center">
                                    <FileText className="mr-2 h-4 w-4"/>
                                    Notes
                                </CardTitle>
                            </CardHeader>
                            <CardContent>
                                <p className="text-sm whitespace-pre-wrap">{license.notes}</p>
                            </CardContent>
                        </Card>
                    )}

                    <div className="flex justify-end">
                        <Button onClick={onClose}>
                            Close
                        </Button>
                    </div>
                </div>
            </DialogContent>
        </Dialog>
    )
}
