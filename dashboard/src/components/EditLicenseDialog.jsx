import {useEffect, useState} from 'react'
import {Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle} from '@/components/ui/dialog.jsx'
import {Button} from '@/components/ui/button.jsx'
import {Input} from '@/components/ui/input.jsx'
import {Label} from '@/components/ui/label.jsx'
import {Textarea} from '@/components/ui/textarea.jsx'
import {Select, SelectContent, SelectItem, SelectTrigger, SelectValue} from '@/components/ui/select.jsx'
import {Checkbox} from '@/components/ui/checkbox.jsx'

const availableFeatures = [
    'BASIC_PROTECTION',
    'HEARTBEAT_VERIFICATION',
    'ADVANCED_ENCRYPTION',
    'CUSTOM_BRANDING',
    'PRIORITY_SUPPORT'
]

export default function EditLicenseDialog({
                                              license,
                                              isOpen,
                                              onClose,
                                              onSave
                                          }) {
    const [editedLicense, setEditedLicense] = useState({
        customerEmail: '',
        customerName: '',
        licenseType: 'STANDARD',
        maxActivations: 5,
        features: ['BASIC_PROTECTION', 'HEARTBEAT_VERIFICATION'],
        notes: '',
        active: true
    })

    useEffect(() => {
        if (license) {
            setEditedLicense({
                customerEmail: license.customerEmail || '',
                customerName: license.customerName || '',
                licenseType: license.licenseType || 'STANDARD',
                maxActivations: license.maxActivations || 5,
                features: license.features || ['BASIC_PROTECTION', 'HEARTBEAT_VERIFICATION'],
                notes: license.notes || '',
                active: license.active !== undefined ? license.active : true
            })
        }
    }, [license])

    const handleSave = () => {
        onSave(editedLicense)
    }

    const toggleFeature = (feature) => {
        setEditedLicense(prev => ({
            ...prev,
            features: prev.features.includes(feature)
                ? prev.features.filter(f => f !== feature)
                : [...prev.features, feature]
        }))
    }

    if (!license) return null

    return (
        <Dialog open={isOpen} onOpenChange={onClose}>
            <DialogContent className="max-w-md">
                <DialogHeader>
                    <DialogTitle>Edit License</DialogTitle>
                    <DialogDescription>
                        Update license information for {license.licenseKey}
                    </DialogDescription>
                </DialogHeader>
                <div className="space-y-4">
                    <div className="space-y-2">
                        <Label htmlFor="edit-customerEmail">Customer Email</Label>
                        <Input
                            id="edit-customerEmail"
                            type="email"
                            value={editedLicense.customerEmail}
                            onChange={(e) => setEditedLicense({...editedLicense, customerEmail: e.target.value})}
                        />
                    </div>
                    <div className="space-y-2">
                        <Label htmlFor="edit-customerName">Customer Name</Label>
                        <Input
                            id="edit-customerName"
                            value={editedLicense.customerName}
                            onChange={(e) => setEditedLicense({...editedLicense, customerName: e.target.value})}
                        />
                    </div>
                    <div className="space-y-2">
                        <Label htmlFor="edit-licenseType">License Type</Label>
                        <Select
                            value={editedLicense.licenseType}
                            onValueChange={(value) => setEditedLicense({...editedLicense, licenseType: value})}
                        >
                            <SelectTrigger>
                                <SelectValue/>
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
                        <Label htmlFor="edit-maxActivations">Max Activations</Label>
                        <Input
                            id="edit-maxActivations"
                            type="number"
                            min="1"
                            value={editedLicense.maxActivations}
                            onChange={(e) => setEditedLicense({
                                ...editedLicense,
                                maxActivations: parseInt(e.target.value) || 1
                            })}
                        />
                    </div>
                    <div className="space-y-2">
                        <Label>Features</Label>
                        <div className="space-y-2">
                            {availableFeatures.map((feature) => (
                                <div key={feature} className="flex items-center space-x-2">
                                    <Checkbox
                                        id={`edit-${feature}`}
                                        checked={editedLicense.features.includes(feature)}
                                        onCheckedChange={() => toggleFeature(feature)}
                                    />
                                    <Label htmlFor={`edit-${feature}`} className="text-sm">
                                        {feature.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, l => l.toUpperCase())}
                                    </Label>
                                </div>
                            ))}
                        </div>
                    </div>
                    <div className="space-y-2">
                        <Label htmlFor="edit-notes">Notes</Label>
                        <Textarea
                            id="edit-notes"
                            value={editedLicense.notes}
                            onChange={(e) => setEditedLicense({...editedLicense, notes: e.target.value})}
                        />
                    </div>
                    <div className="flex items-center space-x-2">
                        <Checkbox
                            id="edit-active"
                            checked={editedLicense.active}
                            onCheckedChange={(checked) => setEditedLicense({...editedLicense, active: checked})}
                        />
                        <Label htmlFor="edit-active">Active License</Label>
                    </div>
                    <div className="flex justify-end space-x-2">
                        <Button variant="outline" onClick={onClose}>
                            Cancel
                        </Button>
                        <Button onClick={handleSave}>
                            Save Changes
                        </Button>
                    </div>
                </div>
            </DialogContent>
        </Dialog>
    )
}
