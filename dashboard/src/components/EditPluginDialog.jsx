import {useEffect, useState} from 'react'
import {Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle} from '@/components/ui/dialog.jsx'
import {Button} from '@/components/ui/button.jsx'
import {Input} from '@/components/ui/input.jsx'
import {Label} from '@/components/ui/label.jsx'
import {Textarea} from '@/components/ui/textarea.jsx'
import {Checkbox} from '@/components/ui/checkbox.jsx'

export default function EditPluginDialog({
                                             plugin,
                                             isOpen,
                                             onClose,
                                             onSave
                                         }) {
    const [editedPlugin, setEditedPlugin] = useState({
        pluginId: '',
        name: '',
        version: '',
        description: '',
        originalMainClass: '',
        encryptionKey: '',
        ownerId: 'admin',
        jarHash: '',
        active: true
    })

    useEffect(() => {
        if (plugin) {
            setEditedPlugin({
                pluginId: plugin.pluginId || '',
                name: plugin.name || '',
                version: plugin.version || '',
                description: plugin.description || '',
                originalMainClass: plugin.originalMainClass || '',
                encryptionKey: plugin.encryptionKey || '',
                ownerId: plugin.ownerId || 'admin',
                jarHash: plugin.jarHash || '',
                active: plugin.active !== undefined ? plugin.active : true
            })
        }
    }, [plugin])

    const handleSave = () => {
        onSave(editedPlugin)
    }

    if (!plugin) return null

    return (
        <Dialog open={isOpen} onOpenChange={onClose}>
            <DialogContent className="max-w-md">
                <DialogHeader>
                    <DialogTitle>Edit Plugin</DialogTitle>
                    <DialogDescription>
                        Update plugin information for {plugin.pluginId}
                    </DialogDescription>
                </DialogHeader>
                <div className="space-y-4">
                    <div className="space-y-2">
                        <Label htmlFor="edit-plugin-name">Plugin Name</Label>
                        <Input
                            id="edit-plugin-name"
                            value={editedPlugin.name}
                            onChange={(e) => setEditedPlugin({...editedPlugin, name: e.target.value})}
                        />
                    </div>
                    <div className="space-y-2">
                        <Label htmlFor="edit-plugin-version">Version</Label>
                        <Input
                            id="edit-plugin-version"
                            value={editedPlugin.version}
                            onChange={(e) => setEditedPlugin({...editedPlugin, version: e.target.value})}
                        />
                    </div>
                    <div className="space-y-2">
                        <Label htmlFor="edit-plugin-description">Description</Label>
                        <Textarea
                            id="edit-plugin-description"
                            value={editedPlugin.description}
                            onChange={(e) => setEditedPlugin({...editedPlugin, description: e.target.value})}
                        />
                    </div>
                    <div className="space-y-2">
                        <Label htmlFor="edit-plugin-mainClass">Original Main Class</Label>
                        <Input
                            id="edit-plugin-mainClass"
                            value={editedPlugin.originalMainClass}
                            onChange={(e) => setEditedPlugin({...editedPlugin, originalMainClass: e.target.value})}
                        />
                    </div>
                    <div className="space-y-2">
                        <Label htmlFor="edit-plugin-encryptionKey">Encryption Key (Base64)</Label>
                        <Textarea
                            id="edit-plugin-encryptionKey"
                            value={editedPlugin.encryptionKey}
                            onChange={(e) => setEditedPlugin({...editedPlugin, encryptionKey: e.target.value})}
                        />
                    </div>
                    <div className="space-y-2">
                        <Label htmlFor="edit-plugin-jarHash">JAR Hash (SHA-256)</Label>
                        <Input
                            id="edit-plugin-jarHash"
                            value={editedPlugin.jarHash}
                            onChange={(e) => setEditedPlugin({...editedPlugin, jarHash: e.target.value})}
                        />
                    </div>
                    <div className="flex items-center space-x-2">
                        <Checkbox
                            id="edit-plugin-active"
                            checked={editedPlugin.active}
                            onCheckedChange={(checked) => setEditedPlugin({...editedPlugin, active: checked})}
                        />
                        <Label htmlFor="edit-plugin-active">Active Plugin</Label>
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
