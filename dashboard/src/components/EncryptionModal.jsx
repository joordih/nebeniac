import {useEffect, useState} from 'react'
import {AlertCircle, CheckCircle, Download, Loader2, Shield} from 'lucide-react'
import {Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle} from '@/components/ui/dialog.jsx'
import {Button} from '@/components/ui/button.jsx'
import {Progress} from '@/components/ui/progress.jsx'
import {Alert, AlertDescription} from '@/components/ui/alert.jsx'
import {Badge} from '@/components/ui/badge.jsx'

const API_BASE_URL = 'http://localhost:8080/api/v1'
const WS_BASE_URL = 'ws://localhost:8082'

export default function EncryptionModal({
                                            isOpen,
                                            onClose,
                                            plugin,
                                            userToken
                                        }) {
    const [step, setStep] = useState('loading')
    const [pluginData, setPluginData] = useState(null)
    const [encryptionData, setEncryptionData] = useState(null)
    const [progress, setProgress] = useState(0)
    const [logs, setLogs] = useState([])
    const [error, setError] = useState('')
    const [isProcessing, setIsProcessing] = useState(false)
    const [websocket, setWebsocket] = useState(null)
    const [sessionId, setSessionId] = useState(null)

    useEffect(() => {
        if (isOpen) {
            setStep('loading')
            setPluginData(null)
            setEncryptionData(null)
            setProgress(0)
            setLogs([])
            setError('')
            setIsProcessing(false)
            setSessionId(generateSessionId())
            loadPluginData()
        } else {
            if (websocket) {
                websocket.close()
                setWebsocket(null)
            }
        }
    }, [isOpen])

    const loadPluginData = async () => {
        try {
            addLog('Loading plugin configuration...', 'info')
            const response = await fetch(`${API_BASE_URL}/plugins/available`, {
                headers: {
                    'Authorization': `Bearer ${userToken}`
                }
            })

            if (!response.ok) {
                throw new Error('Failed to load plugin data')
            }

            const data = await response.json()
            const foundPlugin = data.plugins.find(p => p.pluginId === plugin.pluginId)

            if (!foundPlugin) {
                throw new Error('Plugin not found')
            }

            setPluginData(foundPlugin)

            if (!foundPlugin.targetPackages || foundPlugin.targetPackages.length === 0) {
                addLog('Warning: No target packages defined for this plugin', 'warning')
            } else {
                addLog(`Target packages: ${foundPlugin.targetPackages.join(', ')}`, 'info')
            }

            setStep('ready')
        } catch (err) {
            addLog(`Error loading plugin: ${err.message}`, 'error')
            setError(err.message)
            setStep('error')
        }
    }

    const generateSessionId = () => {
        return 'session_' + Math.random().toString(36).substr(2, 9) + '_' + Date.now()
    }

    const addLog = (message, type = 'info') => {
        const timestamp = new Date().toLocaleTimeString()
        setLogs(prev => [...prev, {message, type, timestamp}])
    }

    const connectWebSocket = () => {
        if (!sessionId) return

        const ws = new WebSocket(`${WS_BASE_URL}?sessionId=${sessionId}`)

        ws.onopen = () => {
            addLog('Connected to encryption service', 'info')
            setWebsocket(ws)
        }

        ws.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data)

                switch (data.type) {
                    case 'log':
                        addLog(data.message, data.level)
                        break
                    case 'progress':
                        setProgress(parseInt(data.message))
                        break
                    case 'completion': {
                        const completionData = JSON.parse(data.message)
                        if (completionData.success) {
                            setEncryptionData({
                                downloadUrl: completionData.downloadUrl,
                                licenseKey: pluginData?.licenseKey || '',
                                targetPackages: pluginData?.targetPackages || [],
                                encryptionKey: pluginData?.encryptionKey || 'Generated encryption key for ' + plugin.pluginId
                            })
                            setStep('complete')
                            addLog('Encryption completed successfully!', 'success')
                        } else {
                            setStep('error')
                            addLog('Encryption failed', 'error')
                        }
                        setIsProcessing(false)
                        break
                    }
                }
            } catch (err) {
                console.error('Error parsing WebSocket message:', err)
                addLog('Error parsing server message: ' + err.message, 'error')
            }
        }

        ws.onerror = (error) => {
            console.error('WebSocket error:', error)
            addLog('WebSocket connection error: ' + error.message, 'error')
            setError('Connection to encryption service failed')
            setIsProcessing(false)
        }

        ws.onclose = (event) => {
            addLog(`Connection closed (${event.code}: ${event.reason})`, 'info')
        }
    }

    const startEncryption = async () => {
        if (!pluginData || !pluginData.targetPackages || pluginData.targetPackages.length === 0) {
            setError('No target packages defined for this plugin')
            return
        }

        setIsProcessing(true)
        setStep('encrypting')
        setError('')
        setProgress(0)

        try {
            addLog('Configuring encryption parameters...', 'info')
            addLog(`Target packages: ${pluginData.targetPackages.join(', ')}`, 'info')

            const configResponse = await fetch(`${API_BASE_URL}/plugins/${plugin.pluginId}/encrypt`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${userToken}`
                },
                body: JSON.stringify({
                    targetPackages: pluginData.targetPackages
                })
            })

            const configData = await configResponse.json()

            if (!configResponse.ok || !configData.success) {
                throw new Error(configData.error || 'Failed to configure encryption')
            }

            addLog('Configuration successful, connecting to encryption service...', 'info')
            setProgress(10)

            connectWebSocket()

            setTimeout(async () => {
                try {
                    const encryptResponse = await fetch(`${API_BASE_URL}/plugins/${plugin.pluginId}/encrypt-docker?sessionId=${sessionId}`, {
                        method: 'POST',
                        headers: {
                            'Authorization': `Bearer ${userToken}`
                        }
                    })

                    const encryptData = await encryptResponse.json()

                    if (!encryptResponse.ok || !encryptData.success) {
                        throw new Error(encryptData.error || 'Failed to start encryption process')
                    }

                    addLog('Docker encryption process started...', 'info')
                    setProgress(20)

                } catch (err) {
                    addLog(`Error starting encryption: ${err.message}`, 'error')
                    setError(err.message)
                    setStep('error')
                    setIsProcessing(false)
                }
            }, 1000)

        } catch (err) {
            addLog(`Error: ${err.message}`, 'error')
            setError(err.message)
            setStep('error')
            setIsProcessing(false)
        }
    }

    const downloadPlugin = () => {
        if (encryptionData && encryptionData.downloadUrl) {
            addLog('Initiating plugin download...', 'info')
            const backendUrl = `${API_BASE_URL}/plugins/${plugin.pluginId}/download/${encryptionData.licenseKey}`
            window.open(backendUrl, '_blank')
        }
    }

    const getStepIcon = () => {
        switch (step) {
            case 'loading':
                return <Loader2 className="h-6 w-6 text-blue-500 animate-spin"/>
            case 'ready':
                return <Shield className="h-6 w-6 text-blue-500"/>
            case 'encrypting':
                return <Loader2 className="h-6 w-6 text-yellow-500 animate-spin"/>
            case 'complete':
                return <CheckCircle className="h-6 w-6 text-green-500"/>
            case 'error':
                return <AlertCircle className="h-6 w-6 text-red-500"/>
            default:
                return <Shield className="h-6 w-6"/>
        }
    }

    const getStepTitle = () => {
        switch (step) {
            case 'loading':
                return 'Loading Plugin Configuration'
            case 'ready':
                return 'Ready to Encrypt'
            case 'encrypting':
                return 'Encrypting Plugin'
            case 'complete':
                return 'Encryption Complete'
            case 'error':
                return 'Encryption Failed'
            default:
                return 'Plugin Encryption'
        }
    }

    return (
        <Dialog open={isOpen} onOpenChange={onClose}>
            <DialogContent className="max-w-4xl max-h-[80vh] overflow-y-auto">
                <DialogHeader>
                    <DialogTitle className="flex items-center space-x-2">
                        {getStepIcon()}
                        <span>{getStepTitle()}</span>
                    </DialogTitle>
                    <DialogDescription>
                        {plugin && `Encrypting plugin: ${plugin.name} (${plugin.pluginId})`}
                    </DialogDescription>
                </DialogHeader>

                <div className="space-y-6">
                    {step === 'loading' && (
                        <div className="space-y-4">
                            <div className="flex items-center justify-center py-8">
                                <Loader2 className="h-8 w-8 animate-spin text-blue-500"/>
                                <span className="ml-2 text-foreground">Loading plugin configuration...</span>
                            </div>
                        </div>
                    )}

                    {step === 'ready' && pluginData && (
                        <div className="space-y-4">
                            <div className="bg-muted/50 dark:bg-muted/20 p-4 rounded-lg border dark:border-gray-700">
                                <h3 className="font-semibold mb-2 text-foreground">Plugin Information</h3>
                                <div className="space-y-1 text-sm text-muted-foreground">
                                    <div><strong className="text-foreground">Name:</strong> {pluginData.name}</div>
                                    <div><strong className="text-foreground">Version:</strong> {pluginData.version}
                                    </div>
                                    <div><strong className="text-foreground">Target Packages:</strong>
                                        {pluginData.targetPackages && pluginData.targetPackages.length > 0
                                            ? pluginData.targetPackages.join(', ')
                                            : <span className="text-orange-600 dark:text-orange-400">No target packages defined for this plugin</span>
                                        }
                                    </div>
                                </div>
                            </div>

                            {error && (
                                <Alert variant="destructive">
                                    <AlertCircle className="h-4 w-4"/>
                                    <AlertDescription>{error}</AlertDescription>
                                </Alert>
                            )}

                            <div className="flex justify-end space-x-2">
                                <Button variant="outline" onClick={onClose}>
                                    Cancel
                                </Button>
                                <Button onClick={startEncryption} disabled={isProcessing}>
                                    <Shield className="h-4 w-4 mr-2"/>
                                    Start Encryption
                                </Button>
                            </div>
                        </div>
                    )}

                    {(step === 'encrypting' || step === 'complete' || step === 'error') && (
                        <div className="space-y-4">
                            <div className="space-y-2">
                                <div className="flex justify-between text-sm text-foreground">
                                    <span>Progress</span>
                                    <span>{progress}%</span>
                                </div>
                                <Progress value={progress} className="w-full"/>
                            </div>

                            <div
                                className="bg-gray-900 dark:bg-card text-green-400 p-4 rounded-lg font-mono text-sm max-h-60 overflow-y-auto border dark:border-gray-700">
                                {logs.map((log, index) => (
                                    <div key={index} className="flex items-start space-x-2">
                                        <span className="text-gray-500 dark:text-gray-400">[{log.timestamp}]</span>
                                        <Badge
                                            variant={log.type === 'error' ? 'destructive' : log.type === 'success' ? 'default' : 'secondary'}
                                            className="text-xs"
                                        >
                                            {log.type.toUpperCase()}
                                        </Badge>
                                        <span
                                            className={log.type === 'error' ? 'text-red-400' : log.type === 'success' ? 'text-green-400 dark:text-green-300' : 'text-gray-200 dark:text-gray-300'}>
                      {log.message}
                    </span>
                                    </div>
                                ))}
                            </div>

                            {step === 'complete' && encryptionData && (
                                <div className="space-y-3">
                                    <Alert>
                                        <CheckCircle className="h-4 w-4"/>
                                        <AlertDescription>
                                            Plugin encrypted successfully! Your custom encryption key has been generated
                                            and stored securely.
                                        </AlertDescription>
                                    </Alert>

                                    <div
                                        className="bg-muted/30 dark:bg-muted/10 p-4 rounded-lg space-y-2 border dark:border-gray-700">
                                        <div className="text-foreground"><strong>License Key:</strong> <span
                                            className="text-muted-foreground">{encryptionData.licenseKey}</span></div>
                                        <div className="text-foreground"><strong>Encrypted Packages:</strong> <span
                                            className="text-muted-foreground">{encryptionData.targetPackages?.join(', ') || 'N/A'}</span>
                                        </div>
                                        <div className="text-foreground"><strong>Encryption Key:</strong> <span
                                            className="text-muted-foreground font-mono">{encryptionData.encryptionKey.substring(0, 32)}...</span>
                                        </div>
                                    </div>
                                </div>
                            )}

                            {error && step === 'error' && (
                                <Alert variant="destructive">
                                    <AlertCircle className="h-4 w-4"/>
                                    <AlertDescription>{error}</AlertDescription>
                                </Alert>
                            )}

                            <div className="flex justify-end space-x-2">
                                {step === 'complete' && (
                                    <Button onClick={downloadPlugin} className="bg-green-600 hover:bg-green-700">
                                        <Download className="h-4 w-4 mr-2"/>
                                        Download Encrypted Plugin
                                    </Button>
                                )}
                                <Button variant="outline" onClick={onClose}>
                                    {step === 'complete' ? 'Close' : 'Cancel'}
                                </Button>
                            </div>
                        </div>
                    )}
                </div>
            </DialogContent>
        </Dialog>
    )
}
