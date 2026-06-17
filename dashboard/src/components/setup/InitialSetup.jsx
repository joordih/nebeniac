import {useEffect, useState} from 'react'
import {useNavigate} from 'react-router-dom'
import {AlertCircle, CheckCircle, Eye, EyeOff, Lock, Mail, Shield, User} from 'lucide-react'
import {Button} from '@/components/ui/button.jsx'
import {Card, CardContent, CardDescription, CardHeader, CardTitle} from '@/components/ui/card.jsx'
import {Input} from '@/components/ui/input.jsx'
import {Label} from '@/components/ui/label.jsx'
import {Alert, AlertDescription} from '@/components/ui/alert.jsx'
import {ERR_SERVER_CONNECTION} from '@/lib/utils.js'

const API_BASE_URL = 'http://localhost:8080/api/v1'

export default function InitialSetup() {
    const navigate = useNavigate()
    const [setupStatus, setSetupStatus] = useState(null)
    const [loading, setLoading] = useState(true)
    const [creating, setCreating] = useState(false)
    const [error, setError] = useState('')
    const [success, setSuccess] = useState(false)
    const [showPassword, setShowPassword] = useState(false)
    const [showConfirmPassword, setShowConfirmPassword] = useState(false)

    const [formData, setFormData] = useState({
        email: '',
        username: 'admin',
        firstName: '',
        lastName: '',
        password: '',
        confirmPassword: ''
    })

    useEffect(() => {
        checkSetupStatus()
    }, [])

    const checkSetupStatus = async () => {
        try {
            const response = await fetch(`${API_BASE_URL}/setup/status`)
            const data = await response.json()

            if (data.success) {
                setSetupStatus(data)


                if (data.setupComplete) {
                    navigate('/login')
                }
            } else {
                setError('Error verificando estado del sistema')
            }
        } catch (err) {
            console.error('Error checking setup status:', err)
            setError(ERR_SERVER_CONNECTION)
        } finally {
            setLoading(false)
        }
    }

    const validatePassword = (password) => {
        if (password.length < 8) {
            return 'Password must be at least 8 characters'
        }
        if (!/(?=.*[a-z])/.test(password)) {
            return 'Password must contain at least one lowercase letter'
        }
        if (!/(?=.*[A-Z])/.test(password)) {
            return 'Password must contain at least one uppercase letter'
        }
        if (!/(?=.*\d)/.test(password)) {
            return 'Password must contain at least one number'
        }
        return null
    }

    const handleSubmit = async (e) => {
        e.preventDefault()
        setCreating(true)
        setError('')


        if (!formData.email || !formData.firstName || !formData.lastName || !formData.password) {
            setError('All fields marked with * are required')
            setCreating(false)
            return
        }

        const passwordError = validatePassword(formData.password)
        if (passwordError) {
            setError(passwordError)
            setCreating(false)
            return
        }

        if (formData.password !== formData.confirmPassword) {
            setError('Passwords do not match')
            setCreating(false)
            return
        }

        try {
            const response = await fetch(`${API_BASE_URL}/setup/admin`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    email: formData.email,
                    username: formData.username || 'admin',
                    firstName: formData.firstName,
                    lastName: formData.lastName,
                    password: formData.password
                })
            })

            const data = await response.json()

            if (data.success) {
                setSuccess(true)
                setTimeout(() => {
                    navigate('/login')
                }, 3000)
            } else {
                setError(data.error || 'Error creating administrator')
            }
        } catch (err) {
            console.error('Setup error:', err)
            setError(ERR_SERVER_CONNECTION)
        } finally {
            setCreating(false)
        }
    }

    const createDefaultAdmin = async () => {
        try {
            setCreating(true)
            setError('')

            const response = await fetch(`${API_BASE_URL}/setup/admin/default`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                }
            })

            const data = await response.json()

            if (data.success) {
                setSuccess(true)
                setError('')

                navigator.clipboard.writeText(data.credentials.password).catch(() => {})
                alert(`User created:\nEmail: ${data.credentials.email}\n\nPassword copied to clipboard. Please save it in a secure place.\n\nCHANGE PASSWORD IMMEDIATELY!`)

                setTimeout(() => {
                    navigate('/login')
                }, 2000)
            } else {
                setError(data.error || 'Error creating default administrator')
            }
        } catch (err) {
            console.error('Default setup error:', err)
            setError(ERR_SERVER_CONNECTION)
        } finally {
            setCreating(false)
        }
    }

    const handleChange = (e) => {
        setFormData(prev => ({
            ...prev,
            [e.target.name]: e.target.value
        }))
    }

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100">
                <div className="text-center">
                    <Shield className="h-12 w-12 mx-auto mb-4 text-blue-600 animate-pulse"/>
                    <p className="text-gray-600">Checking system status...</p>
                </div>
            </div>
        )
    }

    if (success) {
        return (
            <div
                className="min-h-screen flex items-center justify-center bg-gradient-to-br from-green-50 to-emerald-100 p-4">
                <Card className="w-full max-w-md">
                    <CardContent className="text-center p-6">
                        <div className="text-green-500 mb-4">
                            <CheckCircle className="h-12 w-12 mx-auto"/>
                        </div>
                        <h2 className="text-xl font-semibold mb-2">System Configured!</h2>
                        <p className="text-muted-foreground mb-4">
                            Administrator created successfully. You will be redirected to login in a few seconds.
                        </p>
                        <Button onClick={() => navigate('/login')}>
                            Go to Login Now
                        </Button>
                    </CardContent>
                </Card>
            </div>
        )
    }

    return (
        <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100 p-4">
            <Card className="w-full max-w-lg">
                <CardHeader className="text-center">
                    <div className="flex justify-center mb-4">
                        <div className="p-3 bg-blue-600 rounded-full">
                            <Shield className="h-8 w-8 text-white"/>
                        </div>
                    </div>
                    <CardTitle className="text-2xl font-bold">Initial Setup</CardTitle>
                    <CardDescription>
                        Create the first administrator account to start using Nebeniac
                    </CardDescription>
                </CardHeader>

                <CardContent>
                    {setupStatus && !setupStatus.databaseHealthy && (
                        <Alert variant="destructive" className="mb-6">
                            <AlertCircle className="h-4 w-4"/>
                            <AlertDescription>
                                Database is unavailable. Make sure the server is running correctly.
                            </AlertDescription>
                        </Alert>
                    )}

                    <form onSubmit={handleSubmit} className="space-y-4">
                        {error && (
                            <Alert variant="destructive">
                                <AlertDescription>{error}</AlertDescription>
                            </Alert>
                        )}

                        <div className="grid grid-cols-2 gap-4">
                            <div className="space-y-2">
                                <Label htmlFor="firstName">First Name *</Label>
                                <div className="relative">
                                    <User className="absolute left-3 top-3 h-4 w-4 text-muted-foreground"/>
                                    <Input
                                        id="firstName"
                                        name="firstName"
                                        type="text"
                                        placeholder="Juan"
                                        value={formData.firstName}
                                        onChange={handleChange}
                                        className="pl-10"
                                        required
                                    />
                                </div>
                            </div>

                            <div className="space-y-2">
                                <Label htmlFor="lastName">Last Name *</Label>
                                <Input
                                    id="lastName"
                                    name="lastName"
                                    type="text"
                                    placeholder="Smith"
                                    value={formData.lastName}
                                    onChange={handleChange}
                                    required
                                />
                            </div>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="email">Email *</Label>
                            <div className="relative">
                                <Mail className="absolute left-3 top-3 h-4 w-4 text-muted-foreground"/>
                                <Input
                                    id="email"
                                    name="email"
                                    type="email"
                                    placeholder="admin@yourdomain.com"
                                    value={formData.email}
                                    onChange={handleChange}
                                    className="pl-10"
                                    required
                                />
                            </div>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="username">Username</Label>
                            <div className="relative">
                                <User className="absolute left-3 top-3 h-4 w-4 text-muted-foreground"/>
                                <Input
                                    id="username"
                                    name="username"
                                    type="text"
                                    placeholder="admin"
                                    value={formData.username}
                                    onChange={handleChange}
                                    className="pl-10"
                                />
                            </div>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="password">Password *</Label>
                            <div className="relative">
                                <Lock className="absolute left-3 top-3 h-4 w-4 text-muted-foreground"/>
                                <Input
                                    id="password"
                                    name="password"
                                    type={showPassword ? 'text' : 'password'}
                                    placeholder="Minimum 8 characters"
                                    value={formData.password}
                                    onChange={handleChange}
                                    className="pl-10 pr-10"
                                    required
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowPassword(!showPassword)}
                                    className="absolute right-3 top-3 text-muted-foreground hover:text-foreground"
                                >
                                    {showPassword ? <EyeOff className="h-4 w-4"/> : <Eye className="h-4 w-4"/>}
                                </button>
                            </div>
                            <p className="text-xs text-muted-foreground">
                                Must contain at least 8 characters, one uppercase letter, one lowercase letter, and one number
                            </p>
                        </div>

                        <div className="space-y-2">
                            <Label htmlFor="confirmPassword">Confirm Password *</Label>
                            <div className="relative">
                                <Lock className="absolute left-3 top-3 h-4 w-4 text-muted-foreground"/>
                                <Input
                                    id="confirmPassword"
                                    name="confirmPassword"
                                    type={showConfirmPassword ? 'text' : 'password'}
                                    placeholder="Repeat your password"
                                    value={formData.confirmPassword}
                                    onChange={handleChange}
                                    className="pl-10 pr-10"
                                    required
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                                    className="absolute right-3 top-3 text-muted-foreground hover:text-foreground"
                                >
                                    {showConfirmPassword ? <EyeOff className="h-4 w-4"/> : <Eye className="h-4 w-4"/>}
                                </button>
                            </div>
                        </div>

                        <Button
                            type="submit"
                            className="w-full"
                            disabled={creating}
                        >
                            {creating ? 'Creating Administrator...' : 'Create Administrator'}
                        </Button>
                    </form>

                    {import.meta.env.DEV && (
                    <div className="mt-6 pt-6 border-t">
                        <div className="text-center">
                            <p className="text-sm text-muted-foreground mb-3">
                                Development only: create an admin with default credentials:
                            </p>
                            <Button
                                variant="outline"
                                onClick={createDefaultAdmin}
                                disabled={creating}
                                className="w-full"
                            >
                                Crear Admin por Defecto (Solo Desarrollo)
                            </Button>
                            <p className="text-xs text-red-600 mt-2">
                                ⚠️ This will create admin@nebeniac.com / admin123 — change password immediately!
                            </p>
                        </div>
                    </div>
                    )}
                </CardContent>
            </Card>
        </div>
    )
}
