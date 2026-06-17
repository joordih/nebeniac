import {useEffect, useState} from 'react'
import {useNavigate, useSearchParams} from 'react-router-dom'
import {CheckCircle, Eye, EyeOff, Lock, Mail, Shield, User} from 'lucide-react'
import {Button} from '@/components/ui/button.jsx'
import {Card, CardContent, CardDescription, CardHeader, CardTitle} from '@/components/ui/card.jsx'
import {Input} from '@/components/ui/input.jsx'
import {Label} from '@/components/ui/label.jsx'
import {Alert, AlertDescription} from '@/components/ui/alert.jsx'
import {ERR_SERVER_CONNECTION} from '@/lib/utils.js'

const API_BASE_URL = 'http://localhost:8080/api/v1'

export default function CompleteRegistration() {
    const [searchParams] = useSearchParams()
    const navigate = useNavigate()
    const token = searchParams.get('token')

    const [formData, setFormData] = useState({
        firstName: '',
        lastName: '',
        username: '',
        password: '',
        confirmPassword: ''
    })
    const [showPassword, setShowPassword] = useState(false)
    const [showConfirmPassword, setShowConfirmPassword] = useState(false)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState('')
    const [success, setSuccess] = useState(false)

    useEffect(() => {
        if (!token) {
            setError('Invalid verification token')
        }
    }, [token])

    const validatePassword = (password) => {
        if (password.length < 8) {
            return 'Password must be at least 8 characters'
        }
        if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(password)) {
            return 'Password must contain at least one uppercase letter, one lowercase letter, and one number'
        }
        return null
    }

    const handleSubmit = async (e) => {
        e.preventDefault()
        setLoading(true)
        setError('')


        if (!formData.firstName || !formData.lastName || !formData.password) {
            setError('All fields are required')
            setLoading(false)
            return
        }

        const passwordError = validatePassword(formData.password)
        if (passwordError) {
            setError(passwordError)
            setLoading(false)
            return
        }

        if (formData.password !== formData.confirmPassword) {
            setError('Passwords do not match')
            setLoading(false)
            return
        }

        try {
            const response = await fetch(`${API_BASE_URL}/auth/complete-registration`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    token: token,
                    firstName: formData.firstName,
                    lastName: formData.lastName,
                    username: formData.username || null,
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
                setError(data.error || 'Error completing registration')
            }
        } catch (err) {
            console.error('Registration error:', err)
            setError(ERR_SERVER_CONNECTION)
        } finally {
            setLoading(false)
        }
    }

    const handleChange = (e) => {
        setFormData(prev => ({
            ...prev,
            [e.target.name]: e.target.value
        }))
    }

    if (!token) {
        return (
            <div className="dark min-h-screen flex items-center justify-center bg-background p-4">
                <Card className="w-full max-w-md">
                    <CardContent className="text-center p-6">
                        <div className="text-destructive mb-4">
                            <Mail className="h-12 w-12 mx-auto"/>
                        </div>
                        <h2 className="text-xl font-semibold mb-2">Invalid Token</h2>
                        <p className="text-muted-foreground mb-4">
                            The verification link is invalid or has expired.
                        </p>
                        <Button
                            onClick={() => navigate('/login')}
                        >
                            Go to Login
                        </Button>
                    </CardContent>
                </Card>
            </div>
        )
    }

    if (success) {
        return (
            <div className="dark min-h-screen flex items-center justify-center bg-background p-4">
                <Card className="w-full max-w-md">
                    <CardContent className="text-center p-6">
                        <div className="text-green-600 mb-4">
                            <CheckCircle className="h-12 w-12 mx-auto"/>
                        </div>
                        <h2 className="text-xl font-semibold mb-2">Registration Complete!</h2>
                        <p className="text-muted-foreground mb-4">
                            Your account has been created successfully. You will be redirected to login in a few seconds.
                        </p>
                        <Button
                            onClick={() => navigate('/login')}
                        >
                            Go to Login Now
                        </Button>
                    </CardContent>
                </Card>
            </div>
        )
    }

    return (
        <div className="dark min-h-screen flex items-center justify-center bg-background p-4">
            <Card className="w-full max-w-md">
                <CardHeader className="text-center">
                    <div className="flex justify-center mb-4">
                        <div className="p-3 bg-primary rounded-full">
                            <Shield className="h-8 w-8 text-primary-foreground"/>
                        </div>
                    </div>
                    <CardTitle className="text-2xl font-bold">Complete Registration</CardTitle>
                    <CardDescription>
                        Fill in your details to activate your account
                    </CardDescription>
                </CardHeader>

                <CardContent>
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
                            <Label htmlFor="username">Username (optional)</Label>
                            <div className="relative">
                                <User className="absolute left-3 top-3 h-4 w-4 text-muted-foreground"/>
                                <Input
                                    id="username"
                                    name="username"
                                    type="text"
                                    placeholder="juanperez"
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
                            disabled={loading}
                        >
                            {loading ? 'Completing Registration...' : 'Complete Registration'}
                        </Button>
                    </form>

                    <div className="mt-6 pt-6 border-t text-center text-sm text-muted-foreground">
                        <p>By completing registration, you agree to our terms of service.</p>
                    </div>
                </CardContent>
            </Card>
        </div>
    )
}
