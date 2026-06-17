import {useEffect, useState} from 'react'
import {useNavigate} from 'react-router-dom'
import {useAuth} from './contexts/AuthContext.jsx'
import UserDashboard from './components/UserDashboard.jsx'
import {Alert, AlertDescription} from '@/components/ui/alert.jsx'
import {Card, CardContent} from '@/components/ui/card.jsx'

export default function UserPanel() {
    const {user, isAuthenticated, loading} = useAuth()
    const navigate = useNavigate()

    useEffect(() => {
        if (!loading && !isAuthenticated()) {
            navigate('/login')
        }
    }, [loading, isAuthenticated, navigate])

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-background">
                <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
            </div>
        )
    }

    if (!isAuthenticated()) {
        return null
    }

    return (
        <div className="min-h-screen bg-background">
            <UserDashboard user={user}/>
        </div>
    )
}


function LoginForm({onLogin}) {
    const [inputUserId, setInputUserId] = useState('demo-user')

    const handleSubmit = (e) => {
        e.preventDefault()
        if (inputUserId.trim()) {
            onLogin(inputUserId.trim())
        }
    }

    return (
        <div className="min-h-screen flex items-center justify-center bg-background">
            <Card className="w-full max-w-md">
                <CardContent className="p-6">
                    <div className="text-center mb-6">
                        <h1 className="text-2xl font-bold">Panel de Usuario</h1>
                        <p className="text-muted-foreground">
                            Ingresa tu ID de usuario para continuar
                        </p>
                    </div>

                    <form onSubmit={handleSubmit} className="space-y-4">
                        <div>
                            <label htmlFor="userId" className="block text-sm font-medium mb-2">
                                ID de Usuario
                            </label>
                            <input
                                id="userId"
                                type="text"
                                value={inputUserId}
                                onChange={(e) => setInputUserId(e.target.value)}
                                className="w-full px-3 py-2 border border-input rounded-md bg-background"
                                placeholder="Ingresa tu ID de usuario"
                                required
                            />
                        </div>

                        <button
                            type="submit"
                            className="w-full bg-primary text-primary-foreground py-2 px-4 rounded-md hover:bg-primary/90 transition-colors"
                        >
                            Ingresar
                        </button>
                    </form>

                    <Alert className="mt-4">
                        <AlertDescription>
                            <strong>Demo:</strong> Puedes usar cualquier ID de usuario para probar el sistema.
                            Por defecto: "demo-user"
                        </AlertDescription>
                    </Alert>
                </CardContent>
            </Card>
        </div>
    )
}
