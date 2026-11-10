import {useEffect} from 'react'
import {useNavigate} from 'react-router-dom'
import {useAuth} from './contexts/AuthContext.jsx'
import UserDashboard from './components/UserDashboard.jsx'

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

