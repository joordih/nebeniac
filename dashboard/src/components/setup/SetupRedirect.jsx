import {useEffect, useState} from 'react'
import {Navigate} from 'react-router-dom'
import {Shield} from 'lucide-react'

const API_BASE_URL = 'http://localhost:8080/api/v1'

export default function SetupRedirect() {
    const [loading, setLoading] = useState(true)
    const [needsSetup, setNeedsSetup] = useState(false)

    useEffect(() => {
        checkSetupStatus()
    }, [])

    const checkSetupStatus = async () => {
        try {
            const response = await fetch(`${API_BASE_URL}/setup/status`)
            const data = await response.json()

            if (data.success) {
                setNeedsSetup(data.needsInitialSetup)
            } else {

                setNeedsSetup(true)
            }
        } catch (err) {
            console.error('Error checking setup status:', err)

            setNeedsSetup(true)
        } finally {
            setLoading(false)
        }
    }

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 to-indigo-100">
                <div className="text-center">
                    <Shield className="h-12 w-12 mx-auto mb-4 text-blue-600 animate-pulse"/>
                    <p className="text-gray-600">Checking system configuration...</p>
                </div>
            </div>
        )
    }


    if (needsSetup) {
        return <Navigate to="/setup" replace/>
    } else {
        return <Navigate to="/login" replace/>
    }
}
