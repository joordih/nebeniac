import {createContext, useContext, useEffect, useState} from 'react'
import {ERR_SERVER_CONNECTION} from '@/lib/utils.js'
import {API_BASE_URL} from '@/lib/config.js'

const AuthContext = createContext({})

export const useAuth = () => {
    const context = useContext(AuthContext)
    if (!context) {
        throw new Error('useAuth must be used within an AuthProvider')
    }
    return context
}

export const AuthProvider = ({children}) => {
    const [user, setUser] = useState(null)
    const [token, setToken] = useState(null)
    const [loading, setLoading] = useState(true)
    const [initialized, setInitialized] = useState(false)

    useEffect(() => {
        const initializeAuth = async () => {
            try {
                const storedToken = localStorage.getItem('authToken')
                const storedUser = localStorage.getItem('user')

                if (storedToken && storedUser) {
                    const isValid = await verifyToken(storedToken)
                    if (isValid) {
                        setToken(storedToken)
                        setUser(JSON.parse(storedUser))
                    } else {
                        localStorage.removeItem('authToken')
                        localStorage.removeItem('user')
                    }
                }
            } catch (error) {
                console.error('Error initializing auth:', error)
                localStorage.removeItem('authToken')
                localStorage.removeItem('user')
            } finally {
                setLoading(false)
                setInitialized(true)
            }
        }

        initializeAuth()
    }, [])

    const verifyToken = async (tokenToVerify) => {
        try {
            const response = await fetch(`${API_BASE_URL}/auth/verify`, {
                headers: {
                    'Authorization': `Bearer ${tokenToVerify}`
                }
            })

            if (response.ok) {
                const data = await response.json()
                if (data.success && data.user) {
                    setUser(data.user)
                    localStorage.setItem('user', JSON.stringify(data.user))
                    return true
                }
            }
            return false
        } catch (error) {
            console.error('Error verifying token:', error)
            return false
        }
    }

    const login = async (email, password) => {
        try {
            const response = await fetch(`${API_BASE_URL}/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({email, password})
            })

            const data = await response.json()

            if (data.success) {
                setToken(data.token)
                setUser(data.user)
                localStorage.setItem('authToken', data.token)
                localStorage.setItem('user', JSON.stringify(data.user))
                return {success: true, user: data.user}
            } else {
                return {success: false, error: data.error}
            }
        } catch (error) {
            console.error('Login error:', error)
            return {success: false, error: ERR_SERVER_CONNECTION}
        }
    }

    const logout = async () => {
        try {
            if (token) {
                await fetch(`${API_BASE_URL}/auth/logout`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${token}`
                    }
                })
            }
        } catch (error) {
            console.error('Logout error:', error)
        } finally {
            setToken(null)
            setUser(null)
            localStorage.removeItem('authToken')
            localStorage.removeItem('user')
        }
    }

    const requestPasswordReset = async (email) => {
        try {
            const response = await fetch(`${API_BASE_URL}/auth/request-password-reset`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({email})
            })

            const data = await response.json()
            return data
        } catch (error) {
            console.error('Password reset request error:', error)
            return {success: false, error: ERR_SERVER_CONNECTION}
        }
    }

    const resetPassword = async (token, newPassword) => {
        try {
            const response = await fetch(`${API_BASE_URL}/auth/reset-password`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({token, newPassword})
            })

            const data = await response.json()
            return data
        } catch (error) {
            console.error('Password reset error:', error)
            return {success: false, error: ERR_SERVER_CONNECTION}
        }
    }

    const completeRegistration = async (registrationData) => {
        try {
            const response = await fetch(`${API_BASE_URL}/auth/complete-registration`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(registrationData)
            })

            const data = await response.json()
            return data
        } catch (error) {
            console.error('Registration completion error:', error)
            return {success: false, error: ERR_SERVER_CONNECTION}
        }
    }

    const updateUser = async (userData) => {
        try {
            const response = await fetch(`${API_BASE_URL}/users/${user.id}`, {
                method: 'PUT',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`
                },
                body: JSON.stringify(userData)
            })

            const data = await response.json()

            if (data.success) {
                setUser(data.user)
                localStorage.setItem('user', JSON.stringify(data.user))
            }

            return data
        } catch (error) {
            console.error('Update user error:', error)
            return {success: false, error: ERR_SERVER_CONNECTION}
        }
    }

    const isAuthenticated = () => {
        return !!(token && user)
    }

    const isAdmin = () => {
        return user?.role === 'ADMIN'
    }

    const hasPermission = (permission) => {
        if (isAdmin()) return true
        return user?.permissions?.includes(permission) || false
    }

    const getAuthHeaders = () => {
        return token ? {'Authorization': `Bearer ${token}`} : {}
    }

    const value = {
        user,
        token,
        loading,
        initialized,
        login,
        logout,
        requestPasswordReset,
        resetPassword,
        completeRegistration,
        updateUser,
        isAuthenticated,
        isAdmin,
        hasPermission,
        getAuthHeaders,
        verifyToken: () => verifyToken(token)
    }

    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    )
}
