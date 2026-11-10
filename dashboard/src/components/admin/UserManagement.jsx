import {useEffect, useState} from 'react'
import {Mail, Plus, RotateCcw, Shield, Trash2, User} from 'lucide-react'
import {useAuth} from '../../contexts/AuthContext.jsx'
import {Button} from '@/components/ui/button.jsx'
import {Card, CardContent, CardDescription, CardHeader, CardTitle} from '@/components/ui/card.jsx'
import {Badge} from '@/components/ui/badge.jsx'
import {Table, TableBody, TableCell, TableHead, TableHeader, TableRow} from '@/components/ui/table.jsx'
import {
    Dialog,
    DialogContent,
    DialogDescription,
    DialogHeader,
    DialogTitle,
    DialogTrigger
} from '@/components/ui/dialog.jsx'
import {Input} from '@/components/ui/input.jsx'
import {Label} from '@/components/ui/label.jsx'
import {Select, SelectContent, SelectItem, SelectTrigger, SelectValue} from '@/components/ui/select.jsx'
import {Alert, AlertDescription} from '@/components/ui/alert.jsx'
import {ERR_SERVER_CONNECTION} from '@/lib/utils.js'
import {API_BASE_URL} from '@/lib/config.js'

export default function UserManagement() {
    const {getAuthHeaders} = useAuth()
    const [users, setUsers] = useState([])
    const [loading, setLoading] = useState(true)
    const [error, setError] = useState('')
    const [success, setSuccess] = useState('')
    const [showCreateDialog, setShowCreateDialog] = useState(false)
    const [searchTerm, setSearchTerm] = useState('')

    const [newUser, setNewUser] = useState({
        email: '',
        role: 'USER'
    })

    useEffect(() => {
        loadUsers()
    }, [])

    const loadUsers = async () => {
        try {
            setLoading(true)
            const response = await fetch(`${API_BASE_URL}/users`, {
                headers: getAuthHeaders()
            })

            if (response.ok) {
                const data = await response.json()
                if (data.success) {
                    setUsers(data.users || [])
                } else {
                    setError(data.error || 'Error loading users')
                }
            } else {
                setError(ERR_SERVER_CONNECTION)
            }
        } catch (err) {
            console.error('Error loading users:', err)
            setError(ERR_SERVER_CONNECTION)
        } finally {
            setLoading(false)
        }
    }

    const createUser = async () => {
        try {
            if (!newUser.email) {
                setError('Email is required')
                return
            }

            const response = await fetch(`${API_BASE_URL}/users`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    ...getAuthHeaders()
                },
                body: JSON.stringify(newUser)
            })

            const data = await response.json()

            if (data.success) {
                setSuccess(data.message || 'User created successfully')
                setShowCreateDialog(false)
                setNewUser({email: '', role: 'USER'})
                loadUsers()
            } else {
                setError(data.error || 'Error creating user')
            }
        } catch (err) {
            console.error('Error creating user:', err)
            setError(ERR_SERVER_CONNECTION)
        }
    }

    const deleteUser = async (userId, userEmail) => {
        if (!confirm(`Are you sure you want to delete user ${userEmail}?`)) {
            return
        }

        try {
            const response = await fetch(`${API_BASE_URL}/users/${userId}`, {
                method: 'DELETE',
                headers: getAuthHeaders()
            })

            const data = await response.json()

            if (data.success) {
                setSuccess('User deleted successfully')
                loadUsers()
            } else {
                setError(data.error || 'Error deleting user')
            }
        } catch (err) {
            console.error('Error deleting user:', err)
            setError(ERR_SERVER_CONNECTION)
        }
    }

    const resendInvitation = async (userId, userEmail) => {
        try {
            const response = await fetch(`${API_BASE_URL}/users/${userId}/resend-invitation`, {
                method: 'POST',
                headers: getAuthHeaders()
            })

            const data = await response.json()

            if (data.success) {
                setSuccess(`Invitation resent to ${userEmail}`)
            } else {
                setError(data.error || 'Error resending invitation')
            }
        } catch (err) {
            console.error('Error resending invitation:', err)
            setError(ERR_SERVER_CONNECTION)
        }
    }

    const filteredUsers = users.filter(user =>
        user.email?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        user.firstName?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        user.lastName?.toLowerCase().includes(searchTerm.toLowerCase())
    )

    const formatDate = (dateString) => {
        if (!dateString) return 'N/A'
        return new Date(dateString).toLocaleDateString('es-ES', {
            year: 'numeric',
            month: 'short',
            day: 'numeric'
        })
    }

    const getRoleColor = (role) => {
        switch (role) {
            case 'ADMIN':
                return 'destructive'
            case 'USER':
                return 'default'
            default:
                return 'secondary'
        }
    }

    const getStatusColor = (user) => {
        if (!user.active) return 'secondary'
        if (!user.emailVerified) return 'warning'
        return 'success'
    }

    const getStatusText = (user) => {
        if (!user.active) return 'Inactive'
        if (!user.emailVerified) return 'Pending'
        return 'Active'
    }

    if (loading) {
        return (
            <Card>
                <CardContent className="flex items-center justify-center h-64">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
                </CardContent>
            </Card>
        )
    }

    return (
        <div className="space-y-6">
            <div className="flex items-center justify-between">
                <div>
                    <h2 className="text-3xl font-bold tracking-tight">User Management</h2>
                    <p className="text-muted-foreground">
                        Manage system users
                    </p>
                </div>
                <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
                    <DialogTrigger asChild>
                        <Button>
                            <Plus className="mr-2 h-4 w-4"/>
                            Create User
                        </Button>
                    </DialogTrigger>
                    <DialogContent>
                        <DialogHeader>
                            <DialogTitle>Create New User</DialogTitle>
                            <DialogDescription>
                                The user will receive an email to complete their registration
                            </DialogDescription>
                        </DialogHeader>
                        <div className="space-y-4">
                            <div>
                                <Label htmlFor="email">Email</Label>
                                <Input
                                    id="email"
                                    type="email"
                                    placeholder="user@example.com"
                                    value={newUser.email}
                                    onChange={(e) => setNewUser(prev => ({...prev, email: e.target.value}))}
                                />
                            </div>
                            <div>
                                <Label htmlFor="role">Role</Label>
                                <Select
                                    value={newUser.role}
                                    onValueChange={(value) => setNewUser(prev => ({...prev, role: value}))}
                                >
                                    <SelectTrigger>
                                        <SelectValue/>
                                    </SelectTrigger>
                                    <SelectContent>
                                        <SelectItem value="USER">User</SelectItem>
                                        <SelectItem value="ADMIN">Administrator</SelectItem>
                                    </SelectContent>
                                </Select>
                            </div>
                            <div className="flex justify-end space-x-2">
                                <Button variant="outline" onClick={() => setShowCreateDialog(false)}>
                                    Cancel
                                </Button>
                                <Button onClick={createUser}>
                                    Create User
                                </Button>
                            </div>
                        </div>
                    </DialogContent>
                </Dialog>
            </div>

            {error && (
                <Alert variant="destructive">
                    <AlertDescription>{error}</AlertDescription>
                </Alert>
            )}

            {success && (
                <Alert>
                    <AlertDescription>{success}</AlertDescription>
                </Alert>
            )}

            <div className="flex items-center space-x-2">
                <Input
                    placeholder="Search users..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="max-w-sm"
                />
            </div>

            <Card>
                <CardHeader>
                    <CardTitle>Users ({filteredUsers.length})</CardTitle>
                    <CardDescription>
                        All users in the system
                    </CardDescription>
                </CardHeader>
                <CardContent>
                    {filteredUsers.length > 0 ? (
                        <Table>
                            <TableHeader>
                                <TableRow>
                                    <TableHead>User</TableHead>
                                    <TableHead>Email</TableHead>
                                    <TableHead>Role</TableHead>
                                    <TableHead>Status</TableHead>
                                    <TableHead>Created</TableHead>
                                    <TableHead>Last Login</TableHead>
                                    <TableHead>Actions</TableHead>
                                </TableRow>
                            </TableHeader>
                            <TableBody>
                                {filteredUsers.map((user) => (
                                    <TableRow key={user.id}>
                                        <TableCell>
                                            <div className="flex items-center space-x-2">
                                                <User className="h-4 w-4 text-muted-foreground"/>
                                                <div>
                                                    <div className="font-medium">
                                                        {user.fullName || 'No name'}
                                                    </div>
                                                    {user.username && (
                                                        <div className="text-sm text-muted-foreground">
                                                            @{user.username}
                                                        </div>
                                                    )}
                                                </div>
                                            </div>
                                        </TableCell>

                                        <TableCell>
                                            <div className="flex items-center space-x-2">
                                                <Mail className="h-4 w-4 text-muted-foreground"/>
                                                <span>{user.email}</span>
                                            </div>
                                        </TableCell>

                                        <TableCell>
                                            <Badge variant={getRoleColor(user.role)}>
                                                {user.role === 'ADMIN' && <Shield className="w-3 h-3 mr-1"/>}
                                                {user.role}
                                            </Badge>
                                        </TableCell>

                                        <TableCell>
                                            <Badge variant={getStatusColor(user)}>
                                                {getStatusText(user)}
                                            </Badge>
                                        </TableCell>

                                        <TableCell>{formatDate(user.createdAt)}</TableCell>

                                        <TableCell>{formatDate(user.lastLoginAt)}</TableCell>

                                        <TableCell>
                                            <div className="flex items-center space-x-2">
                                                {!user.emailVerified && (
                                                    <Button
                                                        variant="ghost"
                                                        size="sm"
                                                        onClick={() => resendInvitation(user.id, user.email)}
                                                        title="Resend invitation"
                                                    >
                                                        <RotateCcw className="h-4 w-4"/>
                                                    </Button>
                                                )}

                                                <Button
                                                    variant="ghost"
                                                    size="sm"
                                                    onClick={() => deleteUser(user.id, user.email)}
                                                    title="Delete user"
                                                >
                                                    <Trash2 className="h-4 w-4"/>
                                                </Button>
                                            </div>
                                        </TableCell>
                                    </TableRow>
                                ))}
                            </TableBody>
                        </Table>
                    ) : (
                        <div className="text-center py-8">
                            <User className="h-12 w-12 text-muted-foreground mx-auto mb-4"/>
                            <h3 className="text-lg font-medium mb-2">No users</h3>
                            <p className="text-muted-foreground">
                                {searchTerm ? 'No users match your search.' : 'No users in the system yet.'}
                            </p>
                        </div>
                    )}
                </CardContent>
            </Card>
        </div>
    )
}
