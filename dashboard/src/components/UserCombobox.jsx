"use client"

import {useEffect, useState} from 'react'
import {Check, ChevronsUpDown, User} from 'lucide-react'
import {useAuth} from '../contexts/AuthContext.jsx'
import {cn, ERR_SERVER_CONNECTION} from '@/lib/utils.js'
import {Button} from '@/components/ui/button.jsx'
import {Badge} from '@/components/ui/badge.jsx'
import {Popover, PopoverContent, PopoverTrigger,} from '@/components/ui/popover.jsx'
import {Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList,} from '@/components/ui/command.jsx'

const API_BASE_URL = 'http://localhost:8080/api/v1'

export default function UserCombobox({selectedUser, onUserSelect, placeholder = "Seleccionar usuario..."}) {
    const {getAuthHeaders} = useAuth()
    const [open, setOpen] = useState(false)
    const [users, setUsers] = useState([])
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState('')
    const [searchQuery, setSearchQuery] = useState('')

    useEffect(() => {
        if (open) {
            loadUsers()
        }
    }, [open])

    const loadUsers = async (query = '') => {
        try {
            setLoading(true)
            setError('')

            const headers = getAuthHeaders()
            const queryParam = query ? `?q=${encodeURIComponent(query)}` : ''

            const response = await fetch(`${API_BASE_URL}/users/search${queryParam}`, {
                headers
            })

            if (response.ok) {
                const data = await response.json()
                if (data.success) {
                    setUsers(data.users || [])
                } else {
                    setError(data.error || 'Error buscando usuarios')
                }
            } else {
                setError(ERR_SERVER_CONNECTION)
            }
        } catch (err) {
            console.error('Error searching users:', err)
            setError(ERR_SERVER_CONNECTION)
        } finally {
            setLoading(false)
        }
    }

    const handleSearch = (query) => {
        setSearchQuery(query)
        loadUsers(query)
    }

    const handleUserSelect = (user) => {
        onUserSelect(user)
        setOpen(false)
    }

    const displayValue = selectedUser
        ? `${selectedUser.fullName || `${selectedUser.firstName || ''} ${selectedUser.lastName || ''}`.trim()}`
        : placeholder

    return (
        <div className="space-y-2">
            <Popover open={open} onOpenChange={setOpen}>
                <PopoverTrigger asChild>
                    <Button
                        variant="outline"
                        role="combobox"
                        aria-expanded={open}
                        className="w-full justify-between"
                    >
                        <div className="flex items-center gap-2">
                            <User className="h-4 w-4 text-muted-foreground"/>
                            <span className={cn(
                                "truncate",
                                !selectedUser && "text-muted-foreground"
                            )}>
                {displayValue}
              </span>
                        </div>
                        <ChevronsUpDown className="ml-2 h-4 w-4 shrink-0 opacity-50"/>
                    </Button>
                </PopoverTrigger>
                <PopoverContent className="w-full p-0" align="start">
                    <Command>
                        <CommandInput
                            placeholder="Buscar usuarios..."
                            onValueChange={handleSearch}
                            value={searchQuery}
                        />
                        <CommandList>
                            {loading && (
                                <div className="flex items-center justify-center py-6">
                                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary"></div>
                                    <span className="ml-2 text-sm text-muted-foreground">Buscando...</span>
                                </div>
                            )}

                            {error && (
                                <div className="p-4 text-sm text-destructive">
                                    {error}
                                </div>
                            )}

                            {!loading && !error && users.length === 0 && (
                                <CommandEmpty>
                                    {searchQuery ? 'No se encontraron usuarios.' : 'Escribe para buscar usuarios.'}
                                </CommandEmpty>
                            )}

                            {!loading && !error && users.length > 0 && (
                                <CommandGroup>
                                    {users.map((user) => (
                                        <CommandItem
                                            key={user.id}
                                            value={user.id}
                                            onSelect={() => handleUserSelect(user)}
                                            className="flex items-center justify-between"
                                        >
                                            <div className="flex items-center gap-3">
                                                <div
                                                    className="flex h-8 w-8 items-center justify-center rounded-full bg-primary/10">
                                                    <User className="h-4 w-4 text-primary"/>
                                                </div>
                                                <div>
                                                    <div className="font-medium text-sm">
                                                        {user.fullName || `${user.firstName || ''} ${user.lastName || ''}`.trim()}
                                                    </div>
                                                    <div className="text-xs text-muted-foreground">{user.email}</div>
                                                    <div className="flex items-center gap-1 mt-1">
                                                        <Badge variant={user.role === 'ADMIN' ? 'default' : 'secondary'}
                                                               className="text-xs">
                                                            {user.role}
                                                        </Badge>
                                                        {user.emailVerified && (
                                                            <Badge variant="outline" className="text-xs">
                                                                <Check className="h-2 w-2 mr-1"/>
                                                                Verificado
                                                            </Badge>
                                                        )}
                                                    </div>
                                                </div>
                                            </div>
                                            <Check
                                                className={cn(
                                                    "ml-auto h-4 w-4",
                                                    selectedUser?.id === user.id ? "opacity-100" : "opacity-0"
                                                )}
                                            />
                                        </CommandItem>
                                    ))}
                                </CommandGroup>
                            )}
                        </CommandList>
                    </Command>
                </PopoverContent>
            </Popover>

            {selectedUser && (
                <div className="flex items-center gap-2">
                    <Badge variant="secondary" className="flex items-center gap-1">
                        <User className="h-3 w-3"/>
                        {selectedUser.fullName || `${selectedUser.firstName || ''} ${selectedUser.lastName || ''}`.trim()}
                    </Badge>
                    <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        onClick={() => onUserSelect(null)}
                        className="h-6 text-xs"
                    >
                        Limpiar
                    </Button>
                </div>
            )}
        </div>
    )
}
