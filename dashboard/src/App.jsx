import {BrowserRouter as Router, Route, Routes} from 'react-router-dom'
import {AuthProvider} from './contexts/AuthContext.jsx'
import LoginForm from './components/auth/LoginForm.jsx'
import CompleteRegistration from './components/auth/CompleteRegistration.jsx'
import InitialSetup from './components/setup/InitialSetup.jsx'
import SetupRedirect from './components/setup/SetupRedirect.jsx'
import ProtectedRoute from './components/auth/ProtectedRoute.jsx'
import AdminDashboard from './AdminDashboard.jsx'
import UserPanel from './UserPanel.jsx'
import './App.css'

function App() {
    return (
        <AuthProvider>
            <Router>
                <Routes>
                    <Route path="/login" element={<LoginForm/>}/>
                    <Route path="/complete-registration" element={<CompleteRegistration/>}/>
                    <Route path="/setup" element={<InitialSetup/>}/>

                    <Route path="/admin/*" element={
                        <ProtectedRoute requireAdmin={true}>
                            <AdminDashboard/>
                        </ProtectedRoute>
                    }/>

                    <Route path="/user" element={
                        <ProtectedRoute>
                            <UserPanel/>
                        </ProtectedRoute>
                    }/>

                    <Route path="/" element={<SetupRedirect/>}/>
                </Routes>
            </Router>
        </AuthProvider>
    )
}

export default App
