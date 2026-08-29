import { Routes, Route, Navigate } from 'react-router'
import Login from './pages/Login'
import Chat from './pages/Chat'
import { getToken } from './lib/session'

function Guard({ children }: { children: React.ReactNode }) {
  return getToken() ? <>{children}</> : <Navigate to="/" replace />
}

export default function App() {
  return (
    <Routes>
      <Route path="/" element={getToken() ? <Navigate to="/vault" replace /> : <Login />} />
      <Route path="/vault" element={<Guard><Chat /></Guard>} />
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
