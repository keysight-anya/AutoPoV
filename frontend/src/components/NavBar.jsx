import { Link, useLocation } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { Shield, Home, History, Settings, FileText, BarChart } from 'lucide-react'

function NavBar() {
  const location = useLocation()
    const [activeScanId, setActiveScanId] = useState(null)

  useEffect(() => {
    const raw = localStorage.getItem('autopov_active_scans')
    if (!raw) {
      setActiveScanId(null)
      return
    }
    try {
      const list = JSON.parse(raw)
      if (Array.isArray(list) && list.length > 0) {
        setActiveScanId(list[list.length - 1])
      } else {
        setActiveScanId(null)
      }
    } catch {
      setActiveScanId(null)
    }
  }, [location.pathname])


  const isActive = (path) => {
    return location.pathname === path ? 'text-primary-500' : 'text-gray-400 hover:text-gray-200'
  }

  return (
    <nav className="bg-gray-900 border-b border-gray-800">
      <div className="container mx-auto px-4">
        <div className="flex items-center justify-between h-16">
          <Link to="/" className="flex items-center space-x-2">
            <Shield className="w-8 h-8 text-primary-500" />
            <span className="text-xl font-bold">AutoPoV</span>
          </Link>
          
          <div className="flex items-center space-x-6">
            <Link to="/" className={`flex items-center space-x-1 ${isActive('/')}`}>
              <Home className="w-4 h-4" />
              <span>Scan</span>
            </Link>
            
            <Link to="/history" className={`flex items-center space-x-1 ${isActive('/history')}`}>
              <History className="w-4 h-4" />
              <span>History</span>
            </Link>
            
            <Link to="/settings" className={`flex items-center space-x-1 ${isActive('/settings')}`}>
              <Settings className="w-4 h-4" />
              <span>Settings</span>
            </Link>
            

            <Link to="/policy" className={`flex items-center space-x-1 ${isActive('/policy')}`}>
              <BarChart className="w-4 h-4" />
              <span>Policy</span>
            </Link>
            <Link to="/docs" className={`flex items-center space-x-1 ${isActive('/docs')}`}>
              <FileText className="w-4 h-4" />
              <span>Docs</span>
            </Link>
          </div>
        </div>
      </div>
    </nav>
  )
}

export default NavBar
