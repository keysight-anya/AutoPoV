import { Link, useLocation } from 'react-router-dom'
import { useEffect, useState } from 'react'
import { Shield, Clock, History, Settings, FileText, BarChart2 } from 'lucide-react'

function NavBar() {
  const location = useLocation()
  const [activeScanId, setActiveScanId] = useState(null)

  useEffect(() => {
    const raw = localStorage.getItem('autopov_active_scans')
    if (!raw) { setActiveScanId(null); return }
    try {
      const list = JSON.parse(raw)
      setActiveScanId(Array.isArray(list) && list.length > 0 ? list[list.length - 1] : null)
    } catch {
      setActiveScanId(null)
    }
  }, [location.pathname])

  const navLinks = [
    { to: '/', label: 'Scan', icon: Shield },
    { to: '/history', label: 'History', icon: History },
    { to: '/policy', label: 'Policy', icon: BarChart2 },
    { to: '/docs', label: 'Docs', icon: FileText },
    { to: '/settings', label: 'Settings', icon: Settings },
  ]

  return (
    <nav className="sticky top-0 z-50 bg-gray-950/90 backdrop-blur border-b border-gray-800/60">
      <div className="container mx-auto px-4">
        <div className="flex items-center justify-between h-14">
          <Link to="/" className="flex items-center gap-2 group">
            <div className="relative">
              <Shield className="w-7 h-7 text-primary-500 group-hover:text-primary-400 transition-colors" />
              <div className="absolute inset-0 bg-primary-500/20 rounded-full blur-md opacity-0 group-hover:opacity-100 transition-opacity" />
            </div>
            <span className="text-lg font-bold tracking-tight">
              Auto<span className="text-primary-400">PoV</span>
            </span>
          </Link>

          <div className="flex items-center gap-1">
            {navLinks.map(({ to, label, icon: Icon }) => {
              const isActive = location.pathname === to
              return (
                <Link
                  key={to}
                  to={to}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium transition-colors ${
                    isActive
                      ? 'bg-primary-500/10 text-primary-400'
                      : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/60'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  <span>{label}</span>
                </Link>
              )
            })}

            {activeScanId && (
              <Link
                to={`/scan/${activeScanId}`}
                className="flex items-center gap-1.5 ml-2 px-3 py-1.5 rounded-md text-sm font-medium bg-primary-500/15 text-primary-300 border border-primary-500/20 hover:bg-primary-500/25 transition-colors"
              >
                <Clock className="w-3.5 h-3.5 scan-pulse" />
                <span>Scanning…</span>
              </Link>
            )}
          </div>
        </div>
      </div>
    </nav>
  )
}

export default NavBar
