import { Link, useLocation } from 'react-router-dom'
import { useEffect, useState } from 'react'

// Nav items — all uppercase monospace labels
const NAV_LINKS = [
  { to: '/',        label: 'SCAN' },
  { to: '/history', label: 'HISTORY' },
  { to: '/metrics', label: 'METRICS' },
  { to: '/policy',  label: 'POLICY' },
  { to: '/docs',    label: 'DOCS' },
  { to: '/settings',label: 'SETTINGS' },
]

function NavBar() {
  const location  = useLocation()
  const [activeScanId, setActiveScanId] = useState(null)
  const [apiKey, setApiKey] = useState(null)
  const [copied, setCopied] = useState(false)

  // Sync active scan and API key from localStorage on route change
  useEffect(() => {
    // Active scan
    try {
      const raw  = localStorage.getItem("autopov_active_scans")
      const list = raw ? JSON.parse(raw) : []
      setActiveScanId(Array.isArray(list) && list.length > 0 ? list[list.length - 1] : null)
    } catch { setActiveScanId(null) }

    // API key preview
    const stored = localStorage.getItem("autopov_api_key")
    setApiKey(stored || null)
  }, [location.pathname])

  const handleCopy = () => {
    if (!apiKey) return
    navigator.clipboard.writeText(apiKey).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    })
  }

  const keyPreview = apiKey
    ? apiKey.substring(0, 8) + '•••••••••'
    : null

  return (
    <nav className="sticky top-0 z-50 border-b-2 border-primary-600" style={{ background: "#07090f" }}>
      <div className="flex items-center h-12 px-6 gap-6">

        {/* Logo */}
        <Link
          to="/"
          className="flex items-center gap-0 group shrink-0"
          aria-label="AutoPoV home"
        >
          {/* Diamond icon */}
          <svg
            viewBox="0 0 24 24"
            className="w-5 h-5 mr-2.5 text-primary-600 group-hover:text-primary-400 transition-colors"
            fill="none"
          >
            <polygon
              points="12,2 22,12 12,22 2,12"
              stroke="currentColor"
              strokeWidth="1.8"
            />
            <polygon
              points="12,7 17,12 12,17 7,12"
              stroke="currentColor"
              strokeWidth="1"
              opacity=".6"
            />
            <circle cx="12" cy="12" r="2" fill="currentColor" />
          </svg>
          <span
            className="text-base font-bold tracking-tight text-gray-100 group-hover:text-white transition-colors"
            style={{ fontFamily: '"Barlow Condensed", system-ui, sans-serif', letterSpacing: '.06em', fontSize: '17px' }}
          >
            AUTO<span className="text-primary-400">POV</span>
          </span>
        </Link>

        {/* Separator */}
        <div className="w-px h-5 bg-gray-850 shrink-0" />

        {/* Nav links */}
        <div className="flex items-center gap-0">
          {NAV_LINKS.map(({ to, label }) => {
            const isActive =
              to === "/"
                ? location.pathname === "/"
                : location.pathname.startsWith(to)
            return (
              <Link
                key={to}
                to={to}
                className={[
                  "px-3 py-3 text-xs font-semibold tracking-widest transition-colors relative",
                  isActive
                    ? "text-primary-400 after:absolute after:bottom-0 after:left-0 after:right-0 after:h-0.5 after:bg-primary-600"
                    : "text-gray-600 hover:text-gray-300",
                ].join(" ")}
              >
                {label}
              </Link>
            )
          })}
        </div>

        {/* Right side */}
        <div className="ml-auto flex items-center gap-3">

          {/* Active scan indicator */}
          {activeScanId && (
            <Link
              to={`/scan/${activeScanId}`}
              className="flex items-center gap-2 px-3 py-1 border border-primary-600/30 bg-primary-600/8 text-primary-400 text-xs font-semibold tracking-widest hover:border-primary-500/50 transition-colors"
            >
              <span className="w-1.5 h-1.5 bg-primary-400 rounded-full scan-pulse" />
              SCANNING
            </Link>
          )}

          {/* API key pill */}
          {keyPreview ? (
            <button
              onClick={handleCopy}
              title={copied ? "Copied!" : "Click to copy API key"}
              className="flex items-center gap-2 px-3 py-1 border border-gray-850 hover:border-primary-600/40 bg-gray-900 text-xs transition-colors group"
            >
              <span className="text-gray-600 tracking-widest">KEY</span>
              <code className="text-primary-400 font-mono">{keyPreview}</code>
              <span className={[
                "border-l border-gray-850 pl-2 tracking-widest transition-colors",
                copied ? "text-safe-400" : "text-gray-600 group-hover:text-primary-400"
              ].join(" ")}>
                {copied ? "COPIED" : "COPY"}
              </span>
            </button>
          ) : (
            <Link
              to="/settings"
              className="flex items-center gap-1.5 px-3 py-1 border border-warn-500/30 bg-warn-900/30 text-warn-400 text-xs font-semibold tracking-widest hover:border-warn-500/50 transition-colors"
            >
              <span className="w-1.5 h-1.5 border border-warn-400 rounded-sm" />
              SET API KEY
            </Link>
          )}
        </div>
      </div>
    </nav>
  )
}

export default NavBar
