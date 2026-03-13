// frontend/src/components/AppShell.jsx
import { useEffect, useRef, useState } from 'react'
import { Link, Outlet, useLocation } from 'react-router-dom'

// ── SVG Icons ────────────────────────────────────────
function ScanIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  )
}

function HistoryIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <polyline points="12 6 12 12 16 14"/>
    </svg>
  )
}

function PolicyIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 12l2 2 4-4"/>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  )
}

function CogIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.325.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 0 1 1.37.49l1.296 2.247a1.125 1.125 0 0 1-.26 1.431l-1.003.827c-.293.241-.438.613-.43.992a7.723 7.723 0 0 1 0 .255c-.008.378.137.75.43.991l1.004.827c.424.35.534.955.26 1.43l-1.298 2.247a1.125 1.125 0 0 1-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.47 6.47 0 0 1-.22.128c-.331.183-.581.495-.644.869l-.213 1.281c-.09.543-.56.94-1.11.94h-2.594c-.55 0-1.019-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 0 1-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 0 1-1.369-.49l-1.297-2.247a1.125 1.125 0 0 1 .26-1.431l1.004-.827c.292-.24.437-.613.43-.991a6.932 6.932 0 0 1 0-.255c.007-.38-.138-.751-.43-.992l-1.004-.827a1.125 1.125 0 0 1-.26-1.43l1.297-2.247a1.125 1.125 0 0 1 1.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.086.22-.128.332-.183.582-.495.644-.869l.214-1.28Z"/>
      <path d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z"/>
    </svg>
  )
}

function CopyIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 13 13" fill="none" stroke="currentColor" strokeWidth="1.3" strokeLinecap="round" strokeLinejoin="round">
      <rect x="4.5" y="4.5" width="7.5" height="7.5" rx="1"/>
      <path d="M2.5 8.5H1.5a1 1 0 01-1-1V1.5a1 1 0 011-1h6a1 1 0 011 1v1"/>
    </svg>
  )
}

function CheckIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 13 13" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="2 7 5 10 11 3"/>
    </svg>
  )
}

// ── Nav config ────────────────────────────────────────
const NAV_ITEMS = [
  { path: '/',        label: 'SCAN',    Icon: ScanIcon    },
  { path: '/history', label: 'HISTORY', Icon: HistoryIcon },
  { path: '/policy',  label: 'POLICY',  Icon: PolicyIcon  },
]

// ── AppShell ──────────────────────────────────────────
export default function AppShell() {
  const location = useLocation()
  const [apiKey, setApiKey]         = useState('')
  const [copied, setCopied]         = useState(false)
  const [agentsOnline, setAgentsOnline] = useState(6)
  const [metrics, setMetrics]       = useState({ total: 0, confirmed: 0, povs: 0, model: 'claude-3-5-sonnet' })

  // Corner bracket refs — updated imperatively (no re-renders)
  const tlRef = useRef(null)
  const trRef = useRef(null)
  const blRef = useRef(null)
  const brRef = useRef(null)

  // Parallax loop — updates corner elements directly via refs
  useEffect(() => {
    let nx = 0, ny = 0, tx = 0, ty = 0, raf

    const onMouse = (e) => {
      tx = e.clientX / window.innerWidth  - 0.5
      ty = e.clientY / window.innerHeight - 0.5
    }

    const tick = () => {
      nx += (tx - nx) * 0.05
      ny += (ty - ny) * 0.05
      const cx = (-nx * 7).toFixed(2)
      const cy = (-ny * 5).toFixed(2)
      const t  = `translate(${cx}px,${cy}px)`
      if (tlRef.current) tlRef.current.style.transform = t
      if (trRef.current) trRef.current.style.transform = t
      if (blRef.current) blRef.current.style.transform = t
      if (brRef.current) brRef.current.style.transform = t
      raf = requestAnimationFrame(tick)
    }

    window.addEventListener('mousemove', onMouse)
    raf = requestAnimationFrame(tick)
    return () => { window.removeEventListener('mousemove', onMouse); cancelAnimationFrame(raf) }
  }, [])

  // Re-read API key from localStorage on every navigation
  useEffect(() => {
    setApiKey(localStorage.getItem('autopov_api_key') || '')
  }, [location.pathname])

  // Poll health + metrics every 30s
  useEffect(() => {
    const key = localStorage.getItem('autopov_api_key') || ''
    const poll = async () => {
      try {
        const hRes = await fetch('/api/health')
        if (hRes.ok) {
          const h = await hRes.json()
          setAgentsOnline(h.agents_online ?? 6)
        }
      } catch {}
      try {
        const mRes = await fetch('/api/metrics', {
          headers: key ? { Authorization: `Bearer ${key}` } : {}
        })
        if (mRes.ok) {
          const m = await mRes.json()
          setMetrics({
            total:     m.total_scans     ?? 0,
            confirmed: m.confirmed       ?? 0,
            povs:      m.pov_generated   ?? 0,
            model:     m.default_model   ?? 'claude-3-5-sonnet',
          })
        }
      } catch {}
    }
    poll()
    const id = setInterval(poll, 30_000)
    return () => clearInterval(id)
  }, [])

  const maskedKey = apiKey
    ? `sk-ant-•••• ${apiKey.slice(-4)}`
    : '— no key set —'

  const handleCopy = () => {
    navigator.clipboard.writeText(apiKey).catch(() => {})
    setCopied(true)
    setTimeout(() => setCopied(false), 1400)
  }

  const isActive = (path) =>
    path === '/'
      ? location.pathname === '/'
      : location.pathname.startsWith(path)

  // ── Styles (inline, tied to CSS vars) ───────────────
  const topbarStyle = {
    position: 'fixed', top: 0, left: 0, right: 0,
    height: 'var(--topbar-h)',
    background: 'var(--surface1)',
    borderBottom: '1px solid var(--border1)',
    display: 'flex', alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0 16px 0 0',
    zIndex: 40,
  }

  const logoAreaStyle = {
    display: 'flex', alignItems: 'center',
    width: 'var(--sidebar-w)',
    justifyContent: 'center',
    borderRight: '1px solid var(--border1)',
    height: '100%',
  }

  const sidebarStyle = {
    position: 'fixed',
    top: 'var(--topbar-h)',
    left: 0,
    bottom: 'var(--statusbar-h)',
    width: 'var(--sidebar-w)',
    background: 'var(--surface1)',
    borderRight: '1px solid var(--border1)',
    display: 'flex', flexDirection: 'column',
    alignItems: 'center',
    paddingTop: 8, paddingBottom: 8,
    zIndex: 40,
  }

  const mainStyle = {
    position: 'fixed',
    top: 'var(--topbar-h)',
    left: 'var(--sidebar-w)',
    right: 0,
    bottom: 'var(--statusbar-h)',
    overflowY: 'auto',
  }

  const statusbarStyle = {
    position: 'fixed', bottom: 0, left: 0, right: 0,
    height: 'var(--statusbar-h)',
    background: 'var(--surface1)',
    borderTop: '1px solid var(--border1)',
    display: 'flex', alignItems: 'center',
    padding: '0 16px',
    gap: 20,
    zIndex: 40,
    fontFamily: '"JetBrains Mono", monospace',
    fontSize: 10,
    letterSpacing: '.08em',
  }

  const navItemStyle = (active) => ({
    display: 'flex', flexDirection: 'column', alignItems: 'center',
    justifyContent: 'center', gap: 4,
    width: 44, height: 44,
    cursor: 'pointer', textDecoration: 'none',
    color: active ? 'var(--accent)' : 'var(--text3)',
    borderLeft: active ? '2px solid var(--accent)' : '2px solid transparent',
    transition: 'color .15s, border-color .15s',
    fontFamily: '"JetBrains Mono", monospace',
    fontSize: 8, letterSpacing: '.1em',
    userSelect: 'none',
  })

  const dividerStyle = {
    width: 24, height: 1,
    background: 'var(--border1)',
    margin: '6px 0',
  }

  const statItemStyle = { color: 'var(--text3)' }
  const statValueStyle = { color: 'var(--text2)', marginLeft: 6 }
  const statAccentStyle = { color: 'var(--accent)', marginLeft: 6 }

  return (
    <div style={{ background: 'var(--bg)', height: '100vh', overflow: 'hidden' }}>

      {/* ── Topbar ── */}
      <header style={topbarStyle}>
        {/* Logo */}
        <div style={logoAreaStyle}>
          <div style={{
            width: 20, height: 20,
            border: '1.5px solid var(--accent)',
            borderRadius: 3,
            background: 'rgba(254,127,45,0.1)',
          }} />
        </div>

        {/* Brand name */}
        <span style={{
          fontFamily: '"JetBrains Mono", monospace',
          fontSize: 13, letterSpacing: '.18em',
          color: 'var(--text1)', marginLeft: 12, marginRight: 'auto',
        }}>
          AUTO<span style={{ color: 'var(--accent)', fontWeight: 600 }}>POV</span>
        </span>

        {/* Connected indicator */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 6,
          fontFamily: '"JetBrains Mono", monospace',
          fontSize: 10, letterSpacing: '.1em',
          color: 'var(--text3)', marginRight: 16,
        }}>
          <span style={{ color: '#22c55e', fontSize: 8 }}>●</span>
          CONNECTED
        </div>

        {/* API key pill + copy */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 0 }}>
          <div style={{
            padding: '5px 12px',
            background: 'var(--surface2)',
            border: '1px solid var(--border2)',
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: 11, letterSpacing: '.06em',
            color: 'var(--text2)',
            cursor: 'default',
          }}>
            {maskedKey}
          </div>
          <button
            onClick={handleCopy}
            title="Copy API key"
            style={{
              background: 'none', border: 'none',
              color: copied ? 'var(--accent)' : 'var(--text3)',
              cursor: 'pointer', padding: '6px 8px',
              display: 'flex', alignItems: 'center',
              transition: 'color .15s',
            }}
          >
            {copied ? <CheckIcon /> : <CopyIcon />}
          </button>
        </div>
      </header>

      {/* ── Sidebar ── */}
      <nav style={sidebarStyle}>
        {NAV_ITEMS.map(({ path, label, Icon }) => (
          <Link key={path} to={path} style={navItemStyle(isActive(path))}>
            <Icon />
            <span>{label}</span>
          </Link>
        ))}

        <div style={{ flex: 1 }} />
        <div style={dividerStyle} />

        <Link to="/settings" style={navItemStyle(isActive('/settings'))}>
          <CogIcon />
          <span>SETTINGS</span>
        </Link>
      </nav>

      {/* ── Corner brackets ── */}
      <div ref={tlRef} className="corner tl" />
      <div ref={trRef} className="corner tr" />
      <div ref={blRef} className="corner bl" />
      <div ref={brRef} className="corner br" />

      {/* ── Main content area ── */}
      <main style={mainStyle}>
        <Outlet />
      </main>

      {/* ── Status bar ── */}
      <footer style={statusbarStyle}>
        <span style={statItemStyle}>
          ● AGENTS ONLINE
          <span style={statAccentStyle}>({agentsOnline})</span>
        </span>
        <span style={statItemStyle}>
          TOTAL SCANS
          <span style={statValueStyle}>{metrics.total}</span>
        </span>
        <span style={statItemStyle}>
          CONFIRMED
          <span style={statValueStyle}>{metrics.confirmed}</span>
        </span>
        <span style={statItemStyle}>
          PoVs
          <span style={statValueStyle}>{metrics.povs}</span>
        </span>
        <span style={statItemStyle}>
          MODEL
          <span style={{ color: 'var(--accent)', marginLeft: 6, fontWeight: 500 }}>
            {metrics.model}
          </span>
        </span>
        <span style={{ marginLeft: 'auto', color: 'var(--text3)' }}>AutoPoV v0.3.0</span>
      </footer>
    </div>
  )
}
