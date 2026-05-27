import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, Outlet, useLocation } from 'react-router-dom'
import apiClient from '../api/client'

function ScanIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  )
}

function HistoryIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <polyline points="12 6 12 12 16 14" />
    </svg>
  )
}

function PolicyIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 12l2 2 4-4" />
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  )
}

function CogIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.325.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 0 1 1.37.49l1.296 2.247a1.125 1.125 0 0 1-.26 1.431l-1.003.827c-.293.241-.438.613-.43.992a7.723 7.723 0 0 1 0 .255c-.008.378.137.75.43.991l1.004.827c.424.35.534.955.26 1.43l-1.298 2.247a1.125 1.125 0 0 1-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.47 6.47 0 0 1-.22.128c-.331.183-.581.495-.644.869l-.213 1.281c-.09.543-.56.94-1.11.94h-2.594c-.55 0-1.019-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 0 1-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 0 1-1.369-.49l-1.297-2.247a1.125 1.125 0 0 1 .26-1.431l1.004-.827c.292-.24.437-.613.43-.991a6.932 6.932 0 0 1 0-.255c.007-.38-.138-.751-.43-.992l-1.004-.827a1.125 1.125 0 0 1-.26-1.43l1.297-2.247a1.125 1.125 0 0 1 1.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.086.22-.128.332-.183.582-.495.644-.869l.214-1.28Z" />
      <path d="M15 12a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z" />
    </svg>
  )
}

function ScanManagerIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M4 6h16M4 10h16M4 14h16M4 18h16" />
    </svg>
  )
}

const NAV_ITEMS = [
  { path: '/', label: 'SCAN', Icon: ScanIcon },
  { path: '/scan-manager', label: 'MANAGER', Icon: ScanManagerIcon },
  { path: '/history', label: 'HISTORY', Icon: HistoryIcon },
  { path: '/policy', label: 'POLICY', Icon: PolicyIcon },
]

function OverlayPanel({ title, onClose, children }) {
  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(5, 10, 16, 0.72)',
        backdropFilter: 'blur(4px)',
        zIndex: 80,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        padding: 24,
      }}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          width: 'min(520px, 100%)',
          background: 'rgba(18, 28, 40, 0.96)',
          border: '1px solid var(--border2)',
          boxShadow: '0 24px 80px rgba(0,0,0,0.45)',
          padding: 20,
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
          <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 12, letterSpacing: '.14em', color: 'var(--text2)' }}>{title}</div>
          <button
            type="button"
            onClick={onClose}
            style={{ background: 'none', border: '1px solid var(--border2)', color: 'var(--text3)', padding: '4px 10px', cursor: 'pointer' }}
          >
            CLOSE
          </button>
        </div>
        {children}
      </div>
    </div>
  )
}

export default function AppShell() {
  const location = useLocation()
  const [agentsOnline, setAgentsOnline] = useState(7)
  const [metrics, setMetrics] = useState({ total: 0, confirmed: 0, povs: 0 })
  const [runtime, setRuntime] = useState({
    modelMode: 'online',
    selectedModel: '',
    onlineModels: [],
    offlineModels: [],
  })
  const [openPanel, setOpenPanel] = useState(null)

  const tlRef = useRef(null)
  const trRef = useRef(null)
  const blRef = useRef(null)
  const brRef = useRef(null)

  useEffect(() => {
    let nx = 0
    let ny = 0
    let tx = 0
    let ty = 0
    let raf

    const onMouse = (e) => {
      tx = e.clientX / window.innerWidth - 0.5
      ty = e.clientY / window.innerHeight - 0.5
    }

    const tick = () => {
      nx += (tx - nx) * 0.05
      ny += (ty - ny) * 0.05
      const cx = (-nx * 7).toFixed(2)
      const cy = (-ny * 5).toFixed(2)
      const t = `translate(${cx}px,${cy}px)`
      if (tlRef.current) tlRef.current.style.transform = t
      if (trRef.current) trRef.current.style.transform = t
      if (blRef.current) blRef.current.style.transform = t
      if (brRef.current) brRef.current.style.transform = t
      raf = requestAnimationFrame(tick)
    }

    window.addEventListener('mousemove', onMouse)
    raf = requestAnimationFrame(tick)
    return () => {
      window.removeEventListener('mousemove', onMouse)
      cancelAnimationFrame(raf)
    }
  }, [])

  useEffect(() => {
    const poll = async () => {
      try {
        const [healthRes, metricsRes, settingsRes] = await Promise.all([
          apiClient.get('/health'),
          apiClient.get('/metrics'),
          apiClient.get('/settings'),
        ])

        const h = healthRes.data || {}
        const m = metricsRes.data || {}
        const s = settingsRes.data || {}

        setAgentsOnline(h.agents_online ?? 7)
        setMetrics({
          total: m.total_scans ?? 0,
          confirmed: m.confirmed ?? 0,
          povs: m.pov_generated ?? 0,
        })
        setRuntime({
          modelMode: s.model_mode || 'online',
          selectedModel: s.selected_model || '',
          onlineModels: s.available_online_models || [],
          offlineModels: s.available_offline_models || [],
        })
      } catch {}
    }

    poll()
    const id = setInterval(poll, 30000)
    return () => clearInterval(id)
  }, [location.pathname])

  const isActive = (path) => (path === '/' ? location.pathname === '/' : location.pathname.startsWith(path))
  const agentNames = useMemo(
    () => ['investigator', 'pov_generator', 'verifier', 'refiner', 'llm_scout', 'codeql_bridge', 'semgrep_bridge'],
    []
  )
  const modelGroups = useMemo(
    () => [
      { key: 'online', title: 'ONLINE', models: runtime.onlineModels },
      { key: 'offline', title: 'OFFLINE', models: runtime.offlineModels },
    ],
    [runtime.onlineModels, runtime.offlineModels]
  )
  const activeModelLabel = runtime.selectedModel || 'UNSET'

  const topbarStyle = {
    position: 'fixed',
    top: 0,
    left: 0,
    right: 0,
    height: 'var(--topbar-h)',
    background: 'transparent',
    borderBottom: '1px solid var(--border1)',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: '0 16px 0 0',
    zIndex: 40,
  }
  const logoAreaStyle = {
    display: 'flex',
    alignItems: 'center',
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
    background: 'transparent',
    borderRight: '1px solid var(--border1)',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    paddingTop: 8,
    paddingBottom: 8,
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
    position: 'fixed',
    bottom: 0,
    left: 0,
    right: 0,
    height: 'var(--statusbar-h)',
    background: 'transparent',
    borderTop: '1px solid var(--border1)',
    display: 'flex',
    alignItems: 'center',
    padding: '0 16px',
    gap: 20,
    zIndex: 40,
    fontFamily: '"JetBrains Mono", monospace',
    fontSize: 10,
    letterSpacing: '.08em',
  }
  const navItemStyle = (active) => ({
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 4,
    width: 44,
    height: 44,
    cursor: 'pointer',
    textDecoration: 'none',
    color: active ? 'var(--accent)' : 'var(--text3)',
    borderLeft: active ? '2px solid var(--accent)' : '2px solid transparent',
    transition: 'color .15s, border-color .15s',
    fontFamily: '"JetBrains Mono", monospace',
    fontSize: 8,
    letterSpacing: '.1em',
    userSelect: 'none',
  })
  const dividerStyle = { width: 24, height: 1, background: 'var(--border1)', margin: '6px 0' }
  const statItemStyle = { color: 'var(--text3)' }
  const statValueStyle = { color: 'var(--text2)', marginLeft: 6 }
  const statAccentStyle = { color: 'var(--accent)', marginLeft: 6 }
  const pillButtonStyle = {
    background: 'var(--surface2)',
    border: '1px solid var(--border2)',
    color: 'var(--text2)',
    fontFamily: '"JetBrains Mono", monospace',
    fontSize: 11,
    letterSpacing: '.08em',
    padding: '5px 12px',
    cursor: 'pointer',
    transition: 'border-color .15s, color .15s, background .15s',
  }

  return (
    <div style={{ background: 'var(--bg)', height: '100vh', overflow: 'hidden' }}>
      <header style={topbarStyle}>
        <Link to="/" style={{ display: 'flex', alignItems: 'center', textDecoration: 'none', marginRight: 'auto' }}>
          <div style={logoAreaStyle}>
            <svg width="22" height="22" viewBox="0 0 22 22" fill="none">
              <rect x="1.5" y="1.5" width="19" height="19" stroke="#fe7f2d" strokeWidth="1.5" />
              <circle cx="11" cy="11" r="3.5" fill="#fe7f2d" />
              <line x1="11" y1="1.5" x2="11" y2="7" stroke="#fe7f2d" strokeWidth="1" />
              <line x1="11" y1="15" x2="11" y2="20.5" stroke="#fe7f2d" strokeWidth="1" />
              <line x1="1.5" y1="11" x2="7" y2="11" stroke="#fe7f2d" strokeWidth="1" />
              <line x1="15" y1="11" x2="20.5" y2="11" stroke="#fe7f2d" strokeWidth="1" />
            </svg>
          </div>

          <span style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 13, letterSpacing: '.18em', color: 'var(--text1)', marginLeft: 12 }}>
            AUTO<span style={{ color: 'var(--accent)', fontWeight: 600 }}>POV</span>
          </span>
        </Link>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontFamily: '"JetBrains Mono", monospace', fontSize: 10, letterSpacing: '.1em', color: 'var(--text3)' }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#22c55e', display: 'inline-block' }} />
            CONNECTED
          </div>
          <button type="button" onClick={() => setOpenPanel('models')} style={pillButtonStyle}>
            MODELS (2)
          </button>
        </div>
      </header>

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

      <div ref={tlRef} className="corner tl" />
      <div ref={trRef} className="corner tr" />
      <div ref={blRef} className="corner bl" />
      <div ref={brRef} className="corner br" />

      <main style={mainStyle}>
        <Outlet />
      </main>

      <footer style={statusbarStyle}>
        <button type="button" onClick={() => setOpenPanel('agents')} style={pillButtonStyle}>
          AGENTS ({agentsOnline})
        </button>
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
        <button type="button" onClick={() => setOpenPanel('models')} style={pillButtonStyle}>
          MODEL
          <span style={statAccentStyle}>{activeModelLabel}</span>
        </button>
        <span style={{ marginLeft: 'auto', color: 'var(--text3)' }}>AutoPoV v0.3.0</span>
      </footer>

      {openPanel === 'agents' && (
        <OverlayPanel title="ACTIVE AGENTS" onClose={() => setOpenPanel(null)}>
          <div style={{ display: 'grid', gap: 8 }}>
            {agentNames.map((name) => (
              <div key={name} style={{ padding: '10px 12px', border: '1px solid var(--border2)', color: 'var(--text2)', fontFamily: '"JetBrains Mono", monospace', fontSize: 11, letterSpacing: '.08em' }}>
                {name}
              </div>
            ))}
          </div>
        </OverlayPanel>
      )}

      {openPanel === 'models' && (
        <OverlayPanel title="MODEL MODES" onClose={() => setOpenPanel(null)}>
          <div style={{ display: 'grid', gap: 12 }}>
            {modelGroups.map((group) => (
              <div
                key={group.key}
                title={group.models.join(', ') || 'No models configured'}
                style={{
                  padding: '12px 14px',
                  border: `1px solid ${runtime.modelMode === group.key ? 'var(--accent)' : 'var(--border2)'}`,
                  background: runtime.modelMode === group.key ? 'rgba(254,127,45,0.08)' : 'transparent',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                  <span style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 11, letterSpacing: '.12em', color: runtime.modelMode === group.key ? 'var(--accent)' : 'var(--text2)' }}>
                    {group.title}
                  </span>
                  <span style={{ color: 'var(--text3)', fontFamily: '"JetBrains Mono", monospace', fontSize: 10 }}>
                    {group.models.length} models
                  </span>
                </div>
                <div style={{ color: 'var(--text3)', fontFamily: '"JetBrains Mono", monospace', fontSize: 11, lineHeight: 1.6 }}>
                  {group.models.length ? group.models.join(', ') : 'No models available'}
                </div>
              </div>
            ))}
          </div>
        </OverlayPanel>
      )}
    </div>
  )
}
