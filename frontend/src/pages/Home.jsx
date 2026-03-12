import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { AlertCircle } from 'lucide-react'
import ScanForm from '../components/ScanForm'
import { scanGit, scanZip, scanPaste } from '../api/client'
import apiClient from '../api/client'

// Mini stat card
function StatCard({ label, value, color = 'text-gray-100', accent = 'border-l-gray-800' }) {
  return (
    <div className={`bg-gray-900 border border-gray-850 border-l-2 ${accent} p-4`}>
      <div className="label-caps mb-1.5">{label}</div>
      <div className={`stat-num ${color}`}>{value}</div>
    </div>
  )
}

// Recent scan row
function ScanRow({ repo, status, findings, time }) {
  const statusColor = {
    critical:  'text-threat-400',
    confirmed: 'text-primary-400',
    clean:     'text-safe-400',
    failed:    'text-warn-400',
  }[status] || 'text-gray-500'

  const accentColor = {
    critical:  'border-l-threat-500',
    confirmed: 'border-l-primary-500',
    clean:     'border-l-safe-500',
    failed:    'border-l-warn-500',
  }[status] || 'border-l-gray-800'

  return (
    <div className={`bg-gray-900 border border-gray-850 border-l-2 ${accentColor} px-4 py-2.5 flex items-center justify-between gap-4`}>
      <code className="text-gray-300 text-xs truncate flex-1">{repo}</code>
      <span className="text-gray-600 text-xs shrink-0">{findings}</span>
      <span className={`text-xs font-semibold tracking-widest shrink-0 ${statusColor}`}>
        {status.toUpperCase()}
      </span>
      <span className="text-gray-700 text-xs shrink-0">{time}</span>
    </div>
  )
}

function Home() {
  const navigate = useNavigate()
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError]         = useState(null)
  const [recentScans, setRecentScans] = useState([])
  const [stats, setStats]         = useState(null)

  // Load history + stats for right-side panel
  useEffect(() => {
    const apiKey = localStorage.getItem('autopov_api_key')
    if (!apiKey) return

    // Try to load scan history for sidebar stats
    apiClient.get('/history?limit=5', {
      headers: { Authorization: `Bearer ${apiKey}` }
    }).then(res => {
      const scans = res.data?.scans || res.data || []
      setRecentScans(scans.slice(0, 4))

      // Aggregate quick stats
      const total     = scans.length
      const confirmed = scans.reduce((n, s) => n + (s.confirmed_count || 0), 0)
      const critical  = scans.filter(s => (s.confirmed_count || 0) > 0).length
      setStats({ total, confirmed, critical })
    }).catch(() => {})
  }, [])

  const handleSubmit = async ({ type, data, file }) => {
    setIsLoading(true)
    setError(null)
    try {
      let response
      switch (type) {
        case 'git':
          response = await scanGit({ url: data.gitUrl, branch: data.branch, cwes: data.cwes, lite: data.lite })
          break
        case 'zip': {
          const fd = new FormData()
          fd.append('file', file)
          fd.append('cwes', data.cwes.join(','))
          fd.append('lite', data.lite ? 'true' : 'false')
          response = await scanZip(fd)
          break
        }
        case 'paste':
          response = await scanPaste({ code: data.code, language: data.language, filename: data.filename, cwes: data.cwes, lite: data.lite })
          break
        default:
          throw new Error('Invalid scan type')
      }
      // Track as active scan
      try {
        const raw  = localStorage.getItem('autopov_active_scans')
        const list = raw ? JSON.parse(raw) : []
        list.push(response.data.scan_id)
        localStorage.setItem('autopov_active_scans', JSON.stringify(list))
      } catch {}
      navigate(`/scan/${response.data.scan_id}`)
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to start scan')
      setIsLoading(false)
    }
  }

  return (
    <div className="animate-fade-up">

      {/* ── Hero header ─────────────────────────────────── */}
      <div className="border-b border-gray-850 pb-8 mb-10">
        {/* Overline */}
        <div className="flex items-center gap-3 mb-5">
          <div className="w-2 h-2 bg-primary-600 rounded-sm" />
          <span className="label-caps text-primary-400 tracking-widest">
            AUTONOMOUS PROOF-OF-VULNERABILITY PLATFORM
          </span>
        </div>

        {/* Headline — Barlow Condensed */}
        <h1
          className="text-5xl md:text-6xl font-black uppercase leading-none tracking-tight mb-4"
          style={{ fontFamily: '"Barlow Condensed", system-ui, sans-serif' }}
        >
          FIND REAL<br />
          <span className="text-primary-400">EXPLOITS.</span>
        </h1>

        <p className="text-gray-500 text-sm max-w-lg leading-relaxed">
          Multi-agent system: ingests code → scouts vulnerabilities → generates PoV scripts → validates in Docker. 20+ CWEs. Real-time logs.
        </p>
      </div>

      {/* ── Two-column layout ────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-[1fr_340px] gap-8 lg:gap-12 items-start">

        {/* Left: Scan Form */}
        <div>
          {error && (
            <div className="mb-5 p-3.5 border border-threat-500/30 bg-threat-900/20 flex items-start gap-3">
              <AlertCircle className="w-4 h-4 text-threat-400 mt-0.5 shrink-0" />
              <span className="text-threat-300 text-xs">{error}</span>
            </div>
          )}
          <ScanForm onSubmit={handleSubmit} isLoading={isLoading} />
        </div>

        {/* Right: Stats + Recent Activity */}
        <div className="flex flex-col gap-4">

          {/* Stats row */}
          <div className="grid grid-cols-2 gap-3">
            <StatCard
              label="TOTAL SCANS"
              value={stats?.total ?? '—'}
              color="text-gray-100"
              accent="border-l-gray-700"
            />
            <StatCard
              label="CONFIRMED"
              value={stats?.confirmed ?? '—'}
              color="text-primary-400"
              accent="border-l-primary-600"
            />
            <StatCard
              label="W/ FINDINGS"
              value={stats?.critical ?? '—'}
              color="text-threat-400"
              accent="border-l-threat-500"
            />
            <StatCard
              label="AGENTS"
              value="8"
              color="text-safe-400"
              accent="border-l-safe-500"
            />
          </div>

          {/* Recent scans */}
          <div>
            <div className="flex items-center justify-between mb-2.5 px-1">
              <div className="label-caps">RECENT SCANS</div>
            </div>

            {recentScans.length > 0 ? (
              <div className="flex flex-col gap-1.5">
                {recentScans.map((scan, i) => (
                  <ScanRow
                    key={scan.scan_id || i}
                    repo={scan.repository || scan.source || 'unknown'}
                    status={
                      scan.confirmed_count > 0 ? 'critical'
                      : scan.status === 'failed' ? 'failed'
                      : scan.status === 'completed' ? 'clean'
                      : 'confirmed'
                    }
                    findings={`${scan.confirmed_count ?? 0} found`}
                    time={scan.created_at ? scan.created_at.substring(0, 10) : '—'}
                  />
                ))}
              </div>
            ) : (
              <div className="border border-gray-850 border-dashed p-6 text-center">
                <div className="text-gray-700 text-xs tracking-widest mb-1">NO HISTORY</div>
                <div className="text-gray-600 text-xs">Run a scan to see results here</div>
              </div>
            )}
          </div>

          {/* Capability bullets */}
          <div className="border border-gray-850 p-4">
            <div className="label-caps mb-3">AGENT ROSTER</div>
            <div className="flex flex-col gap-1.5">
              {[
                ['INGEST',       'Chunks & embeds codebase into vector store'],
                ['SCOUT',        'Pattern + LLM discovery across 20+ CWEs'],
                ['INVESTIGATOR', 'Deep RAG analysis — REAL vs FALSE_POS'],
                ['POV GEN',      'Writes working exploit script per finding'],
                ['VALIDATION',   'Static → unit test → Docker proof'],
                ['POLICY',       'Routes each task to optimal model'],
              ].map(([name, desc]) => (
                <div key={name} className="flex items-start gap-2.5">
                  <span className="text-primary-600 text-xs font-semibold shrink-0 w-24">{name}</span>
                  <span className="text-gray-600 text-xs leading-relaxed">{desc}</span>
                </div>
              ))}
            </div>
          </div>

        </div>
      </div>
    </div>
  )
}

export default Home
