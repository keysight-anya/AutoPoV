// frontend/src/pages/Results.jsx
import { useEffect, useMemo, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import SeverityFilter from '../components/SeverityFilter'
import FindingCard from '../components/FindingCard'
import { getScanStatus, getReport } from '../api/client'

function getSeverity(cwe) {
  const critical = ['CWE-89','CWE-78','CWE-94','CWE-119','CWE-416']
  const high     = ['CWE-79','CWE-502','CWE-798','CWE-918']
  const medium   = ['CWE-22','CWE-352','CWE-287','CWE-306','CWE-601']
  if (critical.includes(cwe)) return 'CRITICAL'
  if (high.includes(cwe))     return 'HIGH'
  if (medium.includes(cwe))   return 'MEDIUM'
  return 'LOW'
}

export default function Results() {
  const { scanId } = useParams()
  const navigate   = useNavigate()
  const [result,  setResult]  = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)
  const [filter,  setFilter]  = useState('ALL')

  useEffect(() => {
    getScanStatus(scanId)
      .then(res => setResult(res.data.result))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [scanId])

  const findings = result?.findings || []

  const counts = useMemo(() => {
    const c = { ALL: findings.length, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
    findings.forEach(f => { c[getSeverity(f.cwe_type)] = (c[getSeverity(f.cwe_type)] || 0) + 1 })
    return c
  }, [findings])

  const filtered = useMemo(() =>
    filter === 'ALL' ? findings : findings.filter(f => getSeverity(f.cwe_type) === filter),
    [findings, filter]
  )

  const downloadReport = async (format) => {
    try {
      const response = await getReport(scanId, format)
      const blob = new Blob([response.data], { type: format === 'pdf' ? 'application/pdf' : 'application/json' })
      const url  = window.URL.createObjectURL(blob)
      const a    = document.createElement('a')
      a.href = url; a.download = `${scanId}_report.${format}`
      document.body.appendChild(a); a.click()
      window.URL.revokeObjectURL(url); document.body.removeChild(a)
    } catch (err) { console.error('Download failed:', err) }
  }

  const confirmed = findings.filter(f => f.final_status === 'confirmed').length
  const povs      = findings.filter(f => f.pov_script).length

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
      <div style={{ width: 24, height: 24, border: '2px solid var(--border2)', borderTopColor: 'var(--accent)', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )

  if (error) return (
    <div style={{ padding: 24 }}>
      <div style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', padding: '10px 14px', fontFamily: '"JetBrains Mono", monospace', fontSize: 11, color: '#fca5a5' }}>
        Error loading results: {error}
      </div>
    </div>
  )

  if (!result) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', fontFamily: '"JetBrains Mono", monospace', fontSize: 10, letterSpacing: '.14em', color: 'var(--text3)' }}>
      [ NO RESULTS FOUND ]
    </div>
  )

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Stat bar */}
      <div style={{
        padding: '10px 20px',
        background: 'var(--surface1)',
        borderBottom: '1px solid var(--border1)',
        display: 'flex', alignItems: 'center', gap: 20,
        flexShrink: 0,
        fontFamily: '"JetBrains Mono", monospace',
        fontSize: 10, letterSpacing: '.08em',
      }}>
        <span style={{ color: 'var(--text3)' }}>FINDINGS <span style={{ color: 'var(--accent)', marginLeft: 6 }}>{findings.length}</span></span>
        <span style={{ color: 'var(--text3)' }}>CONFIRMED <span style={{ color: '#22c55e', marginLeft: 6 }}>{confirmed}</span></span>
        <span style={{ color: 'var(--text3)' }}>PoVs <span style={{ color: 'var(--accent)', marginLeft: 6 }}>{povs}</span></span>
        <span style={{ color: 'var(--text3)', marginLeft: 'auto', fontFamily: '"JetBrains Mono", monospace', fontSize: 9 }}>
          {scanId}
        </span>
        <button onClick={() => downloadReport('json')} style={{ background: 'none', border: '1px solid var(--border2)', color: 'var(--text3)', padding: '4px 12px', fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.1em', cursor: 'pointer', transition: 'color .15s, border-color .15s' }}
          onMouseOver={e => { e.currentTarget.style.color = 'var(--accent)'; e.currentTarget.style.borderColor = 'var(--accent)' }}
          onMouseOut={e  => { e.currentTarget.style.color = 'var(--text3)';  e.currentTarget.style.borderColor = 'var(--border2)' }}>
          JSON
        </button>
        <button onClick={() => downloadReport('pdf')} style={{ background: 'none', border: '1px solid var(--border2)', color: 'var(--text3)', padding: '4px 12px', fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.1em', cursor: 'pointer', transition: 'color .15s, border-color .15s' }}
          onMouseOver={e => { e.currentTarget.style.color = 'var(--accent)'; e.currentTarget.style.borderColor = 'var(--accent)' }}
          onMouseOut={e  => { e.currentTarget.style.color = 'var(--text3)';  e.currentTarget.style.borderColor = 'var(--border2)' }}>
          PDF
        </button>
      </div>

      {/* Body */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <SeverityFilter counts={counts} active={filter} onChange={setFilter} />

        {/* Findings list */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px' }}>
          {filtered.length === 0 ? (
            <div style={{ textAlign: 'center', paddingTop: 60, fontFamily: '"JetBrains Mono", monospace', fontSize: 10, letterSpacing: '.14em', color: 'var(--text3)' }}>
              [ NO FINDINGS FOR THIS FILTER ]
            </div>
          ) : (
            filtered.map((f, i) => <FindingCard key={i} finding={f} />)
          )}
        </div>
      </div>
    </div>
  )
}
