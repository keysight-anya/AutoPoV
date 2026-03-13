// frontend/src/pages/History.jsx
import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getHistory } from '../api/client'

const STATUS_COLOR = {
  completed: '#22c55e',
  failed:    '#ef4444',
  running:   'var(--accent)',
}

export default function History() {
  const navigate = useNavigate()
  const [scans,   setScans]   = useState([])
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)

  useEffect(() => {
    getHistory(100, 0)
      .then(res => setScans(res.data.history || []))
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [])

  const monoStyle = { fontFamily: '"JetBrains Mono", monospace' }

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
      <div style={{ width: 24, height: 24, border: '2px solid var(--border2)', borderTopColor: 'var(--accent)', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
    </div>
  )

  if (error) return (
    <div style={{ padding: 24 }}>
      <div style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', padding: '10px 14px', ...monoStyle, fontSize: 11, color: '#fca5a5' }}>
        Error: {error}
      </div>
    </div>
  )

  return (
    <div style={{ padding: 24 }}>
      {/* Page label */}
      <div style={{ ...monoStyle, fontSize: 9, letterSpacing: '.18em', color: 'var(--text3)', marginBottom: 20 }}>
        [ SCAN HISTORY ]
      </div>

      {scans.length === 0 ? (
        <div style={{ textAlign: 'center', paddingTop: 80, ...monoStyle, fontSize: 10, letterSpacing: '.14em', color: 'var(--text3)' }}>
          [ NO SCANS YET ]
        </div>
      ) : (
        <table style={{ width: '100%', borderCollapse: 'collapse', ...monoStyle }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border2)' }}>
              {['SCAN ID', 'REPOSITORY', 'DATE', 'FINDINGS', 'STATUS'].map(h => (
                <th key={h} style={{ padding: '8px 12px', textAlign: 'left', fontSize: 9, letterSpacing: '.12em', color: 'var(--text3)', fontWeight: 500 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {scans.map((scan, i) => (
              <tr
                key={scan.scan_id}
                onClick={() => navigate(`/results/${scan.scan_id}`)}
                style={{
                  borderBottom: '1px solid var(--border1)',
                  cursor: 'pointer',
                  transition: 'background .1s',
                }}
                onMouseOver={e  => e.currentTarget.style.background = 'var(--surface1)'}
                onMouseOut={e   => e.currentTarget.style.background = 'transparent'}
              >
                <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text2)' }}>
                  {scan.scan_id?.slice(0, 8)}…
                </td>
                <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text2)' }}>
                  {scan.repository || scan.source || '—'}
                </td>
                <td style={{ padding: '10px 12px', fontSize: 10, color: 'var(--text3)' }}>
                  {scan.created_at ? new Date(scan.created_at).toLocaleDateString() : '—'}
                </td>
                <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--accent)' }}>
                  {scan.findings_count ?? '—'}
                </td>
                <td style={{ padding: '10px 12px' }}>
                  <span style={{
                    fontSize: 9, letterSpacing: '.1em',
                    color: STATUS_COLOR[scan.status] || 'var(--text3)',
                    display: 'flex', alignItems: 'center', gap: 5,
                  }}>
                    <span style={{ fontSize: 7 }}>●</span>
                    {(scan.status || 'UNKNOWN').toUpperCase()}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
