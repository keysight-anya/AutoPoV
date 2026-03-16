// frontend/src/pages/Policy.jsx
import { useEffect, useState } from 'react'
import { getLearningSummary } from '../api/client'

function Panel({ title, children }) {
  return (
    <div style={{
      background: 'var(--surface1)',
      border: '1px solid var(--border1)',
      borderLeft: '3px solid var(--accent)',
      padding: '20px 24px',
      marginBottom: 16,
    }}>
      <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.16em', color: 'var(--text3)', marginBottom: 16 }}>
        {title}
      </div>
      {children}
    </div>
  )
}

function StatCard({ label, value }) {
  return (
    <div style={{ background: 'var(--surface2)', border: '1px solid var(--border1)', padding: '14px 16px' }}>
      <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.12em', color: 'var(--text3)', marginBottom: 6 }}>{label}</div>
      <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 22, color: 'var(--text1)' }}>{value}</div>
    </div>
  )
}

export default function Policy() {
  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)

  useEffect(() => {
    getLearningSummary()
      .then(res => setData(res.data))
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
        Error loading policy data: {error}
      </div>
    </div>
  )

  const stats = data?.overall_stats || {}
  const investigationRows = data?.by_model?.investigation || []
  const povRows           = data?.by_model?.pov_generation  || []

  return (
    <div style={{ padding: 24 }}>
      <div style={{ ...monoStyle, fontSize: 9, letterSpacing: '.18em', color: 'var(--text3)', marginBottom: 20 }}>
        [ MODEL POLICY ]
      </div>

      {/* Stats */}
      <Panel title="OVERALL STATISTICS">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(140px, 1fr))', gap: 10 }}>
          <StatCard label="TOTAL FINDINGS"    value={stats.total_findings    ?? 0} />
          <StatCard label="CONFIRMED"         value={stats.confirmed_count   ?? 0} />
          <StatCard label="CONFIRM RATE"      value={`${((stats.confirmation_rate ?? 0) * 100).toFixed(1)}%`} />
          <StatCard label="POV GENERATED"     value={stats.pov_generated     ?? 0} />
          <StatCard label="POV SUCCESS RATE"  value={`${((stats.pov_success_rate ?? 0) * 100).toFixed(1)}%`} />
          <StatCard label="TOTAL COST"        value={`$${(stats.total_cost_usd ?? 0).toFixed(4)}`} />
        </div>
      </Panel>

      {/* Investigation models */}
      {investigationRows.length > 0 && (
        <Panel title="INVESTIGATION MODELS">
          <table style={{ width: '100%', borderCollapse: 'collapse', ...monoStyle }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border2)' }}>
                {['MODEL', 'TOTAL', 'CONFIRMED', 'RATE', 'COST'].map(h => (
                  <th key={h} style={{ padding: '6px 10px', textAlign: 'left', fontSize: 9, letterSpacing: '.1em', color: 'var(--text3)', fontWeight: 500 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {investigationRows.map((row) => (
                <tr key={row.model} style={{ borderBottom: '1px solid var(--border1)' }}>
                  <td style={{ padding: '8px 10px', fontSize: 11, color: 'var(--text2)' }}>{row.model}</td>
                  <td style={{ padding: '8px 10px', fontSize: 11, color: 'var(--text1)' }}>{row.total}</td>
                  <td style={{ padding: '8px 10px', fontSize: 11, color: '#22c55e' }}>{row.confirmed}</td>
                  <td style={{ padding: '8px 10px', fontSize: 11, color: 'var(--accent)' }}>{((row.confirmation_rate ?? 0) * 100).toFixed(1)}%</td>
                  <td style={{ padding: '8px 10px', fontSize: 11, color: 'var(--text3)' }}>${(row.cost_usd ?? 0).toFixed(4)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}

      {/* PoV models */}
      {povRows.length > 0 && (
        <Panel title="POV GENERATION MODELS">
          <table style={{ width: '100%', borderCollapse: 'collapse', ...monoStyle }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--border2)' }}>
                {['MODEL', 'TOTAL', 'SUCCESS', 'RATE', 'COST'].map(h => (
                  <th key={h} style={{ padding: '6px 10px', textAlign: 'left', fontSize: 9, letterSpacing: '.1em', color: 'var(--text3)', fontWeight: 500 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {povRows.map((row) => (
                <tr key={row.model} style={{ borderBottom: '1px solid var(--border1)' }}>
                  <td style={{ padding: '8px 10px', fontSize: 11, color: 'var(--text2)' }}>{row.model}</td>
                  <td style={{ padding: '8px 10px', fontSize: 11, color: 'var(--text1)' }}>{row.total}</td>
                  <td style={{ padding: '8px 10px', fontSize: 11, color: '#22c55e' }}>{row.pov_success}</td>
                  <td style={{ padding: '8px 10px', fontSize: 11, color: 'var(--accent)' }}>{((row.pov_success_rate ?? 0) * 100).toFixed(1)}%</td>
                  <td style={{ padding: '8px 10px', fontSize: 11, color: 'var(--text3)' }}>${(row.cost_usd ?? 0).toFixed(4)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Panel>
      )}
    </div>
  )
}
