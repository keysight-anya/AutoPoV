import { useEffect, useState } from 'react'
import { getMetrics, healthCheck } from '../api/client'

function StatCard({ label, value, sub, accent }) {
  const border = {
    threat:  'border-l-2 border-l-threat-500',
    safe:    'border-l-2 border-l-safe-500',
    warn:    'border-l-2 border-l-warn-500',
    primary: 'border-l-2 border-l-primary-600',
  }[accent] || ''

  return (
    <div className={`card p-5 ${border}`}>
      <p className="label-caps mb-3">{label}</p>
      <p className="stat-num text-gray-100">{value}</p>
      {sub && <p className="text-xs text-gray-600 mt-1.5">{sub}</p>}
    </div>
  )
}

function ToolStatus({ label, available }) {
  return (
    <div className="flex items-center gap-3 py-2.5 border-b border-gray-850 last:border-0">
      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${available ? 'bg-safe-400' : 'bg-gray-700'}`} />
      <span className="text-xs text-gray-400 flex-1 font-mono">{label}</span>
      {available
        ? <span className="badge-safe">ONLINE</span>
        : <span className="badge-neutral">OFFLINE</span>
      }
    </div>
  )
}

function SectionGrid({ title, children }) {
  return (
    <div>
      <p className="label-caps mb-3">{title}</p>
      {/* gap-px + bg shows through as 1-px dividers — brutalist grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-gray-850">
        {children}
      </div>
    </div>
  )
}

function Metrics() {
  const [metrics,     setMetrics]     = useState(null)
  const [health,      setHealth]      = useState(null)
  const [loading,     setLoading]     = useState(true)
  const [error,       setError]       = useState(null)
  const [lastRefresh, setLastRefresh] = useState(null)

  const fetchAll = async () => {
    setLoading(true)
    setError(null)
    try {
      const [metricsRes, healthRes] = await Promise.all([
        getMetrics().catch(() => null),
        healthCheck().catch(() => null),
      ])
      setMetrics(metricsRes?.data || null)
      setHealth(healthRes?.data || null)
      setLastRefresh(new Date())
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchAll() }, [])

  return (
    <div className="space-y-10 animate-fade-up">

      {/* Header */}
      <div className="flex items-end justify-between">
        <div>
          <p className="label-caps mb-1">// TELEMETRY</p>
          <h1 className="heading-display text-4xl text-gray-100">SYSTEM METRICS</h1>
          {lastRefresh && (
            <p className="text-xs text-gray-600 mt-1 font-mono tracking-widest">
              REFRESHED {lastRefresh.toLocaleTimeString()}
            </p>
          )}
        </div>
        <button
          onClick={fetchAll}
          disabled={loading}
          className="btn-ghost text-xs disabled:opacity-50"
        >
          {loading ? (
            <>
              <span className="inline-block w-3 h-3 border border-current border-t-transparent animate-spin mr-2" />
              LOADING
            </>
          ) : (
            '↻ REFRESH'
          )}
        </button>
      </div>

      {/* Error */}
      {error && (
        <div className="card-threat p-4 flex items-center gap-3">
          <span className="label-caps text-threat-400">ERROR</span>
          <span className="text-threat-300 text-sm">{error}</span>
        </div>
      )}

      {/* Agent health */}
      {health && (
        <div>
          <p className="label-caps mb-3">AGENT SERVER</p>
          <div className="card grid grid-cols-1 md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-gray-850">

            {/* Status cell */}
            <div className="p-5 flex items-center gap-4">
              <span className={`w-2.5 h-2.5 rounded-full flex-shrink-0 ${
                health.status === 'healthy'
                  ? 'bg-safe-400 animate-pulse-glow'
                  : 'bg-threat-500'
              }`} />
              <div>
                <p className="text-sm font-semibold text-gray-200 tracking-widest uppercase">
                  {health.status}
                </p>
                <p className="label-caps text-gray-600 mt-0.5">VERSION {health.version}</p>
              </div>
            </div>

            {/* Tool availability */}
            <div className="p-5">
              <p className="label-caps mb-2">ANALYSIS TOOLS</p>
              <ToolStatus label="Docker — PoV Execution"   available={health.docker_available} />
              <ToolStatus label="CodeQL — Static Analysis" available={health.codeql_available} />
              <ToolStatus label="Joern — Graph Analysis"   available={health.joern_available} />
            </div>
          </div>
        </div>
      )}

      {/* Scan activity */}
      {metrics && metrics.total_scans !== undefined && (
        <SectionGrid title="SCAN ACTIVITY">
          {metrics.total_scans    !== undefined && <StatCard label="TOTAL SCANS" value={metrics.total_scans} />}
          {metrics.completed_scans !== undefined && <StatCard label="COMPLETED"  value={metrics.completed_scans} accent="safe" />}
          {metrics.failed_scans   !== undefined && <StatCard label="FAILED"      value={metrics.failed_scans}   accent="threat" />}
          {metrics.running_scans  !== undefined && <StatCard label="RUNNING"     value={metrics.running_scans}  accent="primary" />}
        </SectionGrid>
      )}

      {/* Findings */}
      {metrics && (metrics.total_findings !== undefined || metrics.confirmed_findings !== undefined) && (
        <SectionGrid title="FINDING STATISTICS">
          {metrics.total_findings     !== undefined && <StatCard label="TOTAL FINDINGS"  value={metrics.total_findings} />}
          {metrics.confirmed_findings !== undefined && <StatCard label="CONFIRMED"        value={metrics.confirmed_findings} accent="safe" />}
          {metrics.false_positives    !== undefined && <StatCard label="FALSE POSITIVES"  value={metrics.false_positives}   accent="warn" />}
          {metrics.avg_confidence     !== undefined && (
            <StatCard label="AVG CONFIDENCE" value={`${(metrics.avg_confidence * 100).toFixed(1)}%`} />
          )}
        </SectionGrid>
      )}

      {/* Cost & performance */}
      {metrics && (metrics.total_cost_usd !== undefined || metrics.avg_duration_s !== undefined) && (
        <SectionGrid title="COST & PERFORMANCE">
          {metrics.total_cost_usd  !== undefined && <StatCard label="TOTAL COST"      value={`$${parseFloat(metrics.total_cost_usd).toFixed(4)}`} />}
          {metrics.avg_cost_usd    !== undefined && <StatCard label="AVG COST / SCAN" value={`$${parseFloat(metrics.avg_cost_usd).toFixed(4)}`} />}
          {metrics.avg_duration_s  !== undefined && <StatCard label="AVG DURATION"    value={`${parseFloat(metrics.avg_duration_s).toFixed(1)}s`} />}
        </SectionGrid>
      )}

      {/* Catch-all extra keys */}
      {metrics && (() => {
        const knownKeys = new Set([
          'total_scans','completed_scans','failed_scans','running_scans',
          'total_findings','confirmed_findings','false_positives','avg_confidence',
          'total_cost_usd','avg_cost_usd','avg_duration_s',
        ])
        const extra = Object.entries(metrics).filter(([k]) => !knownKeys.has(k))
        if (!extra.length) return null
        return (
          <SectionGrid title="ADDITIONAL METRICS">
            {extra.map(([k, v]) => (
              <StatCard
                key={k}
                label={k.replace(/_/g, ' ').toUpperCase()}
                value={typeof v === 'number' ? (Number.isInteger(v) ? v : v.toFixed(4)) : String(v)}
              />
            ))}
          </SectionGrid>
        )
      })()}

      {/* Offline state */}
      {!loading && !metrics && !health && (
        <div className="card p-14 text-center">
          <p className="label-caps text-gray-600 mb-1">NO DATA</p>
          <p className="text-xs text-gray-700">Agent server appears to be offline</p>
        </div>
      )}

    </div>
  )
}

export default Metrics
