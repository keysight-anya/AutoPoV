import { useEffect, useState } from 'react'
import { Activity, RefreshCw } from 'lucide-react'
import { getMetrics, healthCheck } from '../api/client'

function StatCard({ label, value, sub }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <div className="text-sm text-gray-400">{label}</div>
      <div className="text-2xl font-semibold mt-1">{value}</div>
      {sub && <div className="text-xs text-gray-500 mt-1">{sub}</div>}
    </div>
  )
}

function ToolBadge({ label, available }) {
  return (
    <div className={`flex items-center space-x-2 px-3 py-2 rounded-lg border text-sm ${
      available
        ? 'bg-green-900/20 border-green-800 text-green-300'
        : 'bg-gray-800 border-gray-700 text-gray-500'
    }`}>
      <span className={`w-2 h-2 rounded-full ${available ? 'bg-green-400' : 'bg-gray-600'}`} />
      <span>{label}</span>
    </div>
  )
}

function Metrics() {
  const [metrics, setMetrics] = useState(null)
  const [health, setHealth] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [lastRefresh, setLastRefresh] = useState(null)

  const fetchAll = async () => {
    setLoading(true)
    setError(null)
    try {
      const [metricsRes, healthRes] = await Promise.all([
        getMetrics().catch(() => null),
        healthCheck().catch(() => null)
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

  useEffect(() => {
    fetchAll()
  }, [])

  return (
    <div className="max-w-6xl mx-auto space-y-8">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <Activity className="w-8 h-8 text-primary-500" />
          <div>
            <h1 className="text-2xl font-bold">System Metrics</h1>
            <p className="text-sm text-gray-400">
              {lastRefresh ? `Last updated: ${lastRefresh.toLocaleTimeString()}` : 'Agent server statistics'}
            </p>
          </div>
        </div>
        <button
          onClick={fetchAll}
          disabled={loading}
          className="flex items-center space-x-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      {error && (
        <div className="p-4 bg-red-900/30 border border-red-800 rounded-lg">
          <p className="text-red-300">{error}</p>
        </div>
      )}

      {/* Health */}
      {health && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4">Agent Server Health</h2>
          <div className="flex items-center space-x-2 mb-4">
            <span className={`w-3 h-3 rounded-full ${health.status === 'healthy' ? 'bg-green-400' : 'bg-red-400'}`} />
            <span className="font-medium capitalize">{health.status}</span>
            <span className="text-gray-500 text-sm">v{health.version}</span>
          </div>
          <div className="flex flex-wrap gap-3">
            <ToolBadge label="Docker (PoV Execution)" available={health.docker_available} />
            <ToolBadge label="CodeQL (Static Analysis)" available={health.codeql_available} />
            <ToolBadge label="Joern (Graph Analysis)" available={health.joern_available} />
          </div>
        </div>
      )}

      {/* Metrics cards */}
      {metrics && (
        <>
          {/* Scan counts */}
          <div>
            <h2 className="text-lg font-semibold mb-3">Scan Activity</h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {metrics.total_scans !== undefined && (
                <StatCard label="Total Scans" value={metrics.total_scans} />
              )}
              {metrics.completed_scans !== undefined && (
                <StatCard label="Completed" value={metrics.completed_scans} />
              )}
              {metrics.failed_scans !== undefined && (
                <StatCard label="Failed" value={metrics.failed_scans} />
              )}
              {metrics.running_scans !== undefined && (
                <StatCard label="Running" value={metrics.running_scans} />
              )}
            </div>
          </div>

          {/* Findings */}
          {(metrics.total_findings !== undefined || metrics.confirmed_findings !== undefined) && (
            <div>
              <h2 className="text-lg font-semibold mb-3">Finding Statistics</h2>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {metrics.total_findings !== undefined && (
                  <StatCard label="Total Findings" value={metrics.total_findings} />
                )}
                {metrics.confirmed_findings !== undefined && (
                  <StatCard label="Confirmed" value={metrics.confirmed_findings} />
                )}
                {metrics.false_positives !== undefined && (
                  <StatCard label="False Positives" value={metrics.false_positives} />
                )}
                {metrics.avg_confidence !== undefined && (
                  <StatCard
                    label="Avg Confidence"
                    value={`${(metrics.avg_confidence * 100).toFixed(1)}%`}
                  />
                )}
              </div>
            </div>
          )}

          {/* Cost / duration */}
          {(metrics.total_cost_usd !== undefined || metrics.avg_duration_s !== undefined) && (
            <div>
              <h2 className="text-lg font-semibold mb-3">Cost & Performance</h2>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {metrics.total_cost_usd !== undefined && (
                  <StatCard label="Total Cost" value={`$${parseFloat(metrics.total_cost_usd).toFixed(4)}`} />
                )}
                {metrics.avg_cost_usd !== undefined && (
                  <StatCard label="Avg Cost / Scan" value={`$${parseFloat(metrics.avg_cost_usd).toFixed(4)}`} />
                )}
                {metrics.avg_duration_s !== undefined && (
                  <StatCard label="Avg Duration" value={`${parseFloat(metrics.avg_duration_s).toFixed(1)}s`} />
                )}
              </div>
            </div>
          )}

          {/* Remaining raw keys */}
          {(() => {
            const knownKeys = new Set([
              'total_scans', 'completed_scans', 'failed_scans', 'running_scans',
              'total_findings', 'confirmed_findings', 'false_positives', 'avg_confidence',
              'total_cost_usd', 'avg_cost_usd', 'avg_duration_s'
            ])
            const extra = Object.entries(metrics).filter(([k]) => !knownKeys.has(k))
            if (!extra.length) return null
            return (
              <div>
                <h2 className="text-lg font-semibold mb-3">Additional Metrics</h2>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                  {extra.map(([k, v]) => (
                    <StatCard
                      key={k}
                      label={k.replace(/_/g, ' ')}
                      value={typeof v === 'number' ? (Number.isInteger(v) ? v : v.toFixed(4)) : String(v)}
                    />
                  ))}
                </div>
              </div>
            )
          })()}
        </>
      )}

      {!loading && !metrics && !health && (
        <div className="p-8 text-center text-gray-500">
          No metrics available. Make sure the agent server is running.
        </div>
      )}
    </div>
  )
}

export default Metrics
