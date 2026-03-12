import { useEffect, useState } from 'react'
import { getLearningSummary } from '../api/client'

function StatCard({ label, value, accent }) {
  const border = {
    safe:    'border-l-2 border-l-safe-500',
    warn:    'border-l-2 border-l-warn-500',
    primary: 'border-l-2 border-l-primary-600',
  }[accent] || ''

  return (
    <div className={`card p-5 ${border}`}>
      <p className="label-caps mb-3">{label}</p>
      <p className="stat-num text-gray-100">{value}</p>
    </div>
  )
}

function ModelTable({ rows, metricKey }) {
  if (!rows?.length) {
    return (
      <div className="card p-10 text-center">
        <p className="label-caps text-gray-600">NO MODEL DATA</p>
      </div>
    )
  }

  return (
    <div className="card overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-gray-850">
            <th className="px-5 py-3 text-left label-caps">MODEL</th>
            <th className="px-5 py-3 text-right label-caps">TOTAL</th>
            <th className="px-5 py-3 text-right label-caps">CONFIRMED</th>
            <th className="px-5 py-3 text-right label-caps">RATE</th>
            <th className="px-5 py-3 text-right label-caps">COST USD</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row, idx) => (
            <tr key={idx} className="border-t border-gray-850 hover:bg-gray-850/50 transition-colors">
              <td className="px-5 py-3 text-primary-400 font-mono">{row.model}</td>
              <td className="px-5 py-3 text-right text-gray-400">{row.total}</td>
              <td className="px-5 py-3 text-right text-safe-400 font-semibold">{row.confirmed}</td>
              <td className="px-5 py-3 text-right text-gray-200 font-semibold">
                {(row[metricKey] * 100).toFixed(1)}%
              </td>
              <td className="px-5 py-3 text-right text-gray-500 font-mono">${row.cost_usd.toFixed(4)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Policy() {
  const [data,    setData]    = useState(null)
  const [loading, setLoading] = useState(true)
  const [error,   setError]   = useState(null)

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await getLearningSummary()
        setData(response.data)
      } catch (err) {
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [])

  if (loading) {
    return (
      <div className="flex items-center gap-3 py-16 text-gray-600">
        <span className="inline-block w-4 h-4 border border-primary-600 border-t-transparent animate-spin" />
        <span className="label-caps">LOADING POLICY DATA</span>
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-8 animate-fade-up">
        <div>
          <p className="label-caps mb-1">// INTELLIGENCE</p>
          <h1 className="heading-display text-4xl text-gray-100">POLICY DASHBOARD</h1>
        </div>
        <div className="card-threat p-4 flex items-center gap-3">
          <span className="label-caps text-threat-400">ERROR</span>
          <span className="text-threat-300 text-sm">{error}</span>
        </div>
      </div>
    )
  }

  const summary    = data?.summary || {}
  const modelStats = data?.models  || { investigate: [], pov: [] }

  return (
    <div className="space-y-10 animate-fade-up">

      {/* Header */}
      <div>
        <p className="label-caps mb-1">// INTELLIGENCE</p>
        <h1 className="heading-display text-4xl text-gray-100">POLICY DASHBOARD</h1>
        <p className="text-xs text-gray-600 mt-1 tracking-widest">MODEL PERFORMANCE & LEARNING SUMMARY</p>
      </div>

      {/* Summary stats */}
      <div>
        <p className="label-caps mb-3">SUMMARY</p>
        <div className="grid grid-cols-2 md:grid-cols-3 gap-px bg-gray-850">
          <StatCard label="INVESTIGATIONS" value={summary.investigations_total || 0} />
          <StatCard label="POV RUNS"       value={summary.pov_total || 0} />
          <StatCard label="POV SUCCESS"    value={summary.pov_success_total || 0} accent="safe" />
        </div>
      </div>

      {/* Cost */}
      <div>
        <p className="label-caps mb-3">COST BREAKDOWN</p>
        <div className="grid grid-cols-2 gap-px bg-gray-850">
          <StatCard label="INVESTIGATION COST" value={`$${(summary.investigations_cost_usd || 0).toFixed(4)}`} />
          <StatCard label="POV COST"           value={`$${(summary.pov_cost_usd || 0).toFixed(4)}`} />
        </div>
      </div>

      {/* Model performance tables */}
      <div>
        <p className="label-caps mb-3">INVESTIGATION MODELS</p>
        <ModelTable rows={modelStats.investigate} metricKey="confirm_rate" />
      </div>

      <div>
        <p className="label-caps mb-3">POV GENERATION MODELS</p>
        <ModelTable rows={modelStats.pov} metricKey="success_rate" />
      </div>

    </div>
  )
}

export default Policy
