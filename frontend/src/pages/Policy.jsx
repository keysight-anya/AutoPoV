import { useEffect, useState } from 'react'
import { getLearningSummary } from '../api/client'

function StatCard({ label, value }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
      <div className="text-sm text-gray-400">{label}</div>
      <div className="text-2xl font-semibold mt-1">{value}</div>
    </div>
  )
}

function ModelTable({ title, rows, metricKey }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
      <h3 className="text-lg font-medium mb-4">{title}</h3>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-gray-400">
            <tr>
              <th className="text-left py-2">Model</th>
              <th className="text-left py-2">Total</th>
              <th className="text-left py-2">Confirmed</th>
              <th className="text-left py-2">Rate</th>
              <th className="text-left py-2">Cost (USD)</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row, idx) => (
              <tr key={idx} className="border-t border-gray-800">
                <td className="py-2 text-gray-200">{row.model}</td>
                <td className="py-2">{row.total}</td>
                <td className="py-2">{row.confirmed}</td>
                <td className="py-2">{(row[metricKey] * 100).toFixed(1)}%</td>
                <td className="py-2">${row.cost_usd.toFixed(4)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function Policy() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

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
      <div className="flex justify-center items-center h-64">
        <div className="w-8 h-8 border-2 border-primary-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="max-w-4xl mx-auto">
        <div className="p-4 bg-red-900/30 border border-red-800 rounded-lg">
          <p className="text-red-300">Error loading policy data: {error}</p>
        </div>
      </div>
    )
  }

  const summary = data?.summary || {}
  const modelStats = data?.models || { investigate: [], pov: [] }

  return (
    <div className="max-w-6xl mx-auto space-y-8">
      <div>
        <h1 className="text-2xl font-bold">Policy Dashboard</h1>
        <p className="text-sm text-gray-400">Learning and model performance overview</p>
      </div>

      <div className="grid md:grid-cols-3 gap-4">
        <StatCard label="Investigations" value={summary.investigations_total || 0} />
        <StatCard label="PoV Runs" value={summary.pov_total || 0} />
        <StatCard label="PoV Success" value={summary.pov_success_total || 0} />
      </div>

      <div className="grid md:grid-cols-2 gap-4">
        <StatCard label="Investigation Cost" value={`$${(summary.investigations_cost_usd || 0).toFixed(4)}`} />
        <StatCard label="PoV Cost" value={`$${(summary.pov_cost_usd || 0).toFixed(4)}`} />
      </div>

      <ModelTable title="Investigation Models" rows={modelStats.investigate} metricKey="confirm_rate" />
      <ModelTable title="PoV Models" rows={modelStats.pov} metricKey="success_rate" />
    </div>
  )
}

export default Policy
