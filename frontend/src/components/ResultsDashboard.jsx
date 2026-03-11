import { useMemo, useState } from 'react'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { CheckCircle, XCircle, AlertCircle, DollarSign, Clock, FlaskConical, ChevronDown, ChevronUp, TrendingUp } from 'lucide-react'

function StatCard({ icon: Icon, label, value, color = 'text-gray-300', subValue }) {
  return (
    <div className="bg-gray-900/80 rounded-xl p-4 border border-gray-800/60">
      <div className={`flex items-center gap-1.5 text-xs mb-2 ${color} opacity-70`}>
        <Icon className="w-3.5 h-3.5" />
        <span>{label}</span>
      </div>
      <p className={`text-2xl font-bold ${color}`}>{value}</p>
      {subValue && <p className="text-xs text-gray-600 mt-0.5">{subValue}</p>}
    </div>
  )
}

function ProgressBar({ label, value, color }) {
  return (
    <div>
      <div className="flex justify-between items-center mb-1.5">
        <span className="text-xs text-gray-500">{label}</span>
        <span className="text-xs font-medium text-gray-300">{value}%</span>
      </div>
      <div className="w-full bg-gray-800/60 rounded-full h-1.5">
        <div className={`h-1.5 rounded-full transition-all ${color}`} style={{ width: `${value}%` }} />
      </div>
    </div>
  )
}

const TooltipStyle = { backgroundColor: '#111827', border: '1px solid #1f2937', borderRadius: '8px', fontSize: '12px' }

function ResultsDashboard({ result }) {
  const [showCostBreakdown, setShowCostBreakdown] = useState(false)

  const metrics = useMemo(() => {
    if (!result) return null
    const total = result.total_findings || 0
    const confirmed = result.confirmed_vulns || 0
    const fp = result.false_positives || 0
    const failed = result.failed || 0
    const confirmedFindings = (result.findings || []).filter(f => f.final_status === 'confirmed')
    const povTriggered = confirmedFindings.filter(f => f.pov_result?.vulnerability_triggered).length
    return {
      total, confirmed, fp, failed,
      detectionRate: total > 0 ? (confirmed / total * 100).toFixed(1) : 0,
      fpRate: total > 0 ? (fp / total * 100).toFixed(1) : 0,
      povTriggered,
      povSuccessRate: confirmed > 0 ? (povTriggered / confirmed * 100).toFixed(1) : 0,
      cost: result.total_cost_usd || 0,
      duration: result.duration_s || 0
    }
  }, [result])

  const pieData = useMemo(() => {
    if (!metrics) return []
    return [
      { name: 'Confirmed',       value: metrics.confirmed, color: '#10b981' },
      { name: 'False Positives', value: metrics.fp,        color: '#f59e0b' },
      { name: 'Failed',          value: metrics.failed,    color: '#ef4444' }
    ].filter(d => d.value > 0)
  }, [metrics])

  const costBreakdown = useMemo(() => {
    if (!result?.findings) return null
    const modelCosts = {}
    const purposeCosts = { investigation: 0, pov_generation: 0 }
    result.findings.forEach(f => {
      if (f.model_used && f.cost_usd) {
        if (!modelCosts[f.model_used]) modelCosts[f.model_used] = { investigation: 0, pov_generation: 0, total: 0 }
        modelCosts[f.model_used].investigation += f.cost_usd
        modelCosts[f.model_used].total += f.cost_usd
        purposeCosts.investigation += f.cost_usd
      }
      if (f.pov_model_used) {
        const povCost = f.pov_result?.cost_usd || f.validation_result?.cost_usd || 0
        if (povCost > 0) {
          if (!modelCosts[f.pov_model_used]) modelCosts[f.pov_model_used] = { investigation: 0, pov_generation: 0, total: 0 }
          modelCosts[f.pov_model_used].pov_generation += povCost
          modelCosts[f.pov_model_used].total += povCost
          purposeCosts.pov_generation += povCost
        }
      }
    })
    return { modelCosts, purposeCosts }
  }, [result])

  if (!metrics) return <div className="text-gray-500 text-sm">No results available</div>

  return (
    <div className="space-y-5">
      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
        <StatCard icon={AlertCircle}  label="Total Findings" value={metrics.total} />
        <StatCard icon={CheckCircle}  label="Confirmed"      value={metrics.confirmed}     color="text-safe-400"   subValue={`${metrics.detectionRate}% detection`} />
        <StatCard icon={FlaskConical} label="PoV Proven"     value={metrics.povTriggered}  color="text-threat-300" subValue={`${metrics.povSuccessRate}% of confirmed`} />
        <StatCard icon={DollarSign}   label="Cost (USD)"     value={`$${metrics.cost.toFixed(4)}`} />
        <StatCard icon={Clock}        label="Duration"       value={`${metrics.duration.toFixed(1)}s`} />
      </div>

      {/* Charts */}
      <div className="grid md:grid-cols-2 gap-4">
        {/* Pie */}
        <div className="bg-gray-900/80 rounded-xl p-5 border border-gray-800/60">
          <h3 className="text-sm font-medium text-gray-300 mb-4">Findings Distribution</h3>
          {pieData.length > 0 ? (
            <>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" innerRadius={55} outerRadius={75} paddingAngle={4} dataKey="value">
                    {pieData.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                  </Pie>
                  <Tooltip contentStyle={TooltipStyle} />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex justify-center gap-4 mt-3">
                {pieData.map(entry => (
                  <div key={entry.name} className="flex items-center gap-1.5">
                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: entry.color }} />
                    <span className="text-xs text-gray-500">{entry.name}</span>
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="h-[200px] flex items-center justify-center text-gray-600 text-sm">No data</div>
          )}
        </div>

        {/* Rates */}
        <div className="bg-gray-900/80 rounded-xl p-5 border border-gray-800/60">
          <h3 className="text-sm font-medium text-gray-300 mb-4">Performance Rates</h3>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={[
              { name: 'Detection', value: parseFloat(metrics.detectionRate) },
              { name: 'False Pos.', value: parseFloat(metrics.fpRate) },
              { name: 'PoV Rate',   value: parseFloat(metrics.povSuccessRate) }
            ]} barSize={32}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" vertical={false} />
              <XAxis dataKey="name" stroke="#4b5563" tick={{ fontSize: 11 }} />
              <YAxis stroke="#4b5563" tick={{ fontSize: 11 }} unit="%" />
              <Tooltip contentStyle={TooltipStyle} formatter={(v) => [`${v}%`]} />
              <Bar dataKey="value" fill="#0ea5e9" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Detection Stats */}
      <div className="bg-gray-900/80 rounded-xl p-5 border border-gray-800/60">
        <div className="flex items-center gap-2 mb-4">
          <TrendingUp className="w-4 h-4 text-gray-500" />
          <h3 className="text-sm font-medium text-gray-300">Detection Statistics</h3>
        </div>
        <div className="grid md:grid-cols-3 gap-5">
          <ProgressBar label="Detection Rate"       value={metrics.detectionRate}   color="bg-safe-500" />
          <ProgressBar label="False Positive Rate"  value={metrics.fpRate}          color="bg-warn-500" />
          <ProgressBar label="PoV Success Rate"     value={metrics.povSuccessRate}  color="bg-threat-500" />
        </div>
      </div>

      {/* Cost Breakdown */}
      {costBreakdown && (
        <div className="bg-gray-900/80 rounded-xl border border-gray-800/60 overflow-hidden">
          <button
            onClick={() => setShowCostBreakdown(!showCostBreakdown)}
            className="w-full px-5 py-4 flex items-center justify-between hover:bg-gray-800/30 transition-colors"
          >
            <div className="flex items-center gap-2">
              <DollarSign className="w-4 h-4 text-gray-500" />
              <span className="text-sm font-medium text-gray-300">Cost Breakdown</span>
            </div>
            {showCostBreakdown ? <ChevronUp className="w-4 h-4 text-gray-500" /> : <ChevronDown className="w-4 h-4 text-gray-500" />}
          </button>

          {showCostBreakdown && (
            <div className="px-5 pb-5 border-t border-gray-800/60 space-y-4 pt-4">
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-gray-950/60 rounded-lg p-3 border border-gray-800/40">
                  <p className="text-xs text-gray-500 mb-1">Investigation</p>
                  <p className="text-sm font-semibold font-mono">${costBreakdown.purposeCosts.investigation.toFixed(6)}</p>
                </div>
                <div className="bg-gray-950/60 rounded-lg p-3 border border-gray-800/40">
                  <p className="text-xs text-gray-500 mb-1">PoV Generation</p>
                  <p className="text-sm font-semibold font-mono">${costBreakdown.purposeCosts.pov_generation.toFixed(6)}</p>
                </div>
              </div>

              <div className="space-y-2">
                <p className="text-xs text-gray-500 uppercase tracking-wide">By Model</p>
                {Object.entries(costBreakdown.modelCosts).map(([model, costs]) => (
                  <div key={model} className="bg-gray-950/60 rounded-lg p-3 border border-gray-800/40 flex justify-between items-start">
                    <div>
                      <p className="text-xs font-mono text-gray-300 truncate max-w-[200px]" title={model}>{model}</p>
                      <p className="text-xs text-gray-600 mt-0.5">
                        Inv: ${costs.investigation.toFixed(6)} · PoV: ${costs.pov_generation.toFixed(6)}
                      </p>
                    </div>
                    <p className="text-sm font-semibold font-mono shrink-0 ml-2">${costs.total.toFixed(6)}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default ResultsDashboard
