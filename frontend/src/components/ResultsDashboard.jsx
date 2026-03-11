import { useMemo, useState } from 'react'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { CheckCircle, XCircle, AlertCircle, DollarSign, Clock, FlaskConical, ChevronDown, ChevronUp } from 'lucide-react'

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
      total,
      confirmed,
      fp,
      failed,
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
      { name: 'Confirmed', value: metrics.confirmed, color: '#10b981' },
      { name: 'False Positives', value: metrics.fp, color: '#f59e0b' },
      { name: 'Failed', value: metrics.failed, color: '#ef4444' }
    ].filter(d => d.value > 0)
  }, [metrics])

  // Calculate cost breakdown by model and purpose
  const costBreakdown = useMemo(() => {
    if (!result?.findings) return null
    
    const modelCosts = {}
    const purposeCosts = {
      investigation: 0,
      pov_generation: 0,
      validation: 0
    }
    
    result.findings.forEach(f => {
      // Investigation cost
      if (f.model_used && f.cost_usd) {
        if (!modelCosts[f.model_used]) {
          modelCosts[f.model_used] = { investigation: 0, pov_generation: 0, total: 0 }
        }
        modelCosts[f.model_used].investigation += f.cost_usd
        modelCosts[f.model_used].total += f.cost_usd
        purposeCosts.investigation += f.cost_usd
      }
      
      // PoV generation cost
      if (f.pov_model_used) {
        const povCost = f.pov_result?.cost_usd || f.validation_result?.cost_usd || 0
        if (povCost > 0) {
          if (!modelCosts[f.pov_model_used]) {
            modelCosts[f.pov_model_used] = { investigation: 0, pov_generation: 0, total: 0 }
          }
          modelCosts[f.pov_model_used].pov_generation += povCost
          modelCosts[f.pov_model_used].total += povCost
          purposeCosts.pov_generation += povCost
        }
      }
    })
    
    return { modelCosts, purposeCosts }
  }, [result])

  if (!metrics) {
    return <div className="text-gray-500">No results available</div>
  }

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="bg-gray-900 rounded-lg p-4 border border-gray-800">
          <div className="flex items-center space-x-2 text-gray-400 mb-2">
            <AlertCircle className="w-4 h-4" />
            <span className="text-sm">Total Findings</span>
          </div>
          <p className="text-2xl font-bold">{metrics.total}</p>
        </div>

        <div className="bg-gray-900 rounded-lg p-4 border border-gray-800">
          <div className="flex items-center space-x-2 text-green-400 mb-2">
            <CheckCircle className="w-4 h-4" />
            <span className="text-sm">Confirmed</span>
          </div>
          <p className="text-2xl font-bold text-green-400">{metrics.confirmed}</p>
        </div>

        <div className="bg-gray-900 rounded-lg p-4 border border-gray-800">
          <div className="flex items-center space-x-2 text-red-400 mb-2">
            <FlaskConical className="w-4 h-4" />
            <span className="text-sm">PoV Proven</span>
          </div>
          <p className="text-2xl font-bold text-red-300">{metrics.povTriggered}</p>
        </div>

        <div className="bg-gray-900 rounded-lg p-4 border border-gray-800">
          <div className="flex items-center space-x-2 text-gray-400 mb-2">
            <DollarSign className="w-4 h-4" />
            <span className="text-sm">Cost (USD)</span>
          </div>
          <p className="text-2xl font-bold">${metrics.cost.toFixed(4)}</p>
        </div>

        <div className="bg-gray-900 rounded-lg p-4 border border-gray-800">
          <div className="flex items-center space-x-2 text-gray-400 mb-2">
            <Clock className="w-4 h-4" />
            <span className="text-sm">Duration</span>
          </div>
          <p className="text-2xl font-bold">{metrics.duration.toFixed(1)}s</p>
        </div>
      </div>

      {/* Charts */}
      <div className="grid md:grid-cols-2 gap-6">
        {/* Pie Chart */}
        <div className="bg-gray-900 rounded-lg p-6 border border-gray-800">
          <h3 className="text-lg font-medium mb-4">Findings Distribution</h3>
          <ResponsiveContainer width="100%" height={250}>
            <PieChart>
              <Pie
                data={pieData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={80}
                paddingAngle={5}
                dataKey="value"
              >
                {pieData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ backgroundColor: '#1f2937', border: 'none', borderRadius: '8px' }}
              />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex justify-center space-x-4 mt-4">
            {pieData.map((entry) => (
              <div key={entry.name} className="flex items-center space-x-2">
                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: entry.color }} />
                <span className="text-sm text-gray-400">{entry.name}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Bar Chart */}
        <div className="bg-gray-900 rounded-lg p-6 border border-gray-800">
          <h3 className="text-lg font-medium mb-4">Rates</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={[
              { name: 'Detection Rate', value: parseFloat(metrics.detectionRate) },
              { name: 'FP Rate', value: parseFloat(metrics.fpRate) },
              { name: 'PoV Success', value: parseFloat(metrics.povSuccessRate) }
            ]}>
              <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
              <XAxis dataKey="name" stroke="#9ca3af" />
              <YAxis stroke="#9ca3af" />
              <Tooltip
                contentStyle={{ backgroundColor: '#1f2937', border: 'none', borderRadius: '8px' }}
              />
              <Bar dataKey="value" fill="#3b82f6" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Detection Stats */}
      <div className="bg-gray-900 rounded-lg p-6 border border-gray-800">
        <h3 className="text-lg font-medium mb-4">Detection Statistics</h3>
        <div className="grid md:grid-cols-3 gap-4">
          <div>
            <div className="flex justify-between mb-2">
              <span className="text-gray-400">Detection Rate</span>
              <span className="font-medium">{metrics.detectionRate}%</span>
            </div>
            <div className="w-full bg-gray-800 rounded-full h-2">
              <div
                className="bg-green-500 h-2 rounded-full transition-all"
                style={{ width: `${metrics.detectionRate}%` }}
              />
            </div>
          </div>
          <div>
            <div className="flex justify-between mb-2">
              <span className="text-gray-400">False Positive Rate</span>
              <span className="font-medium">{metrics.fpRate}%</span>
            </div>
            <div className="w-full bg-gray-800 rounded-full h-2">
              <div
                className="bg-yellow-500 h-2 rounded-full transition-all"
                style={{ width: `${metrics.fpRate}%` }}
              />
            </div>
          </div>
          <div>
            <div className="flex justify-between mb-2">
              <span className="text-gray-400">PoV Success Rate</span>
              <span className="font-medium">{metrics.povSuccessRate}%</span>
            </div>
            <div className="w-full bg-gray-800 rounded-full h-2">
              <div
                className="bg-red-500 h-2 rounded-full transition-all"
                style={{ width: `${metrics.povSuccessRate}%` }}
              />
            </div>
          </div>
        </div>
      </div>

      {/* Cost Breakdown */}
      {costBreakdown && (
        <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
          <button
            onClick={() => setShowCostBreakdown(!showCostBreakdown)}
            className="w-full p-6 flex items-center justify-between hover:bg-gray-800 transition-colors"
          >
            <div className="flex items-center space-x-2">
              <DollarSign className="w-5 h-5 text-gray-400" />
              <h3 className="text-lg font-medium">Cost Breakdown</h3>
            </div>
            {showCostBreakdown ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
          </button>
          
          {showCostBreakdown && (
            <div className="px-6 pb-6 border-t border-gray-800">
              {/* By Purpose */}
              <div className="mt-4">
                <h4 className="text-sm font-medium text-gray-400 mb-3">By Purpose</h4>
                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-gray-800 rounded-lg p-3">
                    <p className="text-sm text-gray-400">Investigation</p>
                    <p className="text-lg font-semibold">${costBreakdown.purposeCosts.investigation.toFixed(6)}</p>
                  </div>
                  <div className="bg-gray-800 rounded-lg p-3">
                    <p className="text-sm text-gray-400">PoV Generation</p>
                    <p className="text-lg font-semibold">${costBreakdown.purposeCosts.pov_generation.toFixed(6)}</p>
                  </div>
                </div>
              </div>
              
              {/* By Model */}
              <div className="mt-4">
                <h4 className="text-sm font-medium text-gray-400 mb-3">By Model</h4>
                <div className="space-y-2">
                  {Object.entries(costBreakdown.modelCosts).map(([model, costs]) => (
                    <div key={model} className="bg-gray-800 rounded-lg p-3">
                      <div className="flex justify-between items-start">
                        <div>
                          <p className="font-medium text-sm truncate" title={model}>{model}</p>
                          <p className="text-xs text-gray-400 mt-1">
                            Investigation: ${costs.investigation.toFixed(6)} | 
                            PoV: ${costs.pov_generation.toFixed(6)}
                          </p>
                        </div>
                        <p className="text-lg font-semibold">${costs.total.toFixed(6)}</p>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default ResultsDashboard
