import { useMemo } from 'react'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { CheckCircle, XCircle, AlertCircle, DollarSign, Clock } from 'lucide-react'

function ResultsDashboard({ result }) {
  const metrics = useMemo(() => {
    if (!result) return null
    
    const total = result.total_findings || 0
    const confirmed = result.confirmed_vulns || 0
    const fp = result.false_positives || 0
    const failed = result.failed || 0
    
    return {
      total,
      confirmed,
      fp,
      failed,
      detectionRate: total > 0 ? (confirmed / total * 100).toFixed(1) : 0,
      fpRate: total > 0 ? (fp / total * 100).toFixed(1) : 0,
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

  if (!metrics) {
    return <div className="text-gray-500">No results available</div>
  }

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
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
          <h3 className="text-lg font-medium mb-4">Metrics</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={[
              { name: 'Detection Rate', value: parseFloat(metrics.detectionRate) },
              { name: 'FP Rate', value: parseFloat(metrics.fpRate) }
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
        <div className="grid md:grid-cols-2 gap-4">
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
        </div>
      </div>
    </div>
  )
}

export default ResultsDashboard
