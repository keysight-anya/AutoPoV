import { useEffect, useMemo, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, Download, FileText } from 'lucide-react'
import ResultsDashboard from '../components/ResultsDashboard'
import FindingCard from '../components/FindingCard'
import { getScanStatus, getReport, getConfig } from '../api/client'

function Results() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const [result, setResult] = useState(null)
  const [config, setConfig] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [activeTab, setActiveTab] = useState('all')

  const [scanStatus, setScanStatus] = useState(null)
  const [scanError, setScanError] = useState(null)
  const [scanLogs, setScanLogs] = useState([])

  useEffect(() => {
    const fetchResults = async () => {
      try {
        const [scanRes, configRes] = await Promise.all([
          getScanStatus(scanId),
          getConfig().catch(() => null)
        ])
        const data = scanRes.data
        setScanStatus(data.status)
        setScanError(data.error || null)
        setScanLogs(data.logs || [])
        setResult(data.result)
        setConfig(configRes?.data || null)
      } catch (err) {
        setError(err.message)
      } finally {
        setLoading(false)
      }
    }

    fetchResults()
  }, [scanId])

  const downloadReport = async (format) => {
    try {
      const response = await getReport(scanId, format)

      const blob = new Blob([response.data], {
        type: format === 'pdf' ? 'application/pdf' : 'application/json'
      })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${scanId}_report.${format}`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (err) {
      console.error('Failed to download report:', err)
    }
  }

  const modelsUsed = useMemo(() => {
    if (!result?.findings) return []
    const modelsMap = new Map()
    
    result.findings.forEach((f) => {
      // Investigation model
      if (f.model_used) {
        if (!modelsMap.has(f.model_used)) {
          modelsMap.set(f.model_used, { model: f.model_used, roles: new Set(), count: 0 })
        }
        modelsMap.get(f.model_used).roles.add('investigation')
        modelsMap.get(f.model_used).count++
      }
      // PoV model
      if (f.pov_model_used) {
        if (!modelsMap.has(f.pov_model_used)) {
          modelsMap.set(f.pov_model_used, { model: f.pov_model_used, roles: new Set(), count: 0 })
        }
        modelsMap.get(f.pov_model_used).roles.add('pov_generation')
        modelsMap.get(f.pov_model_used).count++
      }
    })
    
    return Array.from(modelsMap.values())
  }, [result])

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
          <p className="text-red-300">Error loading results: {error}</p>
        </div>
      </div>
    )
  }

  if (!result) {
    const isFailed = scanStatus === 'failed'
    return (
      <div className="max-w-4xl mx-auto">
        <div className="flex items-center space-x-4 mb-6">
          <button onClick={() => navigate('/')} className="p-2 hover:bg-gray-800 rounded-lg transition-colors">
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <h1 className="text-2xl font-bold">Scan {isFailed ? 'Failed' : 'Results'}</h1>
            <p className="text-sm text-gray-400">ID: {scanId}</p>
          </div>
        </div>

        <div className={`p-4 rounded-lg border mb-4 ${isFailed ? 'bg-red-900/30 border-red-800' : 'bg-yellow-900/30 border-yellow-800'}`}>
          <p className={`font-medium mb-1 ${isFailed ? 'text-red-300' : 'text-yellow-300'}`}>
            {isFailed ? 'Scan failed — no results were produced.' : 'No results found for this scan.'}
          </p>
          {scanError && (
            <p className="text-sm text-red-400 mt-1 font-mono break-all">
              {scanError.split('\n')[0]}
            </p>
          )}
        </div>

        {scanLogs.length > 0 && (
          <div className="bg-gray-900 rounded-lg border border-gray-800 p-4">
            <h3 className="text-sm font-medium text-gray-400 mb-2">Scan Logs</h3>
            <div className="space-y-1 max-h-64 overflow-y-auto font-mono text-xs">
              {scanLogs.map((log, i) => (
                <div key={i} className={`${log.startsWith('ERROR') ? 'text-red-400' : 'text-gray-300'}`}>
                  {log}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    )
  }

  const confirmedFindings = result.findings?.filter(f => f.final_status === 'confirmed') || []
  const falsePositiveFindings = result.findings?.filter(f => f.final_status === 'skipped') || []
  const failedFindings = result.findings?.filter(f => f.final_status === 'failed') || []
  const pendingFindings = result.findings?.filter(f => !f.final_status || f.final_status === 'pending') || []

  return (
    <div className="max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center space-x-4">
          <button
            onClick={() => navigate('/')}
            className="p-2 hover:bg-gray-800 rounded-lg transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div>
            <h1 className="text-2xl font-bold">Scan Results</h1>
            <p className="text-sm text-gray-400">ID: {scanId}</p>
          </div>
        </div>

        <div className="flex space-x-3">
          <button
            onClick={() => downloadReport('json')}
            className="flex items-center space-x-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
          >
            <FileText className="w-4 h-4" />
            <span>JSON</span>
          </button>
          <button
            onClick={() => downloadReport('pdf')}
            className="flex items-center space-x-2 px-4 py-2 bg-primary-600 hover:bg-primary-700 rounded-lg transition-colors"
          >
            <Download className="w-4 h-4" />
            <span>PDF Report</span>
          </button>
        </div>
      </div>

      {/* Dashboard */}
      <ResultsDashboard result={result} />

      {/* All Findings Tabs */}
      <div className="mt-8">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xl font-bold">
            {activeTab === 'all' && 'All Findings'}
            {activeTab === 'confirmed' && 'Confirmed Vulnerabilities'}
            {activeTab === 'falsepositives' && 'False Positives'}
            {activeTab === 'failed' && 'Failed Analyses'}
            {activeTab === 'pending' && 'Pending Findings'}
          </h2>
          {activeTab !== 'all' && (
            <button 
              onClick={() => setActiveTab('all')}
              className="text-sm text-primary-400 hover:text-primary-300"
            >
              Show All →
            </button>
          )}
        </div>
        
        {/* Summary Stats - Clickable */}
        <div className="grid grid-cols-4 gap-4 mb-6">
          <button 
            onClick={() => setActiveTab('confirmed')}
            className={`bg-green-900/30 border border-green-800 rounded-lg p-4 text-left hover:bg-green-900/50 transition-colors ${activeTab === 'confirmed' ? 'ring-2 ring-green-500' : ''}`}
          >
            <p className="text-sm text-green-400">Confirmed</p>
            <p className="text-2xl font-bold text-green-400">{confirmedFindings.length}</p>
          </button>
          <button 
            onClick={() => setActiveTab('falsepositives')}
            className={`bg-yellow-900/30 border border-yellow-800 rounded-lg p-4 text-left hover:bg-yellow-900/50 transition-colors ${activeTab === 'falsepositives' ? 'ring-2 ring-yellow-500' : ''}`}
          >
            <p className="text-sm text-yellow-400">False Positives</p>
            <p className="text-2xl font-bold text-yellow-400">{falsePositiveFindings.length}</p>
          </button>
          <button 
            onClick={() => setActiveTab('failed')}
            className={`bg-red-900/30 border border-red-800 rounded-lg p-4 text-left hover:bg-red-900/50 transition-colors ${activeTab === 'failed' ? 'ring-2 ring-red-500' : ''}`}
          >
            <p className="text-sm text-red-400">Failed</p>
            <p className="text-2xl font-bold text-red-400">{failedFindings.length}</p>
          </button>
          <button 
            onClick={() => setActiveTab('pending')}
            className={`bg-gray-800 border border-gray-700 rounded-lg p-4 text-left hover:bg-gray-700 transition-colors ${activeTab === 'pending' ? 'ring-2 ring-gray-500' : ''}`}
          >
            <p className="text-sm text-gray-400">Pending</p>
            <p className="text-2xl font-bold text-gray-400">{pendingFindings.length}</p>
          </button>
        </div>

        {/* Confirmed Findings */}
        {(activeTab === 'all' || activeTab === 'confirmed') && confirmedFindings.length > 0 && (
          <div className="mb-6">
            <h3 className="text-lg font-semibold mb-3 text-green-400">Confirmed Vulnerabilities ({confirmedFindings.length})</h3>
            <div className="space-y-4">
              {confirmedFindings.map((finding, index) => (
                <FindingCard key={index} finding={finding} />
              ))}
            </div>
          </div>
        )}

        {/* False Positives */}
        {(activeTab === 'all' || activeTab === 'falsepositives') && falsePositiveFindings.length > 0 && (
          <div className="mb-6">
            <h3 className="text-lg font-semibold mb-3 text-yellow-400">False Positives ({falsePositiveFindings.length})</h3>
            <div className="space-y-4">
              {falsePositiveFindings.map((finding, index) => (
                <FindingCard key={index} finding={finding} />
              ))}
            </div>
          </div>
        )}

        {/* Failed */}
        {(activeTab === 'all' || activeTab === 'failed') && failedFindings.length > 0 && (
          <div className="mb-6">
            <h3 className="text-lg font-semibold mb-3 text-red-400">Failed Analyses ({failedFindings.length})</h3>
            <div className="space-y-4">
              {failedFindings.map((finding, index) => (
                <FindingCard key={index} finding={finding} />
              ))}
            </div>
          </div>
        )}

        {/* Pending */}
        {(activeTab === 'all' || activeTab === 'pending') && pendingFindings.length > 0 && (
          <div className="mb-6">
            <h3 className="text-lg font-semibold mb-3 text-gray-400">Pending ({pendingFindings.length})</h3>
            <div className="space-y-4">
              {pendingFindings.map((finding, index) => (
                <FindingCard key={index} finding={finding} />
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Scan Info */}
      <div className="mt-8 bg-gray-900 rounded-lg p-6 border border-gray-800">
        <h3 className="text-lg font-medium mb-4">Scan Information</h3>
        <div className="grid md:grid-cols-2 gap-4 text-sm">
          <div>
            <span className="text-gray-400">Routing Mode:</span>
            <span className="ml-2">{config?.routing_mode || 'auto'}</span>
          </div>
          <div>
            <span className="text-gray-400">Auto Router Model:</span>
            <span className="ml-2">{config?.auto_router_model || 'openrouter/auto'}</span>
          </div>
          <div>
            <span className="text-gray-400">Model Mode:</span>
            <span className="ml-2">{config?.model_mode || 'online'}</span>
          </div>
          <div className="col-span-2">
            <span className="text-gray-400">Models Used:</span>
            <div className="mt-2 space-y-1">
              {modelsUsed.length > 0 ? (
                modelsUsed.map((m, i) => (
                  <div key={i} className="text-sm bg-gray-800 rounded px-2 py-1 inline-block mr-2">
                    <span className="font-medium">{m.model}</span>
                    <span className="text-gray-500 ml-2">({Array.from(m.roles).join(', ')})</span>
                    <span className="text-gray-500 ml-2">- {m.count} findings</span>
                  </div>
                ))
              ) : (
                <span className="text-gray-500">N/A</span>
              )}
            </div>
          </div>
          <div>
            <span className="text-gray-400">CWEs Checked:</span>
            <span className="ml-2">{result.cwes?.join(', ')}</span>
          </div>
          <div>
            <span className="text-gray-400">Started:</span>
            <span className="ml-2">{new Date(result.start_time).toLocaleString()}</span>
          </div>
          <div>
            <span className="text-gray-400">Completed:</span>
            <span className="ml-2">
              {result.end_time ? new Date(result.end_time).toLocaleString() : 'N/A'}
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Results
