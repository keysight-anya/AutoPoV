import { useEffect, useMemo, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, Download, FileText, RefreshCw, X, Plus, Trash2 } from 'lucide-react'
import ResultsDashboard from '../components/ResultsDashboard'
import FindingCard from '../components/FindingCard'
import { getScanStatus, getReport, getConfig, replayScan } from '../api/client'

function Results() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const [result, setResult] = useState(null)
  const [config, setConfig] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [activeTab, setActiveTab] = useState('all')
  const [showReplayModal, setShowReplayModal] = useState(false)
  const [replayModels, setReplayModels] = useState([''])
  const [replayIncludeFailed, setReplayIncludeFailed] = useState(false)
  const [replayMaxFindings, setReplayMaxFindings] = useState(50)
  const [replayLoading, setReplayLoading] = useState(false)
  const [replayResult, setReplayResult] = useState(null)
  const [replayError, setReplayError] = useState(null)

  useEffect(() => {
    const fetchResults = async () => {
      try {
        const [scanRes, configRes] = await Promise.all([
          getScanStatus(scanId),
          getConfig().catch(() => null)
        ])
        setResult(scanRes.data.result)
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
    return (
      <div className="max-w-4xl mx-auto">
        <div className="p-4 bg-yellow-900/30 border border-yellow-800 rounded-lg">
          <p className="text-yellow-300">No results found for this scan</p>
        </div>
      </div>
    )
  }

  const confirmedFindings = result.findings?.filter(f => f.final_status === 'confirmed') || []
  const falsePositiveFindings = result.findings?.filter(f => f.final_status === 'skipped') || []
  const failedFindings = result.findings?.filter(f => f.final_status === 'failed') || []
  const pendingFindings = result.findings?.filter(f => !f.final_status || f.final_status === 'pending') || []

  const handleReplay = async () => {
    const models = replayModels.filter(m => m.trim())
    if (!models.length) return
    setReplayLoading(true)
    setReplayError(null)
    setReplayResult(null)
    try {
      const res = await replayScan(scanId, {
        models,
        include_failed: replayIncludeFailed,
        max_findings: replayMaxFindings
      })
      setReplayResult(res.data)
    } catch (err) {
      setReplayError(err.response?.data?.detail || err.message || 'Replay failed')
    } finally {
      setReplayLoading(false)
    }
  }

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
            onClick={() => { setShowReplayModal(true); setReplayResult(null); setReplayError(null) }}
            className="flex items-center space-x-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            <span>Replay</span>
          </button>
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

      {/* Replay Modal */}
      {showReplayModal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
          <div className="bg-gray-900 border border-gray-700 rounded-xl w-full max-w-lg mx-4 p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-bold">Replay Against Agent Models</h2>
              <button onClick={() => setShowReplayModal(false)} className="p-1 hover:bg-gray-800 rounded">
                <X className="w-5 h-5" />
              </button>
            </div>

            <p className="text-sm text-gray-400 mb-4">
              The Investigator Agent will re-analyse existing findings using the specified models,
              creating new scan runs you can compare via the Policy dashboard.
            </p>

            {/* Model list */}
            <div className="space-y-2 mb-4">
              <label className="block text-sm font-medium text-gray-400">Models to replay against</label>
              {replayModels.map((m, i) => (
                <div key={i} className="flex items-center space-x-2">
                  <input
                    type="text"
                    value={m}
                    onChange={e => {
                      const next = [...replayModels]
                      next[i] = e.target.value
                      setReplayModels(next)
                    }}
                    placeholder="e.g. anthropic/claude-3-opus"
                    className="flex-1 bg-gray-800 border border-gray-700 rounded px-3 py-1.5 text-sm text-gray-100 focus:outline-none focus:border-primary-500"
                  />
                  {replayModels.length > 1 && (
                    <button onClick={() => setReplayModels(replayModels.filter((_, j) => j !== i))}
                      className="p-1 hover:bg-gray-800 rounded text-red-400">
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </div>
              ))}
              <button
                onClick={() => setReplayModels([...replayModels, ''])}
                className="flex items-center space-x-1 text-sm text-primary-400 hover:text-primary-300 mt-1"
              >
                <Plus className="w-4 h-4" /> <span>Add model</span>
              </button>
            </div>

            {/* Options */}
            <div className="space-y-3 mb-4">
              <label className="flex items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" checked={replayIncludeFailed}
                  onChange={e => setReplayIncludeFailed(e.target.checked)}
                  className="accent-primary-500" />
                Include unconfirmed / failed findings
              </label>
              <div>
                <label className="block text-sm text-gray-400 mb-1">Max findings to replay</label>
                <input type="number" min={1} max={200} value={replayMaxFindings}
                  onChange={e => setReplayMaxFindings(Number(e.target.value))}
                  className="w-24 bg-gray-800 border border-gray-700 rounded px-2 py-1 text-sm text-gray-100 focus:outline-none focus:border-primary-500" />
              </div>
            </div>

            {replayError && (
              <div className="mb-3 p-3 bg-red-900/30 border border-red-800 rounded text-sm text-red-300">
                {replayError}
              </div>
            )}

            {replayResult && (
              <div className="mb-3 p-3 bg-green-900/20 border border-green-800 rounded text-sm text-green-300">
                Replay started! {replayResult.replay_ids?.length} scan(s) created.
                <br />
                <span className="text-gray-400">Track them in Scan History or the Policy dashboard.</span>
              </div>
            )}

            <div className="flex justify-end space-x-3">
              <button onClick={() => setShowReplayModal(false)}
                className="px-4 py-2 text-sm bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors">
                Close
              </button>
              <button onClick={handleReplay} disabled={replayLoading || replayModels.every(m => !m.trim())}
                className="flex items-center space-x-2 px-4 py-2 text-sm bg-primary-600 hover:bg-primary-700 disabled:bg-gray-700 rounded-lg transition-colors">
                <RefreshCw className={`w-4 h-4 ${replayLoading ? 'animate-spin' : ''}`} />
                <span>{replayLoading ? 'Starting...' : 'Start Replay'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

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
