import { useEffect, useMemo, useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import { CheckCircle, Shield, StopCircle, XCircle, Trash2, AlertTriangle } from 'lucide-react'
import AgentPipeline from '../components/AgentPipeline'
import LiveLog from '../components/LiveLog'
import { cancelScan, stopScan, deleteScan, getScanLogs, getScanStatus } from '../api/client'

const RUNNING_STATUSES = [
  'created',
  'checking',
  'cloning',
  'ingesting',
  'running_codeql',
  'investigating',
  'generating_pov',
  'validating_pov',
  'running_pov',
  'running',
]

export default function ScanProgress() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const [logs, setLogs] = useState([])
  const [status, setStatus] = useState('running')
  const [scanInfo, setScanInfo] = useState(null)
  const [error, setError] = useState(null)
  const [cancelling, setCancelling] = useState(false)
  const [showStopConfirm, setShowStopConfirm] = useState(false)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [deleting, setDeleting] = useState(false)

  useEffect(() => {
    const pollStatus = async () => {
      try {
        const res = await getScanStatus(scanId)
        const data = res.data
        setScanInfo(data)
        setStatus(data.status)
        setLogs(data.logs || [])

        if (['completed', 'failed', 'cancelled', 'stopped', 'interrupted'].includes(data.status)) {
          try {
            const raw = localStorage.getItem('autopov_active_scans')
            const list = raw ? JSON.parse(raw) : []
            localStorage.setItem(
              'autopov_active_scans',
              JSON.stringify(Array.isArray(list) ? list.filter((id) => id !== scanId) : [])
            )
          } catch {}
          setTimeout(() => navigate(`/results/${scanId}`), 3000)
        }
      } catch (err) {
        const detail = err.response?.data?.detail
        if (err.response?.status === 404) {
          setStatus('interrupted')
          setError('Scan state is no longer active in memory. If the backend restarted, reopen the latest saved run from History.')
          return
        }
        setError(detail || err.message)
      }
    }

    pollStatus()
    const interval = setInterval(pollStatus, 2000)

    let eventSource
    try {
      eventSource = getScanLogs(scanId)
      eventSource.onmessage = (event) => {
        const data = JSON.parse(event.data)
        if (data.type === 'log') {
          setLogs((prev) => [...prev, data.message])
        } else if (data.type === 'complete') {
          setStatus(data.result?.status || 'completed')
        } else if (data.type === 'error') {
          setError(data.message)
        }
      }
      eventSource.onerror = () => {}
    } catch {}

    return () => {
      clearInterval(interval)
      if (eventSource) eventSource.close()
    }
  }, [scanId, navigate])

  const handleCancel = async () => {
    if (!scanId || cancelling) return
    setCancelling(true)
    setError(null)
    try {
      await cancelScan(scanId)
      setStatus('cancelling')
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to cancel scan')
    } finally {
      setCancelling(false)
    }
  }

  const handleStop = async () => {
    if (!scanId) return
    setShowStopConfirm(false)
    setCancelling(true)
    setError(null)
    try {
      await stopScan(scanId)
      setStatus('stopped')
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to stop scan')
    } finally {
      setCancelling(false)
    }
  }

  const handleDelete = async () => {
    if (!scanId) return
    setShowDeleteConfirm(false)
    setDeleting(true)
    setError(null)
    try {
      await deleteScan(scanId)
      navigate('/history')
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to delete scan')
    } finally {
      setDeleting(false)
    }
  }

  const totalFiles = scanInfo?.result?.language_info?.total_files || scanInfo?.language_info?.total_files || 0
  const totalLoc = scanInfo?.result?.total_loc || scanInfo?.result?.language_info?.total_loc || scanInfo?.language_info?.total_loc || 0

  const cfg = useMemo(() => {
    if (RUNNING_STATUSES.includes(status) || status === 'cancelling') {
      return {
        label: status === 'cancelling' ? 'Cancelling scan...' : `Scanning in progress${typeof scanInfo?.progress === 'number' ? ` (${scanInfo.progress}%)` : ''}`,
        sub: 'Analyzing codebase for vulnerabilities',
        color: 'text-primary-400',
        border: 'border-primary-500/30',
        bg: 'bg-primary-500/5',
      }
    }
    if (status === 'completed') {
      return {
        label: 'Scan completed',
        sub: 'Redirecting to results...',
        color: 'text-green-400',
        border: 'border-green-500/30',
        bg: 'bg-green-500/5',
      }
    }
    if (status === 'cancelled') {
      return {
        label: 'Scan cancelled',
        sub: 'No further work will be performed',
        color: 'text-yellow-400',
        border: 'border-yellow-500/30',
        bg: 'bg-yellow-500/5',
      }
    }
    if (status === 'stopped') {
      return {
        label: 'Scan stopped',
        sub: 'The scan was force-stopped and will not continue',
        color: 'text-yellow-400',
        border: 'border-yellow-500/30',
        bg: 'bg-yellow-500/5',
      }
    }
    if (status === 'interrupted') {
      return {
        label: 'Scan interrupted',
        sub: 'The backend no longer has active state for this scan',
        color: 'text-yellow-400',
        border: 'border-yellow-500/30',
        bg: 'bg-yellow-500/5',
      }
    }
    return {
      label: 'Scan failed',
      sub: 'Review the logs for the exact failure point',
      color: 'text-red-400',
      border: 'border-red-500/30',
      bg: 'bg-red-500/5',
    }
  }, [status, scanInfo?.progress])

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div
        style={{
          padding: '14px 20px',
          borderBottom: '1px solid var(--border1)',
          display: 'flex',
          alignItems: 'center',
          gap: 16,
          background: 'var(--surface1)',
          flexShrink: 0,
        }}
      >
        <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 10, color: 'var(--text3)' }}>
          SCAN ID
        </div>
        <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 11, color: 'var(--text2)' }}>{scanId}</div>
        {totalFiles > 0 && (
          <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 10, color: 'var(--text3)' }}>
            FILES <span style={{ color: 'var(--text2)', marginLeft: 6 }}>{totalFiles}</span>
          </div>
        )}
        {totalLoc > 0 && (
          <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 10, color: 'var(--text3)' }}>
            LOC <span style={{ color: 'var(--text2)', marginLeft: 6 }}>{totalLoc.toLocaleString()}</span>
          </div>
        )}

        <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
          {RUNNING_STATUSES.includes(status) && (
            <>
              <button
                onClick={handleCancel}
                disabled={cancelling}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium bg-yellow-900/30 hover:bg-yellow-900/50 border border-yellow-700/50 text-yellow-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <StopCircle className="w-3.5 h-3.5" />
                <span>{cancelling ? 'Cancelling...' : 'Cancel'}</span>
              </button>
              <button
                onClick={() => setShowStopConfirm(true)}
                disabled={cancelling}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium bg-threat-900/30 hover:bg-threat-900/50 border border-threat-700/50 text-threat-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>Force Stop</span>
              </button>
            </>
          )}
          {!RUNNING_STATUSES.includes(status) && status !== 'cancelling' && (
            <button
              onClick={() => setShowDeleteConfirm(true)}
              disabled={deleting}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium bg-red-900/30 hover:bg-red-900/50 border border-red-700/50 text-red-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <Trash2 className="w-3.5 h-3.5" />
              <span>{deleting ? 'Deleting...' : 'Delete Scan'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Stop Confirmation Dialog */}
      {showStopConfirm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-900 border border-gray-700 rounded-lg p-6 max-w-md mx-4">
            <div className="flex items-center gap-3 mb-4">
              <AlertTriangle className="w-6 h-6 text-red-400" />
              <h3 className="text-lg font-semibold text-white">Force Stop Scan?</h3>
            </div>
            <p className="text-gray-400 mb-6">
              This will immediately stop the scan regardless of what it's currently doing. 
              Any progress will be lost. This action cannot be undone.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setShowStopConfirm(false)}
                className="px-4 py-2 rounded-md text-sm font-medium bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-600"
              >
                Cancel
              </button>
              <button
                onClick={handleStop}
                className="px-4 py-2 rounded-md text-sm font-medium bg-red-600 hover:bg-red-500 text-white"
              >
                Force Stop
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Dialog */}
      {showDeleteConfirm && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <div className="bg-gray-900 border border-gray-700 rounded-lg p-6 max-w-md mx-4">
            <div className="flex items-center gap-3 mb-4">
              <Trash2 className="w-6 h-6 text-red-400" />
              <h3 className="text-lg font-semibold text-white">Delete Scan?</h3>
            </div>
            <p className="text-gray-400 mb-6">
              This will permanently delete this scan and all its data including findings, logs, and any saved snapshots.
              This action cannot be undone.
            </p>
            <div className="flex justify-end gap-3">
              <button
                onClick={() => setShowDeleteConfirm(false)}
                className="px-4 py-2 rounded-md text-sm font-medium bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-600"
              >
                Cancel
              </button>
              <button
                onClick={handleDelete}
                className="px-4 py-2 rounded-md text-sm font-medium bg-red-600 hover:bg-red-500 text-white"
              >
                Delete
              </button>
            </div>
          </div>
        </div>
      )}

      <div className={`flex items-center gap-4 p-5 rounded-xl border mb-5 ${cfg.border} ${cfg.bg}`} style={{ margin: 16 }}>
        {RUNNING_STATUSES.includes(status) || status === 'cancelling' ? (
          <div className="relative w-8 h-8 shrink-0">
            <Shield className="w-8 h-8 text-primary-500/30" />
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="w-4 h-4 border-2 border-primary-500 border-t-transparent rounded-full animate-spin" />
            </div>
          </div>
        ) : status === 'completed' ? (
          <CheckCircle className={`w-7 h-7 shrink-0 ${cfg.color}`} />
        ) : status === 'cancelled' ? (
          <StopCircle className={`w-7 h-7 shrink-0 ${cfg.color}`} />
        ) : (
          <XCircle className={`w-7 h-7 shrink-0 ${cfg.color}`} />
        )}
        <div>
          <p className={`font-semibold ${cfg.color}`}>{cfg.label}</p>
          <p className="text-sm text-gray-500 mt-0.5">{cfg.sub}</p>
        </div>
      </div>

      {error && (
        <div
          style={{
            padding: '10px 16px',
            background: 'rgba(239,68,68,0.1)',
            border: '1px solid rgba(239,68,68,0.3)',
            margin: '0 16px 12px',
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: 11,
            color: '#fca5a5',
          }}
        >
          {error}
        </div>
      )}

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <AgentPipeline logs={logs} status={status} />
        <LiveLog logs={logs} />
      </div>
    </div>
  )
}
