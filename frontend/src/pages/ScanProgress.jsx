import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, CheckCircle, XCircle, Shield, StopCircle } from 'lucide-react'
import LiveLog from '../components/LiveLog'
import { getScanStatus, getScanLogs, cancelScan } from '../api/client'

const STATUS_CONFIG = {
  running:   { label: 'Scanning…',            sub: 'Analyzing codebase for vulnerabilities',         color: 'text-primary-400',  border: 'border-primary-500/20', bg: 'bg-primary-500/5' },
  completed: { label: 'Scan Complete',         sub: 'Redirecting to results…',                       color: 'text-safe-400',     border: 'border-safe-500/20',   bg: 'bg-safe-900/20' },
  failed:    { label: 'Scan Failed',           sub: 'Check logs below for details',                  color: 'text-threat-400',   border: 'border-threat-500/20', bg: 'bg-threat-900/20' },
  cancelled: { label: 'Scan Cancelled',        sub: 'The scan was stopped',                          color: 'text-warn-400',     border: 'border-warn-500/20',   bg: 'bg-warn-900/20' },
}

function ScanProgress() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const [logs, setLogs] = useState([])
  const [status, setStatus] = useState('running')
  const [error, setError] = useState(null)
  const [cancelling, setCancelling] = useState(false)

  useEffect(() => {
    const pollStatus = async () => {
      try {
        const response = await getScanStatus(scanId)
        const data = response.data
        setStatus(data.status)
        setLogs(data.logs || [])

        if (data.status === 'completed' || data.status === 'failed') {
          try {
            const raw = localStorage.getItem('autopov_active_scans')
            const list = raw ? JSON.parse(raw) : []
            const next = Array.isArray(list) ? list.filter(id => id !== scanId) : []
            localStorage.setItem('autopov_active_scans', JSON.stringify(next))
          } catch {}
          setTimeout(() => navigate(`/results/${scanId}`), 3000)
        }
      } catch (err) {
        setError(err.message)
      }
    }

    pollStatus()
    const interval = setInterval(pollStatus, 2000)

    let eventSource
    try {
      eventSource = getScanLogs(scanId)
      eventSource.onmessage = (event) => {
        const data = JSON.parse(event.data)
        if (data.type === 'log') setLogs(prev => [...prev, data.message])
        else if (data.type === 'complete') setStatus('completed')
      }
      eventSource.onerror = () => {}
    } catch {}

    return () => {
      clearInterval(interval)
      if (eventSource) eventSource.close()
    }
  }, [scanId, navigate])

  const cfg = STATUS_CONFIG[status] || STATUS_CONFIG.running

  const handleCancel = async () => {
    if (cancelling) return
    setCancelling(true)
    try {
      await cancelScan(scanId)
      setStatus('cancelled')
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to cancel scan')
      setCancelling(false)
    }
  }

  return (
    <div className="max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center justify-between gap-3 mb-6">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/')}
            className="p-2 hover:bg-gray-800/60 rounded-lg transition-colors text-gray-400 hover:text-gray-200"
          >
            <ArrowLeft className="w-4 h-4" />
          </button>
          <div>
            <h1 className="text-xl font-bold">Scan Progress</h1>
            <p className="text-xs text-gray-600 font-mono mt-0.5">{scanId}</p>
          </div>
        </div>

        {/* Cancel button — only shown while scan is running */}
        {status === 'running' && (
          <button
            onClick={handleCancel}
            disabled={cancelling}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm font-medium bg-threat-900/30 hover:bg-threat-900/50 border border-threat-700/50 text-threat-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <StopCircle className="w-3.5 h-3.5" />
            <span>{cancelling ? 'Cancelling…' : 'Cancel Scan'}</span>
          </button>
        )}
      </div>

      {/* Status card */}
      <div className={`flex items-center gap-4 p-5 rounded-xl border mb-5 ${cfg.border} ${cfg.bg}`}>
        {status === 'running' ? (
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

      {/* Poll error */}
      {error && (
        <div className="mb-5 p-3.5 bg-threat-900/20 border border-threat-500/20 rounded-xl text-sm text-threat-300">
          {error}
        </div>
      )}

      {/* Live logs */}
      <LiveLog logs={logs} />
    </div>
  )
}

export default ScanProgress
