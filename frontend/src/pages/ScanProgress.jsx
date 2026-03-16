// frontend/src/pages/ScanProgress.jsx
import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import AgentPipeline from '../components/AgentPipeline'
import LiveLog from '../components/LiveLog'
import { getScanStatus, getScanLogs } from '../api/client'

export default function ScanProgress() {
  const { scanId } = useParams()
  const navigate   = useNavigate()
  const [logs,   setLogs]   = useState([])
  const [status, setStatus] = useState('running')
  const [error,  setError]  = useState(null)

  useEffect(() => {
    const pollStatus = async () => {
      try {
        const res  = await getScanStatus(scanId)
        const data = res.data
        setStatus(data.status)
<<<<<<< HEAD
        setLogs(data.logs || [])

        if (data.status === 'completed' || data.status === 'failed' || data.status === 'cancelled') {
=======
        if (data.logs) setLogs(data.logs)
        if (data.status === 'completed' || data.status === 'failed') {
>>>>>>> origin/sandbox/ui-overhaul
          try {
            const raw  = localStorage.getItem('autopov_active_scans')
            const list = raw ? JSON.parse(raw) : []
            localStorage.setItem('autopov_active_scans', JSON.stringify(
              Array.isArray(list) ? list.filter(id => id !== scanId) : []
            ))
          } catch {}
          setTimeout(() => navigate(`/results/${scanId}`), 3000)
        }
<<<<<<< HEAD
      } catch (err) {
        const detail = err.response?.data?.detail
        if (err.response?.status === 404) {
          setStatus('interrupted')
          setError('Scan state is no longer active in memory. If the backend restarted, reopen the latest saved run from History.')
          return
        }
        setError(detail || err.message)
      }
=======
      } catch (err) { setError(err.message) }
>>>>>>> origin/sandbox/ui-overhaul
    }

    pollStatus()
    const interval = setInterval(pollStatus, 2000)

    let eventSource
    try {
      eventSource = getScanLogs(scanId)
<<<<<<< HEAD
      eventSource.onmessage = (event) => {
        const data = JSON.parse(event.data)
        if (data.type === 'log') setLogs(prev => [...prev, data.message])
        else if (data.type === 'complete') setStatus(data.result?.status || 'completed')
        else if (data.type === 'error') setError(data.message)
=======
      eventSource.onmessage = (e) => {
        const d = JSON.parse(e.data)
        if (d.type === 'log')      setLogs(prev => [...prev, d.message])
        if (d.type === 'complete') setStatus('completed')
>>>>>>> origin/sandbox/ui-overhaul
      }
      eventSource.onerror = () => {}
    } catch {}

    return () => {
      clearInterval(interval)
      if (eventSource) eventSource.close()
    }
  }, [scanId, navigate])

  const statusColor =
    status === 'completed' ? '#22c55e'
  : status === 'failed'    ? '#ef4444'
  : 'var(--accent)'

  const statusLabel =
    status === 'completed' ? 'COMPLETED — redirecting to results…'
  : status === 'failed'    ? 'SCAN FAILED'
  : 'RUNNING…'

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      {/* Scan ID header */}
      <div style={{
        padding: '14px 20px',
        borderBottom: '1px solid var(--border1)',
        display: 'flex', alignItems: 'center', gap: 16,
        background: 'var(--surface1)',
        flexShrink: 0,
      }}>
        <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 10, color: 'var(--text3)' }}>
          SCAN ID
        </div>
<<<<<<< HEAD

        {/* Cancel button — only shown while scan is running */}
        {['created', 'checking', 'cloning', 'ingesting', 'running_codeql', 'investigating', 'generating_pov', 'validating_pov', 'running_pov', 'running'].includes(status) && (
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
        {['created', 'checking', 'cloning', 'ingesting', 'running_codeql', 'investigating', 'generating_pov', 'validating_pov', 'running_pov', 'running'].includes(status) ? (
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
=======
        <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 12, color: 'var(--text2)' }}>
          {scanId}
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ color: statusColor, fontSize: 8 }}>●</span>
          <span style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 10, letterSpacing: '.1em', color: statusColor }}>
            {statusLabel}
          </span>
>>>>>>> origin/sandbox/ui-overhaul
        </div>
      </div>

      {/* Error */}
      {error && (
        <div style={{ padding: '10px 16px', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', margin: 12, fontFamily: '"JetBrains Mono", monospace', fontSize: 11, color: '#fca5a5' }}>
          {error}
        </div>
      )}

      {/* Two-column body */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <AgentPipeline logs={logs} status={status} />
        <LiveLog logs={logs} />
      </div>
    </div>
  )
}
