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
        if (data.logs) setLogs(data.logs)
        if (data.status === 'completed' || data.status === 'failed') {
          try {
            const raw  = localStorage.getItem('autopov_active_scans')
            const list = raw ? JSON.parse(raw) : []
            localStorage.setItem('autopov_active_scans', JSON.stringify(
              Array.isArray(list) ? list.filter(id => id !== scanId) : []
            ))
          } catch {}
          setTimeout(() => navigate(`/results/${scanId}`), 3000)
        }
      } catch (err) { setError(err.message) }
    }

    pollStatus()
    const interval = setInterval(pollStatus, 2000)

    let eventSource
    try {
      eventSource = getScanLogs(scanId)
      eventSource.onmessage = (e) => {
        const d = JSON.parse(e.data)
        if (d.type === 'log')      setLogs(prev => [...prev, d.message])
        if (d.type === 'complete') setStatus('completed')
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
        <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 12, color: 'var(--text2)' }}>
          {scanId}
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
          <span style={{ color: statusColor, fontSize: 8 }}>●</span>
          <span style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 10, letterSpacing: '.1em', color: statusColor }}>
            {statusLabel}
          </span>
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
