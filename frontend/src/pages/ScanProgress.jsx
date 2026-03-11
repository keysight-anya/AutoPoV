import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, CheckCircle, XCircle, StopCircle } from 'lucide-react'
import LiveLog from '../components/LiveLog'
import { getScanStatus, getScanLogs, cancelScan } from '../api/client'

function ScanProgress() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const [logs, setLogs] = useState([])
  const [status, setStatus] = useState('running')
  const [result, setResult] = useState(null)
  const [error, setError] = useState(null)
  const [cancelling, setCancelling] = useState(false)

  useEffect(() => {
    // Poll for status
    const pollStatus = async () => {
      try {
        const response = await getScanStatus(scanId)
        const data = response.data
        
        setStatus(data.status)
        setLogs(data.logs || [])
        
        if (data.result) {
          setResult(data.result)
        }

        if (data.status === 'completed' || data.status === 'failed') {
          try {
            const raw = localStorage.getItem('autopov_active_scans')
            const list = raw ? JSON.parse(raw) : []
            const next = Array.isArray(list) ? list.filter(id => id !== scanId) : []
            localStorage.setItem('autopov_active_scans', JSON.stringify(next))
          } catch {}
          // Navigate to results after a delay
          setTimeout(() => {
            navigate(`/results/${scanId}`)
          }, 3000)
        }
      } catch (err) {
        setError(err.message)
      }
    }

    // Initial poll
    pollStatus()

    // Set up polling interval
    const interval = setInterval(pollStatus, 2000)

    // Set up SSE for live logs
    let eventSource
    try {
      eventSource = getScanLogs(scanId)
      eventSource.onmessage = (event) => {
        const data = JSON.parse(event.data)
        if (data.type === 'log') {
          setLogs(prev => [...prev, data.message])
        } else if (data.type === 'complete') {
          setResult(data.result)
          setStatus('completed')
        }
      }
      eventSource.onerror = () => {
        // SSE error, polling will handle updates
      }
    } catch (err) {
      // SSE not available, polling will handle updates
    }

    return () => {
      clearInterval(interval)
      if (eventSource) {
        eventSource.close()
      }
    }
  }, [scanId, navigate])

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

  const getStatusIcon = () => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-6 h-6 text-green-400" />
      case 'failed':
        return <XCircle className="w-6 h-6 text-red-400" />
      case 'cancelled':
        return <StopCircle className="w-6 h-6 text-yellow-400" />
      default:
        return (
          <div className="w-6 h-6 border-2 border-primary-500 border-t-transparent rounded-full animate-spin" />
        )
    }
  }

  return (
    <div className="max-w-4xl mx-auto">
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
            <h1 className="text-2xl font-bold">Scan Progress</h1>
            <p className="text-sm text-gray-400">ID: {scanId}</p>
          </div>
        </div>

        {/* Cancel button — only shown while scan is running */}
        {status === 'running' && (
          <button
            onClick={handleCancel}
            disabled={cancelling}
            className="flex items-center space-x-2 px-4 py-2 bg-red-900/40 hover:bg-red-900/70 border border-red-700 text-red-300 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <StopCircle className="w-4 h-4" />
            <span>{cancelling ? 'Cancelling...' : 'Cancel Scan'}</span>
          </button>
        )}
      </div>

      {/* Status */}
      <div className="bg-gray-900 rounded-lg p-6 border border-gray-800 mb-6">
        <div className="flex items-center space-x-3">
          {getStatusIcon()}
          <div>
            <p className="font-medium capitalize">{status}</p>
            {status === 'running' && (
              <p className="text-sm text-gray-400">Scanning for vulnerabilities...</p>
            )}
            {status === 'completed' && (
              <p className="text-sm text-green-400">Scan complete! Redirecting to results...</p>
            )}
            {status === 'failed' && (
              <p className="text-sm text-red-400">Scan failed. Check logs for details.</p>
            )}
            {status === 'cancelled' && (
              <p className="text-sm text-yellow-400">Scan was cancelled.</p>
            )}
          </div>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="mb-6 p-4 bg-red-900/30 border border-red-800 rounded-lg">
          <p className="text-red-300">{error}</p>
        </div>
      )}

      {/* Live Logs */}
      <LiveLog logs={logs} />
    </div>
  )
}

export default ScanProgress
