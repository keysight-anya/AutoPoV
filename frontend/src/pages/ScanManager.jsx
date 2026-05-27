import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { 
  Play, 
  Square, 
  Trash2, 
  RefreshCw, 
  AlertTriangle, 
  CheckCircle, 
  XCircle, 
  Clock,
  Search,
  Filter,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Shield,
  Activity,
  Database
} from 'lucide-react'
import { 
  getActiveScans, 
  getHistory, 
  getCacheStats,
  clearCache,
  cleanupStuckScans,
  stopScan, 
  deleteScan,
  cancelScan 
} from '../api/client'

const STATUS_COLORS = {
  running: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
  investigating: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
  generating_pov: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
  validating_pov: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
  running_pov: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
  ingesting: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
  checking: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
  cloning: 'text-blue-400 bg-blue-400/10 border-blue-400/30',
  completed: 'text-green-400 bg-green-400/10 border-green-400/30',
  confirmed: 'text-green-400 bg-green-400/10 border-green-400/30',
  cancelled: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
  stopped: 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30',
  failed: 'text-red-400 bg-red-400/10 border-red-400/30',
  error: 'text-red-400 bg-red-400/10 border-red-400/30',
  pending: 'text-gray-400 bg-gray-400/10 border-gray-400/30',
  created: 'text-gray-400 bg-gray-400/10 border-gray-400/30',
}

const STATUS_ICONS = {
  running: Activity,
  investigating: Activity,
  generating_pov: Activity,
  validating_pov: Activity,
  running_pov: Activity,
  ingesting: Activity,
  checking: Activity,
  cloning: Activity,
  completed: CheckCircle,
  confirmed: CheckCircle,
  cancelled: Square,
  stopped: Square,
  failed: XCircle,
  error: XCircle,
  pending: Clock,
  created: Clock,
}

// Statuses that are truly active (running)
const ACTIVE_STATUSES = [
  'running', 'investigating', 'generating_pov', 'validating_pov', 
  'running_pov', 'ingesting', 'checking', 'cloning', 'created', 'pending'
]

// Statuses that can be cancelled/stopped
const CANCELLABLE_STATUSES = ACTIVE_STATUSES

export default function ScanManager() {
  const navigate = useNavigate()
  const [activeScans, setActiveScans] = useState([])
  const [historyScans, setHistoryScans] = useState([])
  const [cacheStats, setCacheStats] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('all') // all, active, completed, failed
  const [searchQuery, setSearchQuery] = useState('')
  const [expandedScans, setExpandedScans] = useState(new Set())
  const [actionInProgress, setActionInProgress] = useState({})
  const [showConfirmDialog, setShowConfirmDialog] = useState(null)
  const [refreshInterval, setRefreshInterval] = useState(null)

  const fetchData = async () => {
    try {
      setError(null)
      const [activeRes, historyRes, cacheRes] = await Promise.all([
        getActiveScans(),
        getHistory(100, 0),
        getCacheStats()
      ])
      
      setActiveScans(activeRes.data?.active_scans || [])
      setHistoryScans(historyRes.data?.history || [])
      setCacheStats(cacheRes.data)
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to fetch scan data')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchData()
    // Auto-refresh every 5 seconds when viewing active scans
    const interval = setInterval(fetchData, 5000)
    setRefreshInterval(interval)
    return () => clearInterval(interval)
  }, [])

  const handleStop = async (scanId) => {
    setActionInProgress(prev => ({ ...prev, [scanId]: 'stopping' }))
    try {
      await stopScan(scanId)
      await fetchData()
    } catch (err) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setActionInProgress(prev => ({ ...prev, [scanId]: null }))
      setShowConfirmDialog(null)
    }
  }

  const handleCancel = async (scanId) => {
    setActionInProgress(prev => ({ ...prev, [scanId]: 'cancelling' }))
    try {
      await cancelScan(scanId)
      await fetchData()
    } catch (err) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setActionInProgress(prev => ({ ...prev, [scanId]: null }))
    }
  }

  const handleDelete = async (scanId) => {
    setActionInProgress(prev => ({ ...prev, [scanId]: 'deleting' }))
    try {
      await deleteScan(scanId)
      await fetchData()
    } catch (err) {
      setError(err.response?.data?.detail || err.message)
    } finally {
      setActionInProgress(prev => ({ ...prev, [scanId]: null }))
      setShowConfirmDialog(null)
    }
  }

  const handleClearCache = async () => {
    try {
      await clearCache()
      await fetchData()
    } catch (err) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const handleCleanupStuck = async () => {
    try {
      await cleanupStuckScans()
      await fetchData()
    } catch (err) {
      setError(err.response?.data?.detail || err.message)
    }
  }

  const toggleExpand = (scanId) => {
    setExpandedScans(prev => {
      const newSet = new Set(prev)
      if (newSet.has(scanId)) {
        newSet.delete(scanId)
      } else {
        newSet.add(scanId)
      }
      return newSet
    })
  }

  // Combine and de-duplicate scans by scan_id
  const scanMap = new Map()
  ;[
    ...historyScans.map(s => ({ ...s, isActive: false })),
    ...activeScans.map(s => ({ ...s, isActive: true }))
  ].forEach((scan) => {
    const existing = scanMap.get(scan.scan_id)
    if (!existing) {
      scanMap.set(scan.scan_id, scan)
      return
    }

    const scanIsActive = ACTIVE_STATUSES.includes(scan.status)
    const existingIsActive = ACTIVE_STATUSES.includes(existing.status)
    if (scanIsActive && !existingIsActive) return
    if (!scanIsActive && existingIsActive) {
      scanMap.set(scan.scan_id, scan)
      return
    }

    const scanTime = new Date(scan.created_at || scan.start_time || 0).getTime()
    const existingTime = new Date(existing.created_at || existing.start_time || 0).getTime()
    if (scanTime >= existingTime) {
      scanMap.set(scan.scan_id, scan)
    }
  })
  const allScans = Array.from(scanMap.values())

  const filteredScans = allScans.filter(scan => {
    // Filter by status
    if (filter === 'active') return ACTIVE_STATUSES.includes(scan.status)
    if (filter === 'completed') return scan.status === 'completed'
    if (filter === 'failed') return ['failed', 'error'].includes(scan.status)
    
    // Filter by search query
    if (searchQuery) {
      const query = searchQuery.toLowerCase()
      return (
        scan.scan_id?.toLowerCase().includes(query) ||
        scan.status?.toLowerCase().includes(query) ||
        scan.model_name?.toLowerCase().includes(query)
      )
    }
    
    return true
  })

  // Sort: active first, then by date
  const sortedScans = filteredScans.sort((a, b) => {
    const aIsActive = ACTIVE_STATUSES.includes(a.status)
    const bIsActive = ACTIVE_STATUSES.includes(b.status)
    if (aIsActive && !bIsActive) return -1
    if (!aIsActive && bIsActive) return 1
    return new Date(b.created_at || b.start_time) - new Date(a.created_at || a.start_time)
  })

  const formatDate = (dateStr) => {
    if (!dateStr) return 'N/A'
    const date = new Date(dateStr)
    return date.toLocaleString()
  }

  const formatDuration = (seconds) => {
    const numericSeconds = Number(seconds)
    if (!Number.isFinite(numericSeconds) || numericSeconds < 0) return 'N/A'
    const mins = Math.floor(numericSeconds / 60)
    const secs = Math.floor(numericSeconds % 60)
    if (mins > 60) {
      const hours = Math.floor(mins / 60)
      return `${hours}h ${mins % 60}m`
    }
    return `${mins}m ${secs}s`
  }

  const formatCurrency = (value) => {
    const numericValue = Number(value)
    if (!Number.isFinite(numericValue)) return 'N/A'
    return `$${numericValue.toFixed(4)}`
  }

  const formatProgress = (value) => {
    const numericValue = Number(value)
    if (!Number.isFinite(numericValue)) return 'N/A'
    return `${numericValue}%`
  }

  return (
    <div style={{ padding: '20px', height: '100%', overflowY: 'auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
          <Shield className="w-6 h-6 text-primary-400" />
          <h1 style={{ 
            fontFamily: '"JetBrains Mono", monospace', 
            fontSize: 20, 
            fontWeight: 600,
            color: 'var(--text1)',
            letterSpacing: '.05em'
          }}>
            SCAN MANAGER
          </h1>
        </div>
        <p style={{ color: 'var(--text3)', fontSize: 13 }}>
          Manage all scans, view active jobs, and control scan lifecycle
        </p>
      </div>

      {/* Stats Bar */}
      <div style={{ 
        display: 'grid', 
        gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', 
        gap: 12,
        marginBottom: 20 
      }}>
        <div style={{ 
          padding: 16, 
          background: 'var(--surface1)', 
          border: '1px solid var(--border1)',
          borderRadius: 8
        }}>
          <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>ACTIVE SCANS</div>
          <div style={{ fontSize: 24, fontWeight: 600, color: 'var(--accent)' }}>
            {activeScans.filter(s => ACTIVE_STATUSES.includes(s.status)).length}
          </div>
        </div>
        <div style={{ 
          padding: 16, 
          background: 'var(--surface1)', 
          border: '1px solid var(--border1)',
          borderRadius: 8
        }}>
          <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>TOTAL SCANS</div>
          <div style={{ fontSize: 24, fontWeight: 600, color: 'var(--text2)' }}>
            {historyScans.length}
          </div>
        </div>
        <div style={{ 
          padding: 16, 
          background: 'var(--surface1)', 
          border: '1px solid var(--border1)',
          borderRadius: 8
        }}>
          <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>CACHE ENTRIES</div>
          <div style={{ fontSize: 24, fontWeight: 600, color: 'var(--text2)' }}>
            {(cacheStats?.prompt_cache_entries || 0) + (cacheStats?.result_cache_entries || 0)}
          </div>
        </div>
        <div style={{ 
          padding: 16, 
          background: 'var(--surface1)', 
          border: '1px solid var(--border1)',
          borderRadius: 8
        }}>
          <div style={{ fontSize: 11, color: 'var(--text3)', marginBottom: 4 }}>CACHE HITS</div>
          <div style={{ fontSize: 24, fontWeight: 600, color: 'var(--success)' }}>
            {cacheStats?.prompt_cache_hits || 0}
          </div>
        </div>
      </div>

      {/* Controls */}
      <div style={{ 
        display: 'flex', 
        gap: 12, 
        marginBottom: 20,
        flexWrap: 'wrap',
        alignItems: 'center'
      }}>
        {/* Search */}
        <div style={{ position: 'relative', flex: 1, minWidth: 200 }}>
          <Search className="w-4 h-4" style={{ 
            position: 'absolute', 
            left: 12, 
            top: '50%', 
            transform: 'translateY(-50%)',
            color: 'var(--text3)'
          }} />
          <input
            type="text"
            placeholder="Search scans..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            style={{
              width: '100%',
              padding: '10px 12px 10px 40px',
              background: 'var(--surface1)',
              border: '1px solid var(--border1)',
              borderRadius: 6,
              color: 'var(--text1)',
              fontSize: 13,
              outline: 'none',
            }}
          />
        </div>

        {/* Filter Buttons */}
        <div style={{ display: 'flex', gap: 8 }}>
          {['all', 'active', 'completed', 'failed'].map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              style={{
                padding: '10px 16px',
                background: filter === f ? 'var(--accent)' : 'var(--surface1)',
                border: '1px solid var(--border1)',
                borderRadius: 6,
                color: filter === f ? '#000' : 'var(--text2)',
                fontSize: 12,
                fontWeight: 500,
                textTransform: 'uppercase',
                letterSpacing: '.05em',
                cursor: 'pointer',
              }}
            >
              {f}
            </button>
          ))}
        </div>

        {/* Refresh Button */}
        <button
          onClick={fetchData}
          disabled={loading}
          style={{
            padding: '10px 16px',
            background: 'var(--surface1)',
            border: '1px solid var(--border1)',
            borderRadius: 6,
            color: 'var(--text2)',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            cursor: loading ? 'not-allowed' : 'pointer',
            opacity: loading ? 0.6 : 1,
          }}
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          <span>Refresh</span>
        </button>

        {/* Clear Cache Button */}
        <button
          onClick={handleClearCache}
          style={{
            padding: '10px 16px',
            background: 'var(--surface1)',
            border: '1px solid var(--border1)',
            borderRadius: 6,
            color: 'var(--text2)',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            cursor: 'pointer',
          }}
        >
          <Database className="w-4 h-4" />
          <span>Clear Cache</span>
        </button>

        {/* Cleanup Stuck Scans Button */}
        <button
          onClick={handleCleanupStuck}
          style={{
            padding: '10px 16px',
            background: 'var(--surface1)',
            border: '1px solid var(--border1)',
            borderRadius: 6,
            color: 'var(--text2)',
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            cursor: 'pointer',
          }}
        >
          <Trash2 className="w-4 h-4" />
          <span>Cleanup Stuck</span>
        </button>
      </div>

      {/* Error */}
      {error && (
        <div style={{
          padding: '12px 16px',
          background: 'rgba(239, 68, 68, 0.1)',
          border: '1px solid rgba(239, 68, 68, 0.3)',
          borderRadius: 6,
          marginBottom: 16,
          color: '#fca5a5',
          fontSize: 13,
        }}>
          {error}
        </div>
      )}

      {/* Scans List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {sortedScans.length === 0 ? (
          <div style={{
            padding: 40,
            textAlign: 'center',
            color: 'var(--text3)',
            background: 'var(--surface1)',
            border: '1px solid var(--border1)',
            borderRadius: 8,
          }}>
            <Shield className="w-12 h-12 mx-auto mb-4 opacity-30" />
            <p>No scans found</p>
          </div>
        ) : (
          sortedScans.map((scan) => {
            const StatusIcon = STATUS_ICONS[scan.status] || Clock
            const isExpanded = expandedScans.has(scan.scan_id)
            const isActive = ACTIVE_STATUSES.includes(scan.status)
            const action = actionInProgress[scan.scan_id]

            return (
              <div
                key={scan.scan_id}
                style={{
                  background: 'var(--surface1)',
                  border: '1px solid var(--border1)',
                  borderRadius: 8,
                  overflow: 'hidden',
                }}
              >
                {/* Main Row */}
                <div
                  style={{
                    padding: '16px 20px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 16,
                    cursor: 'pointer',
                  }}
                  onClick={() => toggleExpand(scan.scan_id)}
                >
                  {/* Expand Icon */}
                  <button style={{ 
                    background: 'none', 
                    border: 'none', 
                    color: 'var(--text3)',
                    padding: 4,
                  }}>
                    {isExpanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
                  </button>

                  {/* Status */}
                  <div style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                    padding: '6px 12px',
                    borderRadius: 4,
                    fontSize: 11,
                    fontWeight: 500,
                    textTransform: 'uppercase',
                    letterSpacing: '.05em',
                    whiteSpace: 'nowrap',
                    ...parseStatusColor(scan.status),
                  }}>
                    <StatusIcon className="w-3.5 h-3.5" />
                    {scan.status}
                  </div>

                  {/* Scan ID */}
                  <div style={{ 
                    fontFamily: '"JetBrains Mono", monospace', 
                    fontSize: 12,
                    color: 'var(--text2)',
                    minWidth: 220,
                  }}>
                    {scan.scan_id}
                  </div>

                  {/* Model */}
                  <div style={{ 
                    fontSize: 12, 
                    color: 'var(--text3)',
                    flex: 1,
                  }}>
                    {scan.model_name || 'N/A'}
                  </div>

                  {/* Date */}
                  <div style={{ 
                    fontSize: 12, 
                    color: 'var(--text3)',
                    minWidth: 150,
                  }}>
                    {formatDate(scan.created_at || scan.start_time)}
                  </div>

                  {/* Findings */}
                  <div style={{ 
                    fontSize: 12, 
                    color: 'var(--text2)',
                    minWidth: 80,
                    textAlign: 'right'
                  }}>
                    {scan.total_findings !== undefined ? `${scan.total_findings} findings` : 
                     scan.findings_count !== undefined ? `${scan.findings_count} findings` : '-'}
                  </div>

                  {/* Actions */}
                  <div style={{ display: 'flex', gap: 8 }}>
                    {isActive && (
                      <>
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            handleCancel(scan.scan_id)
                          }}
                          disabled={action}
                          style={{
                            padding: '8px 12px',
                            background: 'rgba(234, 179, 8, 0.1)',
                            border: '1px solid rgba(234, 179, 8, 0.3)',
                            borderRadius: 4,
                            color: '#eab308',
                            fontSize: 11,
                            display: 'flex',
                            alignItems: 'center',
                            gap: 6,
                            cursor: action ? 'not-allowed' : 'pointer',
                            opacity: action ? 0.6 : 1,
                          }}
                        >
                          <Square className="w-3.5 h-3.5" />
                          {action === 'cancelling' ? '...' : 'Cancel'}
                        </button>
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            setShowConfirmDialog({ scanId: scan.scan_id, action: 'stop' })
                          }}
                          disabled={action}
                          style={{
                            padding: '8px 12px',
                            background: 'rgba(239, 68, 68, 0.1)',
                            border: '1px solid rgba(239, 68, 68, 0.3)',
                            borderRadius: 4,
                            color: '#ef4444',
                            fontSize: 11,
                            display: 'flex',
                            alignItems: 'center',
                            gap: 6,
                            cursor: action ? 'not-allowed' : 'pointer',
                            opacity: action ? 0.6 : 1,
                          }}
                        >
                          <AlertTriangle className="w-3.5 h-3.5" />
                          {action === 'stopping' ? '...' : 'Stop'}
                        </button>
                      </>
                    )}
                    
                    {!isActive && (
                      <button
                        onClick={(e) => {
                          e.stopPropagation()
                          setShowConfirmDialog({ scanId: scan.scan_id, action: 'delete' })
                        }}
                        disabled={action}
                        style={{
                          padding: '8px 12px',
                          background: 'rgba(239, 68, 68, 0.1)',
                          border: '1px solid rgba(239, 68, 68, 0.3)',
                          borderRadius: 4,
                          color: '#ef4444',
                          fontSize: 11,
                          display: 'flex',
                          alignItems: 'center',
                          gap: 6,
                          cursor: action ? 'not-allowed' : 'pointer',
                          opacity: action ? 0.6 : 1,
                        }}
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        {action === 'deleting' ? '...' : 'Delete'}
                      </button>
                    )}

                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        navigate(`/scan/${scan.scan_id}`)
                      }}
                      style={{
                        padding: '8px 12px',
                        background: 'var(--surface2)',
                        border: '1px solid var(--border2)',
                        borderRadius: 4,
                        color: 'var(--text2)',
                        fontSize: 11,
                        display: 'flex',
                        alignItems: 'center',
                        gap: 6,
                        cursor: 'pointer',
                      }}
                    >
                      <ExternalLink className="w-3.5 h-3.5" />
                      View
                    </button>
                  </div>
                </div>

                {/* Expanded Details */}
                {isExpanded && (
                  <div style={{
                    padding: '16px 20px',
                    borderTop: '1px solid var(--border1)',
                    background: 'rgba(0,0,0,0.2)',
                  }}>
                    <div style={{ 
                      display: 'grid', 
                      gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                      gap: 16,
                      fontSize: 12,
                    }}>
                      <div>
                        <span style={{ color: 'var(--text3)' }}>Scan ID: </span>
                        <span style={{ color: 'var(--text2)', fontFamily: '"JetBrains Mono", monospace' }}>
                          {scan.scan_id}
                        </span>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text3)' }}>Status: </span>
                        <span style={{ color: 'var(--text2)' }}>{scan.status}</span>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text3)' }}>Model: </span>
                        <span style={{ color: 'var(--text2)' }}>{scan.model_name || 'N/A'}</span>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text3)' }}>Created: </span>
                        <span style={{ color: 'var(--text2)' }}>
                          {formatDate(scan.created_at || scan.start_time)}
                        </span>
                      </div>
                      {scan.duration_s && (
                        <div>
                          <span style={{ color: 'var(--text3)' }}>Duration: </span>
                          <span style={{ color: 'var(--text2)' }}>{formatDuration(scan.duration_s)}</span>
                        </div>
                      )}
                      {scan.total_findings !== undefined && (
                        <div>
                          <span style={{ color: 'var(--text3)' }}>Total Findings: </span>
                          <span style={{ color: 'var(--text2)' }}>{scan.total_findings}</span>
                        </div>
                      )}
                      {scan.confirmed_vulns !== undefined && (
                        <div>
                          <span style={{ color: 'var(--text3)' }}>Confirmed: </span>
                          <span style={{ color: 'var(--success)' }}>{scan.confirmed_vulns}</span>
                        </div>
                      )}
                      {scan.false_positives !== undefined && (
                        <div>
                          <span style={{ color: 'var(--text3)' }}>False Positives: </span>
                          <span style={{ color: 'var(--text2)' }}>{scan.false_positives}</span>
                        </div>
                      )}
                      {scan.failed !== undefined && (
                        <div>
                          <span style={{ color: 'var(--text3)' }}>Failed: </span>
                          <span style={{ color: 'var(--text2)' }}>{scan.failed}</span>
                        </div>
                      )}
                      {scan.total_cost_usd !== undefined && (
                        <div>
                          <span style={{ color: 'var(--text3)' }}>Cost: </span>
                          <span style={{ color: 'var(--text2)' }}>{formatCurrency(scan.total_cost_usd)}</span>
                        </div>
                      )}
                      {scan.progress !== undefined && (
                        <div>
                          <span style={{ color: 'var(--text3)' }}>Progress: </span>
                          <span style={{ color: 'var(--text2)' }}>{formatProgress(scan.progress)}</span>
                        </div>
                      )}
                      {scan.detected_language && (
                        <div>
                          <span style={{ color: 'var(--text3)' }}>Language: </span>
                          <span style={{ color: 'var(--text2)' }}>{scan.detected_language}</span>
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            )
          })
        )}
      </div>

      {/* Confirmation Dialog */}
      {showConfirmDialog && (
        <div style={{
          position: 'fixed',
          inset: 0,
          background: 'rgba(0,0,0,0.7)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 100,
        }}>
          <div style={{
            background: 'var(--surface1)',
            border: '1px solid var(--border2)',
            borderRadius: 8,
            padding: 24,
            maxWidth: 400,
            width: '90%',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
              <AlertTriangle className="w-6 h-6 text-red-400" />
              <h3 style={{ fontSize: 16, fontWeight: 600, color: 'var(--text1)' }}>
                {showConfirmDialog.action === 'stop' ? 'Force Stop Scan?' : 'Delete Scan?'}
              </h3>
            </div>
            <p style={{ color: 'var(--text3)', marginBottom: 24, fontSize: 13 }}>
              {showConfirmDialog.action === 'stop' 
                ? 'This will immediately stop the scan regardless of what it\'s currently doing. Any progress will be lost.'
                : 'This will permanently delete this scan and all its data including findings, logs, and snapshots.'}
              This action cannot be undone.
            </p>
            <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
              <button
                onClick={() => setShowConfirmDialog(null)}
                style={{
                  padding: '10px 16px',
                  background: 'var(--surface2)',
                  border: '1px solid var(--border2)',
                  borderRadius: 6,
                  color: 'var(--text2)',
                  fontSize: 13,
                  cursor: 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  if (showConfirmDialog.action === 'stop') {
                    handleStop(showConfirmDialog.scanId)
                  } else {
                    handleDelete(showConfirmDialog.scanId)
                  }
                }}
                style={{
                  padding: '10px 16px',
                  background: '#dc2626',
                  border: 'none',
                  borderRadius: 6,
                  color: '#fff',
                  fontSize: 13,
                  cursor: 'pointer',
                }}
              >
                {showConfirmDialog.action === 'stop' ? 'Force Stop' : 'Delete'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// Helper to parse status colors
function parseStatusColor(status) {
  const colorClass = STATUS_COLORS[status] || STATUS_COLORS.pending
  const [color, bg, border] = colorClass.split(' ')
  return {
    color: color?.replace('text-', '').replace('400', ''),
    background: bg?.replace('bg-', '').replace('/10', ''),
    borderColor: border?.replace('border-', '').replace('/30', ''),
  }
}
