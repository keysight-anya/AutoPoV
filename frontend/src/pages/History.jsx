import { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { History, ExternalLink, CheckCircle, XCircle, Clock, ChevronLeft, ChevronRight } from 'lucide-react'
import { getHistory } from '../api/client'

const PAGE_SIZE = 20

function HistoryPage() {
  const navigate = useNavigate()
  const [scans, setScans] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [page, setPage] = useState(0)
  const [hasMore, setHasMore] = useState(true)
  const [total, setTotal] = useState(null)

  const fetchHistory = useCallback(async (pageNum) => {
    setLoading(true)
    setError(null)
    try {
      const offset = pageNum * PAGE_SIZE
      const response = await getHistory(PAGE_SIZE + 1, offset)
      const rows = response.data.history || []
      // Use one extra row to determine if there's a next page
      setHasMore(rows.length > PAGE_SIZE)
      setScans(rows.slice(0, PAGE_SIZE))
      // Try to get total from header if available, otherwise approximate
      if (response.data.total !== undefined) {
        setTotal(response.data.total)
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchHistory(page)
  }, [page, fetchHistory])

  const getStatusIcon = (status) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-green-400" />
      case 'failed':
        return <XCircle className="w-5 h-5 text-red-400" />
      default:
        return <Clock className="w-5 h-5 text-blue-400" />
    }
  }

  const getStatusClass = (status) => {
    switch (status) {
      case 'completed':
        return 'bg-green-900/30 text-green-400'
      case 'failed':
        return 'bg-red-900/30 text-red-400'
      default:
        return 'bg-blue-900/30 text-blue-400'
    }
  }

  if (loading) {
    return (
      <div className="flex justify-center items-center h-64">
        <div className="w-8 h-8 border-2 border-primary-500 border-t-transparent rounded-full animate-spin" />
      </div>
    )
  }

  return (
    <div className="max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex items-center space-x-3 mb-6">
        <History className="w-8 h-8 text-primary-500" />
        <h1 className="text-2xl font-bold">Scan History</h1>
        {total !== null && (
          <span className="text-sm text-gray-400">({total} total)</span>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="mb-6 p-4 bg-red-900/30 border border-red-800 rounded-lg">
          <p className="text-red-300">{error}</p>
        </div>
      )}

      {/* Scans Table */}
      <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-850 border-b border-gray-800">
            <tr>
              <th className="text-left px-6 py-4 text-sm font-medium text-gray-400">Scan ID</th>
              <th className="text-left px-6 py-4 text-sm font-medium text-gray-400">Status</th>
              <th className="text-left px-6 py-4 text-sm font-medium text-gray-400">Model</th>
              <th className="text-left px-6 py-4 text-sm font-medium text-gray-400">Confirmed</th>
              <th className="text-left px-6 py-4 text-sm font-medium text-gray-400">Cost</th>
              <th className="text-left px-6 py-4 text-sm font-medium text-gray-400">Date</th>
              <th className="text-left px-6 py-4 text-sm font-medium text-gray-400">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {scans.length === 0 ? (
              <tr>
                <td colSpan="7" className="px-6 py-8 text-center text-gray-500">
                  No scans found
                </td>
              </tr>
            ) : (
              scans.map((scan) => (
                <tr key={scan.scan_id} className="hover:bg-gray-850">
                  <td className="px-6 py-4 font-mono text-sm">
                    {scan.scan_id?.substring(0, 8)}...
                  </td>
                  <td className="px-6 py-4">
                    <div className="flex items-center space-x-2">
                      {getStatusIcon(scan.status)}
                      <span className={`px-2 py-1 rounded-full text-xs font-medium capitalize ${getStatusClass(scan.status)}`}>
                        {scan.status}
                      </span>
                    </div>
                  </td>
                  <td className="px-6 py-4 text-sm">{scan.model_name}</td>
                  <td className="px-6 py-4">
                    <span className="text-green-400 font-medium">
                      {scan.confirmed_vulns}
                    </span>
                    <span className="text-gray-500 text-sm">
                      {' '}/ {scan.total_findings}
                    </span>
                  </td>
                  <td className="px-6 py-4 text-sm">
                    ${parseFloat(scan.total_cost_usd || 0).toFixed(4)}
                  </td>
                  <td className="px-6 py-4 text-sm text-gray-400">
                    {new Date(scan.start_time).toLocaleDateString()}
                  </td>
                  <td className="px-6 py-4">
                    <button
                      onClick={() => navigate(`/results/${scan.scan_id}`)}
                      className="flex items-center space-x-1 text-primary-500 hover:text-primary-400"
                    >
                      <span>View</span>
                      <ExternalLink className="w-4 h-4" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination Controls */}
      <div className="flex items-center justify-between mt-4">
        <span className="text-sm text-gray-400">
          Page {page + 1}
          {scans.length > 0 && (
            <> &mdash; showing {page * PAGE_SIZE + 1}–{page * PAGE_SIZE + scans.length}</>
          )}
        </span>
        <div className="flex items-center space-x-2">
          <button
            disabled={page === 0}
            onClick={() => setPage(p => p - 1)}
            className="flex items-center px-3 py-1.5 rounded border border-gray-700 text-sm text-gray-300 hover:bg-gray-800 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <ChevronLeft className="w-4 h-4 mr-1" />
            Previous
          </button>
          <button
            disabled={!hasMore}
            onClick={() => setPage(p => p + 1)}
            className="flex items-center px-3 py-1.5 rounded border border-gray-700 text-sm text-gray-300 hover:bg-gray-800 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            Next
            <ChevronRight className="w-4 h-4 ml-1" />
          </button>
        </div>
      </div>
    </div>
  )
}

export default HistoryPage
