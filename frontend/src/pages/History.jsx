import { useEffect, useState, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { getHistory } from '../api/client'

const PAGE_SIZE = 20

function StatusBadge({ status }) {
  const cls = {
    completed: 'badge-safe',
    failed:    'badge-threat',
    running:   'badge-primary',
  }[status] || 'badge-neutral'
  return <span className={cls}>{status?.toUpperCase()}</span>
}

function HistoryPage() {
  const navigate = useNavigate()
  const [scans,    setScans]    = useState([])
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState(null)
  const [page,     setPage]     = useState(0)
  const [hasMore,  setHasMore]  = useState(true)
  const [total,    setTotal]    = useState(null)

  const fetchHistory = useCallback(async (pageNum) => {
    setLoading(true)
    setError(null)
    try {
      const offset   = pageNum * PAGE_SIZE
      const response = await getHistory(PAGE_SIZE + 1, offset)
      const rows     = response.data.history || []
      setHasMore(rows.length > PAGE_SIZE)
      setScans(rows.slice(0, PAGE_SIZE))
      if (response.data.total !== undefined) setTotal(response.data.total)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { fetchHistory(page) }, [page, fetchHistory])

  return (
    <div className="animate-fade-up">

      {/* Header */}
      <div className="mb-8">
        <p className="label-caps mb-1">// AUDIT LOG</p>
        <h1 className="heading-display text-4xl text-gray-100">
          SCAN HISTORY
          {total !== null && (
            <span className="ml-4 text-xl text-gray-600">{total} RECORDS</span>
          )}
        </h1>
      </div>

      {/* Error banner */}
      {error && (
        <div className="card-threat p-4 mb-6 flex items-center gap-3">
          <span className="label-caps text-threat-400">ERROR</span>
          <span className="text-threat-300 text-sm">{error}</span>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="flex items-center gap-3 py-16 text-gray-600">
          <span className="inline-block w-4 h-4 border border-primary-600 border-t-transparent animate-spin" />
          <span className="label-caps">LOADING RECORDS</span>
        </div>
      )}

      {/* Table */}
      {!loading && (
        <div className="card overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-850">
                <th className="px-5 py-3 text-left label-caps">SCAN ID</th>
                <th className="px-5 py-3 text-left label-caps">STATUS</th>
                <th className="px-5 py-3 text-left label-caps">MODEL</th>
                <th className="px-5 py-3 text-left label-caps">CONFIRMED</th>
                <th className="px-5 py-3 text-left label-caps">COST</th>
                <th className="px-5 py-3 text-left label-caps">DATE</th>
                <th className="px-5 py-3 text-left label-caps"></th>
              </tr>
            </thead>
            <tbody>
              {scans.length === 0 ? (
                <tr>
                  <td colSpan="7" className="px-5 py-14 text-center">
                    <p className="label-caps text-gray-600">NO RECORDS FOUND</p>
                  </td>
                </tr>
              ) : (
                scans.map((scan) => (
                  <tr
                    key={scan.scan_id}
                    className="border-t border-gray-850 hover:bg-gray-850/50 transition-colors cursor-pointer"
                    onClick={() => navigate(`/results/${scan.scan_id}`)}
                  >
                    <td className="px-5 py-3.5 font-mono text-primary-400 text-xs tracking-widest">
                      {scan.scan_id?.substring(0, 12)}…
                    </td>
                    <td className="px-5 py-3.5">
                      <StatusBadge status={scan.status} />
                    </td>
                    <td className="px-5 py-3.5 text-gray-500 text-xs">{scan.model_name}</td>
                    <td className="px-5 py-3.5">
                      <span className="text-safe-400 font-semibold text-sm">{scan.confirmed_vulns}</span>
                      <span className="text-gray-600 text-xs"> / {scan.total_findings}</span>
                    </td>
                    <td className="px-5 py-3.5 text-gray-500 font-mono text-xs">
                      ${parseFloat(scan.total_cost_usd || 0).toFixed(4)}
                    </td>
                    <td className="px-5 py-3.5 text-gray-600 text-xs">
                      {new Date(scan.start_time).toLocaleDateString()}
                    </td>
                    <td className="px-5 py-3.5 text-right">
                      <span className="text-primary-500 hover:text-primary-300 text-xs tracking-widest transition-colors">
                        VIEW →
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* Pagination */}
      {!loading && (
        <div className="flex items-center justify-between mt-5">
          <span className="label-caps text-gray-600">
            PAGE {page + 1}
            {scans.length > 0 && (
              <> · {page * PAGE_SIZE + 1}–{page * PAGE_SIZE + scans.length}</>
            )}
          </span>
          <div className="flex gap-2">
            <button
              disabled={page === 0}
              onClick={() => setPage(p => p - 1)}
              className="btn-ghost text-xs disabled:opacity-30 disabled:cursor-not-allowed"
            >
              ← PREV
            </button>
            <button
              disabled={!hasMore}
              onClick={() => setPage(p => p + 1)}
              className="btn-ghost text-xs disabled:opacity-30 disabled:cursor-not-allowed"
            >
              NEXT →
            </button>
          </div>
        </div>
      )}

    </div>
  )
}

export default HistoryPage
