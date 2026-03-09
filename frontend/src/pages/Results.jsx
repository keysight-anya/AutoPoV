import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { ArrowLeft, Download, FileText } from 'lucide-react'
import ResultsDashboard from '../components/ResultsDashboard'
import FindingCard from '../components/FindingCard'
import { getScanStatus, getReport } from '../api/client'

function Results() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  useEffect(() => {
    const fetchResults = async () => {
      try {
        const response = await getScanStatus(scanId)
        setResult(response.data.result)
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

      {/* Confirmed Findings */}
      {confirmedFindings.length > 0 && (
        <div className="mt-8">
          <h2 className="text-xl font-bold mb-4">Confirmed Vulnerabilities</h2>
          <div className="space-y-4">
            {confirmedFindings.map((finding, index) => (
              <FindingCard key={index} finding={finding} />
            ))}
          </div>
        </div>
      )}

      {/* Scan Info */}
      <div className="mt-8 bg-gray-900 rounded-lg p-6 border border-gray-800">
        <h3 className="text-lg font-medium mb-4">Scan Information</h3>
        <div className="grid md:grid-cols-2 gap-4 text-sm">
          <div>
            <span className="text-gray-400">Model:</span>
            <span className="ml-2">{result.model_name}</span>
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
