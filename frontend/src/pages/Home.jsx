import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, AlertCircle, Bug, FlaskConical, BarChart2, Zap } from 'lucide-react'
import ScanForm from '../components/ScanForm'
import { scanGit, scanZip, scanPaste } from '../api/client'

function Home() {
  const navigate = useNavigate()
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState(null)

  const handleSubmit = async ({ type, data, file }) => {
    setIsLoading(true)
    setError(null)

    try {
      let response

      switch (type) {
        case 'git':
          response = await scanGit({
            url: data.gitUrl,
            branch: data.branch,
            cwes: data.cwes,
            lite: data.lite
          })
          break

        case 'zip': {
          const formData = new FormData()
          formData.append('file', file)
          formData.append('cwes', data.cwes.join(','))
          formData.append('lite', data.lite ? 'true' : 'false')
          response = await scanZip(formData)
          break
        }

        case 'paste':
          response = await scanPaste({
            code: data.code,
            language: data.language,
            filename: data.filename,
            cwes: data.cwes,
            lite: data.lite
          })
          break

        default:
          throw new Error('Invalid scan type')
      }

      navigate(`/scan/${response.data.scan_id}`)
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to start scan')
      setIsLoading(false)
    }
  }

  return (
    <div className="max-w-4xl mx-auto">
      {/* Hero */}
      <div className="relative text-center mb-10 py-10">
        <div className="absolute inset-0 bg-grid opacity-40 pointer-events-none rounded-2xl" />

        {/* Pill badge */}
        <div className="inline-flex items-center gap-1.5 px-3 py-1 mb-5 rounded-full bg-primary-500/10 border border-primary-500/20 text-primary-400 text-xs font-medium">
          <Zap className="w-3 h-3" />
          AI-Powered Vulnerability Analysis
        </div>

        {/* Glowing shield */}
        <div className="relative flex justify-center mb-5">
          <div className="relative">
            <div className="absolute inset-0 bg-primary-500/30 rounded-full blur-2xl scale-150 opacity-60" />
            <Shield className="relative w-14 h-14 text-primary-400" />
          </div>
        </div>

        <h1 className="relative text-4xl font-bold tracking-tight mb-3">
          Auto<span className="text-primary-400">PoV</span>
        </h1>
        <p className="relative text-gray-400 text-base max-w-xl mx-auto">
          Autonomous Proof-of-Vulnerability framework — detects, validates, and generates working exploits for real vulnerabilities.
        </p>
      </div>

      {/* Error */}
      {error && (
        <div className="mb-6 p-4 bg-red-900/20 border border-red-800/60 rounded-lg flex items-start gap-3">
          <AlertCircle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
          <span className="text-red-300 text-sm">{error}</span>
        </div>
      )}

      {/* Scan Form */}
      <ScanForm onSubmit={handleSubmit} isLoading={isLoading} />

      {/* Feature grid */}
      <div className="mt-10 grid md:grid-cols-3 gap-4">
        <div className="bg-gray-900/60 rounded-xl p-5 border border-gray-800/60 hover:border-threat-500/30 transition-colors group">
          <div className="w-8 h-8 rounded-lg bg-threat-500/10 border border-threat-500/20 flex items-center justify-center mb-3 group-hover:bg-threat-500/20 transition-colors">
            <Bug className="w-4 h-4 text-threat-400" />
          </div>
          <h3 className="font-medium text-sm mb-1.5">Deep Vulnerability Detection</h3>
          <p className="text-xs text-gray-500 leading-relaxed">
            LLM-driven code analysis across OWASP Top 10 — finds injection flaws, auth bypass, and logic errors.
          </p>
        </div>

        <div className="bg-gray-900/60 rounded-xl p-5 border border-gray-800/60 hover:border-primary-500/30 transition-colors group">
          <div className="w-8 h-8 rounded-lg bg-primary-500/10 border border-primary-500/20 flex items-center justify-center mb-3 group-hover:bg-primary-500/20 transition-colors">
            <FlaskConical className="w-4 h-4 text-primary-400" />
          </div>
          <h3 className="font-medium text-sm mb-1.5">Proof-of-Vulnerability</h3>
          <p className="text-xs text-gray-500 leading-relaxed">
            Automatically generates and executes exploit scripts to confirm findings are real, not false positives.
          </p>
        </div>

        <div className="bg-gray-900/60 rounded-xl p-5 border border-gray-800/60 hover:border-warn-500/30 transition-colors group">
          <div className="w-8 h-8 rounded-lg bg-warn-500/10 border border-warn-500/20 flex items-center justify-center mb-3 group-hover:bg-warn-500/20 transition-colors">
            <BarChart2 className="w-4 h-4 text-warn-400" />
          </div>
          <h3 className="font-medium text-sm mb-1.5">LLM Benchmarking</h3>
          <p className="text-xs text-gray-500 leading-relaxed">
            Compare model performance on vulnerability detection tasks with detection rate and cost metrics.
          </p>
        </div>
      </div>
    </div>
  )
}

export default Home
