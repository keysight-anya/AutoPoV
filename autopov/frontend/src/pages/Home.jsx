import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, AlertCircle } from 'lucide-react'
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
            model: data.model,
            cwes: data.cwes
          })
          break

        case 'zip':
          const formData = new FormData()
          formData.append('file', file)
          formData.append('model', data.model)
          formData.append('cwes', data.cwes.join(','))
          response = await scanZip(formData)
          break

        case 'paste':
          response = await scanPaste({
            code: data.code,
            language: data.language,
            filename: data.filename,
            model: data.model,
            cwes: data.cwes
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
      {/* Header */}
      <div className="text-center mb-8">
        <div className="flex justify-center mb-4">
          <Shield className="w-16 h-16 text-primary-500" />
        </div>
        <h1 className="text-4xl font-bold mb-4">AutoPoV</h1>
        <p className="text-xl text-gray-400">
          Autonomous Proof-of-Vulnerability Framework for LLM Benchmarking
        </p>
      </div>

      {/* Error Message */}
      {error && (
        <div className="mb-6 p-4 bg-red-900/30 border border-red-800 rounded-lg flex items-center space-x-2">
          <AlertCircle className="w-5 h-5 text-red-400" />
          <span className="text-red-300">{error}</span>
        </div>
      )}

      {/* Scan Form */}
      <ScanForm onSubmit={handleSubmit} isLoading={isLoading} />

      {/* Features */}
      <div className="mt-12 grid md:grid-cols-3 gap-6">
        <div className="bg-gray-900 rounded-lg p-6 border border-gray-800">
          <h3 className="font-medium mb-2">AI-Powered Detection</h3>
          <p className="text-sm text-gray-400">
            Uses LLMs to analyze code and identify vulnerabilities with high accuracy
          </p>
        </div>
        <div className="bg-gray-900 rounded-lg p-6 border border-gray-800">
          <h3 className="font-medium mb-2">PoV Generation</h3>
          <p className="text-sm text-gray-400">
            Automatically generates and executes Proof-of-Vulnerability scripts
          </p>
        </div>
        <div className="bg-gray-900 rounded-lg p-6 border border-gray-800">
          <h3 className="font-medium mb-2">Benchmarking</h3>
          <p className="text-sm text-gray-400">
            Compare LLM performance on vulnerability detection tasks
          </p>
        </div>
      </div>
    </div>
  )
}

export default Home
