import { useState } from 'react'
import { GitBranch, FileArchive, Code, Upload } from 'lucide-react'

function ScanForm({ onSubmit, isLoading }) {
  const [activeTab, setActiveTab] = useState('git')
  const [formData, setFormData] = useState({
    gitUrl: '',
    branch: '',
    code: '',
    language: 'python',
    filename: '',
    cwes: ['CWE-89', 'CWE-79', 'CWE-94', 'CWE-78', 'CWE-22', 'CWE-798', 'CWE-502', 'CWE-352', 'CWE-601', 'CWE-312'],
    lite: false
  })
  const [selectedFile, setSelectedFile] = useState(null)

  // OWASP Top 10 2021 + high-impact web vulnerabilities (matching CLI)
  const cweOptions = [
    { value: 'CWE-89', label: 'CWE-89: SQL Injection' },
    { value: 'CWE-79', label: 'CWE-79: Cross-site Scripting (XSS)' },
    { value: 'CWE-20', label: 'CWE-20: Improper Input Validation' },
    { value: 'CWE-200', label: 'CWE-200: Information Exposure' },
    { value: 'CWE-22', label: 'CWE-22: Path Traversal' },
    { value: 'CWE-352', label: 'CWE-352: CSRF' },
    { value: 'CWE-502', label: 'CWE-502: Deserialization' },
    { value: 'CWE-287', label: 'CWE-287: Authentication' },
    { value: 'CWE-798', label: 'CWE-798: Hardcoded Credentials' },
    { value: 'CWE-306', label: 'CWE-306: Missing Authentication' },
    { value: 'CWE-94', label: 'CWE-94: Code Injection' },
    { value: 'CWE-78', label: 'CWE-78: Command Injection' },
    { value: 'CWE-601', label: 'CWE-601: URL Redirection' },
    { value: 'CWE-312', label: 'CWE-312: Cleartext Storage' },
    { value: 'CWE-327', label: 'CWE-327: Broken Crypto' },
    { value: 'CWE-918', label: 'CWE-918: SSRF' },
    { value: 'CWE-434', label: 'CWE-434: Unrestricted Upload' },
    { value: 'CWE-611', label: 'CWE-611: XXE' },
    { value: 'CWE-400', label: 'CWE-400: Resource Exhaustion' },
    { value: 'CWE-384', label: 'CWE-384: Session Fixation' }
  ]

  const handleSubmit = (e) => {
    e.preventDefault()
    onSubmit({ type: activeTab, data: formData, file: selectedFile })
  }

  const handleCweChange = (cwe) => {
    setFormData(prev => ({
      ...prev,
      cwes: prev.cwes.includes(cwe)
        ? prev.cwes.filter(c => c !== cwe)
        : [...prev.cwes, cwe]
    }))
  }

  const tabs = [
    { id: 'git', label: 'Git Repository', icon: GitBranch },
    { id: 'zip', label: 'ZIP Upload', icon: FileArchive },
    { id: 'paste', label: 'Paste Code', icon: Code }
  ]

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-800">
      {/* Tabs */}
      <div className="flex border-b border-gray-800">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center space-x-2 px-6 py-4 font-medium transition-colors ${
              activeTab === tab.id
                ? 'text-primary-500 border-b-2 border-primary-500'
                : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            <tab.icon className="w-4 h-4" />
            <span>{tab.label}</span>
          </button>
        ))}
      </div>

      {/* Form */}
      <form onSubmit={handleSubmit} className="p-6 space-y-6">
        <div className="bg-gray-950 border border-gray-800 rounded-lg p-3 text-sm text-gray-400">
          Model selection is automatic (OpenRouter auto). You don't need to pick a model.
        </div>

        <label className="flex items-center gap-2 text-sm text-gray-300">
          <input
            type="checkbox"
            checked={formData.lite}
            onChange={(e) => setFormData({ ...formData, lite: e.target.checked })}
            className="accent-primary-500"
          />
          Lite scan (static only, faster)
        </label>

        {/* Git Repository Tab */}
        {activeTab === 'git' && (
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">
                Repository URL
              </label>
              <input
                type="url"
                value={formData.gitUrl}
                onChange={(e) => setFormData({ ...formData, gitUrl: e.target.value })}
                placeholder="https://github.com/user/repo.git"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-gray-100 focus:outline-none focus:border-primary-500"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">
                Branch (optional)
              </label>
              <input
                type="text"
                value={formData.branch}
                onChange={(e) => setFormData({ ...formData, branch: e.target.value })}
                placeholder="main"
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-gray-100 focus:outline-none focus:border-primary-500"
              />
            </div>
          </div>
        )}

        {/* ZIP Upload Tab */}
        {activeTab === 'zip' && (
          <div className="space-y-4">
            <div className="border-2 border-dashed border-gray-700 rounded-lg p-8 text-center">
              <Upload className="w-12 h-12 text-gray-500 mx-auto mb-4" />
              <label className="cursor-pointer">
                <span className="text-primary-500 hover:text-primary-400">
                  Click to upload ZIP file
                </span>
                <input
                  type="file"
                  accept=".zip"
                  onChange={(e) => setSelectedFile(e.target.files[0])}
                  className="hidden"
                  required
                />
              </label>
              {selectedFile && (
                <p className="mt-2 text-sm text-gray-400">
                  Selected: {selectedFile.name}
                </p>
              )}
            </div>
          </div>
        )}

        {/* Paste Code Tab */}
        {activeTab === 'paste' && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-2">
                  Language
                </label>
                <select
                  value={formData.language}
                  onChange={(e) => setFormData({ ...formData, language: e.target.value })}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-gray-100 focus:outline-none focus:border-primary-500"
                >
                  <option value="python">Python</option>
                  <option value="javascript">JavaScript</option>
                  <option value="c">C</option>
                  <option value="cpp">C++</option>
                  <option value="java">Java</option>
                  <option value="go">Go</option>
                  <option value="rust">Rust</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-2">
                  Filename (optional)
                </label>
                <input
                  type="text"
                  value={formData.filename}
                  onChange={(e) => setFormData({ ...formData, filename: e.target.value })}
                  placeholder="source.py"
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-gray-100 focus:outline-none focus:border-primary-500"
                />
              </div>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">
                Code
              </label>
              <textarea
                value={formData.code}
                onChange={(e) => setFormData({ ...formData, code: e.target.value })}
                rows={12}
                placeholder="Paste your code here..."
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-gray-100 font-mono text-sm focus:outline-none focus:border-primary-500"
                required
              />
            </div>
          </div>
        )}

        {/* CWE Selection */}
        <div>
          <label className="block text-sm font-medium text-gray-400 mb-3">
            CWEs to Check ({formData.cwes.length} selected)
          </label>
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3 max-h-64 overflow-y-auto p-2 bg-gray-800/50 rounded-lg">
            {cweOptions.map(cwe => (
              <label key={cwe.value} className="flex items-center space-x-2 cursor-pointer hover:bg-gray-800 p-1 rounded">
                <input
                  type="checkbox"
                  checked={formData.cwes.includes(cwe.value)}
                  onChange={() => handleCweChange(cwe.value)}
                  className="w-4 h-4 rounded border-gray-700 bg-gray-800 text-primary-500 focus:ring-primary-500"
                />
                <span className="text-sm text-gray-300">{cwe.label}</span>
              </label>
            ))}
          </div>
          <p className="mt-2 text-xs text-gray-500">
            Select the vulnerability types to scan for. Default selection covers OWASP Top 10.
          </p>
        </div>

        {/* Submit Button */}
        <button
          type="submit"
          disabled={isLoading}
          className="w-full bg-primary-600 hover:bg-primary-700 disabled:bg-gray-700 text-white font-medium py-3 rounded-lg transition-colors flex items-center justify-center space-x-2"
        >
          {isLoading ? (
            <>
              <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
              <span>Starting Scan...</span>
            </>
          ) : (
            <span>Start Scan</span>
          )}
        </button>
      </form>
    </div>
  )
}

export default ScanForm
