import { useState } from 'react'
import { GitBranch, FileArchive, Code, Upload, Zap, Shield } from 'lucide-react'

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

  const cweOptions = [
    { value: 'CWE-89',  label: 'SQL Injection' },
    { value: 'CWE-79',  label: 'XSS' },
    { value: 'CWE-20',  label: 'Input Validation' },
    { value: 'CWE-200', label: 'Info Exposure' },
    { value: 'CWE-22',  label: 'Path Traversal' },
    { value: 'CWE-352', label: 'CSRF' },
    { value: 'CWE-502', label: 'Deserialization' },
    { value: 'CWE-287', label: 'Authentication' },
    { value: 'CWE-798', label: 'Hardcoded Creds' },
    { value: 'CWE-306', label: 'Missing Auth' },
    { value: 'CWE-94',  label: 'Code Injection' },
    { value: 'CWE-78',  label: 'Command Injection' },
    { value: 'CWE-601', label: 'URL Redirect' },
    { value: 'CWE-312', label: 'Cleartext Storage' },
    { value: 'CWE-327', label: 'Broken Crypto' },
    { value: 'CWE-918', label: 'SSRF' },
    { value: 'CWE-434', label: 'Unrestricted Upload' },
    { value: 'CWE-611', label: 'XXE' },
    { value: 'CWE-400', label: 'Resource Exhaustion' },
    { value: 'CWE-384', label: 'Session Fixation' }
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

  const selectAll = () => setFormData(prev => ({ ...prev, cwes: cweOptions.map(c => c.value) }))
  const selectNone = () => setFormData(prev => ({ ...prev, cwes: [] }))

  const tabs = [
    { id: 'git',   label: 'Git Repo', icon: GitBranch },
    { id: 'zip',   label: 'ZIP Upload', icon: FileArchive },
    { id: 'paste', label: 'Paste Code', icon: Code }
  ]

  const inputCls = 'w-full bg-gray-950 border border-gray-700/60 rounded-lg px-3.5 py-2.5 text-sm text-gray-100 placeholder-gray-600 focus:outline-none focus:border-primary-500/60 transition-colors'

  return (
    <div className="bg-gray-900/80 rounded-xl border border-gray-800/60 overflow-hidden">
      {/* Tabs */}
      <div className="flex gap-1 p-3 bg-gray-950/60 border-b border-gray-800/60">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`flex items-center gap-1.5 px-4 py-1.5 rounded-md text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? 'bg-primary-500/15 text-primary-400 border border-primary-500/20'
                : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/40'
            }`}
          >
            <tab.icon className="w-3.5 h-3.5" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Form */}
      <form onSubmit={handleSubmit} className="p-5 space-y-5">
        {/* Model info + lite toggle row */}
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-2 text-xs text-gray-500 bg-gray-950/60 border border-gray-800/40 rounded-lg px-3 py-2">
            <Shield className="w-3.5 h-3.5 text-primary-500/60" />
            Model: OpenRouter auto
          </div>
          <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer select-none">
            <div
              className={`relative w-8 h-5 rounded-full transition-colors cursor-pointer ${formData.lite ? 'bg-primary-500' : 'bg-gray-700'}`}
              onClick={() => setFormData({ ...formData, lite: !formData.lite })}
            >
              <div className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-all duration-200 ${formData.lite ? 'left-3.5' : 'left-0.5'}`} />
            </div>
            Lite scan
          </label>
        </div>

        {/* Git tab */}
        {activeTab === 'git' && (
          <div className="space-y-3">
            <div>
              <label className="block text-xs font-medium text-gray-500 mb-1.5 uppercase tracking-wide">Repository URL</label>
              <input
                type="url"
                value={formData.gitUrl}
                onChange={(e) => setFormData({ ...formData, gitUrl: e.target.value })}
                placeholder="https://github.com/user/repo.git"
                className={inputCls}
                required
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 mb-1.5 uppercase tracking-wide">Branch <span className="normal-case text-gray-600">(optional)</span></label>
              <input
                type="text"
                value={formData.branch}
                onChange={(e) => setFormData({ ...formData, branch: e.target.value })}
                placeholder="main"
                className={inputCls}
              />
            </div>
          </div>
        )}

        {/* ZIP tab */}
        {activeTab === 'zip' && (
          <div>
            <label className="flex flex-col items-center justify-center border-2 border-dashed border-gray-700/60 hover:border-primary-500/40 rounded-xl p-10 text-center cursor-pointer transition-colors group">
              <Upload className="w-10 h-10 text-gray-600 group-hover:text-primary-500/60 mb-3 transition-colors" />
              <span className="text-sm text-primary-400 group-hover:text-primary-300">
                {selectedFile ? selectedFile.name : 'Click to select ZIP file'}
              </span>
              {selectedFile && (
                <span className="text-xs text-gray-500 mt-1">
                  {(selectedFile.size / 1024).toFixed(0)} KB
                </span>
              )}
              <input
                type="file"
                accept=".zip"
                onChange={(e) => setSelectedFile(e.target.files[0])}
                className="hidden"
                required
              />
            </label>
          </div>
        )}

        {/* Paste tab */}
        {activeTab === 'paste' && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-gray-500 mb-1.5 uppercase tracking-wide">Language</label>
                <select
                  value={formData.language}
                  onChange={(e) => setFormData({ ...formData, language: e.target.value })}
                  className={inputCls}
                >
                  <option value="python">Python</option>
                  <option value="javascript">JavaScript</option>
                  <option value="typescript">TypeScript</option>
                  <option value="c">C</option>
                  <option value="cpp">C++</option>
                  <option value="java">Java</option>
                  <option value="go">Go</option>
                  <option value="rust">Rust</option>
                </select>
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-500 mb-1.5 uppercase tracking-wide">Filename <span className="normal-case text-gray-600">(optional)</span></label>
                <input
                  type="text"
                  value={formData.filename}
                  onChange={(e) => setFormData({ ...formData, filename: e.target.value })}
                  placeholder="source.py"
                  className={inputCls}
                />
              </div>
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-500 mb-1.5 uppercase tracking-wide">Code</label>
              <textarea
                value={formData.code}
                onChange={(e) => setFormData({ ...formData, code: e.target.value })}
                rows={10}
                placeholder="Paste your code here..."
                className={`${inputCls} font-mono resize-y`}
                required
              />
            </div>
          </div>
        )}

        {/* CWE Selection */}
        <div>
          <div className="flex items-center justify-between mb-2">
            <label className="text-xs font-medium text-gray-500 uppercase tracking-wide">
              Vulnerabilities to scan
            </label>
            <div className="flex items-center gap-2">
              <span className="text-xs text-gray-600">{formData.cwes.length}/{cweOptions.length}</span>
              <button type="button" onClick={selectAll} className="text-xs text-primary-500 hover:text-primary-400 transition-colors">All</button>
              <span className="text-gray-700">·</span>
              <button type="button" onClick={selectNone} className="text-xs text-gray-500 hover:text-gray-400 transition-colors">None</button>
            </div>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-1.5 max-h-52 overflow-y-auto pr-1">
            {cweOptions.map(cwe => {
              const checked = formData.cwes.includes(cwe.value)
              return (
                <button
                  key={cwe.value}
                  type="button"
                  onClick={() => handleCweChange(cwe.value)}
                  className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-left text-xs transition-colors ${
                    checked
                      ? 'bg-primary-500/15 text-primary-300 border border-primary-500/25'
                      : 'bg-gray-800/40 text-gray-500 border border-gray-700/40 hover:text-gray-300 hover:border-gray-600/60'
                  }`}
                >
                  <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${checked ? 'bg-primary-400' : 'bg-gray-600'}`} />
                  <span className="truncate">{cwe.value}</span>
                </button>
              )
            })}
          </div>
        </div>

        {/* Submit */}
        <button
          type="submit"
          disabled={isLoading}
          className="w-full flex items-center justify-center gap-2 bg-primary-600 hover:bg-primary-500 disabled:bg-gray-800 disabled:text-gray-500 text-white font-medium py-2.5 rounded-lg text-sm transition-colors"
        >
          {isLoading ? (
            <>
              <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
              Starting Scan…
            </>
          ) : (
            <>
              <Zap className="w-4 h-4" />
              Start Scan
            </>
          )}
        </button>
      </form>
    </div>
  )
}

export default ScanForm
