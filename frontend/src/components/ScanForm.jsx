import { useState } from 'react'
import { GitBranch, FileArchive, Code, Upload, Zap, Shield } from 'lucide-react'

function ScanForm({ onSubmit, isLoading }) {
  const [activeTab, setActiveTab] = useState('git')
  const [formData, setFormData] = useState({
    gitUrl: '',
    branch: '',
    code: '',
    language: 'python',
    filename: ''
  })
  const [selectedFile, setSelectedFile] = useState(null)

  const handleSubmit = (e) => {
    e.preventDefault()
    onSubmit({ type: activeTab, data: formData, file: selectedFile })
  }

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
        {/* Model info row */}
        <div className="flex items-center gap-2 text-xs text-gray-500 bg-gray-950/60 border border-gray-800/40 rounded-lg px-3 py-2">
          <Shield className="w-3.5 h-3.5 text-primary-500/60" />
          Uses saved model settings for all agents
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
