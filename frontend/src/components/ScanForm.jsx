import { useState } from 'react'
import { GitBranch, FileArchive, Code, Upload, Zap } from 'lucide-react'

const CWE_OPTIONS = [
  { value: 'CWE-89',  label: 'SQL Injection' },
  { value: 'CWE-79',  label: 'XSS' },
  { value: 'CWE-20',  label: 'Input Validation' },
  { value: 'CWE-200', label: 'Info Exposure' },
  { value: 'CWE-22',  label: 'Path Traversal' },
  { value: 'CWE-352', label: 'CSRF' },
  { value: 'CWE-502', label: 'Deserialization' },
  { value: 'CWE-287', label: 'Auth Bypass' },
  { value: 'CWE-798', label: 'Hardcoded Creds' },
  { value: 'CWE-306', label: 'Missing Auth' },
  { value: 'CWE-94',  label: 'Code Injection' },
  { value: 'CWE-78',  label: 'Command Injection' },
  { value: 'CWE-601', label: 'URL Redirect' },
  { value: 'CWE-312', label: 'Cleartext Store' },
  { value: 'CWE-327', label: 'Broken Crypto' },
  { value: 'CWE-918', label: 'SSRF' },
  { value: 'CWE-434', label: 'File Upload' },
  { value: 'CWE-611', label: 'XXE' },
  { value: 'CWE-400', label: 'Resource DoS' },
  { value: 'CWE-384', label: 'Session Fix' },
]

const DEFAULT_CWES = [
  'CWE-89','CWE-79','CWE-94','CWE-78','CWE-22','CWE-798',
  'CWE-502','CWE-352','CWE-601','CWE-312',
]

const TABS = [
  { id: 'git',   label: 'GIT REPO',   icon: GitBranch  },
  { id: 'zip',   label: 'ZIP UPLOAD', icon: FileArchive },
  { id: 'paste', label: 'PASTE CODE', icon: Code        },
]

function ScanForm({ onSubmit, isLoading }) {
  const [activeTab, setActiveTab] = useState('git')
  const [formData, setFormData]   = useState({
    gitUrl: '', branch: '', code: '',
    language: 'python', filename: '',
    cwes: DEFAULT_CWES, lite: false,
  })
  const [selectedFile, setSelectedFile] = useState(null)

  const handleSubmit = (e) => {
    e.preventDefault()
    onSubmit({ type: activeTab, data: formData, file: selectedFile })
  }

  const toggleCwe   = (cwe) => setFormData(p => ({
    ...p,
    cwes: p.cwes.includes(cwe) ? p.cwes.filter(c => c !== cwe) : [...p.cwes, cwe]
  }))
  const selectAll   = () => setFormData(p => ({ ...p, cwes: CWE_OPTIONS.map(c => c.value) }))
  const selectNone  = () => setFormData(p => ({ ...p, cwes: [] }))

  return (
    <div className="border border-gray-850 bg-gray-900">

      {/* ── Tab bar ──────────────────────────────────────── */}
      <div className="flex border-b border-gray-850">
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={[
              'flex items-center gap-2 px-5 py-3 text-xs font-semibold tracking-widest transition-colors border-r border-gray-850 last:border-r-0',
              activeTab === tab.id
                ? 'text-primary-400 bg-gray-850 border-b-2 border-b-primary-600 -mb-px'
                : 'text-gray-600 hover:text-gray-400 hover:bg-gray-850/50',
            ].join(' ')}
          >
            <tab.icon className="w-3.5 h-3.5" />
            {tab.label}
          </button>
        ))}

        {/* Lite toggle — right-aligned */}
        <div className="ml-auto flex items-center gap-3 px-5">
          <span className="label-caps">LITE</span>
          <button
            type="button"
            onClick={() => setFormData(p => ({ ...p, lite: !p.lite }))}
            className={[
              'relative w-9 h-5 transition-colors',
              formData.lite ? 'bg-primary-600' : 'bg-gray-850 border border-gray-800',
            ].join(' ')}
            aria-label="Toggle lite scan"
          >
            <span className={[
              'absolute top-0.5 w-4 h-4 bg-white transition-all duration-150',
              formData.lite ? 'left-4' : 'left-0.5',
            ].join(' ')} />
          </button>
        </div>
      </div>

      {/* ── Form body ────────────────────────────────────── */}
      <form onSubmit={handleSubmit} className="p-5 space-y-5">

        {/* GIT TAB */}
        {activeTab === 'git' && (
          <div className="space-y-3">
            <div>
              <label className="label-caps block mb-2">REPOSITORY URL</label>
              <input
                type="url"
                value={formData.gitUrl}
                onChange={e => setFormData(p => ({ ...p, gitUrl: e.target.value }))}
                placeholder="https://github.com/user/repo.git"
                className="input-stark"
                required
              />
            </div>
            <div>
              <label className="label-caps block mb-2">BRANCH <span className="normal-case text-gray-700">(optional)</span></label>
              <input
                type="text"
                value={formData.branch}
                onChange={e => setFormData(p => ({ ...p, branch: e.target.value }))}
                placeholder="main"
                className="input-stark"
              />
            </div>
          </div>
        )}

        {/* ZIP TAB */}
        {activeTab === 'zip' && (
          <label className="flex flex-col items-center justify-center border border-dashed border-gray-800 hover:border-primary-600/50 p-12 text-center cursor-pointer transition-colors group">
            <Upload className="w-8 h-8 text-gray-700 group-hover:text-primary-600/80 mb-4 transition-colors" />
            <span className="text-sm text-primary-400 group-hover:text-primary-300 mb-1">
              {selectedFile ? selectedFile.name : 'Click to select ZIP archive'}
            </span>
            {selectedFile && (
              <span className="text-xs text-gray-600">
                {(selectedFile.size / 1024).toFixed(0)} KB
              </span>
            )}
            <input
              type="file"
              accept=".zip"
              onChange={e => setSelectedFile(e.target.files[0])}
              className="hidden"
              required
            />
          </label>
        )}

        {/* PASTE TAB */}
        {activeTab === 'paste' && (
          <div className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="label-caps block mb-2">LANGUAGE</label>
                <select
                  value={formData.language}
                  onChange={e => setFormData(p => ({ ...p, language: e.target.value }))}
                  className="input-stark"
                >
                  {['python','javascript','typescript','c','cpp','java','go','rust','ruby','php'].map(l => (
                    <option key={l} value={l}>{l}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="label-caps block mb-2">FILENAME <span className="normal-case text-gray-700">(optional)</span></label>
                <input
                  type="text"
                  value={formData.filename}
                  onChange={e => setFormData(p => ({ ...p, filename: e.target.value }))}
                  placeholder="source.py"
                  className="input-stark"
                />
              </div>
            </div>
            <div>
              <label className="label-caps block mb-2">CODE</label>
              <textarea
                value={formData.code}
                onChange={e => setFormData(p => ({ ...p, code: e.target.value }))}
                rows={9}
                placeholder="// paste your code here…"
                className="input-stark font-mono resize-y"
                required
              />
            </div>
          </div>
        )}

        {/* ── CWE Selection ─────────────────────────────── */}
        <div>
          <div className="flex items-center justify-between mb-2.5">
            <label className="label-caps">VULNERABILITY CLASSES</label>
            <div className="flex items-center gap-3 text-xs">
              <span className="text-gray-700">{formData.cwes.length}/{CWE_OPTIONS.length} selected</span>
              <button type="button" onClick={selectAll}  className="text-primary-500 hover:text-primary-400 tracking-widest">ALL</button>
              <span className="text-gray-800">·</span>
              <button type="button" onClick={selectNone} className="text-gray-600 hover:text-gray-400 tracking-widest">NONE</button>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-1.5 max-h-48 overflow-y-auto pr-0.5">
            {CWE_OPTIONS.map(cwe => {
              const on = formData.cwes.includes(cwe.value)
              return (
                <button
                  key={cwe.value}
                  type="button"
                  onClick={() => toggleCwe(cwe.value)}
                  className={[
                    'flex items-center gap-1.5 px-2.5 py-1.5 text-left text-xs border transition-colors',
                    on
                      ? 'bg-primary-600/10 border-primary-500/30 text-primary-400'
                      : 'bg-gray-850/40 border-gray-850 text-gray-600 hover:text-gray-400 hover:border-gray-800',
                  ].join(' ')}
                >
                  <span className={`w-1.5 h-1.5 rounded-sm shrink-0 ${on ? 'bg-primary-500' : 'bg-gray-700'}`} />
                  <span className="truncate font-mono text-xs">{cwe.value}</span>
                </button>
              )
            })}
          </div>
        </div>

        {/* ── Submit ────────────────────────────────────── */}
        <button
          type="submit"
          disabled={isLoading}
          className="btn-primary w-full py-3 text-sm font-bold tracking-widest"
        >
          {isLoading ? (
            <>
              <span className="w-3.5 h-3.5 border-2 border-white/25 border-t-white rounded-full animate-spin" />
              INITIALIZING…
            </>
          ) : (
            <>
              <Zap className="w-4 h-4" />
              EXECUTE SCAN
            </>
          )}
        </button>
      </form>
    </div>
  )
}

export default ScanForm
