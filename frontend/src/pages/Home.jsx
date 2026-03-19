import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import ParallaxBg from '../components/ParallaxBg'
import { scanGit, scanPaste, scanZip } from '../api/client'

export default function Home() {
  const navigate = useNavigate()
  const [activeTab, setActiveTab] = useState('git')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState(null)
  const [selectedFile, setSelectedFile] = useState(null)
  const [btnPulsing, setBtnPulsing] = useState(false)
  const [formData, setFormData] = useState({
    gitUrl: '',
    branch: '',
    code: '',
    language: 'python',
    filename: '',
  })

  const fileRef = useRef(null)
  const gitUrlRef = useRef(null)
  const codeRef = useRef(null)

  useEffect(() => {
    if (activeTab === 'git') gitUrlRef.current?.focus()
    if (activeTab === 'paste') codeRef.current?.focus()
  }, [activeTab])

  const update = (patch) => setFormData((prev) => ({ ...prev, ...patch }))

  const handleSubmit = async (e) => {
    e.preventDefault()
    setBtnPulsing(true)
    setTimeout(() => setBtnPulsing(false), 600)
    setIsLoading(true)
    setError(null)

    try {
      let response
      if (activeTab === 'git') {
        response = await scanGit({ url: formData.gitUrl, branch: formData.branch })
      } else if (activeTab === 'zip') {
        const fd = new FormData()
        fd.append('file', selectedFile)
        response = await scanZip(fd)
      } else {
        response = await scanPaste({
          code: formData.code,
          language: formData.language,
          filename: formData.filename,
        })
      }

      try {
        const raw = localStorage.getItem('autopov_active_scans')
        const list = raw ? JSON.parse(raw) : []
        list.push(response.data.scan_id)
        localStorage.setItem('autopov_active_scans', JSON.stringify(list))
      } catch {}

      navigate(`/scan/${response.data.scan_id}`)
    } catch (err) {
      setError(err.response?.data?.detail || err.message || 'Failed to start scan')
      setIsLoading(false)
    }
  }

  const monoFont = '"JetBrains Mono", monospace'
  const labelStyle = {
    fontFamily: monoFont,
    fontSize: 10,
    letterSpacing: '.14em',
    color: 'var(--text3)',
    textTransform: 'uppercase',
    marginBottom: 8,
    display: 'block',
  }
  const inputBase = {
    width: '100%',
    background: 'var(--surface2)',
    border: '1px solid var(--border2)',
    padding: '10px 14px',
    color: 'var(--text1)',
    fontFamily: monoFont,
    fontSize: 12,
    outline: 'none',
  }
  const textareaStyle = { ...inputBase, resize: 'vertical', minHeight: 180 }
  const selectStyle = { ...inputBase, cursor: 'pointer', appearance: 'none' }

  return (
    <div
      style={{
        position: 'relative',
        minHeight: '100%',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        padding: '32px 24px',
      }}
    >
      <ParallaxBg />

      <div style={{ position: 'relative', zIndex: 1, width: '100%', maxWidth: 620 }}>
        <div
          style={{
            textAlign: 'center',
            marginBottom: 8,
            fontFamily: monoFont,
            fontSize: 10,
            letterSpacing: '.18em',
            color: 'var(--text3)',
          }}
        >
          [ VULNERABILITY ANALYSIS ]
        </div>

        <div
          style={{
            textAlign: 'center',
            marginBottom: 4,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 12,
            fontFamily: monoFont,
            fontSize: 10,
            letterSpacing: '.12em',
            color: 'var(--text3)',
          }}
        >
          <span style={{ flex: 1, height: 1, background: 'var(--accent)', opacity: 0.4 }} />
          INITIATE SCAN
          <span style={{ flex: 1, height: 1, background: 'var(--accent)', opacity: 0.4 }} />
        </div>

        <h1
          style={{
            textAlign: 'center',
            marginBottom: 8,
            fontSize: 32,
            fontWeight: 700,
            letterSpacing: '.04em',
            color: 'var(--text1)',
          }}
        >
          AutoPoV
        </h1>

        <p
          style={{
            textAlign: 'center',
            marginBottom: 24,
            fontFamily: monoFont,
            fontSize: 11,
            letterSpacing: '.06em',
            color: 'var(--text3)',
          }}
        >
          Autonomous proof-of-vulnerability framework.
        </p>

        {error && (
          <div
            style={{
              background: 'rgba(239,68,68,0.1)',
              border: '1px solid rgba(239,68,68,0.35)',
              padding: '10px 14px',
              marginBottom: 16,
              fontFamily: monoFont,
              fontSize: 11,
              color: '#fca5a5',
            }}
          >
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          <div className="tabs-row">
            <div className="tabs-group">
              {[
                { id: 'git', label: 'REPOSITORY URL' },
                { id: 'zip', label: 'ZIP ARCHIVE' },
                { id: 'paste', label: 'PASTE CODE' },
              ].map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  className={`glass-tab${activeTab === tab.id ? ' active' : ''}`}
                  onClick={() => setActiveTab(tab.id)}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          <div style={{ marginBottom: 18 }}>
            {activeTab === 'git' && (
              <div>
                <span style={labelStyle}>Repository URL</span>
                <div className="input-glow-wrap">
                  <span style={{ padding: '0 12px', color: 'var(--accent)', fontSize: 16, flexShrink: 0 }}>{'>'}</span>
                  <input
                    ref={gitUrlRef}
                    autoFocus
                    type="url"
                    value={formData.gitUrl}
                    onChange={(e) => update({ gitUrl: e.target.value })}
                    placeholder="https://github.com/org/repo"
                    required
                    style={{ ...inputBase, border: 'none', background: 'transparent', flex: 1, paddingLeft: 0 }}
                  />
                </div>
              </div>
            )}

            {activeTab === 'zip' && (
              <div
                onClick={() => fileRef.current?.click()}
                style={{
                  border: `2px dashed ${selectedFile ? 'var(--accent)' : 'var(--border2)'}`,
                  padding: '32px',
                  textAlign: 'center',
                  cursor: 'pointer',
                  transition: 'border-color .15s',
                }}
              >
                <input
                  ref={fileRef}
                  type="file"
                  accept=".zip"
                  onChange={(e) => setSelectedFile(e.target.files[0])}
                  style={{ display: 'none' }}
                  required
                />
                <div style={{ fontFamily: monoFont, fontSize: 11, letterSpacing: '.1em', color: selectedFile ? 'var(--accent)' : 'var(--text3)' }}>
                  {selectedFile ? selectedFile.name : 'DROP ZIP FILE OR CLICK TO BROWSE'}
                </div>
              </div>
            )}

            {activeTab === 'paste' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <div style={{ display: 'flex', gap: 10 }}>
                  <div style={{ flex: 1 }}>
                    <span style={labelStyle}>Language</span>
                    <select value={formData.language} onChange={(e) => update({ language: e.target.value })} style={selectStyle}>
                      {['python', 'javascript', 'c', 'cpp', 'java', 'go', 'rust'].map((l) => (
                        <option key={l} value={l}>
                          {l}
                        </option>
                      ))}
                    </select>
                  </div>
                  <div style={{ flex: 1 }}>
                    <span style={labelStyle}>Filename (optional)</span>
                    <input
                      type="text"
                      value={formData.filename}
                      onChange={(e) => update({ filename: e.target.value })}
                      placeholder="source.py"
                      style={inputBase}
                    />
                  </div>
                </div>
                <div>
                  <span style={labelStyle}>Code</span>
                  <textarea
                    ref={codeRef}
                    value={formData.code}
                    onChange={(e) => update({ code: e.target.value })}
                    placeholder="Paste your code here..."
                    required
                    style={textareaStyle}
                  />
                </div>
              </div>
            )}
          </div>

          <button
            type="submit"
            disabled={isLoading}
            className={`scan-btn${btnPulsing ? ' pulsing' : ''}`}
            style={{ opacity: isLoading ? 0.5 : 1, cursor: isLoading ? 'not-allowed' : 'pointer' }}
          >
            {isLoading ? (
              <>
                <span className="spin-ring" />
                STARTING SCAN...
              </>
            ) : (
              'ANALYZE REPOSITORY'
            )}
          </button>
        </form>

        {(() => {
          const hasInput =
            (activeTab === 'git' && formData.gitUrl.length > 0) ||
            (activeTab === 'zip' && selectedFile != null) ||
            (activeTab === 'paste' && formData.code.length > 0)
          if (isLoading) {
            return (
              <div style={{ marginTop: 16, textAlign: 'center', fontFamily: monoFont, fontSize: 10, letterSpacing: '.12em', color: 'var(--text3)' }}>
                INITIALIZING SCAN...
              </div>
            )
          }
          if (hasInput) return null
          return (
            <div style={{ marginTop: 16, textAlign: 'center', fontFamily: monoFont, fontSize: 10, letterSpacing: '.12em', color: 'var(--text3)' }}>
              AWAITING INPUT
              <span className="status-dots">
                <span className="dot">.</span>
                <span className="dot">.</span>
                <span className="dot">.</span>
                <span className="dot">.</span>
              </span>
            </div>
          )
        })()}
      </div>
    </div>
  )
}
