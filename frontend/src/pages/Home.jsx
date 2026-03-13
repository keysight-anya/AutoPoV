// frontend/src/pages/Home.jsx
import { useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import ParallaxBg from '../components/ParallaxBg'
import { scanGit, scanZip, scanPaste } from '../api/client'

const CWE_OPTIONS = [
  { value: 'CWE-89',  label: 'SQL Injection'          },
  { value: 'CWE-79',  label: 'XSS'                    },
  { value: 'CWE-20',  label: 'Input Validation'        },
  { value: 'CWE-200', label: 'Information Exposure'    },
  { value: 'CWE-22',  label: 'Path Traversal'          },
  { value: 'CWE-352', label: 'CSRF'                    },
  { value: 'CWE-502', label: 'Deserialization'         },
  { value: 'CWE-287', label: 'Authentication'          },
  { value: 'CWE-798', label: 'Hardcoded Credentials'   },
  { value: 'CWE-306', label: 'Missing Auth'            },
  { value: 'CWE-94',  label: 'Code Injection'          },
  { value: 'CWE-78',  label: 'Command Injection'       },
  { value: 'CWE-601', label: 'URL Redirection'         },
  { value: 'CWE-312', label: 'Cleartext Storage'       },
  { value: 'CWE-327', label: 'Broken Crypto'           },
  { value: 'CWE-918', label: 'SSRF'                    },
  { value: 'CWE-434', label: 'Unrestricted Upload'     },
  { value: 'CWE-611', label: 'XXE'                     },
  { value: 'CWE-400', label: 'Resource Exhaustion'     },
  { value: 'CWE-384', label: 'Session Fixation'        },
]

const DEFAULT_CWES = CWE_OPTIONS.map(c => c.value)

export default function Home() {
  const navigate = useNavigate()

  const [activeTab,    setActiveTab]    = useState('git')
  const [depthDeep,    setDepthDeep]    = useState(false)
  const [vulnOpen,     setVulnOpen]     = useState(false)
  const [isLoading,    setIsLoading]    = useState(false)
  const [error,        setError]        = useState(null)
  const [selectedFile, setSelectedFile] = useState(null)
  const [formData, setFormData] = useState({
    gitUrl:   '',
    branch:   '',
    code:     '',
    language: 'python',
    filename: '',
    cwes:     DEFAULT_CWES,
  })

  const fileRef = useRef(null)

  const update = (patch) => setFormData(p => ({ ...p, ...patch }))

  const toggleCwe = (cwe) => {
    setFormData(p => ({
      ...p,
      cwes: p.cwes.includes(cwe) ? p.cwes.filter(c => c !== cwe) : [...p.cwes, cwe],
    }))
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setIsLoading(true)
    setError(null)
    const lite = !depthDeep
    try {
      let response
      if (activeTab === 'git') {
        response = await scanGit({ url: formData.gitUrl, branch: formData.branch, cwes: formData.cwes, lite })
      } else if (activeTab === 'zip') {
        const fd = new FormData()
        fd.append('file', selectedFile)
        fd.append('cwes', formData.cwes.join(','))
        fd.append('lite', lite ? 'true' : 'false')
        response = await scanZip(fd)
      } else {
        response = await scanPaste({ code: formData.code, language: formData.language, filename: formData.filename, cwes: formData.cwes, lite })
      }
      // Track active scan in localStorage
      try {
        const raw  = localStorage.getItem('autopov_active_scans')
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

  // ── Styles ────────────────────────────────────────────
  const pageStyle = {
    position: 'relative',
    minHeight: '100%',
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    padding: '32px 24px',
  }

  const cardStyle = {
    position: 'relative',
    zIndex: 1,
    width: '100%',
    maxWidth: 600,
  }

  const labelStyle = {
    fontFamily: '"JetBrains Mono", monospace',
    fontSize: 10,
    letterSpacing: '.14em',
    color: 'var(--text3)',
    textTransform: 'uppercase',
    marginBottom: 8,
    display: 'block',
  }

  const inputStyle = {
    width: '100%',
    background: 'var(--surface2)',
    border: '1px solid var(--border2)',
    padding: '10px 14px',
    color: 'var(--text1)',
    fontFamily: '"JetBrains Mono", monospace',
    fontSize: 12,
    outline: 'none',
  }

  const textareaStyle = {
    ...inputStyle,
    fontFamily: '"JetBrains Mono", monospace',
    fontSize: 12,
    resize: 'vertical',
    minHeight: 180,
  }

  const selectStyle = {
    ...inputStyle,
    cursor: 'pointer',
    appearance: 'none',
  }

  const btnPrimaryStyle = {
    width: '100%',
    padding: '14px',
    background: isLoading ? 'var(--border2)' : 'var(--accent)',
    color: isLoading ? 'var(--text3)' : '#fff',
    border: 'none',
    fontFamily: '"JetBrains Mono", monospace',
    fontSize: 11,
    letterSpacing: '.16em',
    textTransform: 'uppercase',
    cursor: isLoading ? 'not-allowed' : 'pointer',
    transition: 'background .15s',
    display: 'flex',
    alignItems: 'center',
    justifyContent: 'center',
    gap: 8,
  }

  return (
    <div style={pageStyle}>
      <ParallaxBg />

      <div style={cardStyle}>
        {/* Page label */}
        <div style={{
          textAlign: 'center', marginBottom: 8,
          fontFamily: '"JetBrains Mono", monospace',
          fontSize: 10, letterSpacing: '.18em',
          color: 'var(--text3)',
        }}>
          [ VULNERABILITY ANALYSIS ]
        </div>

        {/* Heading */}
        <div style={{
          textAlign: 'center', marginBottom: 4,
          display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12,
          fontFamily: '"JetBrains Mono", monospace',
          fontSize: 10, letterSpacing: '.12em',
          color: 'var(--text3)',
        }}>
          <span style={{ flex: 1, height: 1, background: 'var(--accent)', opacity: .4 }} />
          INITIATE SCAN
          <span style={{ flex: 1, height: 1, background: 'var(--accent)', opacity: .4 }} />
        </div>

        <h1 style={{
          textAlign: 'center', marginBottom: 6,
          fontSize: 32, fontWeight: 700, letterSpacing: '.04em',
          color: 'var(--text1)',
        }}>
          AutoPoV
        </h1>

        <p style={{
          textAlign: 'center', marginBottom: 28,
          fontFamily: '"JetBrains Mono", monospace',
          fontSize: 11, letterSpacing: '.06em',
          color: 'var(--text3)',
        }}>
          Autonomous Proof-of-Vulnerability Framework for LLM Benchmarking
        </p>

        {/* Error */}
        {error && (
          <div style={{
            background: 'rgba(239,68,68,0.1)',
            border: '1px solid rgba(239,68,68,0.35)',
            padding: '10px 14px', marginBottom: 16,
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: 11, color: '#fca5a5',
          }}>
            {error}
          </div>
        )}

        <form onSubmit={handleSubmit}>
          {/* Tab row */}
          <div className="tabs-row">
            <div className="tabs-group">
              {[
                { id: 'git',   label: 'Repository URL' },
                { id: 'zip',   label: 'ZIP Archive'    },
                { id: 'paste', label: 'Paste Code'     },
              ].map(tab => (
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
            <button
              type="button"
              className={`depth-btn${depthDeep ? ' deep' : ''}`}
              onClick={() => setDepthDeep(d => !d)}
            >
              {depthDeep ? 'DEEP' : 'LITE'}
            </button>
          </div>

          {/* Tab content */}
          <div style={{ marginBottom: 16 }}>
            {/* Git URL */}
            {activeTab === 'git' && (
              <div>
                <span style={labelStyle}>Repository URL</span>
                <div style={{ display: 'flex', alignItems: 'center', border: '1px solid var(--border2)', background: 'var(--surface2)' }}>
                  <span style={{ padding: '0 12px', color: 'var(--accent)', fontSize: 16 }}>⊕</span>
                  <input
                    type="url"
                    value={formData.gitUrl}
                    onChange={e => update({ gitUrl: e.target.value })}
                    placeholder="https://github.com/org/repo"
                    required
                    style={{ ...inputStyle, border: 'none', background: 'transparent', flex: 1, paddingLeft: 0 }}
                  />
                </div>
              </div>
            )}

            {/* ZIP upload */}
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
                  onChange={e => setSelectedFile(e.target.files[0])}
                  style={{ display: 'none' }}
                  required
                />
                <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 11, letterSpacing: '.1em', color: selectedFile ? 'var(--accent)' : 'var(--text3)' }}>
                  {selectedFile ? selectedFile.name : 'DROP ZIP FILE OR CLICK TO BROWSE'}
                </div>
              </div>
            )}

            {/* Paste code */}
            {activeTab === 'paste' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                <div style={{ display: 'flex', gap: 10 }}>
                  <div style={{ flex: 1 }}>
                    <span style={labelStyle}>Language</span>
                    <select value={formData.language} onChange={e => update({ language: e.target.value })} style={selectStyle}>
                      {['python','javascript','c','cpp','java','go','rust'].map(l => (
                        <option key={l} value={l}>{l}</option>
                      ))}
                    </select>
                  </div>
                  <div style={{ flex: 1 }}>
                    <span style={labelStyle}>Filename (optional)</span>
                    <input type="text" value={formData.filename} onChange={e => update({ filename: e.target.value })} placeholder="source.py" style={inputStyle} />
                  </div>
                </div>
                <div>
                  <span style={labelStyle}>Code</span>
                  <textarea value={formData.code} onChange={e => update({ code: e.target.value })} placeholder="Paste your code here..." required style={textareaStyle} />
                </div>
              </div>
            )}
          </div>

          {/* Vulnerability Scope */}
          <div style={{ marginBottom: 16 }}>
            <div
              onClick={() => setVulnOpen(o => !o)}
              style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '10px 14px',
                background: 'var(--surface1)',
                border: '1px solid var(--border2)',
                cursor: 'pointer',
                fontFamily: '"JetBrains Mono", monospace',
                fontSize: 10, letterSpacing: '.1em', color: 'var(--text2)',
              }}
            >
              <span style={{
                display: 'inline-block',
                transform: vulnOpen ? 'rotate(0deg)' : 'rotate(-90deg)',
                transition: 'transform .2s',
                fontSize: 10, color: 'var(--text3)',
              }}>▼</span>
              VULNERABILITY SCOPE
              <span style={{
                marginLeft: 8, padding: '1px 8px',
                background: 'var(--accent)', color: '#fff',
                fontFamily: '"JetBrains Mono", monospace', fontSize: 9,
              }}>{formData.cwes.length}</span>
              <span style={{ color: 'var(--text3)' }}>/ {CWE_OPTIONS.length} selected</span>
              <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
                <button
                  type="button"
                  onClick={e => { e.stopPropagation(); update({ cwes: DEFAULT_CWES }) }}
                  style={{ background: 'none', border: '1px solid var(--border2)', color: 'var(--text3)', padding: '2px 8px', fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.1em', cursor: 'pointer' }}
                >SELECT ALL</button>
                <button
                  type="button"
                  onClick={e => { e.stopPropagation(); update({ cwes: [] }) }}
                  style={{ background: 'none', border: '1px solid var(--border2)', color: 'var(--text3)', padding: '2px 8px', fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.1em', cursor: 'pointer' }}
                >CLEAR</button>
              </div>
            </div>

            {vulnOpen && (
              <div style={{
                background: 'var(--surface1)',
                border: '1px solid var(--border2)',
                borderTop: 'none',
                padding: '12px 14px',
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fill, minmax(170px, 1fr))',
                gap: 6,
              }}>
                {CWE_OPTIONS.map(cwe => (
                  <label key={cwe.value} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontFamily: '"JetBrains Mono", monospace', fontSize: 10, color: 'var(--text2)' }}>
                    <input
                      type="checkbox"
                      checked={formData.cwes.includes(cwe.value)}
                      onChange={() => toggleCwe(cwe.value)}
                      style={{ accentColor: 'var(--accent)' }}
                    />
                    <span style={{ color: 'var(--accent)', marginRight: 2 }}>{cwe.value}</span>
                    {cwe.label}
                  </label>
                ))}
              </div>
            )}
          </div>

          {/* Submit */}
          <button type="submit" disabled={isLoading} style={btnPrimaryStyle}>
            {isLoading ? (
              <>
                <span style={{
                  width: 14, height: 14,
                  border: '2px solid rgba(255,255,255,0.3)',
                  borderTopColor: '#fff',
                  borderRadius: '50%',
                  display: 'inline-block',
                  animation: 'spin 0.8s linear infinite',
                }} />
                STARTING SCAN…
              </>
            ) : (
              '⊕  ANALYZE REPOSITORY'
            )}
          </button>
        </form>

        {/* Status line */}
        <div style={{
          marginTop: 16, textAlign: 'center',
          fontFamily: '"JetBrains Mono", monospace',
          fontSize: 10, letterSpacing: '.12em',
          color: 'var(--text3)',
        }}>
          {isLoading ? 'INITIALIZING SCAN…' : `AWAITING INPUT ${'─'.repeat(8)}`}
        </div>
      </div>

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>
    </div>
  )
}
