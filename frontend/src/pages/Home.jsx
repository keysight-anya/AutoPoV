import { useState, useRef, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import ParallaxBg from '../components/ParallaxBg'
import { scanGit, scanZip, scanPaste } from '../api/client'

// ── Vulnerability categories matching the scan mockup ──
const CWE_CATEGORIES = [
  { label: 'INJECTION', items: [
    { value: 'CWE-89',   label: 'SQL',          sublabel: 'SQL Injection'       },
    { value: 'CWE-78',   label: 'COMMAND',      sublabel: 'Command Injection'   },
    { value: 'CWE-90',   label: 'LDAP',         sublabel: 'LDAP Injection'      },
    { value: 'CWE-1336', label: 'TEMPLATE',     sublabel: 'Template Injection'  },
  ]},
  { label: 'AUTHENTICATION', items: [
    { value: 'CWE-287',  label: 'BROKEN AUTH',  sublabel: 'Broken Authentication' },
    { value: 'CWE-798',  label: 'HARDCODED',    sublabel: 'Hardcoded Credentials' },
    { value: 'CWE-384',  label: 'WEAK SESSION', sublabel: 'Session Fixation'    },
  ]},
  { label: 'CRYPTOGRAPHY', items: [
    { value: 'CWE-327',  label: 'WEAK CIPHER',  sublabel: 'Broken Cryptography' },
    { value: 'CWE-338',  label: 'INSECURE RNG', sublabel: 'Insecure Randomness' },
    { value: 'CWE-321',  label: 'HARDCODED KEY',sublabel: 'Hardcoded Key'       },
  ]},
  { label: 'INPUT HANDLING', items: [
    { value: 'CWE-79',   label: 'XSS',          sublabel: 'Cross-Site Scripting' },
    { value: 'CWE-22',   label: 'PATH TRAV',    sublabel: 'Path Traversal'      },
    { value: 'CWE-787',  label: 'BUFFER OVF',   sublabel: 'Buffer Overflow'     },
    { value: 'CWE-190',  label: 'INT OVF',      sublabel: 'Integer Overflow'    },
  ]},
  { label: 'ACCESS CONTROL', items: [
    { value: 'CWE-639',  label: 'IDOR',         sublabel: 'Insecure Direct Object Ref' },
    { value: 'CWE-862',  label: 'MISSING AUTH', sublabel: 'Missing Authorization'      },
    { value: 'CWE-269',  label: 'PRIV ESC',     sublabel: 'Privilege Escalation'       },
  ]},
  { label: 'SECRETS', items: [
    { value: 'CWE-540',  label: 'API KEYS',     sublabel: 'Hardcoded API Keys'  },
    { value: 'CWE-615',  label: 'ENV VARS',     sublabel: 'Insecure Env Vars'   },
    { value: 'CWE-502',  label: 'DESER',        sublabel: 'Deserialization'     },
  ]},
]

const CWE_OPTIONS  = CWE_CATEGORIES.flatMap(c => c.items)
const DEFAULT_CWES = CWE_OPTIONS.map(c => c.value)

export default function Home() {
  const navigate = useNavigate()

  const [activeTab,    setActiveTab]    = useState('git')
  const [depthDeep,    setDepthDeep]    = useState(false)
  const [vulnOpen,     setVulnOpen]     = useState(false)
  const [isLoading,    setIsLoading]    = useState(false)
  const [error,        setError]        = useState(null)
  const [selectedFile, setSelectedFile] = useState(null)
  const [btnPulsing,   setBtnPulsing]   = useState(false)
  const [formData, setFormData] = useState({
    gitUrl:   '',
    branch:   '',
    code:     '',
    language: 'python',
    filename: '',
    cwes:     DEFAULT_CWES,
  })

  const fileRef   = useRef(null)
  const gitUrlRef = useRef(null)
  const codeRef   = useRef(null)

  // Auto-focus the relevant input when tab changes
  useEffect(() => {
    if (activeTab === 'git')   gitUrlRef.current?.focus()
    if (activeTab === 'paste') codeRef.current?.focus()
  }, [activeTab])

  const update = (patch) => setFormData(p => ({ ...p, ...patch }))

  const toggleCwe = (cwe) => {
    setFormData(p => ({
      ...p,
      cwes: p.cwes.includes(cwe) ? p.cwes.filter(c => c !== cwe) : [...p.cwes, cwe],
    }))
  }

  const toggleCategory = (e, cat) => {
    e.stopPropagation()
    const vals    = cat.items.map(i => i.value)
    const allOn   = vals.every(v => formData.cwes.includes(v))
    setFormData(p => ({
      ...p,
      cwes: allOn
        ? p.cwes.filter(v => !vals.includes(v))
        : [...new Set([...p.cwes, ...vals])],
    }))
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    // Pulse the button once on click
    setBtnPulsing(true)
    setTimeout(() => setBtnPulsing(false), 600)

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
  const selectStyle   = { ...inputBase, cursor: 'pointer', appearance: 'none' }

  return (
    <div style={{
      position: 'relative',
      minHeight: '100%',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '32px 24px',
    }}>
      <ParallaxBg />

      {/* Card */}
      <div style={{ position: 'relative', zIndex: 1, width: '100%', maxWidth: 600 }}>

        {/* Page label */}
        <div style={{
          textAlign: 'center', marginBottom: 8,
          fontFamily: monoFont,
          fontSize: 10, letterSpacing: '.18em',
          color: 'var(--text3)',
        }}>
          [ VULNERABILITY ANALYSIS ]
        </div>

        {/* INITIATE SCAN rule */}
        <div style={{
          textAlign: 'center', marginBottom: 4,
          display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 12,
          fontFamily: monoFont,
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
          fontFamily: monoFont,
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
            fontFamily: monoFont,
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
                { id: 'git',   label: 'REPOSITORY URL' },
                { id: 'zip',   label: 'ZIP ARCHIVE'    },
                { id: 'paste', label: 'PASTE CODE'     },
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

            {/* Git URL tab */}
            {activeTab === 'git' && (
              <div>
                <span style={labelStyle}>Repository URL</span>
                <div className="input-glow-wrap">
                  <span style={{ padding: '0 12px', color: 'var(--accent)', fontSize: 16, flexShrink: 0 }}>⊕</span>
                  <input
                    ref={gitUrlRef}
                    autoFocus
                    type="url"
                    value={formData.gitUrl}
                    onChange={e => update({ gitUrl: e.target.value })}
                    placeholder="https://github.com/org/repo"
                    required
                    style={{ ...inputBase, border: 'none', background: 'transparent', flex: 1, paddingLeft: 0 }}
                  />
                </div>
              </div>
            )}

            {/* ZIP upload tab */}
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
                <div style={{ fontFamily: monoFont, fontSize: 11, letterSpacing: '.1em', color: selectedFile ? 'var(--accent)' : 'var(--text3)' }}>
                  {selectedFile ? selectedFile.name : 'DROP ZIP FILE OR CLICK TO BROWSE'}
                </div>
              </div>
            )}

            {/* Paste code tab */}
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
                    <input type="text" value={formData.filename} onChange={e => update({ filename: e.target.value })} placeholder="source.py" style={inputBase} />
                  </div>
                </div>
                <div>
                  <span style={labelStyle}>Code</span>
                  <textarea ref={codeRef} value={formData.code} onChange={e => update({ code: e.target.value })} placeholder="Paste your code here..." required style={textareaStyle} />
                </div>
              </div>
            )}
          </div>

          {/* Vulnerability scope */}
          <div style={{ marginBottom: 16 }}>
            <div
              onClick={() => setVulnOpen(o => !o)}
              style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '10px 14px',
                background: 'var(--surface1)',
                border: '1px solid var(--border2)',
                cursor: 'pointer',
                fontFamily: monoFont,
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
                fontFamily: monoFont, fontSize: 9,
              }}>{formData.cwes.length}</span>
              <span style={{ color: 'var(--text3)' }}>/ {CWE_OPTIONS.length} selected</span>
              <div style={{ marginLeft: 'auto', display: 'flex', gap: 8 }}>
                <button
                  type="button"
                  onClick={e => { e.stopPropagation(); update({ cwes: DEFAULT_CWES }) }}
                  style={{ background: 'none', border: '1px solid var(--border2)', color: 'var(--text3)', padding: '2px 8px', fontFamily: monoFont, fontSize: 9, letterSpacing: '.1em', cursor: 'pointer' }}
                >SELECT ALL</button>
                <button
                  type="button"
                  onClick={e => { e.stopPropagation(); update({ cwes: [] }) }}
                  style={{ background: 'none', border: '1px solid var(--border2)', color: 'var(--text3)', padding: '2px 8px', fontFamily: monoFont, fontSize: 9, letterSpacing: '.1em', cursor: 'pointer' }}
                >CLEAR</button>
              </div>
            </div>

            {/* Category grid */}
            {vulnOpen && (
              <div style={{
                background: 'var(--surface1)',
                border: '1px solid var(--border2)',
                borderTop: 'none',
                padding: '8px 10px',
                display: 'flex',
                flexDirection: 'column',
                gap: 6,
              }}>
                {CWE_CATEGORIES.map(cat => {
                  const allOn = cat.items.every(i => formData.cwes.includes(i.value))
                  return (
                    <div key={cat.label} style={{ display: 'flex', alignItems: 'flex-start', gap: 8 }}>
                      {/* Category label — fixed width, click to toggle all */}
                      <div
                        onClick={e => toggleCategory(e, cat)}
                        style={{
                          flexShrink: 0,
                          width: 96,
                          paddingTop: 5,
                          fontFamily: monoFont,
                          fontSize: 8, letterSpacing: '.14em',
                          color: allOn ? 'var(--accent)' : 'var(--text3)',
                          cursor: 'pointer',
                          userSelect: 'none',
                        }}
                      >
                        {cat.label}
                      </div>
                      {/* CWE chips */}
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, flex: 1 }}>
                        {cat.items.map(cwe => {
                          const on = formData.cwes.includes(cwe.value)
                          return (
                            <button
                              key={cwe.value}
                              type="button"
                              onClick={() => toggleCwe(cwe.value)}
                              title={cwe.sublabel}
                              style={{
                                display: 'flex', flexDirection: 'column', alignItems: 'center',
                                padding: '4px 8px',
                                background: on ? 'var(--accent)' : 'var(--surface2)',
                                border: `1px solid ${on ? 'var(--accent)' : 'var(--border2)'}`,
                                color: on ? '#fff' : 'var(--text3)',
                                fontFamily: monoFont,
                                cursor: 'pointer',
                                transition: 'background .12s, border-color .12s, color .12s',
                                minWidth: 58,
                              }}
                            >
                              <span style={{ fontSize: 9, letterSpacing: '.04em', fontWeight: 600 }}>{cwe.label}</span>
                              <span style={{ fontSize: 7, letterSpacing: '.03em', opacity: .6, marginTop: 1 }}>{cwe.value}</span>
                            </button>
                          )
                        })}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>

          {/* Submit — outline style, fills on hover, pulses on click */}
          <button
            type="submit"
            disabled={isLoading}
            className={`scan-btn${btnPulsing ? ' pulsing' : ''}`}
            style={{ opacity: isLoading ? 0.5 : 1, cursor: isLoading ? 'not-allowed' : 'pointer' }}
          >
            {isLoading ? (
              <>
                <span className="spin-ring" />
                STARTING SCAN…
              </>
            ) : (
              '⊕  ANALYZE REPOSITORY'
            )}
          </button>

        </form>

        {/* Animated status line — hides once the user starts typing */}
        {(() => {
          const hasInput =
            (activeTab === 'git'   && formData.gitUrl.length > 0) ||
            (activeTab === 'zip'   && selectedFile != null) ||
            (activeTab === 'paste' && formData.code.length > 0)
          if (isLoading) return (
            <div style={{ marginTop: 16, textAlign: 'center', fontFamily: monoFont, fontSize: 10, letterSpacing: '.12em', color: 'var(--text3)' }}>
              INITIALIZING SCAN&hellip;
            </div>
          )
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
