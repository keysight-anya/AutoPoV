// frontend/src/pages/Settings.jsx
import { useState, useEffect, useRef } from 'react'
import WebhookSetup from '../components/WebhookSetup'

function Panel({ title, children }) {
  return (
    <div style={{
      background: 'var(--surface1)',
      border: '1px solid var(--border1)',
      borderLeft: '3px solid var(--accent)',
      padding: '20px 24px',
      marginBottom: 16,
    }}>
      <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.16em', color: 'var(--text3)', marginBottom: 16 }}>
        {title}
      </div>
      {children}
    </div>
  )
}

function KeyField({ label, value, onChange, placeholder, show, onToggleShow, onSave, saved }) {
  const monoStyle = { fontFamily: '"JetBrains Mono", monospace' }
  const inputStyle = {
    width: '100%',
    background: 'var(--surface2)',
    border: '1px solid var(--border2)',
    padding: '10px 14px',
    color: 'var(--text1)',
    fontFamily: '"JetBrains Mono", monospace',
    fontSize: 12,
    outline: 'none',
    marginBottom: 12,
    boxSizing: 'border-box',
  }
  const btnStyle = (primary) => ({
    padding: '8px 20px',
    background: primary ? 'var(--accent)' : 'none',
    border: `1px solid ${primary ? 'var(--accent)' : 'var(--border2)'}`,
    color: primary ? '#fff' : 'var(--text3)',
    fontFamily: '"JetBrains Mono", monospace',
    fontSize: 10, letterSpacing: '.1em',
    cursor: 'pointer',
  })
  return (
    <>
      <div style={{ position: 'relative', marginBottom: 4 }}>
        <input
          type={show ? 'text' : 'password'}
          value={value}
          onChange={e => onChange(e.target.value)}
          placeholder={placeholder}
          style={inputStyle}
        />
        <button
          type="button"
          onClick={onToggleShow}
          style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-62%)', background: 'none', border: 'none', color: 'var(--text3)', cursor: 'pointer', ...monoStyle, fontSize: 9, letterSpacing: '.1em' }}
        >
          {show ? 'HIDE' : 'SHOW'}
        </button>
      </div>
      <button type="button" onClick={onSave} style={btnStyle(true)}>
        {saved ? '✓ SAVED' : 'SAVE KEY'}
      </button>
    </>
  )
}

export default function Settings() {
  const [apiKey,        setApiKey]        = useState('')
  const [orKey,         setOrKey]         = useState('')
  const [savedApiKey,   setSavedApiKey]   = useState(false)
  const [savedOrKey,    setSavedOrKey]    = useState(false)
  const [showApiKey,    setShowApiKey]    = useState(false)
  const [showOrKey,     setShowOrKey]     = useState(false)
  const [tab,           setTab]           = useState('api')
  const apiKeyTimerRef = useRef(null)
  const orKeyTimerRef  = useRef(null)

  useEffect(() => {
    setApiKey(localStorage.getItem('autopov_api_key') || '')
    setOrKey(localStorage.getItem('openrouter_api_key') || '')
  }, [])

  useEffect(() => () => {
    clearTimeout(apiKeyTimerRef.current)
    clearTimeout(orKeyTimerRef.current)
  }, [])

  const saveKey = (storageKey, value, setSaved, timerRef) => {
    if (value.trim()) {
      localStorage.setItem(storageKey, value.trim())
    } else {
      localStorage.removeItem(storageKey)
    }
    setSaved(true)
    clearTimeout(timerRef.current)
    timerRef.current = setTimeout(() => setSaved(false), 2000)
  }

  const monoStyle = { fontFamily: '"JetBrains Mono", monospace' }

  return (
    <div style={{ padding: 24, maxWidth: 640 }}>
      <div style={{ ...monoStyle, fontSize: 9, letterSpacing: '.18em', color: 'var(--text3)', marginBottom: 20 }}>
        [ SETTINGS ]
      </div>

      <div className="tabs-row" style={{ marginBottom: 24 }}>
        <div className="tabs-group">
          {[
            { id: 'api',      label: 'API KEY'    },
            { id: 'llm',      label: 'LLM'        },
            { id: 'webhooks', label: 'WEBHOOKS'   },
          ].map(t => (
            <button key={t.id} type="button" className={`glass-tab${tab === t.id ? ' active' : ''}`} onClick={() => setTab(t.id)}>
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {tab === 'api' && (
        <>
          <Panel title="API KEY CONFIGURATION">
            <p style={{ fontSize: 12, color: 'var(--text2)', marginBottom: 14, lineHeight: 1.6 }}>
              Enter your AutoPoV backend API key. Generate one via:
            </p>
            <div style={{ background: 'var(--bg)', border: '1px solid var(--border1)', padding: '8px 12px', marginBottom: 16 }}>
              <code style={{ ...monoStyle, fontSize: 11, color: '#86efac' }}>autopov keys generate</code>
            </div>
            <KeyField
              value={apiKey}
              onChange={setApiKey}
              placeholder="apov_..."
              show={showApiKey}
              onToggleShow={() => setShowApiKey(s => !s)}
              onSave={() => saveKey('autopov_api_key', apiKey, setSavedApiKey, apiKeyTimerRef)}
              saved={savedApiKey}
            />
          </Panel>

          <Panel title="ENVIRONMENT VARIABLE">
            <div style={{ background: 'var(--bg)', border: '1px solid var(--border1)', padding: '8px 12px' }}>
              <code style={{ ...monoStyle, fontSize: 11, color: '#86efac' }}>
                export AUTOPOV_API_KEY=your_key_here
              </code>
            </div>
          </Panel>
        </>
      )}

      {tab === 'llm' && (
        <>
          <Panel title="OPENROUTER API KEY">
            <p style={{ fontSize: 12, color: 'var(--text2)', marginBottom: 14, lineHeight: 1.6 }}>
              Enter your OpenRouter API key to power vulnerability analysis.
              This key is sent with each scan request and takes precedence over the
              server-side environment variable.
            </p>
            <div style={{ background: 'var(--bg)', border: '1px solid var(--border1)', padding: '8px 12px', marginBottom: 16 }}>
              <code style={{ ...monoStyle, fontSize: 11, color: 'var(--text3)' }}>
                Get a key at{' '}
                <a href="https://openrouter.ai/keys" target="_blank" rel="noreferrer" style={{ color: 'var(--accent)' }}>
                  openrouter.ai/keys
                </a>
              </code>
            </div>
            <KeyField
              value={orKey}
              onChange={setOrKey}
              placeholder="sk-or-v1-..."
              show={showOrKey}
              onToggleShow={() => setShowOrKey(s => !s)}
              onSave={() => saveKey('openrouter_api_key', orKey, setSavedOrKey, orKeyTimerRef)}
              saved={savedOrKey}
            />
          </Panel>

          <Panel title="FALLBACK BEHAVIOUR">
            <p style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.6 }}>
              If no key is saved here, the server falls back to the
              <code style={{ ...monoStyle, fontSize: 11, color: '#86efac', margin: '0 4px' }}>OPENROUTER_API_KEY</code>
              environment variable configured on the backend.
            </p>
          </Panel>
        </>
      )}

      {tab === 'webhooks' && <WebhookSetup />}
    </div>
  )
}
