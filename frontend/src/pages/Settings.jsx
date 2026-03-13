// frontend/src/pages/Settings.jsx
import { useState, useEffect } from 'react'
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

export default function Settings() {
  const [apiKey,  setApiKey]  = useState('')
  const [saved,   setSaved]   = useState(false)
  const [show,    setShow]    = useState(false)
  const [tab,     setTab]     = useState('api')

  useEffect(() => {
    setApiKey(localStorage.getItem('autopov_api_key') || '')
  }, [])

  const saveApiKey = () => {
    localStorage.setItem('autopov_api_key', apiKey)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
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
    marginBottom: 12,
  }

  const btnStyle = (primary) => ({
    padding: '8px 20px',
    background: primary ? 'var(--accent)' : 'none',
    border: `1px solid ${primary ? 'var(--accent)' : 'var(--border2)'}`,
    color: primary ? '#fff' : 'var(--text3)',
    fontFamily: '"JetBrains Mono", monospace',
    fontSize: 10, letterSpacing: '.1em',
    cursor: 'pointer',
    transition: 'background .15s, color .15s',
  })

  const monoStyle = { fontFamily: '"JetBrains Mono", monospace' }

  return (
    <div style={{ padding: 24, maxWidth: 640 }}>
      {/* Page label */}
      <div style={{ ...monoStyle, fontSize: 9, letterSpacing: '.18em', color: 'var(--text3)', marginBottom: 20 }}>
        [ SETTINGS ]
      </div>

      {/* Tabs */}
      <div className="tabs-row" style={{ marginBottom: 24 }}>
        <div className="tabs-group">
          {['api', 'webhooks'].map(t => (
            <button key={t} type="button" className={`glass-tab${tab === t ? ' active' : ''}`} onClick={() => setTab(t)}>
              {t === 'api' ? 'API KEY' : 'WEBHOOKS'}
            </button>
          ))}
        </div>
      </div>

      {tab === 'api' && (
        <>
          <Panel title="API KEY CONFIGURATION">
            <p style={{ fontSize: 12, color: 'var(--text2)', marginBottom: 14, lineHeight: 1.6 }}>
              Enter your AutoPoV API key. Generate one via:
            </p>
            <div style={{ background: 'var(--bg)', border: '1px solid var(--border1)', padding: '8px 12px', marginBottom: 16 }}>
              <code style={{ ...monoStyle, fontSize: 11, color: '#86efac' }}>autopov keys generate</code>
            </div>

            <div style={{ position: 'relative', marginBottom: 12 }}>
              <input
                type={show ? 'text' : 'password'}
                value={apiKey}
                onChange={e => setApiKey(e.target.value)}
                placeholder="apov_..."
                style={inputStyle}
              />
              <button
                type="button"
                onClick={() => setShow(s => !s)}
                style={{ position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)', background: 'none', border: 'none', color: 'var(--text3)', cursor: 'pointer', ...monoStyle, fontSize: 9, letterSpacing: '.1em' }}
              >
                {show ? 'HIDE' : 'SHOW'}
              </button>
            </div>

            <button onClick={saveApiKey} style={btnStyle(true)}>
              {saved ? '✓ SAVED' : 'SAVE KEY'}
            </button>
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

      {tab === 'webhooks' && <WebhookSetup />}
    </div>
  )
}
