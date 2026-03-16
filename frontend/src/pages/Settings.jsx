<<<<<<< HEAD
import { useState, useEffect } from 'react'
import { Settings, Key, Save, Check, Trash2, RefreshCw, AlertCircle, Plus, Cpu } from 'lucide-react'
import WebhookSetup from '../components/WebhookSetup'
import { listApiKeys, generateApiKey } from '../api/client'
import apiClient from '../api/client'

const OFFLINE_MODEL_LABELS = {
  "llama4": {
    title: "Llama 4",
    description: "Latest Meta Llama family model currently listed by Ollama"
  },
  "glm-4.7-flash": {
    title: "GLM-4.7-Flash",
    description: "Latest locally runnable GLM model currently listed by Ollama"
  },
  "qwen3": {
    title: "Qwen 3",
    description: "Latest Qwen generation currently listed by Ollama"
  }
}

const ONLINE_MODEL_LABELS = {
  "openai/gpt-5.2": {
    title: "OpenAI GPT-5.2",
    description: "Latest OpenAI flagship model on OpenRouter"
  },
  "anthropic/claude-opus-4.6": {
    title: "Anthropic Claude Opus 4.6",
    description: "Latest Claude model currently available on OpenRouter"
  }
}

function SettingsPage() {
  const [apiKey, setApiKey] = useState('')
  const [saved, setSaved] = useState(false)
  const [activeTab, setActiveTab] = useState('api')

  // Key management state (now public)
  const [keys, setKeys] = useState([])
  const [keysLoading, setKeysLoading] = useState(false)
  const [keysError, setKeysError] = useState(null)
  const [newKeyName, setNewKeyName] = useState('')
  const [generatedKey, setGeneratedKey] = useState(null)
  const [generatingKey, setGeneratingKey] = useState(false)
  const [revoking, setRevoking] = useState(null)

  // Model configuration state
  const [settings, setSettings] = useState(null)
  const [settingsLoading, setSettingsLoading] = useState(false)
  const [settingsError, setSettingsError] = useState(null)
  const [settingsSaved, setSettingsSaved] = useState(false)
  const [openRouterKey, setOpenRouterKey] = useState('')

  useEffect(() => {
    // Set default tab to Model Config
    setActiveTab('models')
  }, [])

  const saveApiKey = () => {
    localStorage.setItem('autopov_api_key', apiKey)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const loadKeys = async () => {
    setKeysLoading(true)
    setKeysError(null)
    try {
      const res = await listApiKeys()
      setKeys(res.data.keys || [])
    } catch (err) {
      setKeysError(err.response?.data?.detail || err.message || 'Failed to load keys')
    } finally {
      setKeysLoading(false)
    }
  }

  const handleGenerateKey = async () => {
    setGeneratingKey(true)
    setKeysError(null)
    setGeneratedKey(null)
    try {
      const res = await generateApiKey(newKeyName || 'default')
      setGeneratedKey(res.data.key)
      setNewKeyName('')
      await loadKeys()
    } catch (err) {
      setKeysError(err.response?.data?.detail || err.message || 'Failed to generate key')
    } finally {
      setGeneratingKey(false)
    }
  }

  const handleRevokeKey = async (keyId) => {
    if (!window.confirm('Revoke this API key? This cannot be undone.')) return
    setRevoking(keyId)
    setKeysError(null)
    try {
      await apiClient.delete(`/keys/${keyId}`)
      setKeys(prev => prev.filter(k => k.key_id !== keyId))
    } catch (err) {
      setKeysError(err.response?.data?.detail || err.message || 'Failed to revoke key')
    } finally {
      setRevoking(null)
    }
  }

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text)
  }

  // Load settings from backend
  const loadSettings = async () => {
    setSettingsLoading(true)
    setSettingsError(null)
    try {
      const res = await apiClient.get('/settings')
      setSettings(res.data)
    } catch (err) {
      setSettingsError(err.response?.data?.detail || err.message || 'Failed to load settings')
    } finally {
      setSettingsLoading(false)
    }
  }

  // Save settings to backend
  const saveSettings = async () => {
    if (settings?.model_mode === 'online' && !settings?.selected_model) {
      const confirmed = window.confirm('No online model is selected. Use OpenRouter automatic routing (openrouter/auto) for all agents?')
      if (!confirmed) return
    }

    setSettingsLoading(true)
    setSettingsError(null)
    try {
      const payload = {
        model_mode: settings?.model_mode,
        selected_model: settings?.selected_model || ''
      }
      if (openRouterKey && !settings?.openrouter_key_from_env) {
        payload.openrouter_api_key = openRouterKey
      }
      await apiClient.post('/settings', payload)
      setSettingsSaved(true)
      setTimeout(() => setSettingsSaved(false), 2000)
      await loadSettings()
    } catch (err) {
      setSettingsError(err.response?.data?.detail || err.message || 'Failed to save settings')
    } finally {
      setSettingsLoading(false)
    }
  }

  // Load settings/keys when tabs are selected
  useEffect(() => {
    if (activeTab === 'models') {
      loadSettings()
    } else if (activeTab === 'apikeys') {
      loadKeys()
    }
  }, [activeTab])

  return (
    <div className="max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center space-x-3 mb-6">
        <Settings className="w-8 h-8 text-primary-500" />
        <h1 className="text-2xl font-bold">Settings</h1>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-800 mb-6">
        <button
          onClick={() => setActiveTab('models')}
          className={`px-6 py-3 font-medium transition-colors ${
            activeTab === 'models'
              ? 'text-primary-500 border-b-2 border-primary-500'
              : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          Model Config
        </button>
        <button
          onClick={() => setActiveTab('apikeys')}
          className={`px-6 py-3 font-medium transition-colors ${
            activeTab === 'apikeys'
              ? 'text-primary-500 border-b-2 border-primary-500'
              : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          API Keys
        </button>
        <button
          onClick={() => setActiveTab('webhooks')}
          className={`px-6 py-3 font-medium transition-colors ${
            activeTab === 'webhooks'
              ? 'text-primary-500 border-b-2 border-primary-500'
              : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          Webhooks
        </button>
      </div>

      {/* Webhooks Tab */}
      {activeTab === 'webhooks' && <WebhookSetup />}

      {/* API Keys Tab */}
      {activeTab === 'apikeys' && (
        <div className="space-y-6">
          {/* Info box */}
          <div className="bg-blue-900/20 border border-blue-800 rounded-lg p-4">
            <p className="text-blue-300 text-sm">
              API keys are required for CLI access and external integrations. 
              The web interface works without authentication.
            </p>
          </div>

          {keysError && (
            <div className="flex items-center space-x-2 p-3 bg-red-900/30 border border-red-800 rounded-lg text-red-300 text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{keysError}</span>
            </div>
          )}

          {/* Generate new key */}
          <div className="bg-gray-900 rounded-lg border border-gray-800 p-6">
            <div className="flex items-center space-x-2 mb-4">
              <Plus className="w-5 h-5 text-primary-500" />
              <h2 className="text-lg font-medium">Generate New API Key</h2>
            </div>
            <div className="flex space-x-3">
              <input
                type="text"
                value={newKeyName}
                onChange={e => setNewKeyName(e.target.value)}
                placeholder="Key name (e.g. ci-bot)"
                className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-gray-100 focus:outline-none focus:border-primary-500"
              />
              <button
                onClick={handleGenerateKey}
                disabled={generatingKey}
                className="flex items-center space-x-2 px-4 py-2 bg-primary-600 hover:bg-primary-700 disabled:bg-gray-700 rounded-lg transition-colors"
              >
                {generatingKey ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : (
                  <Key className="w-4 h-4" />
                )}
                <span>Generate</span>
              </button>
            </div>
            {generatedKey && (
              <div className="mt-4 p-4 bg-green-900/20 border border-green-800 rounded-lg">
                <p className="text-sm text-green-300 mb-2 font-medium">New key generated — copy it now, it won't be shown again:</p>
                <div className="flex space-x-2">
                  <code className="flex-1 bg-gray-950 px-3 py-2 rounded text-sm text-green-400 break-all">{generatedKey}</code>
                  <button
                    onClick={() => copyToClipboard(generatedKey)}
                    className="px-3 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm transition-colors"
                  >
                    Copy
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* Keys table */}
          {keys.length > 0 && (
            <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-gray-850 border-b border-gray-800">
                  <tr>
                    <th className="text-left px-4 py-3 text-gray-400">ID</th>
                    <th className="text-left px-4 py-3 text-gray-400">Name</th>
                    <th className="text-left px-4 py-3 text-gray-400">Created</th>
                    <th className="text-left px-4 py-3 text-gray-400">Last Used</th>
                    <th className="text-left px-4 py-3 text-gray-400">Active</th>
                    <th className="text-left px-4 py-3 text-gray-400">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-800">
                  {keys.map(k => (
                    <tr key={k.key_id} className="hover:bg-gray-850">
                      <td className="px-4 py-3 font-mono text-gray-400">{k.key_id?.substring(0, 8)}...</td>
                      <td className="px-4 py-3">{k.name || '—'}</td>
                      <td className="px-4 py-3 text-gray-400">{(k.created_at || 'N/A').substring(0, 10)}</td>
                      <td className="px-4 py-3 text-gray-400">{k.last_used ? k.last_used.substring(0, 10) : 'never'}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full ${k.is_active ? 'bg-green-900/40 text-green-300' : 'bg-gray-700 text-gray-500'}`}>
                          {k.is_active ? 'Active' : 'Revoked'}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        {k.is_active && (
                          <button
                            onClick={() => handleRevokeKey(k.key_id)}
                            disabled={revoking === k.key_id}
                            className="flex items-center space-x-1 text-red-400 hover:text-red-300 disabled:opacity-50"
                          >
                            <Trash2 className="w-4 h-4" />
                            <span>{revoking === k.key_id ? 'Revoking...' : 'Revoke'}</span>
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* Model Configuration Tab */}
      {activeTab === 'models' && (
        <div className="space-y-6">
          {/* Info box */}
          <div className="bg-blue-900/20 border border-blue-800 rounded-lg p-4">
            <p className="text-blue-300 text-sm">
              Choose one explicit online model or leave the selection empty to use OpenRouter automatic routing by default. When auto is used, the same default route applies across all agents.
              Changes take effect on the next scan.
            </p>
          </div>

          {settingsError && (
            <div className="flex items-center space-x-2 p-3 bg-red-900/30 border border-red-800 rounded-lg text-red-300 text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{settingsError}</span>
            </div>
          )}

          {settingsLoading && !settings && (
            <div className="flex items-center justify-center p-8">
              <RefreshCw className="w-6 h-6 animate-spin text-primary-500" />
              <span className="ml-2 text-gray-400">Loading settings...</span>
            </div>
          )}

          {settings && (
            <>
              {/* Model Mode Selection */}
              <div className="bg-gray-900 rounded-lg border border-gray-800 p-6">
                <div className="flex items-center space-x-2 mb-4">
                  <Cpu className="w-5 h-5 text-primary-500" />
                  <h2 className="text-lg font-medium">Model Mode</h2>
                </div>
                <div className="flex space-x-4">
                  <button
                    onClick={() => setSettings(prev => ({ ...prev, model_mode: 'online' }))}
                    className={`flex-1 py-3 px-4 rounded-lg border transition-colors ${
                      settings.model_mode === 'online'
                        ? 'bg-primary-600 border-primary-500 text-white'
                        : 'bg-gray-800 border-gray-700 text-gray-400 hover:bg-gray-750'
                    }`}
                  >
                    <div className="font-medium">Online (OpenRouter)</div>
                    <div className="text-xs opacity-75">Use cloud-based models via OpenRouter</div>
                  </button>
                  <button
                    onClick={() => setSettings(prev => ({ ...prev, model_mode: 'offline' }))}
                    className={`flex-1 py-3 px-4 rounded-lg border transition-colors ${
                      settings.model_mode === 'offline'
                        ? 'bg-primary-600 border-primary-500 text-white'
                        : 'bg-gray-800 border-gray-700 text-gray-400 hover:bg-gray-750'
                    }`}
                  >
                    <div className="font-medium">Offline (Ollama)</div>
                    <div className="text-xs opacity-75">Use local models via Ollama</div>
                  </button>
                </div>
              </div>

              {/* Online Model Selection */}
              {settings.model_mode === 'online' && (
                <div className="bg-gray-900 rounded-lg border border-gray-800 p-6">
                  <div className="flex items-center justify-between mb-4 gap-3">
                    <div className="flex items-center space-x-2">
                      <Cpu className="w-5 h-5 text-primary-500" />
                      <h2 className="text-lg font-medium">Select Online Model</h2>
                    </div>
                    <button
                      type="button"
                      onClick={() => setSettings(prev => ({ ...prev, selected_model: '' }))}
                      className="text-sm text-gray-400 hover:text-gray-200 transition-colors"
                    >
                      Clear selection
                    </button>
                  </div>

                  <div className="space-y-3">
                    {(settings.available_online_models || []).map((model) => {
                      const meta = ONLINE_MODEL_LABELS[model] || {
                        title: model,
                        description: 'Available through OpenRouter'
                      }
                      return (
                        <label key={model} className="flex items-center p-4 bg-gray-800 rounded-lg cursor-pointer hover:bg-gray-750 transition-colors">
                          <input
                            type="radio"
                            name="online_model"
                            value={model}
                            checked={settings.selected_model === model}
                            onChange={(e) => setSettings(prev => ({ ...prev, selected_model: e.target.value }))}
                            className="w-4 h-4 text-primary-500"
                          />
                          <div className="ml-3">
                            <div className="font-medium">{meta.title}</div>
                            <div className="text-sm text-gray-400">{meta.description}</div>
                          </div>
                        </label>
                      )
                    })}
                  </div>

                  {!settings.selected_model && (
                    <div className="mt-4 rounded-lg border border-primary-500/30 bg-primary-500/10 p-4 text-sm text-primary-200">
                      No explicit online model selected. Saving now will use {settings.auto_router_model || 'openrouter/auto'} for all agents after confirmation.
                    </div>
                  )}
                </div>
              )}

              {/* Offline Model Selection */}
              {settings.model_mode === 'offline' && (
                <div className="bg-gray-900 rounded-lg border border-gray-800 p-6">
                  <div className="flex items-center space-x-2 mb-4">
                    <Cpu className="w-5 h-5 text-primary-500" />
                    <h2 className="text-lg font-medium">Select Ollama Model</h2>
                  </div>
                  <div className="mb-4 rounded-lg border border-green-700/40 bg-green-900/20 p-4 text-sm text-green-100">
                    These entries are restricted to locally runnable Ollama models only.
                  </div>
                  <div className="space-y-3">
                    {(settings.available_offline_models || []).map((model) => {
                      const meta = OFFLINE_MODEL_LABELS[model] || {
                        title: model,
                        description: 'Available through Ollama'
                      }
                      return (
                        <label key={model} className="flex items-center p-4 bg-gray-800 rounded-lg cursor-pointer hover:bg-gray-750 transition-colors">
                          <input
                            type="radio"
                            name="offline_model"
                            value={model}
                            checked={settings.selected_model === model}
                            onChange={(e) => setSettings(prev => ({ ...prev, selected_model: e.target.value }))}
                            className="w-4 h-4 text-primary-500"
                          />
                          <div className="ml-3">
                            <div className="font-medium">{meta.title}</div>
                            <div className="text-sm text-gray-400">{meta.description}</div>
                          </div>
                        </label>
                      )
                    })}
                  </div>
                </div>
              )}

              {/* Current Selection Display */}
              <div className="bg-green-900/20 border border-green-800 rounded-lg p-4">
                <p className="text-green-300 text-sm">
                  <strong>Current Selection:</strong> {settings.selected_model || `${settings.auto_router_model || 'openrouter/auto'} (automatic default)`}
                </p>
              </div>

              {/* Save Button */}
              <button
                onClick={saveSettings}
                disabled={settingsLoading || (settings.model_mode === 'offline' && !settings.selected_model)}
                className="flex items-center space-x-2 bg-primary-600 hover:bg-primary-700 disabled:bg-gray-700 px-6 py-3 rounded-lg transition-colors"
              >
                {settingsLoading ? (
                  <RefreshCw className="w-4 h-4 animate-spin" />
                ) : settingsSaved ? (
                  <Check className="w-4 h-4" />
                ) : (
                  <Save className="w-4 h-4" />
                )}
                <span>
                  {settingsLoading ? 'Saving...' : settingsSaved ? 'Saved!' : 'Save Model Selection'}
                </span>
              </button>
            </>
          )}
        </div>
      )}
=======
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
>>>>>>> origin/sandbox/ui-overhaul
    </div>
  )
}

<<<<<<< HEAD
export default SettingsPage
=======
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
>>>>>>> origin/sandbox/ui-overhaul
