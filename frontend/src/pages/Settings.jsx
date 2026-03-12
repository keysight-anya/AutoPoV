import { useState, useEffect } from 'react'
import { Copy, Check, Eye, EyeOff, RefreshCw, Trash2, AlertCircle, Key } from 'lucide-react'
import WebhookSetup from '../components/WebhookSetup'
import { listApiKeys, generateApiKey } from '../api/client'
import apiClient from '../api/client'

// ── Prominent API Key Hero ────────────────────────────────
function ApiKeyHero() {
  const [apiKey, setApiKey]       = useState('')
  const [revealed, setRevealed]   = useState(false)
  const [copied, setCopied]       = useState(false)
  const [editing, setEditing]     = useState(false)
  const [draftKey, setDraftKey]   = useState('')

  useEffect(() => {
    const stored = localStorage.getItem('autopov_api_key') || ''
    setApiKey(stored)
    setDraftKey(stored)
  }, [])

  const saveKey = () => {
    localStorage.setItem('autopov_api_key', draftKey)
    setApiKey(draftKey)
    setEditing(false)
  }

  const handleCopy = () => {
    if (!apiKey) return
    navigator.clipboard.writeText(apiKey).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  const displayKey = revealed
    ? (apiKey || '—')
    : apiKey
      ? apiKey.substring(0, 8) + '••••••••••••••••••••••'
      : null

  return (
    <div className="border border-gray-850 p-6">
      {/* Section label */}
      <div className="flex items-center justify-between mb-4">
        <div className="label-caps text-primary-400 flex items-center gap-2">
          <Key className="w-3.5 h-3.5" />
          API KEY
        </div>
        {apiKey && (
          <div className="flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 bg-safe-500 rounded-sm" />
            <span className="label-caps text-safe-400">ACTIVE</span>
          </div>
        )}
      </div>

      {/* Key display */}
      {apiKey && !editing ? (
        <div className="bg-gray-950 border border-gray-850 p-4 mb-4">
          <div className="flex items-center gap-3">
            <code className="flex-1 font-mono text-sm text-primary-300 break-all">
              {displayKey}
            </code>
            <div className="flex items-center gap-2 shrink-0">
              <button
                onClick={() => setRevealed(r => !r)}
                className="p-1.5 text-gray-600 hover:text-gray-300 transition-colors"
                title={revealed ? 'Hide key' : 'Reveal key'}
              >
                {revealed ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
              <button
                onClick={handleCopy}
                className={[
                  'flex items-center gap-1.5 px-3 py-1.5 border text-xs font-semibold tracking-widest transition-colors',
                  copied
                    ? 'border-safe-500/40 text-safe-400 bg-safe-900/20'
                    : 'border-primary-600/40 text-primary-400 hover:border-primary-500/60 hover:bg-primary-600/10',
                ].join(' ')}
              >
                {copied ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                {copied ? 'COPIED' : 'COPY'}
              </button>
            </div>
          </div>
        </div>
      ) : (
        <div className="mb-4">
          <div className="label-caps mb-2">ENTER YOUR API KEY</div>
          <input
            type="text"
            value={draftKey}
            onChange={e => setDraftKey(e.target.value)}
            placeholder="apov_..."
            className="input-stark mb-3"
            autoFocus
          />
        </div>
      )}

      {/* Actions */}
      <div className="flex items-center gap-3">
        {editing ? (
          <>
            <button
              onClick={saveKey}
              disabled={!draftKey.trim()}
              className="btn-primary px-5 py-2 text-xs tracking-widest"
            >
              <Check className="w-3.5 h-3.5" />
              SAVE KEY
            </button>
            <button
              onClick={() => { setEditing(false); setDraftKey(apiKey) }}
              className="btn-ghost px-4 py-2 text-xs tracking-widest"
            >
              CANCEL
            </button>
          </>
        ) : (
          <button
            onClick={() => setEditing(true)}
            className="btn-ghost px-4 py-2 text-xs tracking-widest"
          >
            {apiKey ? 'CHANGE KEY' : 'SET KEY'}
          </button>
        )}
      </div>

      {/* CLI hint */}
      <div className="mt-5 pt-4 border-t border-gray-850">
        <div className="label-caps mb-2">USE IN CLI / HTTP</div>
        <div className="flex flex-col gap-1.5">
          <div className="bg-gray-950 border border-gray-850 px-3 py-2">
            <code className="text-xs text-safe-400">
              export AUTOPOV_API_KEY=<span className="text-safe-600">{apiKey ? apiKey.substring(0, 8) + '...' : 'apov_...'}</span>
            </code>
          </div>
          <div className="bg-gray-950 border border-gray-850 px-3 py-2">
            <code className="text-xs text-gray-500">
              Authorization: Bearer <span className="text-gray-600">{apiKey ? apiKey.substring(0, 8) + '...' : 'apov_...'}</span>
            </code>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Key Management (admin) ────────────────────────────────
function KeyManagement() {
  const [adminKey, setAdminKey]       = useState('')
  const [keys, setKeys]               = useState([])
  const [keysLoading, setKeysLoading] = useState(false)
  const [keysError, setKeysError]     = useState(null)
  const [newKeyName, setNewKeyName]   = useState('')
  const [generatedKey, setGeneratedKey] = useState(null)
  const [generatingKey, setGeneratingKey] = useState(false)
  const [revoking, setRevoking]       = useState(null)
  const [copiedGen, setCopiedGen]     = useState(false)

  const loadKeys = async () => {
    if (!adminKey.trim()) return
    setKeysLoading(true)
    setKeysError(null)
    try {
      const res = await listApiKeys(adminKey)
      setKeys(res.data.keys || [])
    } catch (err) {
      setKeysError(err.response?.data?.detail || err.message || 'Failed to load keys')
    } finally { setKeysLoading(false) }
  }

  const handleGenerate = async () => {
    if (!adminKey.trim()) return
    setGeneratingKey(true)
    setKeysError(null)
    setGeneratedKey(null)
    try {
      const res = await generateApiKey(adminKey, newKeyName || 'default')
      setGeneratedKey(res.data.key)
      setNewKeyName('')
      await loadKeys()
    } catch (err) {
      setKeysError(err.response?.data?.detail || err.message || 'Failed to generate key')
    } finally { setGeneratingKey(false) }
  }

  const handleRevoke = async (keyId) => {
    if (!window.confirm('Revoke this API key? Cannot be undone.')) return
    setRevoking(keyId)
    setKeysError(null)
    try {
      await apiClient.delete(`/keys/${keyId}`, {
        headers: { Authorization: `Bearer ${adminKey}` }
      })
      setKeys(p => p.filter(k => k.key_id !== keyId))
    } catch (err) {
      setKeysError(err.response?.data?.detail || err.message || 'Failed to revoke key')
    } finally { setRevoking(null) }
  }

  return (
    <div className="flex flex-col gap-5">
      {/* Admin key input */}
      <div className="border border-gray-850 p-5">
        <div className="label-caps text-warn-400 mb-3 flex items-center gap-2">
          <Key className="w-3.5 h-3.5" />
          ADMIN KEY
        </div>
        <p className="text-gray-600 text-xs mb-4 leading-relaxed">
          The admin key is set via the <code className="text-gray-500 bg-gray-850 px-1.5 py-0.5">ADMIN_API_KEY</code> env variable.
          Required to create or revoke API keys.
        </p>
        <div className="flex gap-2">
          <input
            type="password"
            value={adminKey}
            onChange={e => setAdminKey(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && loadKeys()}
            placeholder="Admin key…"
            className="input-stark flex-1"
          />
          <button
            onClick={loadKeys}
            disabled={keysLoading || !adminKey.trim()}
            className="btn-ghost px-4 text-xs tracking-widest flex items-center gap-2"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${keysLoading ? 'animate-spin' : ''}`} />
            LOAD
          </button>
        </div>
      </div>

      {keysError && (
        <div className="flex items-center gap-2.5 p-3 border border-threat-500/30 bg-threat-900/20 text-threat-300 text-xs">
          <AlertCircle className="w-4 h-4 shrink-0" />
          {keysError}
        </div>
      )}

      {/* Generate new key */}
      <div className="border border-gray-850 p-5">
        <div className="label-caps mb-3">GENERATE NEW KEY</div>
        <div className="flex gap-2 mb-3">
          <input
            type="text"
            value={newKeyName}
            onChange={e => setNewKeyName(e.target.value)}
            placeholder="Key name (e.g. ci-bot)"
            className="input-stark flex-1"
          />
          <button
            onClick={handleGenerate}
            disabled={generatingKey || !adminKey.trim()}
            className="btn-primary px-5 text-xs tracking-widest flex items-center gap-2"
          >
            {generatingKey
              ? <RefreshCw className="w-3.5 h-3.5 animate-spin" />
              : <Key className="w-3.5 h-3.5" />
            }
            {generatingKey ? 'GENERATING' : 'GENERATE'}
          </button>
        </div>

        {generatedKey && (
          <div className="border border-safe-500/25 bg-safe-900/15 p-4">
            <div className="label-caps text-safe-400 mb-2">NEW KEY — SAVE THIS NOW</div>
            <div className="flex items-center gap-3">
              <code className="flex-1 font-mono text-sm text-safe-300 break-all">{generatedKey}</code>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(generatedKey)
                  setCopiedGen(true)
                  setTimeout(() => setCopiedGen(false), 2000)
                  // Auto-save to localStorage if no key is set yet
                  if (!localStorage.getItem('autopov_api_key')) {
                    localStorage.setItem('autopov_api_key', generatedKey)
                  }
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 border border-safe-500/30 text-safe-400 text-xs font-semibold tracking-widest hover:bg-safe-900/20 transition-colors"
              >
                {copiedGen ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                {copiedGen ? 'COPIED' : 'COPY'}
              </button>
            </div>
            <p className="text-gray-600 text-xs mt-2">Not shown again. Stored locally if no key was previously set.</p>
          </div>
        )}
      </div>

      {/* Keys table */}
      {keys.length > 0 && (
        <div className="border border-gray-850 overflow-hidden">
          <div className="border-b border-gray-850 px-4 py-2.5">
            <div className="label-caps">ACTIVE KEYS ({keys.length})</div>
          </div>
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-gray-850">
                {['ID', 'NAME', 'CREATED', 'LAST USED', 'STATUS', ''].map(h => (
                  <th key={h} className="text-left px-4 py-2.5 label-caps">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-850">
              {keys.map(k => (
                <tr key={k.key_id} className="hover:bg-gray-850/40 transition-colors">
                  <td className="px-4 py-3 font-mono text-gray-500">{(k.key_id || '').substring(0, 8)}…</td>
                  <td className="px-4 py-3 text-gray-300">{k.name || '—'}</td>
                  <td className="px-4 py-3 text-gray-600">{(k.created_at || 'N/A').substring(0, 10)}</td>
                  <td className="px-4 py-3 text-gray-600">{k.last_used ? k.last_used.substring(0, 10) : 'never'}</td>
                  <td className="px-4 py-3">
                    <span className={k.is_active ? 'badge-safe' : 'badge-neutral'}>
                      {k.is_active ? 'ACTIVE' : 'REVOKED'}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {k.is_active && (
                      <button
                        onClick={() => handleRevoke(k.key_id)}
                        disabled={revoking === k.key_id}
                        className="flex items-center gap-1.5 text-threat-400 hover:text-threat-300 disabled:opacity-40 text-xs tracking-widest"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                        {revoking === k.key_id ? 'REVOKING' : 'REVOKE'}
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
  )
}

// ── Main Settings Page ────────────────────────────────────
const TABS = [
  { id: 'api',      label: 'API KEY'  },
  { id: 'admin',    label: 'KEY MGMT' },
  { id: 'webhooks', label: 'WEBHOOKS' },
]

function SettingsPage() {
  const [activeTab, setActiveTab] = useState('api')

  return (
    <div className="max-w-3xl animate-fade-up">

      {/* Header */}
      <div className="border-b border-gray-850 pb-7 mb-8">
        <div className="label-caps text-primary-400 mb-3">// CONFIGURATION</div>
        <h1
          className="text-4xl font-black uppercase leading-none"
          style={{ fontFamily: '"Barlow Condensed", system-ui, sans-serif' }}
        >
          SETTINGS
        </h1>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-850 mb-7 gap-0">
        {TABS.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={[
              'px-5 py-3 text-xs font-semibold tracking-widest transition-colors border-r border-gray-850 last:border-r-0',
              activeTab === tab.id
                ? 'text-primary-400 border-b-2 border-b-primary-600 -mb-px bg-gray-850/40'
                : 'text-gray-600 hover:text-gray-400',
            ].join(' ')}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {activeTab === 'api'      && <ApiKeyHero />}
      {activeTab === 'admin'    && <KeyManagement />}
      {activeTab === 'webhooks' && <WebhookSetup />}
    </div>
  )
}

export default SettingsPage
