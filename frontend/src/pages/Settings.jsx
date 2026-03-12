import { useState, useEffect } from 'react'
import { Settings, Key, Save, Check, Trash2, RefreshCw, AlertCircle } from 'lucide-react'
import WebhookSetup from '../components/WebhookSetup'
import { listApiKeys, generateApiKey } from '../api/client'
import apiClient from '../api/client'

function SettingsPage() {
  const [apiKey, setApiKey] = useState('')
  const [saved, setSaved] = useState(false)
  const [activeTab, setActiveTab] = useState('api')

  // Admin key management state
  const [adminKey, setAdminKey] = useState('')
  const [keys, setKeys] = useState([])
  const [keysLoading, setKeysLoading] = useState(false)
  const [keysError, setKeysError] = useState(null)
  const [newKeyName, setNewKeyName] = useState('')
  const [generatedKey, setGeneratedKey] = useState(null)
  const [generatingKey, setGeneratingKey] = useState(false)
  const [revoking, setRevoking] = useState(null) // key_id being revoked

  useEffect(() => {
    const stored = localStorage.getItem('autopov_api_key')
    if (stored) {
      setApiKey(stored)
    }
  }, [])

  const saveApiKey = () => {
    localStorage.setItem('autopov_api_key', apiKey)
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const loadKeys = async () => {
    if (!adminKey.trim()) return
    setKeysLoading(true)
    setKeysError(null)
    try {
      const res = await listApiKeys(adminKey)
      setKeys(res.data.keys || [])
    } catch (err) {
      setKeysError(err.response?.data?.detail || err.message || 'Failed to load keys')
    } finally {
      setKeysLoading(false)
    }
  }

  const handleGenerateKey = async () => {
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
    } finally {
      setGeneratingKey(false)
    }
  }

  const handleRevokeKey = async (keyId) => {
    if (!window.confirm('Revoke this API key? This cannot be undone.')) return
    setRevoking(keyId)
    setKeysError(null)
    try {
      await apiClient.delete(`/keys/${keyId}`, {
        headers: { Authorization: `Bearer ${adminKey}` }
      })
      setKeys(prev => prev.filter(k => k.key_id !== keyId))
    } catch (err) {
      setKeysError(err.response?.data?.detail || err.message || 'Failed to revoke key')
    } finally {
      setRevoking(null)
    }
  }

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
          onClick={() => setActiveTab('api')}
          className={`px-6 py-3 font-medium transition-colors ${
            activeTab === 'api'
              ? 'text-primary-500 border-b-2 border-primary-500'
              : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          API Key
        </button>
        <button
          onClick={() => setActiveTab('admin')}
          className={`px-6 py-3 font-medium transition-colors ${
            activeTab === 'admin'
              ? 'text-primary-500 border-b-2 border-primary-500'
              : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          Key Management
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

      {/* API Key Tab */}
      {activeTab === 'api' && (
        <div className="bg-gray-900 rounded-lg border border-gray-800 p-6">
          <div className="flex items-center space-x-2 mb-4">
            <Key className="w-5 h-5 text-primary-500" />
            <h2 className="text-lg font-medium">API Key Configuration</h2>
          </div>

          <p className="text-gray-400 mb-4">
            Enter your AutoPoV API key to authenticate requests. You can generate an API key 
            using the CLI command: <code className="bg-gray-800 px-2 py-1 rounded">autopov keys generate</code>
          </p>

          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-2">
                API Key
              </label>
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="apov_..."
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-gray-100 focus:outline-none focus:border-primary-500"
              />
            </div>

            <button
              onClick={saveApiKey}
              className="flex items-center space-x-2 bg-primary-600 hover:bg-primary-700 px-4 py-2 rounded-lg transition-colors"
            >
              {saved ? (
                <>
                  <Check className="w-4 h-4" />
                  <span>Saved!</span>
                </>
              ) : (
                <>
                  <Save className="w-4 h-4" />
                  <span>Save API Key</span>
                </>
              )}
            </button>
          </div>

          <div className="mt-6 p-4 bg-gray-850 rounded-lg">
            <h3 className="font-medium mb-2">Environment Variable</h3>
            <p className="text-sm text-gray-400 mb-2">
              You can also set the API key via environment variable:
            </p>
            <code className="block bg-gray-950 px-3 py-2 rounded text-sm text-green-400">
              export AUTOPOV_API_KEY=your_api_key_here
            </code>
          </div>
        </div>
      )}

      {/* Webhooks Tab */}
      {activeTab === 'webhooks' && <WebhookSetup />}

      {/* Admin Key Management Tab */}
      {activeTab === 'admin' && (
        <div className="space-y-6">
          {/* Admin key input */}
          <div className="bg-gray-900 rounded-lg border border-gray-800 p-6">
            <div className="flex items-center space-x-2 mb-4">
              <Key className="w-5 h-5 text-yellow-500" />
              <h2 className="text-lg font-medium">Admin Key</h2>
            </div>
            <p className="text-gray-400 text-sm mb-4">
              Enter your admin key to manage API keys. The admin key is set via the
              <code className="bg-gray-800 px-1 mx-1 rounded">ADMIN_API_KEY</code> environment variable.
            </p>
            <div className="flex space-x-3">
              <input
                type="password"
                value={adminKey}
                onChange={e => setAdminKey(e.target.value)}
                placeholder="Admin key..."
                className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-gray-100 focus:outline-none focus:border-primary-500"
              />
              <button
                onClick={loadKeys}
                disabled={keysLoading || !adminKey.trim()}
                className="flex items-center space-x-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 disabled:opacity-50 rounded-lg transition-colors"
              >
                <RefreshCw className={`w-4 h-4 ${keysLoading ? 'animate-spin' : ''}`} />
                <span>Load Keys</span>
              </button>
            </div>
          </div>

          {keysError && (
            <div className="flex items-center space-x-2 p-3 bg-red-900/30 border border-red-800 rounded-lg text-red-300 text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{keysError}</span>
            </div>
          )}

          {/* Generate new key */}
          <div className="bg-gray-900 rounded-lg border border-gray-800 p-6">
            <h3 className="font-medium mb-3">Generate New API Key</h3>
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
                disabled={generatingKey || !adminKey.trim()}
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
              <div className="mt-3 p-3 bg-green-900/20 border border-green-800 rounded-lg">
                <p className="text-sm text-green-300 mb-1 font-medium">New key — save this, it won't be shown again:</p>
                <code className="block bg-gray-950 px-3 py-2 rounded text-sm text-green-400 break-all">{generatedKey}</code>
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
    </div>
  )
}

export default SettingsPage
