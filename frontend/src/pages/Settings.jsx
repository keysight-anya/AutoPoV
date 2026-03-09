import { useState, useEffect } from 'react'
import { Settings, Key, Save, Check } from 'lucide-react'
import WebhookSetup from '../components/WebhookSetup'

function SettingsPage() {
  const [apiKey, setApiKey] = useState('')
  const [saved, setSaved] = useState(false)
  const [activeTab, setActiveTab] = useState('api')

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
    </div>
  )
}

export default SettingsPage
