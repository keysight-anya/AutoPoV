import { useState } from 'react'
import { Copy, Check, Webhook } from 'lucide-react'

function WebhookSetup() {
  const [copied, setCopied] = useState(null)
  const baseUrl = window.location.origin.replace(':5173', ':8000')

  const webhooks = [
    {
      name: 'GitHub',
      url: `${baseUrl}/api/webhook/github`,
      secretHeader: 'X-Hub-Signature-256',
      setup: 'Settings > Webhooks > Add webhook'
    },
    {
      name: 'GitLab',
      url: `${baseUrl}/api/webhook/gitlab`,
      secretHeader: 'X-Gitlab-Token',
      setup: 'Settings > Webhooks'
    }
  ]

  const copyToClipboard = (text, index) => {
    navigator.clipboard.writeText(text)
    setCopied(index)
    setTimeout(() => setCopied(null), 2000)
  }

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-800 p-6">
      <div className="flex items-center space-x-2 mb-6">
        <Webhook className="w-5 h-5 text-primary-500" />
        <h3 className="text-lg font-medium">Webhook Setup</h3>
      </div>

      <div className="space-y-6">
        {webhooks.map((webhook, index) => (
          <div key={webhook.name} className="border border-gray-800 rounded-lg p-4">
            <h4 className="font-medium mb-3">{webhook.name}</h4>
            
            <div className="space-y-3">
              <div>
                <label className="block text-sm text-gray-400 mb-1">Payload URL</label>
                <div className="flex items-center space-x-2">
                  <code className="flex-1 bg-gray-800 px-3 py-2 rounded text-sm text-green-400">
                    {webhook.url}
                  </code>
                  <button
                    onClick={() => copyToClipboard(webhook.url, index)}
                    className="p-2 hover:bg-gray-800 rounded"
                  >
                    {copied === index ? (
                      <Check className="w-4 h-4 text-green-400" />
                    ) : (
                      <Copy className="w-4 h-4 text-gray-400" />
                    )}
                  </button>
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Secret Header</label>
                  <code className="block bg-gray-800 px-3 py-2 rounded text-sm">
                    {webhook.secretHeader}
                  </code>
                </div>
                <div>
                  <label className="block text-sm text-gray-400 mb-1">Setup Location</label>
                  <p className="text-sm text-gray-300">{webhook.setup}</p>
                </div>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="mt-6 p-4 bg-blue-900/20 border border-blue-800 rounded-lg">
        <p className="text-sm text-blue-300">
          <strong>Note:</strong> Make sure to set the webhook secret in your environment variables 
          (GITHUB_WEBHOOK_SECRET or GITLAB_WEBHOOK_SECRET) to verify webhook signatures.
        </p>
      </div>
    </div>
  )
}

export default WebhookSetup
