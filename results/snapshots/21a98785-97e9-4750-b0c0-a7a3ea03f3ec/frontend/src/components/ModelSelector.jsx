import { useState, useEffect } from 'react'
import { Cpu, Cloud } from 'lucide-react'

function ModelSelector({ value, onChange }) {
  const [mode, setMode] = useState('online')
  
  const onlineModels = [
    { value: 'openai/gpt-4o', label: 'GPT-4o', provider: 'OpenAI' },
    { value: 'openai/gpt-4o-mini', label: 'GPT-4o Mini', provider: 'OpenAI' },
    { value: 'anthropic/claude-3.5-sonnet', label: 'Claude 3.5 Sonnet', provider: 'Anthropic' },
    { value: 'anthropic/claude-3-opus', label: 'Claude 3 Opus', provider: 'Anthropic' },
    { value: 'anthropic/claude-3-haiku', label: 'Claude 3 Haiku', provider: 'Anthropic' },
    { value: 'google/gemini-2.0-flash-001', label: 'Gemini 2.0 Flash', provider: 'Google' },
    { value: 'meta-llama/llama-3.3-70b-instruct', label: 'Llama 3.3 70B', provider: 'Meta' },
    { value: 'deepseek/deepseek-chat', label: 'DeepSeek V3', provider: 'DeepSeek' },
    { value: 'qwen/qwen-2.5-72b-instruct', label: 'Qwen 2.5 72B', provider: 'Alibaba' }
  ]
  
  const offlineModels = [
    { value: 'llama3:70b', label: 'Llama 3 70B', provider: 'Ollama' },
    { value: 'mixtral:8x7b', label: 'Mixtral 8x7B', provider: 'Ollama' },
    { value: 'codellama:70b', label: 'CodeLlama 70B', provider: 'Ollama' },
    { value: 'qwen2.5-coder:32b', label: 'Qwen 2.5 Coder 32B', provider: 'Ollama' }
  ]

  const models = mode === 'online' ? onlineModels : offlineModels

  return (
    <div className="space-y-4">
      {/* Mode Toggle */}
      <div className="flex items-center space-x-4">
        <span className="text-sm font-medium text-gray-400">Model Mode:</span>
        <div className="flex bg-gray-800 rounded-lg p-1">
          <button
            type="button"
            onClick={() => setMode('online')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              mode === 'online'
                ? 'bg-primary-600 text-white'
                : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            <Cloud className="w-4 h-4" />
            <span>Online</span>
          </button>
          <button
            type="button"
            onClick={() => setMode('offline')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              mode === 'offline'
                ? 'bg-primary-600 text-white'
                : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            <Cpu className="w-4 h-4" />
            <span>Offline</span>
          </button>
        </div>
      </div>

      {/* Model Selection */}
      <div>
        <label className="block text-sm font-medium text-gray-400 mb-2">
          Select Model
        </label>
        <select
          value={value}
          onChange={(e) => onChange(e.target.value)}
          className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2 text-gray-100 focus:outline-none focus:border-primary-500"
        >
          {models.map(model => (
            <option key={model.value} value={model.value}>
              {model.label} ({model.provider})
            </option>
          ))}
        </select>
        <p className="mt-1 text-xs text-gray-500">
          {mode === 'online' 
            ? 'Uses OpenRouter API (requires API key)'
            : 'Uses local Ollama instance (no external calls)'}
        </p>
      </div>
    </div>
  )
}

export default ModelSelector
