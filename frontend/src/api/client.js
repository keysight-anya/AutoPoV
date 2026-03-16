import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api'


// Get AutoPoV backend API key
const getApiKey = () => {
  return localStorage.getItem('autopov_api_key') || import.meta.env.VITE_API_KEY
}

const getCsrfToken = () => {
  if (typeof document === 'undefined') return null
  const match = document.cookie.match(/(?:^|; )autopov_csrf=([^;]*)/)
  return match ? decodeURIComponent(match[1]) : null
}

const shouldUseApiKey = (config) => {
  return Boolean(config?.useApiKey)
}

// Get OpenRouter API key (for per-request LLM key injection)
const getOpenRouterKey = () => {
  return localStorage.getItem('openrouter_api_key') || null
}

// Create axios instance
const apiClient = axios.create({
  baseURL: API_URL,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json'
  }
})

apiClient.interceptors.request.use((config) => {
  if (shouldUseApiKey(config)) {
    const apiKey = getApiKey()
    if (apiKey) {
      config.headers.Authorization = `Bearer ${apiKey}`
    }
  } else if (config.headers?.Authorization) {
    delete config.headers.Authorization
  }

  const csrfToken = getCsrfToken()
  if (csrfToken && config.method && !['get', 'head', 'options'].includes(config.method)) {
    config.headers['X-CSRF-Token'] = csrfToken
  }
  return config
})

export const healthCheck = () => apiClient.get('/health')
export const getConfig = () => apiClient.get('/config')
export const scanGit = (data) => apiClient.post('/scan/git', data)
export const scanZip = (formData) => apiClient.post('/scan/zip', formData, {
  headers: {
    'Content-Type': 'multipart/form-data'
  }
})
export const scanPaste = (data) => apiClient.post('/scan/paste', data)

export const scanGit = (data) => apiClient.post('/scan/git', {
  ...data,
  openrouter_api_key: getOpenRouterKey()
})

export const scanZip = (formData) => {
  const orKey = getOpenRouterKey()
  if (orKey) formData.append('openrouter_api_key', orKey)
  return apiClient.post('/scan/zip', formData, {
    headers: { 'Content-Type': 'multipart/form-data' }
  })
}

export const scanPaste = (data) => apiClient.post('/scan/paste', {
  ...data,
  openrouter_api_key: getOpenRouterKey()
})

export const getScanStatus = (scanId) => apiClient.get(`/scan/${scanId}`)

export const getScanLogs = (scanId) => {
  const streamUrl = `${API_URL}/scan/${scanId}/stream`
  return new EventSource(streamUrl, { withCredentials: true })
}

export const getHistory = (limit = 100, offset = 0) => apiClient.get(`/history?limit=${limit}&offset=${offset}`)
export const getReport = (scanId, format = 'json') => apiClient.get(`/report/${scanId}?format=${format}`, {
  responseType: format === 'pdf' ? 'blob' : 'json'
})
export const getMetrics = () => apiClient.get('/metrics')

export const generateApiKey = (name = 'default') => apiClient.post('/keys/generate', null, {
  params: { name }
})

export const listApiKeys = () => apiClient.get('/keys')
export const cancelScan = (scanId) => apiClient.post(`/scan/${scanId}/cancel`)
export const getLearningSummary = () => apiClient.get('/learning/summary')
export const replayScan = (scanId, data) => apiClient.post(`/scan/${scanId}/replay`, data)

export const apiClientWithKey = (apiKey) => axios.create({
  baseURL: API_URL,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
    Authorization: `Bearer ${apiKey}`
  }
})

export default apiClient
