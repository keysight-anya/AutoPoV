import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api'

// Get AutoPoV backend API key
const getApiKey = () => {
  return localStorage.getItem('autopov_api_key') || import.meta.env.VITE_API_KEY
}

// Get OpenRouter API key (for per-request LLM key injection)
const getOpenRouterKey = () => {
  return localStorage.getItem('openrouter_api_key') || null
}

// Create axios instance
const apiClient = axios.create({
  baseURL: API_URL,
  headers: {
    'Content-Type': 'application/json'
  }
})

// Request interceptor to add auth header
apiClient.interceptors.request.use((config) => {
  const apiKey = getApiKey()
  if (apiKey) {
    config.headers.Authorization = `Bearer ${apiKey}`
  }
  return config
})

// API functions
export const healthCheck = () => apiClient.get('/health')

export const getConfig = () => apiClient.get('/config')

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
  const apiKey = getApiKey()
  return new EventSource(`${API_URL}/scan/${scanId}/stream?api_key=${apiKey}`)
}

export const getHistory = (limit = 100, offset = 0) => 
  apiClient.get(`/history?limit=${limit}&offset=${offset}`)

export const getReport = (scanId, format = 'json') => 
  apiClient.get(`/report/${scanId}?format=${format}`, {
    responseType: format === 'pdf' ? 'blob' : 'json'
  })

export const getMetrics = () => apiClient.get('/metrics')

export const generateApiKey = (adminKey, name = 'default') => 
  apiClient.post('/keys/generate', null, {
    params: { name },
    headers: { Authorization: `Bearer ${adminKey}` }
  })

export const listApiKeys = (adminKey) => 
  apiClient.get('/keys', {
    headers: { Authorization: `Bearer ${adminKey}` }
  })

export const cancelScan = (scanId) => apiClient.post(`/scan/${scanId}/cancel`)

export default apiClient

export const getLearningSummary = () => apiClient.get('/learning/summary')

export const replayScan = (scanId, data) => apiClient.post(`/scan/${scanId}/replay`, data)

