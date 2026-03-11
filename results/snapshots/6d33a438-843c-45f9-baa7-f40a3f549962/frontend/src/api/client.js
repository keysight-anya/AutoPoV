import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000/api'

// Get API key from localStorage or environment
const getApiKey = () => {
  return localStorage.getItem('autopov_api_key') || import.meta.env.VITE_API_KEY
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

export const scanGit = (data) => apiClient.post('/scan/git', data)

export const scanZip = (formData) => apiClient.post('/scan/zip', formData, {
  headers: {
    'Content-Type': 'multipart/form-data'
  }
})

export const scanPaste = (data) => apiClient.post('/scan/paste', data)

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

export default apiClient
