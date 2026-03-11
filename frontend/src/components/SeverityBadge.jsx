const SEVERITY = {
  critical: { label: 'Critical', cls: 'bg-threat-900/60 text-threat-300 border border-threat-500/25' },
  high:     { label: 'High',     cls: 'bg-red-900/40 text-red-300 border border-red-500/20' },
  medium:   { label: 'Medium',   cls: 'bg-warn-900/50 text-warn-300 border border-warn-500/20' },
  low:      { label: 'Low',      cls: 'bg-blue-900/30 text-blue-300 border border-blue-500/20' },
  info:     { label: 'Info',     cls: 'bg-gray-800 text-gray-400 border border-gray-700/50' }
}

const CWE_SEVERITY = {
  'CWE-89':  'critical',  // SQL Injection
  'CWE-94':  'critical',  // Code Injection
  'CWE-78':  'critical',  // Command Injection
  'CWE-119': 'critical',  // Buffer Overflow
  'CWE-416': 'critical',  // Use After Free
  'CWE-502': 'critical',  // Deserialization
  'CWE-918': 'high',      // SSRF
  'CWE-22':  'high',      // Path Traversal
  'CWE-79':  'high',      // XSS
  'CWE-611': 'high',      // XXE
  'CWE-434': 'high',      // Unrestricted Upload
  'CWE-287': 'high',      // Authentication
  'CWE-306': 'high',      // Missing Auth
  'CWE-798': 'high',      // Hardcoded Creds
  'CWE-190': 'medium',    // Integer Overflow
  'CWE-352': 'medium',    // CSRF
  'CWE-601': 'medium',    // URL Redirection
  'CWE-312': 'medium',    // Cleartext Storage
  'CWE-327': 'medium',    // Broken Crypto
  'CWE-200': 'medium',    // Info Exposure
  'CWE-384': 'medium',    // Session Fixation
  'CWE-400': 'low',       // Resource Exhaustion
  'CWE-20':  'low',       // Input Validation
}

function SeverityBadge({ cwe }) {
  const key = CWE_SEVERITY[cwe] || 'info'
  const { label, cls } = SEVERITY[key]
  return (
    <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${cls}`}>
      {label}
    </span>
  )
}

export default SeverityBadge
