const SEVERITY = {
  critical: { label: 'Critical', cls: 'bg-threat-900/60 text-threat-300 border border-threat-500/25' },
  high:     { label: 'High',     cls: 'bg-red-900/40 text-red-300 border border-red-500/20' },
  medium:   { label: 'Medium',   cls: 'bg-warn-900/50 text-warn-300 border border-warn-500/20' },
  low:      { label: 'Low',      cls: 'bg-blue-900/30 text-blue-300 border border-blue-500/20' },
  info:     { label: 'Info',     cls: 'bg-gray-800 text-gray-400 border border-gray-700/50' }
}

// CWE-agnostic severity based on confidence and verdict
function getSeverity(finding) {
  const confidence = finding?.confidence || 0
  const verdict = finding?.llm_verdict || finding?.final_status
  
  // If it's not a real vulnerability, mark as info
  if (verdict === 'FALSE_POSITIVE' || verdict === 'skipped') {
    return 'info'
  }
  
  // Use confidence to determine severity (CWE-agnostic)
  if (confidence >= 0.9) return 'critical'
  if (confidence >= 0.8) return 'high'
  if (confidence >= 0.7) return 'medium'
  return 'low'
}

function SeverityBadge({ finding }) {
  const key = getSeverity(finding)
  const { label, cls } = SEVERITY[key]
  return (
    <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${cls}`}>
      {label}
    </span>
  )
}

export default SeverityBadge
