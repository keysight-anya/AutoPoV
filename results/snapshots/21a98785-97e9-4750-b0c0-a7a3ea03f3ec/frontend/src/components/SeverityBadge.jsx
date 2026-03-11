function SeverityBadge({ cwe }) {
  const getSeverity = (cwe) => {
    switch (cwe) {
      case 'CWE-89':  // SQL Injection
      case 'CWE-94':  // Code Injection
        return { level: 'Critical', color: 'bg-red-900 text-red-300' }
      case 'CWE-119': // Buffer Overflow
      case 'CWE-416': // Use After Free
        return { level: 'High', color: 'bg-orange-900 text-orange-300' }
      case 'CWE-190': // Integer Overflow
        return { level: 'Medium', color: 'bg-yellow-900 text-yellow-300' }
      default:
        return { level: 'Low', color: 'bg-blue-900 text-blue-300' }
    }
  }

  const { level, color } = getSeverity(cwe)

  return (
    <span className={`px-2 py-1 rounded-full text-xs font-medium ${color}`}>
      {level}
    </span>
  )
}

export default SeverityBadge
