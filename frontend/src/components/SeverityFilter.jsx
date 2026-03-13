// frontend/src/components/SeverityFilter.jsx

const SEVERITY_COLOR = {
  ALL:      'var(--text2)',
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#eab308',
  LOW:      '#3b82f6',
  INFO:     'var(--text3)',
}

export default function SeverityFilter({ counts = {}, active = 'ALL', onChange }) {
  const filters = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

  return (
    <div style={{
      width: 160, flexShrink: 0,
      borderRight: '1px solid var(--border1)',
      padding: '16px 0',
    }}>
      <div style={{
        fontFamily: '"JetBrains Mono", monospace',
        fontSize: 9, letterSpacing: '.14em',
        color: 'var(--text3)', padding: '0 14px',
        marginBottom: 12,
      }}>
        SEVERITY
      </div>

      {filters.map(f => (
        <div
          key={f}
          onClick={() => onChange(f)}
          style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '8px 14px',
            cursor: 'pointer',
            borderLeft: active === f ? `2px solid ${SEVERITY_COLOR[f]}` : '2px solid transparent',
            background: active === f ? 'rgba(255,255,255,0.03)' : 'transparent',
            transition: 'background .1s, border-color .1s',
          }}
        >
          <span style={{
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: 10, letterSpacing: '.1em',
            color: active === f ? SEVERITY_COLOR[f] : 'var(--text3)',
          }}>
            {f}
          </span>
          <span style={{
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: 10,
            color: active === f ? SEVERITY_COLOR[f] : 'var(--text3)',
          }}>
            {counts[f] ?? 0}
          </span>
        </div>
      ))}
    </div>
  )
}
