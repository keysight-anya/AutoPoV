// frontend/src/components/FindingCard.jsx
import { useState } from 'react'

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#3b82f6',
  info:     'var(--text3)',
}

function getSeverity(cwe) {
  const critical = ['CWE-89', 'CWE-78', 'CWE-94', 'CWE-119', 'CWE-416']
  const high     = ['CWE-79', 'CWE-502', 'CWE-798', 'CWE-918']
  const medium   = ['CWE-22', 'CWE-352', 'CWE-287', 'CWE-306', 'CWE-601']
  if (critical.includes(cwe)) return 'critical'
  if (high.includes(cwe))     return 'high'
  if (medium.includes(cwe))   return 'medium'
  return 'low'
}

export default function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false)

  const severity = getSeverity(finding.cwe_type)
  const sevColor = SEVERITY_COLORS[severity]
  const validation = finding.validation_result
  const unitTest   = validation?.unit_test_result
  const staticResult = validation?.static_result

  const statusColor =
    finding.final_status === 'confirmed' ? '#22c55e'
  : finding.final_status === 'skipped'   ? '#fde047'
  : '#f87171'

  return (
    <div style={{
      background: 'var(--surface1)',
      border: '1px solid var(--border1)',
      borderLeft: `3px solid ${sevColor}`,
      marginBottom: 8,
      overflow: 'hidden',
    }}>
      {/* Header row */}
      <div
        onClick={() => setExpanded(e => !e)}
        style={{
          display: 'flex', alignItems: 'center', gap: 12,
          padding: '12px 16px',
          cursor: 'pointer',
        }}
      >
        {/* Status dot */}
        <span style={{ color: statusColor, fontSize: 10, flexShrink: 0 }}>●</span>

        {/* CWE badge */}
        <span style={{
          fontFamily: '"JetBrains Mono", monospace',
          fontSize: 9, letterSpacing: '.1em',
          padding: '2px 8px',
          border: `1px solid ${sevColor}`,
          color: sevColor,
          flexShrink: 0,
        }}>
          {finding.cwe_type}
        </span>

        {/* File path */}
        <span style={{
          fontFamily: '"JetBrains Mono", monospace',
          fontSize: 10, color: 'var(--text2)',
          flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>
          {finding.filepath}:{finding.line_number}
        </span>

        {/* Confidence */}
        <span style={{
          fontFamily: '"JetBrains Mono", monospace',
          fontSize: 9, letterSpacing: '.06em',
          color: finding.confidence >= 0.8 ? '#22c55e'
               : finding.confidence >= 0.6 ? '#fde047' : '#f87171',
          flexShrink: 0,
        }}>
          {(finding.confidence * 100).toFixed(0)}%
        </span>

        {/* Expand chevron */}
        <span style={{
          color: 'var(--text3)', fontSize: 10, flexShrink: 0,
          transform: expanded ? 'rotate(0deg)' : 'rotate(-90deg)',
          transition: 'transform .15s',
          display: 'inline-block',
        }}>▼</span>
      </div>

      {/* Expanded content */}
      {expanded && (
        <div style={{ borderTop: '1px solid var(--border1)', padding: '14px 16px' }}>
          {/* Explanation */}
          {finding.llm_explanation && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.12em', color: 'var(--text3)', marginBottom: 6 }}>EXPLANATION</div>
              <p style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.6, margin: 0 }}>{finding.llm_explanation}</p>
            </div>
          )}

          {/* Vulnerable code */}
          {finding.code_chunk && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.12em', color: 'var(--text3)', marginBottom: 6 }}>VULNERABLE CODE</div>
              <pre style={{ background: 'var(--bg)', border: '1px solid var(--border1)', padding: '10px 12px', margin: 0, overflowX: 'auto', fontSize: 11, color: '#fca5a5', fontFamily: '"JetBrains Mono", monospace' }}>{finding.code_chunk}</pre>
            </div>
          )}

          {/* PoV script */}
          {finding.pov_script && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.12em', color: 'var(--text3)', marginBottom: 6 }}>PROOF OF VULNERABILITY</div>
              <pre style={{ background: 'var(--bg)', border: '1px solid var(--border1)', padding: '10px 12px', margin: 0, overflowX: 'auto', fontSize: 11, color: '#86efac', fontFamily: '"JetBrains Mono", monospace' }}>{finding.pov_script}</pre>
            </div>
          )}

          {/* PoV result */}
          {finding.pov_result && (
            <div style={{ marginBottom: 14 }}>
              <div style={{
                padding: '8px 12px',
                background: finding.pov_result.vulnerability_triggered ? 'rgba(239,68,68,0.1)' : 'var(--surface2)',
                border: `1px solid ${finding.pov_result.vulnerability_triggered ? 'rgba(239,68,68,0.3)' : 'var(--border1)'}`,
                fontFamily: '"JetBrains Mono", monospace',
                fontSize: 10, letterSpacing: '.1em',
                color: finding.pov_result.vulnerability_triggered ? '#fca5a5' : 'var(--text3)',
              }}>
                {finding.pov_result.vulnerability_triggered ? '⚠ VULNERABILITY TRIGGERED' : 'POV DID NOT TRIGGER'}
              </div>
            </div>
          )}

          {/* Metadata */}
          <div style={{
            display: 'flex', flexWrap: 'wrap', gap: 16,
            borderTop: '1px solid var(--border1)', paddingTop: 10,
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: 9, letterSpacing: '.06em', color: 'var(--text3)',
          }}>
            {finding.inference_time_s && <span>INFERENCE {finding.inference_time_s.toFixed(2)}s</span>}
            {finding.cost_usd        && <span>COST ${finding.cost_usd.toFixed(4)}</span>}
            {finding.model_used      && <span>MODEL {finding.model_used}</span>}
          </div>
        </div>
      )}
    </div>
  )
}
