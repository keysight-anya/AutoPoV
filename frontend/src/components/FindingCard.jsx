// frontend/src/components/FindingCard.jsx
import { useState } from 'react'

const SEVERITY_COLORS = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#3b82f6',
  info:     'var(--text3)',
}

function getSeverity(finding) {
  // Use confidence-based severity for CWE-agnostic approach
  const confidence = finding.confidence || 0
  const verdict = finding.llm_verdict || finding.final_status
  
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


function sentenceCase(value) {
  if (!value) return ''
  const text = String(value).replace(/[_-]+/g, ' ').trim()
  if (!text) return ''
  return text.charAt(0).toUpperCase() + text.slice(1)
}

function summarizeObservedOutcome(povResult) {
  if (!povResult) return ''
  const summary = povResult.proof_summary || povResult?.evidence?.summary
  if (summary) return summary
  const excerpt = (povResult?.evidence?.combined_excerpt || povResult?.stderr || povResult?.stdout || '').toLowerCase()
  if (excerpt.includes('assert')) return 'The program hit an assertion failure while executing the vulnerable path.'
  if (excerpt.includes('addresssanitizer')) return 'AddressSanitizer reported memory corruption during execution.'
  if (excerpt.includes('segmentation fault')) return 'The target crashed with a segmentation fault during execution.'
  if (excerpt.includes('vulnerability triggered')) return 'The exploit script reported that the vulnerability was triggered.'
  return povResult.vulnerability_triggered ? 'The exploit produced a concrete runtime failure in the vulnerable path.' : 'The runtime proof attempt did not show the expected exploit outcome.'
}

function inferTriggerInput(finding, povResult) {
  const code = String(finding?.code_chunk || '').toLowerCase()
  const povScript = String(finding?.pov_script || '').toLowerCase()
  if (code.includes('strcpy(buf, "empty")') || povScript.includes('empty string')) {
    return 'An empty string was passed into the vulnerable function while the destination buffer was kept too small.'
  }
  if (povScript.includes('mqjs_bin') || povScript.includes('target_binary') || povScript.includes('subprocess.run([binary')) {
    return 'A generated proof script ran the built target binary with crafted input designed to reach the vulnerable code path.'
  }
  if (povScript.includes('payload')) {
    return 'A crafted payload was supplied to the target entrypoint to trigger the vulnerable behavior.'
  }
  return 'AutoPoV generated attacker-controlled input and executed the vulnerable path with that input.'
}

function inferBusinessImpact(finding, povResult) {
  const code = String(finding?.code_chunk || '').toLowerCase()
  const excerpt = String(povResult?.evidence?.combined_excerpt || povResult?.stderr || '').toLowerCase()
  const refs = Array.isArray(finding?.taxonomy_refs) ? finding.taxonomy_refs.join(' ').toLowerCase() : ''
  if (code.includes('strcpy') || excerpt.includes('addresssanitizer') || excerpt.includes('segmentation fault') || refs.includes('cwe-120')) {
    return 'This can lead to memory corruption and denial of service, and depending on surrounding conditions may be usable for more serious native-code exploitation.'
  }
  if (excerpt.includes('assert')) {
    return 'An attacker can make the target abort or crash by driving execution into the unsafe path.'
  }
  if (refs.includes('cwe-476') || excerpt.includes('null pointer')) {
    return 'An attacker can crash the program by forcing it to dereference invalid or missing data.'
  }
  return 'This shows the target can be driven into an unsafe runtime state with attacker-controlled input.'
}

function buildProofNarrative(finding, povResult) {
  if (!povResult) return null
  const method = sentenceCase((povResult.validation_method || 'runtime_harness').replace(/_/g, ' '))
  const trigger = inferTriggerInput(finding, povResult)
  const observed = summarizeObservedOutcome(povResult)
  const impact = inferBusinessImpact(finding, povResult)
  const entrypoint = finding?.exploit_contract?.target_entrypoint || finding?.target_entrypoint || finding?.execution_profile || null
  const target = povResult?.target_binary || povResult?.target_url || null
  return {
    simpleSummary: povResult.vulnerability_triggered
      ? 'AutoPoV executed the vulnerable path with crafted input and observed a real runtime failure, so this finding is treated as proven.'
      : 'AutoPoV generated and executed a proof attempt, but the runtime outcome did not prove exploitation.',
    method,
    trigger,
    observed,
    impact,
    whyItProves: povResult.vulnerability_triggered
      ? 'This is considered proof because the issue was triggered during actual execution, the target reached the vulnerable code path, and the runtime behavior matched the expected exploit outcome.'
      : 'This is not considered proven because the runtime execution did not produce the expected exploit evidence.',
    entrypoint,
    target,
  }
}

export default function FindingCard({ finding, forceExpanded = false }) {
  const [expanded, setExpanded] = useState(false)
  const isExpanded = forceExpanded || expanded

  const severity = getSeverity(finding)
  const sevColor = SEVERITY_COLORS[severity]
  const validation = finding.validation_result
  const unitTest   = validation?.unit_test_result
  const staticResult = validation?.static_result
  const povResult = finding.pov_result || finding.pov_test_result

  const taxonomyRefs = Array.isArray(finding.taxonomy_refs) ? finding.taxonomy_refs.filter(Boolean) : []
  const proofNarrative = buildProofNarrative(finding, povResult)

  const proofLabel =
    finding.final_status === 'confirmed' ? 'PROVEN'
  : finding.final_status === 'failed' ? 'PROOF FAILED'
  : finding.pov_script || finding.validation_result || povResult ? 'UNPROVEN'
  : 'ANALYZED'

  const statusColor =
    finding.final_status === 'confirmed' ? '#22c55e'
  : finding.final_status === 'failed' ? '#f87171'
  : '#fde047'

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
        onClick={() => { if (!forceExpanded) setExpanded(e => !e) }}
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
          {finding.cwe_type || 'UNCLASSIFIED'}
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

        <span style={{
          fontFamily: '"JetBrains Mono", monospace',
          fontSize: 9, letterSpacing: '.08em',
          color: statusColor,
          flexShrink: 0,
        }}>
          {proofLabel}
        </span>

        {/* Expand chevron */}
        <span style={{
          color: 'var(--text3)', fontSize: 10, flexShrink: 0,
          transform: isExpanded ? 'rotate(0deg)' : 'rotate(-90deg)',
          transition: 'transform .15s',
          display: 'inline-block',
        }}>▼</span>
      </div>

      {/* Expanded content */}
      {isExpanded && (
        <div style={{ borderTop: '1px solid var(--border1)', padding: '14px 16px' }}>
          {taxonomyRefs.length > 0 && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.12em', color: 'var(--text3)', marginBottom: 6 }}>TAXONOMY REFS</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {taxonomyRefs.map((ref) => (
                  <span key={ref} style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.08em', padding: '2px 8px', border: '1px solid var(--border2)', color: 'var(--text2)' }}>
                    {ref}
                  </span>
                ))}
              </div>
            </div>
          )}

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
          {povResult && (
            <div style={{ marginBottom: 14 }}>
              <div style={{
                padding: '8px 12px',
                background: povResult.vulnerability_triggered ? 'rgba(239,68,68,0.1)' : 'var(--surface2)',
                border: `1px solid ${povResult.vulnerability_triggered ? 'rgba(239,68,68,0.3)' : 'var(--border1)'}`,
                fontFamily: '"JetBrains Mono", monospace',
                fontSize: 10, letterSpacing: '.1em',
                color: povResult.vulnerability_triggered ? '#fca5a5' : 'var(--text3)',
              }}>
                {povResult.vulnerability_triggered ? 'VULNERABILITY TRIGGERED' : 'POV DID NOT TRIGGER'}
              </div>
            </div>
          )}

          {proofNarrative && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.12em', color: 'var(--text3)', marginBottom: 6 }}>
                {povResult?.vulnerability_triggered ? 'WHY THIS IS PROVEN' : 'WHY THIS IS NOT YET PROVEN'}
              </div>
              <div style={{ background: 'var(--bg)', border: '1px solid var(--border1)', padding: '12px 14px' }}>
                <div style={{ fontSize: 13, color: 'var(--text1)', lineHeight: 1.65, marginBottom: 12 }}>
                  {proofNarrative.simpleSummary}
                </div>
                <div style={{ display: 'grid', gap: 10 }}>
                  <div>
                    <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.1em', color: 'var(--text3)', marginBottom: 4 }}>TRIGGER</div>
                    <div style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.6 }}>{proofNarrative.trigger}</div>
                  </div>
                  <div>
                    <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.1em', color: 'var(--text3)', marginBottom: 4 }}>OBSERVED OUTCOME</div>
                    <div style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.6 }}>{proofNarrative.observed}</div>
                  </div>
                  <div>
                    <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.1em', color: 'var(--text3)', marginBottom: 4 }}>WHY THIS MATTERS</div>
                    <div style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.6 }}>{proofNarrative.impact}</div>
                  </div>
                  <div>
                    <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.1em', color: 'var(--text3)', marginBottom: 4 }}>WHY AUTOPOV COUNTS THIS AS PROOF</div>
                    <div style={{ fontSize: 12, color: 'var(--text2)', lineHeight: 1.6 }}>{proofNarrative.whyItProves}</div>
                  </div>
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 14, marginTop: 12, paddingTop: 10, borderTop: '1px solid var(--border1)', fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.08em', color: 'var(--text3)' }}>
                  <span>METHOD {proofNarrative.method.toUpperCase()}</span>
                  {proofNarrative.entrypoint && <span>ENTRYPOINT {String(proofNarrative.entrypoint)}</span>}
                  {proofNarrative.target && <span>TARGET {String(proofNarrative.target)}</span>}
                  {typeof povResult?.exit_code !== 'undefined' && <span>EXIT {String(povResult.exit_code)}</span>}
                  {povResult?.execution_time_s && <span>TIME {Number(povResult.execution_time_s).toFixed(2)}s</span>}
                </div>
              </div>
            </div>
          )}

          {povResult && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.12em', color: 'var(--text3)', marginBottom: 6 }}>RUNTIME EVIDENCE</div>
              <div style={{ background: 'var(--bg)', border: '1px solid var(--border1)', padding: '10px 12px' }}>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16, marginBottom: 10, fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.06em', color: 'var(--text3)' }}>
                  <span>METHOD {(povResult.validation_method || 'runtime_harness').toUpperCase()}</span>
                  {typeof povResult.exit_code !== 'undefined' && <span>EXIT {String(povResult.exit_code)}</span>}
                  {povResult.execution_time_s && <span>TIME {Number(povResult.execution_time_s).toFixed(2)}s</span>}
                </div>
                {povResult.proof_summary && (
                  <div style={{ marginBottom: 10, fontSize: 12, color: 'var(--text2)', lineHeight: 1.6 }}>
                    {povResult.proof_summary}
                  </div>
                )}
                {(povResult.target_binary || povResult.target_url) && (
                  <div style={{ marginBottom: 10, fontFamily: '"JetBrains Mono", monospace', fontSize: 10, color: 'var(--text2)', wordBreak: 'break-all' }}>
                    {povResult.target_binary ? `TARGET ${povResult.target_binary}` : `TARGET ${povResult.target_url}`}
                  </div>
                )}
                {povResult.evidence?.combined_excerpt && (
                  <pre style={{ background: 'var(--surface2)', border: '1px solid var(--border1)', padding: '10px 12px', margin: 0, overflowX: 'auto', whiteSpace: 'pre-wrap', fontSize: 11, color: '#fca5a5', fontFamily: '"JetBrains Mono", monospace', maxHeight: 220 }}>
                    {povResult.evidence.combined_excerpt}
                  </pre>
                )}
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
