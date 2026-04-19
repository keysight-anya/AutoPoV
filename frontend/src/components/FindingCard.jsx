// frontend/src/components/FindingCard.jsx
import { useEffect, useState } from 'react'
import { getFindingArtifacts, getFindingArtifactFile } from '../api/client'

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


function getFailureReason(finding) {
  const status = finding.final_status || ''
  const povResult = finding.pov_result || {}
  const validation = finding.validation_result || {}

  if (status === 'unproven_low_confidence') {
    const conf = (finding.confidence || 0)
    return `Confidence ${(conf * 100).toFixed(0)}% was below the proof threshold — investigation verdict was uncertain`
  }
  if (status === 'unproven_budget_exhausted') {
    return 'Proof budget cap was reached — no attempt was made for this finding'
  }
  if (status === 'contract_gate_failed' || status === 'unproven_contract_gate') {
    const reasons = finding.contract_gate_reasons || validation.issues || []
    if (reasons.length > 0) return 'Contract gate blocked PoV: ' + reasons.slice(0, 2).join('; ')
    return 'Contract gate blocked PoV generation (missing entrypoint or success indicators)'
  }
  if (status === 'pov_generation_failed' || status === 'failed') {
    const err = povResult.error || finding.pov_error || 'Model returned no usable script'
    return `PoV generation failed: ${err}`
  }
  if (status === 'unproven_lite' || status === 'skipped_lite') {
    return 'LITE_MODE is enabled — PoV generation was skipped'
  }
  return null
}

function sentenceCase(value) {
  if (!value) return ''
  const text = String(value).replace(/[_-]+/g, ' ').trim()
  if (!text) return ''
  return text.charAt(0).toUpperCase() + text.slice(1)
}

const CWE_LABELS = {
  'CWE-20': 'Improper Input Validation',
  'CWE-22': 'Path Traversal',
  'CWE-78': 'OS Command Injection',
  'CWE-79': 'Cross-Site Scripting',
  'CWE-89': 'SQL Injection',
  'CWE-94': 'Code Injection',
  'CWE-120': 'Buffer Overflow',
  'CWE-121': 'Stack Buffer Overflow',
  'CWE-122': 'Heap Buffer Overflow',
  'CWE-125': 'Out-of-bounds Read',
  'CWE-134': 'Format String',
  'CWE-190': 'Integer Overflow',
  'CWE-200': 'Information Exposure',
  'CWE-352': 'Cross-Site Request Forgery',
  'CWE-416': 'Use After Free',
  'CWE-476': 'Null Pointer Dereference',
  'CWE-502': 'Deserialization of Untrusted Data',
  'CWE-798': 'Hard-coded Credentials',
  'CWE-862': 'Missing Authorization',
}

function inferUnmappedWeaknessLabel(finding) {
  const explanation = String(finding?.llm_explanation || '').toLowerCase()
  const code = String(finding?.code_chunk || '').toLowerCase()
  const filepath = String(finding?.filepath || '').toLowerCase()
  const entrypoint = String(finding?.exploit_contract?.target_entrypoint || '').toLowerCase()
  const profile = String(finding?.execution_profile || finding?.detected_language || '').toLowerCase()

  if (explanation.includes('null') && explanation.includes('dereference')) return 'Null Dereference Risk'
  if (code.includes('strcpy') || code.includes('memcpy') || code.includes('sprintf(') || code.includes('gets(')) return 'Unsafe Memory Operation'
  if (explanation.includes('authorization') || explanation.includes('access control') || explanation.includes('auth bypass')) return 'Authorization Bypass Risk'
  if (explanation.includes('xss') || explanation.includes('cross-site scripting') || code.includes('innerhtml') || code.includes('<script')) return 'Script Injection Risk'
  if (explanation.includes('code execution') || explanation.includes('command injection') || explanation.includes('eval(') || code.includes('system(') || code.includes('popen(')) return 'Code Execution Risk'
  if (explanation.includes('path traversal') || explanation.includes('directory traversal')) return 'Path Traversal Risk'
  if (explanation.includes('information disclosure') || explanation.includes('information exposure') || explanation.includes('sensitive')) return 'Information Exposure Risk'
  if (entrypoint.includes('load') || filepath.endsWith('.js') || profile === 'javascript') return 'Unsafe Script Loading Path'
  if (profile === 'c' || profile === 'cpp' || filepath.endsWith('.c') || filepath.endsWith('.cpp') || filepath.endsWith('.cc')) return 'Unsafe Native Code Path'
  if (profile === 'php' || filepath.endsWith('.php')) return 'Unsafe Server-side Execution Path'
  if (profile === 'python' || filepath.endsWith('.py')) return 'Unsafe Python Execution Path'
  return 'Unmapped Vulnerability Pattern'
}

function getWeaknessLabel(finding) {
  const cwe = String(finding?.cwe_type || '').trim().toUpperCase()
  if (!cwe || cwe === 'UNCLASSIFIED' || cwe === 'UNKNOWN') return inferUnmappedWeaknessLabel(finding)
  return CWE_LABELS[cwe] || sentenceCase(cwe)
}

function getClassificationLabel(finding) {
  const cwe = String(finding?.cwe_type || '').trim().toUpperCase()
  if (!cwe || cwe === 'UNCLASSIFIED' || cwe === 'UNKNOWN') return 'CWE Unmapped'
  return cwe
}

function getVerdictTone(finding) {
  const verdict = String(finding?.llm_verdict || '').toUpperCase()
  if (verdict === 'REAL') return { label: 'Real', color: '#f59e0b', border: 'rgba(245,158,11,0.35)' }
  if (verdict === 'FALSE_POSITIVE') return { label: 'Rejected', color: 'var(--text2)', border: 'var(--border2)' }
  return { label: 'Needs Review', color: 'var(--text3)', border: 'var(--border2)' }
}

function getProofTone(finding, povResult) {
  if (finding.final_status === 'confirmed') {
    return { label: 'Proven', color: '#22c55e', border: 'rgba(34,197,94,0.35)' }
  }
  if (
    finding.final_status === 'failed' ||
    finding.final_status === 'pov_generation_failed' ||
    finding.final_status === 'pov_failed'
  ) {
    return { label: 'Proof Failed', color: '#f87171', border: 'rgba(248,113,113,0.35)' }
  }
  if (
    finding.final_status === 'contract_gate_failed' ||
    finding.final_status === 'unproven_contract_gate'
  ) {
    return { label: 'Gate Blocked', color: '#f97316', border: 'rgba(249,115,22,0.35)' }
  }
  if (finding.final_status === 'unproven_low_confidence') {
    return { label: 'Below Threshold', color: '#fde047', border: 'rgba(253,224,71,0.35)' }
  }
  if (finding.final_status === 'unproven_budget_exhausted') {
    return { label: 'Budget Exhausted', color: '#a78bfa', border: 'rgba(167,139,250,0.35)' }
  }
  if (finding.final_status === 'unproven_lite' || finding.final_status === 'skipped_lite') {
    return { label: 'Lite Mode Skip', color: 'var(--text3)', border: 'var(--border2)' }
  }
  if (String(finding.final_status || '').startsWith('unproven') || finding.pov_script || finding.validation_result || povResult) {
    return { label: 'Proof Pending', color: '#fde047', border: 'rgba(253,224,71,0.35)' }
  }
  return { label: 'Analyzed', color: 'var(--text3)', border: 'var(--border2)' }
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

export default function FindingCard({ finding, forceExpanded = false, scanId = '', findingIndex = null }) {
  const [expanded, setExpanded] = useState(false)
  const [artifactFiles, setArtifactFiles] = useState([])
  const [artifactDir, setArtifactDir] = useState('')
  const [artifactLoading, setArtifactLoading] = useState(false)
  const [artifactError, setArtifactError] = useState('')
  const [selectedArtifact, setSelectedArtifact] = useState(null)
  const [selectedArtifactContent, setSelectedArtifactContent] = useState('')
  const [artifactContentLoading, setArtifactContentLoading] = useState(false)
  const isExpanded = forceExpanded || expanded

  const severity = getSeverity(finding)
  const sevColor = SEVERITY_COLORS[severity]
  const validation = finding.validation_result
  const unitTest   = validation?.unit_test_result
  const staticResult = validation?.static_result
  const povResult = finding.pov_result || finding.pov_test_result

  const failureReason = getFailureReason(finding)

  const taxonomyRefs = Array.isArray(finding.taxonomy_refs) ? finding.taxonomy_refs.filter(Boolean) : []
  const proofNarrative = buildProofNarrative(finding, povResult)
  const weaknessLabel = getWeaknessLabel(finding)
  const classificationLabel = getClassificationLabel(finding)
  const verdictTone = getVerdictTone(finding)
  const proofTone = getProofTone(finding, povResult)

  useEffect(() => {
    let cancelled = false
    if (!isExpanded || !scanId || findingIndex === null || findingIndex === undefined) return undefined

    setArtifactLoading(true)
    setArtifactError('')
    getFindingArtifacts(scanId, findingIndex)
      .then((res) => {
        if (cancelled) return
        const payload = res?.data || {}
        setArtifactFiles(payload.files || [])
        setArtifactDir(payload.artifact_dir || '')
      })
      .catch((err) => {
        if (cancelled) return
        setArtifactFiles([])
        setArtifactDir('')
        setArtifactError(err?.response?.data?.detail || err.message || 'Failed to load proof artifacts')
      })
      .finally(() => {
        if (!cancelled) setArtifactLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [isExpanded, scanId, findingIndex])

  const openArtifact = async (name) => {
    if (!scanId || findingIndex === null || findingIndex === undefined) return
    setArtifactContentLoading(true)
    setSelectedArtifact(name)
    try {
      const res = await getFindingArtifactFile(scanId, findingIndex, name)
      setSelectedArtifactContent(res?.data?.content || '')
      setArtifactError('')
    } catch (err) {
      setSelectedArtifactContent('')
      setArtifactError(err?.response?.data?.detail || err.message || 'Failed to load artifact content')
    } finally {
      setArtifactContentLoading(false)
    }
  }

  const statusColor = proofTone.color

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

        <div style={{
          flex: 1,
          minWidth: 0,
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          overflow: 'hidden',
          whiteSpace: 'nowrap',
        }}>
          <span style={{
            fontSize: 13,
            color: 'var(--text1)',
            fontWeight: 600,
            flexShrink: 0,
          }}>
            {weaknessLabel}
          </span>
          <span style={{
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: 9,
            letterSpacing: '.08em',
            padding: '2px 8px',
            border: '1px solid var(--border2)',
            color: 'var(--text2)',
            flexShrink: 0,
          }}>
            {classificationLabel}
          </span>
          <span style={{
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: 10,
            color: 'var(--text2)',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            minWidth: 0,
            flex: 1,
          }}>
            {finding.filepath}:{finding.line_number}
          </span>
          <span style={{
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: 9,
            letterSpacing: '.08em',
            padding: '2px 8px',
            border: `1px solid ${verdictTone.border}`,
            color: verdictTone.color,
            flexShrink: 0,
          }}>
            {verdictTone.label.toUpperCase()}
          </span>
          <span style={{
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: 9,
            letterSpacing: '.08em',
            padding: '2px 8px',
            border: `1px solid ${proofTone.border}`,
            color: proofTone.color,
            flexShrink: 0,
          }}>
            {proofTone.label.toUpperCase()}
          </span>
          <span style={{
            fontFamily: '"JetBrains Mono", monospace',
            fontSize: 9,
            letterSpacing: '.06em',
            color: finding.confidence >= 0.8 ? '#22c55e'
                 : finding.confidence >= 0.6 ? '#fde047' : '#f87171',
            flexShrink: 0,
          }}>
            {(finding.confidence * 100).toFixed(0)}% CONFIDENCE
          </span>
        </div>

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
          <div style={{ marginBottom: 14 }}>
            <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.12em', color: 'var(--text3)', marginBottom: 6 }}>CLASSIFICATION</div>
            <div style={{ background: 'var(--bg)', border: '1px solid var(--border1)', padding: '10px 12px' }}>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: taxonomyRefs.length > 0 ? 10 : 0 }}>
                <span style={{ fontSize: 13, color: 'var(--text1)', fontWeight: 600 }}>{weaknessLabel}</span>
                <span style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.08em', padding: '2px 8px', border: '1px solid var(--border2)', color: 'var(--text2)' }}>
                  {classificationLabel}
                </span>
              </div>
              {taxonomyRefs.length > 0 && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  {taxonomyRefs.map((ref) => (
                    <span key={ref} style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.08em', padding: '2px 8px', border: '1px solid var(--border2)', color: 'var(--text2)' }}>
                      {ref}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>

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

          {/* Failure reason — shown when no PoV was run or proof was blocked */}
          {failureReason && !povResult && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.12em', color: 'var(--text3)', marginBottom: 6 }}>PROOF FAILURE REASON</div>
              <div style={{
                padding: '10px 14px',
                background: 'rgba(248,113,113,0.07)',
                border: '1px solid rgba(248,113,113,0.25)',
                fontSize: 12,
                color: '#fca5a5',
                lineHeight: 1.6,
              }}>
                {failureReason}
              </div>
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


          {(artifactLoading || artifactFiles.length > 0 || artifactError) && (
            <div style={{ marginBottom: 14 }}>
              <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.12em', color: 'var(--text3)', marginBottom: 6 }}>ARTIFACT FILES</div>
              <div style={{ background: 'var(--bg)', border: '1px solid var(--border1)', padding: '10px 12px' }}>
                {artifactDir && (
                  <div style={{ marginBottom: 10, fontFamily: '"JetBrains Mono", monospace', fontSize: 9, color: 'var(--text3)', wordBreak: 'break-all' }}>
                    {artifactDir}
                  </div>
                )}
                {artifactLoading ? (
                  <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 10, color: 'var(--text3)' }}>Loading artifact files...</div>
                ) : artifactFiles.length > 0 ? (
                  <div style={{ display: 'grid', gap: 8 }}>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                      {artifactFiles.map((file) => (
                        <button
                          key={file.name}
                          type="button"
                          onClick={() => openArtifact(file.name)}
                          style={{
                            background: selectedArtifact === file.name ? 'rgba(249,115,22,0.12)' : 'var(--surface2)',
                            border: '1px solid var(--border1)',
                            color: selectedArtifact === file.name ? 'var(--accent)' : 'var(--text2)',
                            padding: '6px 10px',
                            cursor: 'pointer',
                            fontFamily: '"JetBrains Mono", monospace',
                            fontSize: 9,
                            letterSpacing: '.06em',
                          }}
                        >
                          {file.name}
                        </button>
                      ))}
                    </div>
                    {artifactContentLoading && (
                      <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 10, color: 'var(--text3)' }}>Loading artifact content...</div>
                    )}
                    {selectedArtifact && !artifactContentLoading && (
                      <pre style={{ background: 'var(--surface2)', border: '1px solid var(--border1)', padding: '10px 12px', margin: 0, overflowX: 'auto', whiteSpace: 'pre-wrap', fontSize: 11, color: 'var(--text2)', fontFamily: '"JetBrains Mono", monospace', maxHeight: 260 }}>
                        {selectedArtifactContent || '[ EMPTY FILE ]'}
                      </pre>
                    )}
                  </div>
                ) : (
                  <div style={{ fontFamily: '"JetBrains Mono", monospace', fontSize: 10, color: 'var(--text3)' }}>No artifact files saved for this finding.</div>
                )}
                {artifactError && (
                  <div style={{ marginTop: 10, fontFamily: '"JetBrains Mono", monospace', fontSize: 10, color: '#fca5a5' }}>{artifactError}</div>
                )}
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
