// frontend/src/pages/Results.jsx
import { useEffect, useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import SeverityFilter from '../components/SeverityFilter'
import FindingCard from '../components/FindingCard'
import { getScanStatus, getReport } from '../api/client'

// CWE-agnostic severity based on confidence and verdict
function getSeverity(finding) {
  const confidence = finding?.confidence || 0
  const verdict = finding?.llm_verdict || finding?.final_status
  
  // If it's not a real vulnerability, mark as info
  if (verdict === 'FALSE_POSITIVE' || verdict === 'skipped') {
    return 'INFO'
  }
  
  // Use confidence to determine severity (CWE-agnostic)
  if (confidence >= 0.9) return 'CRITICAL'
  if (confidence >= 0.8) return 'HIGH'
  if (confidence >= 0.7) return 'MEDIUM'
  return 'LOW'
}


function collectOpenRouterUsage(findings, scanOpenRouterUsage = []) {
  const calls = []
  const seenGenerationIds = new Set()

  const normalizeUsageEntries = (usage) => {
    if (!usage) return []
    if (Array.isArray(usage)) return usage.filter(Boolean)
    if (typeof usage === 'string') {
      try {
        return normalizeUsageEntries(JSON.parse(usage))
      } catch {
        return []
      }
    }
    if (typeof usage === 'object') return [usage]
    return []
  }

  const pushCall = (usage, agentRole, finding, attempt = null) => {
    for (const entry of normalizeUsageEntries(usage)) {
      const generationId = entry?.generation_id
      if (generationId) {
        if (seenGenerationIds.has(generationId)) continue
        seenGenerationIds.add(generationId)
      }

      calls.push({
        generation_id: generationId || null,
        agent_role: entry?.agent_role || agentRole,
        provider_name: entry?.provider_name || 'unknown',
        model: entry?.model_permaslug || entry?.model || 'unknown',
        cost_usd: Number(entry?.cost_usd || 0),
        tokens_prompt: Number(entry?.native_tokens_prompt || entry?.tokens_prompt || 0),
        tokens_completion: Number(entry?.native_tokens_completion || entry?.tokens_completion || 0),
        total_tokens: Number((entry?.native_tokens_prompt || entry?.tokens_prompt || 0) + (entry?.native_tokens_completion || entry?.tokens_completion || 0)),
        native_tokens_reasoning: Number(entry?.native_tokens_reasoning || 0),
        finding_ref: `${finding?.filepath || 'unknown'}:${finding?.line_number || 0}`,
        attempt,
      })
    }
  }

  normalizeUsageEntries(scanOpenRouterUsage).forEach((entry) => {
    pushCall(entry, entry?.agent_role || 'scan', { filepath: entry?.filepath, line_number: entry?.line_number }, entry?.attempt ?? null)
  })

  findings.forEach((finding) => {
    pushCall(finding?.scout_openrouter_usage, 'llm_scout', finding)
    pushCall(finding?.openrouter_usage, 'investigator', finding)
    pushCall(finding?.pov_openrouter_usage, 'pov_generation', finding)
    pushCall(finding?.validation_result?.openrouter_usage, 'llm_validation', finding)
    pushCall(finding?.pov_result?.openrouter_usage, 'runtime_validation', finding)
    ;(finding?.refinement_history || []).forEach((item) => {
      pushCall(item?.openrouter_usage, 'pov_refinement', finding, item?.attempt ?? null)
    })
  })

  const grouped = new Map()
  calls.forEach((call) => {
    const key = `${call.agent_role}::${call.model}::${call.provider_name}`
    if (!grouped.has(key)) {
      grouped.set(key, {
        agent_role: call.agent_role,
        model: call.model,
        provider_name: call.provider_name,
        calls: 0,
        cost_usd: 0,
        prompt_tokens: 0,
        completion_tokens: 0,
        reasoning_tokens: 0,
      })
    }
    const row = grouped.get(key)
    row.calls += 1
    row.cost_usd += call.cost_usd
    row.prompt_tokens += call.tokens_prompt
    row.completion_tokens += call.tokens_completion
    row.reasoning_tokens += call.native_tokens_reasoning
  })

  const summary = Array.from(grouped.values()).sort((a, b) => b.cost_usd - a.cost_usd)
  return {
    calls,
    summary,
    totalCostUsd: summary.reduce((acc, row) => acc + row.cost_usd, 0),
    totalPromptTokens: summary.reduce((acc, row) => acc + row.prompt_tokens, 0),
    totalCompletionTokens: summary.reduce((acc, row) => acc + row.completion_tokens, 0),
    totalReasoningTokens: summary.reduce((acc, row) => acc + row.reasoning_tokens, 0),
  }
}

const statButtonStyle = (active, color) => ({
  background: 'none',
  border: 'none',
  padding: 0,
  cursor: 'pointer',
  fontFamily: '"JetBrains Mono", monospace',
  fontSize: 10,
  letterSpacing: '.08em',
  color: active ? color : 'var(--text3)',
})

export default function Results() {
  const { scanId } = useParams()
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [filter, setFilter] = useState('ALL')
  const [viewFilter, setViewFilter] = useState('all')
  const [downloadError, setDownloadError] = useState(null)

  useEffect(() => {
    let cancelled = false
    let timer = null

    const fetchResult = async (attempt = 0) => {
      try {
        const res = await getScanStatus(scanId)
        const payload = res?.data?.result
        if (payload) {
          if (!cancelled) {
            setResult(payload)
            setError(null)
            setLoading(false)
          }
          return
        }

        if (attempt < 9) {
          timer = setTimeout(() => fetchResult(attempt + 1), 1500)
          return
        }

        try {
          const reportRes = await getReport(scanId, 'json')
          if (!cancelled && reportRes?.data) {
            setResult(reportRes.data)
            setError(null)
            setLoading(false)
            return
          }
        } catch {
        }

        if (!cancelled) {
          setResult(null)
          setLoading(false)
        }
      } catch (err) {
        if (attempt < 4) {
          timer = setTimeout(() => fetchResult(attempt + 1), 1500)
          return
        }
        if (!cancelled) {
          setError(err.message)
          setLoading(false)
        }
      }
    }

    setLoading(true)
    setError(null)
    setResult(null)
    fetchResult()

    return () => {
      cancelled = true
      if (timer) clearTimeout(timer)
    }
  }, [scanId])

  const findings = result?.findings || []
  const totalFiles = result?.language_info?.total_files || 0
  const totalLoc = result?.total_loc || result?.language_info?.total_loc || 0
  const provenFindings = useMemo(() => findings.filter(f => f.final_status === 'confirmed'), [findings])
  const povFindings = useMemo(() => findings.filter(f => f.pov_script || f.pov_result), [findings])
  const realFindings = useMemo(() => findings.filter(f => f.llm_verdict === 'REAL'), [findings])
  const failedFindings = useMemo(() => findings.filter(f => f.final_status === 'failed'), [findings])
  const unprovenFindings = useMemo(
    () => findings.filter(f => String(f.final_status || '').startsWith('unproven')),
    [findings]
  )
  const falsePositiveFindings = useMemo(
    () => findings.filter(f => f.llm_verdict === 'FALSE_POSITIVE' || f.final_status === 'skipped'),
    [findings]
  )
  const openrouterUsage = useMemo(() => collectOpenRouterUsage(findings, result?.scan_openrouter_usage || []), [findings, result])

  const counts = useMemo(() => {
    const c = { ALL: findings.length, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
    findings.forEach(f => { const s = getSeverity(f); c[s] = (c[s] || 0) + 1 })
    return c
  }, [findings])

  const filtered = useMemo(() => {
    let base = findings
    if (viewFilter === 'real') base = realFindings
    if (viewFilter === 'confirmed') base = provenFindings
    if (viewFilter === 'failed') base = failedFindings
    if (viewFilter === 'unproven') base = unprovenFindings
    if (viewFilter === 'false_positive') base = falsePositiveFindings
    if (viewFilter === 'pov') base = povFindings
    if (filter !== 'ALL') base = base.filter(f => getSeverity(f) === filter)
    return base
  }, [findings, realFindings, provenFindings, failedFindings, unprovenFindings, falsePositiveFindings, povFindings, filter, viewFilter])

  const downloadReport = async (format) => {
    try {
      setDownloadError(null)
      const response = await getReport(scanId, format)
      const blob = format === 'pdf'
        ? response.data
        : new Blob([JSON.stringify(response.data, null, 2)], { type: 'application/json' })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${scanId}_report.${format}`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (err) {
      console.error('Download failed:', err)
      setDownloadError(err?.response?.data?.detail || err.message || 'Report download failed')
    }
  }

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%' }}>
      <div style={{ width: 24, height: 24, border: '2px solid var(--border2)', borderTopColor: 'var(--accent)', borderRadius: '50%', animation: 'spin 0.8s linear infinite' }} />
    </div>
  )

  if (error) return (
    <div style={{ padding: 24 }}>
      <div style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', padding: '10px 14px', fontFamily: '"JetBrains Mono", monospace', fontSize: 11, color: '#fca5a5' }}>
        Error loading results: {error}
      </div>
    </div>
  )

  if (!result) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', fontFamily: '"JetBrains Mono", monospace', fontSize: 10, letterSpacing: '.14em', color: 'var(--text3)' }}>
      [ NO RESULTS FOUND ]
    </div>
  )

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <div style={{
        padding: '10px 20px',
        background: 'var(--surface1)',
        borderBottom: '1px solid var(--border1)',
        display: 'flex', alignItems: 'center', gap: 20, flexWrap: 'wrap',
        flexShrink: 0,
        fontFamily: '"JetBrains Mono", monospace',
        fontSize: 10, letterSpacing: '.08em',
      }}>
        <button type="button" onClick={() => setViewFilter('all')} style={statButtonStyle(viewFilter === 'all', 'var(--accent)')}>
          FINDINGS <span style={{ color: 'var(--accent)', marginLeft: 6 }}>{findings.length}</span>
        </button>
        <button type="button" onClick={() => setViewFilter('real')} style={statButtonStyle(viewFilter === 'real', '#f59e0b')}>
          REAL <span style={{ color: '#f59e0b', marginLeft: 6 }}>{realFindings.length}</span>
        </button>
        <button type="button" onClick={() => setViewFilter('confirmed')} style={statButtonStyle(viewFilter === 'confirmed', '#22c55e')}>
          PROVEN <span style={{ color: '#22c55e', marginLeft: 6 }}>{provenFindings.length}</span>
        </button>
        <button type="button" onClick={() => setViewFilter('failed')} style={statButtonStyle(viewFilter === 'failed', '#f87171')}>
          FAILED <span style={{ color: '#f87171', marginLeft: 6 }}>{failedFindings.length}</span>
        </button>
        <button type="button" onClick={() => setViewFilter('unproven')} style={statButtonStyle(viewFilter === 'unproven', '#fde047')}>
          UNPROVEN <span style={{ color: '#fde047', marginLeft: 6 }}>{unprovenFindings.length}</span>
        </button>
        <button type="button" onClick={() => setViewFilter('false_positive')} style={statButtonStyle(viewFilter === 'false_positive', 'var(--text2)')}>
          FALSE POS <span style={{ color: 'var(--text2)', marginLeft: 6 }}>{falsePositiveFindings.length}</span>
        </button>
        <button type="button" onClick={() => setViewFilter('pov')} style={statButtonStyle(viewFilter === 'pov', 'var(--accent)')}>
          PoVs <span style={{ color: 'var(--accent)', marginLeft: 6 }}>{povFindings.length}</span>
        </button>
        <span style={{ color: 'var(--text3)', fontFamily: '"JetBrains Mono", monospace', fontSize: 9, marginLeft: 8 }}>
          FILES <span style={{ color: 'var(--text2)', marginLeft: 6 }}>{totalFiles}</span>
        </span>
        <span style={{ color: 'var(--text3)', fontFamily: '"JetBrains Mono", monospace', fontSize: 9 }}>
          LOC <span style={{ color: 'var(--text2)', marginLeft: 6 }}>{totalLoc.toLocaleString()}</span>
        </span>
        <span style={{ color: 'var(--text3)', marginLeft: 'auto', fontFamily: '"JetBrains Mono", monospace', fontSize: 9 }}>
          {scanId}
        </span>
        <button onClick={() => downloadReport('json')} style={{ background: 'none', border: '1px solid var(--border2)', color: 'var(--text3)', padding: '4px 12px', fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.1em', cursor: 'pointer' }}>JSON</button>
        <button onClick={() => downloadReport('pdf')} style={{ background: 'none', border: '1px solid var(--border2)', color: 'var(--text3)', padding: '4px 12px', fontFamily: '"JetBrains Mono", monospace', fontSize: 9, letterSpacing: '.1em', cursor: 'pointer' }}>PDF</button>
      </div>

      {downloadError && (
        <div style={{ padding: '10px 20px', borderBottom: '1px solid rgba(239,68,68,0.3)', background: 'rgba(239,68,68,0.08)', color: '#fca5a5', fontFamily: '"JetBrains Mono", monospace', fontSize: 10 }}>
          {downloadError}
        </div>
      )}

      {openrouterUsage.summary.length > 0 && (
        <div style={{ padding: '12px 20px', borderBottom: '1px solid var(--border1)', background: 'var(--surface1)' }}>
          <div style={{ display: 'flex', gap: 20, flexWrap: 'wrap', fontFamily: '"JetBrains Mono", monospace', fontSize: 10, letterSpacing: '.08em', marginBottom: 10 }}>
            <span style={{ color: 'var(--text3)' }}>OPENROUTER CALLS <span style={{ color: 'var(--text2)', marginLeft: 6 }}>{openrouterUsage.calls.length}</span></span>
            <span style={{ color: 'var(--text3)' }}>EXACT COST <span style={{ color: 'var(--text2)', marginLeft: 6 }}>${openrouterUsage.totalCostUsd.toFixed(6)}</span></span>
            <span style={{ color: 'var(--text3)' }}>PROMPT <span style={{ color: 'var(--text2)', marginLeft: 6 }}>{openrouterUsage.totalPromptTokens.toLocaleString()}</span></span>
            <span style={{ color: 'var(--text3)' }}>COMPLETION <span style={{ color: 'var(--text2)', marginLeft: 6 }}>{openrouterUsage.totalCompletionTokens.toLocaleString()}</span></span>
            <span style={{ color: 'var(--text3)' }}>REASONING <span style={{ color: 'var(--text2)', marginLeft: 6 }}>{openrouterUsage.totalReasoningTokens.toLocaleString()}</span></span>
          </div>
          <div style={{ border: '1px solid var(--border1)', overflow: 'hidden' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '120px 1.6fr 70px 100px 110px', padding: '8px 12px', background: 'var(--surface2)', fontFamily: '"JetBrains Mono", monospace', fontSize: 10, letterSpacing: '.08em', color: 'var(--text3)' }}>
              <span>AGENT</span>
              <span>MODEL</span>
              <span>CALLS</span>
              <span>REASONING</span>
              <span>COST</span>
            </div>
            {openrouterUsage.summary.map((row, idx) => (
              <div key={`${row.agent_role}:${row.model}:${idx}`} style={{ display: 'grid', gridTemplateColumns: '120px 1.6fr 70px 100px 110px', padding: '8px 12px', borderTop: idx === 0 ? 'none' : '1px solid var(--border1)', fontFamily: '"JetBrains Mono", monospace', fontSize: 10, color: 'var(--text2)' }}>
                <span>{row.agent_role}</span>
                <span style={{ color: 'var(--accent)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{row.model}</span>
                <span>{row.calls}</span>
                <span>{row.reasoning_tokens.toLocaleString()}</span>
                <span>${row.cost_usd.toFixed(6)}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <SeverityFilter counts={counts} active={filter} onChange={setFilter} />
        <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px' }}>
          {filtered.length === 0 ? (
            <div style={{ textAlign: 'center', paddingTop: 60, fontFamily: '"JetBrains Mono", monospace', fontSize: 10, letterSpacing: '.14em', color: 'var(--text3)' }}>
              [ NO FINDINGS FOR THIS FILTER ]
            </div>
          ) : (
            filtered.map((f, idx) => (
              <FindingCard
                key={`${f.filepath}:${f.line_number}:${f.cwe_type}:${idx}`}
                finding={f}
                forceExpanded={viewFilter === 'pov'}
                scanId={scanId}
                findingIndex={findings.indexOf(f)}
              />
            ))
          )}
        </div>
      </div>
    </div>
  )
}
