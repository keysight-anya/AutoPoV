import { useState } from 'react'
import { ChevronDown, ChevronUp, FileCode, AlertTriangle, CheckCircle, FlaskConical, XCircle } from 'lucide-react'
import SeverityBadge from './SeverityBadge'

const STATUS_CONFIG = {
  confirmed:  { icon: CheckCircle,  color: 'text-safe-400',   border: 'border-l-safe-500',   bg: 'bg-safe-900' },
  skipped:    { icon: AlertTriangle, color: 'text-warn-400',   border: 'border-l-warn-500',   bg: 'bg-warn-900' },
  default:    { icon: XCircle,       color: 'text-threat-400', border: 'border-l-threat-500', bg: 'bg-threat-900' }
}

function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false)

  const cfg = STATUS_CONFIG[finding.final_status] || STATUS_CONFIG.default
  const StatusIcon = cfg.icon

  const confidenceColor = (c) => {
    if (c >= 0.8) return 'text-safe-400'
    if (c >= 0.6) return 'text-warn-400'
    return 'text-threat-400'
  }

  const validation = finding.validation_result
  const unitTest = validation?.unit_test_result
  const staticResult = validation?.static_result

  return (
    <div className={`bg-gray-900/80 rounded-xl border border-gray-800/60 border-l-2 ${cfg.border} overflow-hidden transition-all`}>
      {/* Header */}
      <div
        className="flex items-center justify-between px-4 py-3.5 cursor-pointer hover:bg-gray-800/30 transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-3 min-w-0">
          <StatusIcon className={`w-4 h-4 shrink-0 ${cfg.color}`} />
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <SeverityBadge cwe={finding.cwe_type} />
              <span className="font-medium text-sm">{finding.cwe_type}</span>
            </div>
            <div className="flex items-center gap-1.5 text-xs text-gray-500 mt-0.5">
              <FileCode className="w-3 h-3 shrink-0" />
              <span className="font-mono truncate">{finding.filepath}:{finding.line_number}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center gap-3 shrink-0 ml-3">
          <span className={`text-xs font-medium ${confidenceColor(finding.confidence)}`}>
            {(finding.confidence * 100).toFixed(0)}% conf.
          </span>
          {expanded
            ? <ChevronUp className="w-4 h-4 text-gray-500" />
            : <ChevronDown className="w-4 h-4 text-gray-500" />
          }
        </div>
      </div>

      {/* Expanded */}
      {expanded && (
        <div className="border-t border-gray-800/60 p-4 space-y-4">
          {/* Explanation */}
          {finding.llm_explanation && (
            <div>
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-1.5">Analysis</p>
              <p className="text-sm text-gray-300 leading-relaxed">{finding.llm_explanation}</p>
            </div>
          )}

          {/* Vulnerable Code */}
          {finding.code_chunk && (
            <div>
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-1.5">Vulnerable Code</p>
              <pre className="bg-gray-950 border border-threat-500/10 p-3 rounded-lg overflow-x-auto">
                <code className="text-xs text-threat-300 font-mono leading-relaxed">{finding.code_chunk}</code>
              </pre>
            </div>
          )}

          {/* PoV status grid */}
          <div>
            <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-1.5">PoV Status</p>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              {[
                { label: 'Generated', value: finding.pov_script ? 'Yes' : 'No', positive: !!finding.pov_script },
                { label: 'Method', value: validation?.validation_method || '—', positive: null },
                { label: 'Will Trigger', value: validation?.will_trigger || '—', positive: null },
                { label: 'Triggered', value: finding.pov_result?.vulnerability_triggered ? 'Yes' : 'No', positive: finding.pov_result?.vulnerability_triggered }
              ].map(({ label, value, positive }) => (
                <div key={label} className="bg-gray-950/60 border border-gray-800/40 rounded-lg p-2.5">
                  <p className="text-xs text-gray-500 mb-0.5">{label}</p>
                  <p className={`text-sm font-medium ${positive === true ? 'text-safe-400' : positive === false ? 'text-threat-400' : 'text-gray-300'}`}>
                    {value}
                  </p>
                </div>
              ))}
            </div>
          </div>

          {/* PoV Script */}
          {finding.pov_script && (
            <div>
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-1.5">Proof of Vulnerability</p>
              <pre className="bg-gray-950 border border-safe-500/10 p-3 rounded-lg overflow-x-auto">
                <code className="text-xs text-safe-300 font-mono leading-relaxed">{finding.pov_script}</code>
              </pre>
            </div>
          )}

          {/* PoV Execution */}
          {finding.pov_result && (
            <div>
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-1.5">Execution Result</p>
              <div className={`flex items-start gap-2.5 p-3 rounded-lg border ${
                finding.pov_result.vulnerability_triggered
                  ? 'bg-threat-900/40 border-threat-500/20'
                  : 'bg-gray-950/60 border-gray-800/40'
              }`}>
                <FlaskConical className={`w-4 h-4 mt-0.5 shrink-0 ${finding.pov_result.vulnerability_triggered ? 'text-threat-400' : 'text-gray-500'}`} />
                <div>
                  <p className={`text-sm font-medium ${finding.pov_result.vulnerability_triggered ? 'text-threat-300' : 'text-gray-400'}`}>
                    {finding.pov_result.vulnerability_triggered ? 'VULNERABILITY TRIGGERED' : 'PoV did not trigger'}
                  </p>
                  {(finding.pov_result.stdout || finding.pov_result.stderr) && (
                    <pre className="mt-2 text-xs text-gray-500 overflow-x-auto whitespace-pre-wrap">
                      {(finding.pov_result.stdout || '') + (finding.pov_result.stderr ? '\n' + finding.pov_result.stderr : '')}
                    </pre>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Validation details */}
          {(staticResult || unitTest || validation?.issues?.length > 0) && (
            <div>
              <p className="text-xs font-medium text-gray-500 uppercase tracking-wide mb-1.5">Validation Details</p>
              <div className="bg-gray-950/60 border border-gray-800/40 rounded-lg p-3 space-y-2 text-xs text-gray-400">
                {staticResult && (
                  <div className="flex gap-4">
                    <span className="text-gray-500">Static confidence:</span>
                    <span>{(staticResult.confidence * 100).toFixed(0)}%</span>
                    {staticResult.matched_patterns?.length > 0 && (
                      <span>{staticResult.matched_patterns.length} patterns matched</span>
                    )}
                  </div>
                )}
                {unitTest && (
                  <div className="flex gap-4">
                    <span className="text-gray-500">Unit test:</span>
                    <span>{unitTest.success ? 'executed' : 'failed'}</span>
                    <span>triggered: {unitTest.vulnerability_triggered ? 'yes' : 'no'}</span>
                    {unitTest.stderr && <span className="text-threat-400 truncate">{unitTest.stderr}</span>}
                  </div>
                )}
                {validation?.issues?.length > 0 && (
                  <ul className="list-disc list-inside text-warn-300 space-y-0.5">
                    {validation.issues.slice(0, 3).map((issue, idx) => <li key={idx}>{issue}</li>)}
                  </ul>
                )}
              </div>
            </div>
          )}

          {/* Metadata */}
          <div className="flex flex-wrap items-center gap-3 text-xs text-gray-600 pt-2 border-t border-gray-800/40">
            {finding.inference_time_s && <span>Inference: {finding.inference_time_s.toFixed(2)}s</span>}
            {finding.cost_usd != null && <span>Cost: ${finding.cost_usd.toFixed(4)}</span>}
            {finding.model_used && <span className="font-mono">{finding.model_used.split('/').pop()}</span>}
            {finding.pov_model_used && <span className="font-mono">PoV: {finding.pov_model_used.split('/').pop()}</span>}
          </div>
        </div>
      )}
    </div>
  )
}

export default FindingCard
