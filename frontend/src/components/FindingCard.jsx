import { useState } from 'react'
import { ChevronDown, ChevronUp, FileCode, AlertTriangle, CheckCircle, Code, FlaskConical } from 'lucide-react'
import SeverityBadge from './SeverityBadge'

function FindingCard({ finding }) {
  const [expanded, setExpanded] = useState(false)

  const getStatusIcon = () => {
    switch (finding.final_status) {
      case 'confirmed':
        return <CheckCircle className="w-5 h-5 text-green-400" />
      case 'skipped':
        return <AlertTriangle className="w-5 h-5 text-yellow-400" />
      default:
        return <AlertTriangle className="w-5 h-5 text-red-400" />
    }
  }

  const getConfidenceColor = (confidence) => {
    if (confidence >= 0.8) return 'text-green-400'
    if (confidence >= 0.6) return 'text-yellow-400'
    return 'text-red-400'
  }

  const validation = finding.validation_result
  const unitTest = validation?.unit_test_result
  const staticResult = validation?.static_result

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
      {/* Header */}
      <div
        className="flex items-center justify-between p-4 cursor-pointer hover:bg-gray-850"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center space-x-4">
          {getStatusIcon()}
          <div>
            <div className="flex items-center space-x-2">
              <SeverityBadge cwe={finding.cwe_type} />
              <span className="font-medium">{finding.cwe_type}</span>
            </div>
            <div className="flex items-center space-x-2 text-sm text-gray-400 mt-1">
              <FileCode className="w-4 h-4" />
              <span>{finding.filepath}:{finding.line_number}</span>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-4">
          <span className={`text-sm font-medium ${getConfidenceColor(finding.confidence)}`}>
            Confidence: {(finding.confidence * 100).toFixed(0)}%
          </span>
          {expanded ? (
            <ChevronUp className="w-5 h-5 text-gray-400" />
          ) : (
            <ChevronDown className="w-5 h-5 text-gray-400" />
          )}
        </div>
      </div>

      {/* Expanded Content */}
      {expanded && (
        <div className="border-t border-gray-800 p-4 space-y-4">
          {/* Explanation */}
          <div>
            <h4 className="text-sm font-medium text-gray-400 mb-2">Explanation</h4>
            <p className="text-gray-300">{finding.llm_explanation}</p>
          </div>

          {/* Vulnerable Code */}
          {finding.code_chunk && (
            <div>
              <h4 className="text-sm font-medium text-gray-400 mb-2">Vulnerable Code</h4>
              <pre className="bg-gray-950 p-3 rounded-lg overflow-x-auto">
                <code className="text-sm text-red-300">{finding.code_chunk}</code>
              </pre>
            </div>
          )}

          {/* PoV Summary */}
          <div>
            <h4 className="text-sm font-medium text-gray-400 mb-2">PoV Status</h4>
            <div className="grid md:grid-cols-2 gap-3 text-sm">
              <div className="bg-gray-950 border border-gray-800 rounded-lg p-3">
                <div className="text-gray-400">Generated</div>
                <div className="font-medium">
                  {finding.pov_script ? 'Yes' : 'No'}
                </div>
              </div>
              <div className="bg-gray-950 border border-gray-800 rounded-lg p-3">
                <div className="text-gray-400">Validation Method</div>
                <div className="font-medium">
                  {validation?.validation_method || 'N/A'}
                </div>
              </div>
              <div className="bg-gray-950 border border-gray-800 rounded-lg p-3">
                <div className="text-gray-400">Will Trigger</div>
                <div className="font-medium">
                  {validation?.will_trigger || 'N/A'}
                </div>
              </div>
              <div className="bg-gray-950 border border-gray-800 rounded-lg p-3">
                <div className="text-gray-400">Triggered</div>
                <div className="font-medium">
                  {finding.pov_result?.vulnerability_triggered ? 'Yes' : 'No'}
                </div>
              </div>
            </div>
          </div>

          {/* PoV Script */}
          {finding.pov_script && (
            <div>
              <h4 className="text-sm font-medium text-gray-400 mb-2">Proof of Vulnerability</h4>
              <pre className="bg-gray-950 p-3 rounded-lg overflow-x-auto">
                <code className="text-sm text-green-300">{finding.pov_script}</code>
              </pre>
            </div>
          )}

          {/* Validation Details */}
          {validation && (
            <div>
              <h4 className="text-sm font-medium text-gray-400 mb-2">Validation Details</h4>
              <div className="bg-gray-950 border border-gray-800 rounded-lg p-3 space-y-2 text-sm">
                {staticResult && (
                  <div>
                    <div className="text-gray-400">Static Analysis</div>
                    <div>Confidence: {(staticResult.confidence * 100).toFixed(0)}%</div>
                    {staticResult.matched_patterns?.length > 0 && (
                      <div>Matched Patterns: {staticResult.matched_patterns.length}</div>
                    )}
                  </div>
                )}
                {unitTest && (
                  <div>
                    <div className="text-gray-400">Unit Test</div>
                    <div>Status: {unitTest.success ? 'Executed' : 'Failed'}</div>
                    <div>Triggered: {unitTest.vulnerability_triggered ? 'Yes' : 'No'}</div>
                    {unitTest.stderr && (
                      <div className="text-red-400">Error: {unitTest.stderr}</div>
                    )}
                  </div>
                )}
                {validation.issues?.length > 0 && (
                  <div>
                    <div className="text-gray-400">Issues</div>
                    <ul className="list-disc list-inside text-yellow-300">
                      {validation.issues.slice(0, 3).map((issue, idx) => (
                        <li key={idx}>{issue}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* PoV Execution Result */}
          {finding.pov_result && (
            <div>
              <h4 className="text-sm font-medium text-gray-400 mb-2">PoV Execution</h4>
              <div className={`p-3 rounded-lg border ${
                finding.pov_result.vulnerability_triggered
                  ? 'bg-red-900/30 border-red-800'
                  : 'bg-gray-950 border-gray-800'
              }`}>
                <div className="flex items-center space-x-2">
                  <FlaskConical className="w-4 h-4" />
                  <span className="font-medium">
                    {finding.pov_result.vulnerability_triggered
                      ? 'VULNERABILITY TRIGGERED'
                      : 'PoV did not trigger vulnerability'}
                  </span>
                </div>
                {(finding.pov_result.stdout || finding.pov_result.stderr) && (
                  <pre className='mt-2 text-xs text-gray-400 overflow-x-auto'>
                    {(finding.pov_result.stdout || '') + (finding.pov_result.stderr ? '\n' + finding.pov_result.stderr : '')}
                  </pre>
                )}
              </div>
            </div>
          )}

          {/* Metadata */}
          <div className="flex flex-wrap items-center gap-4 text-sm text-gray-500 pt-2 border-t border-gray-800">
            <span>Inference: {finding.inference_time_s?.toFixed(2)}s</span>
            <span>Cost: ${finding.cost_usd?.toFixed(4)}</span>
            {finding.model_used && <span>Model: {finding.model_used}</span>}
            {finding.pov_model_used && <span>PoV Model: {finding.pov_model_used}</span>}
          </div>
        </div>
      )}
    </div>
  )
}

export default FindingCard
