import { useEffect, useRef } from 'react'
import { Terminal } from 'lucide-react'

const LINE_COLOR = (msg) => {
  if (/VULNERABILITY TRIGGERED/i.test(msg)) return 'text-threat-400 font-semibold'
  if (/error|failed|exception/i.test(msg)) return 'text-red-400'
  if (/success|confirmed|complete/i.test(msg)) return 'text-safe-400'
  if (/warning|warn/i.test(msg)) return 'text-warn-400'
  if (/\[INFO\]|→|✓/i.test(msg)) return 'text-primary-400'
  return 'text-gray-400'
}

function LiveLog({ logs }) {
  const logEndRef = useRef(null)

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  const parseLine = (log) => {
    const match = log.match(/^\[(.*?)\]\s(.*)$/)
    if (match) return { ts: match[1], msg: match[2] }
    return { ts: null, msg: log }
  }

  return (
    <div className="bg-gray-950 rounded-xl border border-gray-800/60 overflow-hidden">
      {/* Header */}
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-gray-800/60 bg-gray-900/60">
        <div className="flex gap-1.5">
          <div className="w-2.5 h-2.5 rounded-full bg-red-500/60" />
          <div className="w-2.5 h-2.5 rounded-full bg-warn-500/60" />
          <div className="w-2.5 h-2.5 rounded-full bg-safe-500/60" />
        </div>
        <div className="flex items-center gap-1.5 text-xs text-gray-500 ml-2">
          <Terminal className="w-3.5 h-3.5 text-primary-500/70" />
          <span>scan log</span>
        </div>
        <span className="ml-auto text-xs text-gray-700">{logs.length} lines</span>
      </div>

      {/* Log body */}
      <div className="h-96 overflow-y-auto p-4 font-mono text-xs leading-relaxed">
        {logs.length === 0 ? (
          <span className="text-gray-600 italic">Waiting for scan output…</span>
        ) : (
          <div className="space-y-0.5">
            {logs.map((log, i) => {
              const { ts, msg } = parseLine(log)
              return (
                <div key={i} className="log-entry flex gap-3 group">
                  {ts && (
                    <span className="text-gray-700 shrink-0 group-hover:text-gray-500 transition-colors">
                      {new Date(ts).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                    </span>
                  )}
                  <span className={LINE_COLOR(msg)}>{msg}</span>
                </div>
              )
            })}
            <div ref={logEndRef} />
          </div>
        )}
      </div>
    </div>
  )
}

export default LiveLog
