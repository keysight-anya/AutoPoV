// frontend/src/components/LiveLog.jsx
import { useEffect, useRef } from 'react'

const LOG_COLOR = (msg) => {
  if (/error|failed|exception/i.test(msg))               return '#fca5a5'  // red
  if (/success|confirmed|completed/i.test(msg))          return '#86efac'  // green
  if (/vulnerability triggered/i.test(msg))              return '#f87171'  // bright red
  if (/warning|skipped/i.test(msg))                      return '#fde047'  // yellow
  return 'var(--text2)'
}

export default function LiveLog({ logs = [] }) {
  const bottomRef = useRef(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  const parse = (line) => {
    const m = line.match(/^\[(.*?)\] (.*)$/)
    return m ? { ts: m[1], msg: m[2] } : { ts: null, msg: line }
  }

  return (
    <div style={{
      flex: 1,
      display: 'flex',
      flexDirection: 'column',
      overflow: 'hidden',
    }}>
      {/* Terminal header */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '8px 14px',
        background: 'var(--surface2)',
        borderBottom: '1px solid var(--border1)',
        fontFamily: '"JetBrains Mono", monospace',
        fontSize: 9, letterSpacing: '.12em', color: 'var(--text3)',
      }}>
        <span style={{ color: 'var(--accent)' }}>●</span>
        LIVE LOG
        <span style={{ marginLeft: 'auto' }}>{logs.length} lines</span>
      </div>

      {/* Log content */}
      <div style={{
        flex: 1,
        overflowY: 'auto',
        padding: '12px 14px',
        background: 'var(--bg)',
        fontFamily: '"JetBrains Mono", monospace',
        fontSize: 11,
      }}>
        {logs.length === 0 ? (
          <span style={{ color: 'var(--text3)' }}>Waiting for scan to start…</span>
        ) : (
          logs.map((line, i) => {
            const { ts, msg } = parse(line)
            return (
              <div key={i} className="log-entry" style={{ display: 'flex', gap: 10, marginBottom: 2 }}>
                {ts && (
                  <span style={{ color: 'var(--text3)', flexShrink: 0, fontSize: 10 }}>
                    {new Date(ts).toLocaleTimeString()}
                  </span>
                )}
                <span style={{ color: LOG_COLOR(msg) }}>{msg}</span>
              </div>
            )
          })
        )}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}
