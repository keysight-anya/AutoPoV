// frontend/src/components/AgentPipeline.jsx

const AGENTS = [
  { id: 'ingest',       label: 'INGEST',       desc: 'Chunks & embeds codebase' },
  { id: 'scout',        label: 'SCOUT',        desc: 'Pattern + LLM discovery'  },
  { id: 'investigator', label: 'INVESTIGATOR', desc: 'Deep RAG analysis'        },
  { id: 'pov_gen',      label: 'POV GEN',      desc: 'Writes exploit script'    },
  { id: 'validation',   label: 'VALIDATION',   desc: 'Static → unit test → Docker' },
  { id: 'policy',       label: 'POLICY',       desc: 'Routes to optimal model'  },
]

// Infer which agent is active from log messages
function inferActiveAgent(logs) {
  const last = [...logs].reverse().find(l =>
    l.includes('INGEST') || l.includes('SCOUT') || l.includes('INVESTIGATOR') ||
    l.includes('POV') || l.includes('VALIDATION') || l.includes('POLICY')
  ) || ''
  if (last.includes('INGEST'))       return 'ingest'
  if (last.includes('SCOUT'))        return 'scout'
  if (last.includes('INVESTIGATOR')) return 'investigator'
  if (last.includes('POV'))          return 'pov_gen'
  if (last.includes('VALIDATION'))   return 'validation'
  if (last.includes('POLICY'))       return 'policy'
  return 'ingest'
}

function SpinnerIcon() {
  return (
    <div style={{
      width: 14, height: 14,
      border: '1.5px solid var(--border2)',
      borderTopColor: 'var(--accent)',
      borderRadius: '50%',
      animation: 'spin 0.8s linear infinite',
      flexShrink: 0,
    }} />
  )
}

function DotIcon({ color }) {
  return (
    <div style={{
      width: 8, height: 8,
      borderRadius: '50%',
      background: color,
      flexShrink: 0,
      margin: 3,
    }} />
  )
}

export default function AgentPipeline({ logs = [], status = 'running' }) {
  const activeId = inferActiveAgent(logs)
  const activeIdx = AGENTS.findIndex(a => a.id === activeId)

  return (
    <div style={{
      width: 220,
      flexShrink: 0,
      borderRight: '1px solid var(--border1)',
      padding: '20px 0',
    }}>
      <div style={{
        fontFamily: '"JetBrains Mono", monospace',
        fontSize: 9, letterSpacing: '.14em',
        color: 'var(--text3)',
        padding: '0 16px',
        marginBottom: 16,
      }}>
        AGENT PIPELINE
      </div>

      {AGENTS.map((agent, idx) => {
        let rowStatus = 'pending'
        if (status === 'completed') rowStatus = 'done'
        else if (status === 'failed' && idx === activeIdx) rowStatus = 'failed'
        else if (idx < activeIdx) rowStatus = 'done'
        else if (idx === activeIdx) rowStatus = 'running'

        return (
          <div
            key={agent.id}
            className={`agent-row ${rowStatus}`}
          >
            {rowStatus === 'running'  && <SpinnerIcon />}
            {rowStatus === 'done'     && <DotIcon color="rgba(34,197,94,0.7)" />}
            {rowStatus === 'failed'   && <DotIcon color="rgba(239,68,68,0.7)" />}
            {rowStatus === 'pending'  && <DotIcon color="var(--border2)" />}

            <div>
              <div style={{
                fontFamily: '"JetBrains Mono", monospace',
                fontSize: 10, letterSpacing: '.1em',
                color: rowStatus === 'running' ? 'var(--accent)'
                     : rowStatus === 'done'    ? 'var(--text2)'
                     : 'var(--text3)',
              }}>
                {agent.label}
              </div>
              <div style={{
                fontFamily: '"JetBrains Mono", monospace',
                fontSize: 9, color: 'var(--text3)',
                marginTop: 1,
              }}>
                {agent.desc}
              </div>
            </div>
          </div>
        )
      })}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </div>
  )
}
