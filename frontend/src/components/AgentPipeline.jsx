// frontend/src/components/AgentPipeline.jsx

const STAGES = [
  { id: "ingest", label: "INGEST", desc: "Clone, chunk, and index codebase" },
  { id: "scout", label: "SCOUT", desc: "CodeQL, Semgrep, heuristic, and LLM discovery" },
  { id: "investigator", label: "INVESTIGATOR", desc: "Evidence review and confidence scoring" },
  { id: "pov_gen", label: "POV GEN", desc: "Generates exploit contract and proof script" },
  { id: "validation", label: "VALIDATION", desc: "Static, unit, and runtime confirmation" },
]

function inferActiveStage(logs, status) {
  if (status === "ingesting") return "ingest"
  if (status === "running_codeql") return "scout"
  if (status === "investigating") return "investigator"
  if (status === "generating_pov") return "pov_gen"
  if (["validating_pov", "running_pov"].includes(status)) return "validation"

  const joined = logs.join("\n")
  if (/Running agentic discovery|CodeQL|Semgrep|Heuristic scout|LLM scout/i.test(joined)) return "scout"
  if (/Investigating |Investigation completed|Verdict:/i.test(joined)) return "investigator"
  if (/Generating PoV|PoV generated|Refining PoV/i.test(joined)) return "pov_gen"
  if (/Validating PoV|Validation method|VULNERABILITY TRIGGERED|runtime harness|Docker/i.test(joined)) return "validation"
  return "ingest"
}

function SpinnerIcon() {
  return (
    <div style={{
      width: 14,
      height: 14,
      border: "1.5px solid var(--border2)",
      borderTopColor: "var(--accent)",
      borderRadius: "50%",
      animation: "spin 0.8s linear infinite",
      flexShrink: 0,
    }} />
  )
}

function DotIcon({ color }) {
  return (
    <div style={{
      width: 8,
      height: 8,
      borderRadius: "50%",
      background: color,
      flexShrink: 0,
      margin: 3,
    }} />
  )
}

export default function AgentPipeline({ logs = [], status = "running" }) {
  const activeId = inferActiveStage(logs, status)
  const activeIdx = STAGES.findIndex((stage) => stage.id === activeId)
  const terminalStatus = ["completed", "failed", "cancelled", "interrupted"].includes(status)

  return (
    <div style={{ width: 260, flexShrink: 0, borderRight: "1px solid var(--border1)", padding: "20px 0" }}>
      <div style={{
        fontFamily: '"JetBrains Mono", monospace',
        fontSize: 9,
        letterSpacing: ".14em",
        color: "var(--text3)",
        padding: "0 16px",
        marginBottom: 16,
      }}>
        EXECUTION PIPELINE
      </div>

      {STAGES.map((stage, idx) => {
        let rowStatus = "pending"
        if (status === "completed") rowStatus = "done"
        else if (["failed", "interrupted"].includes(status) && idx === activeIdx) rowStatus = "failed"
        else if (status === "cancelled" && idx >= activeIdx) rowStatus = "pending"
        else if (idx < activeIdx) rowStatus = "done"
        else if (!terminalStatus && idx === activeIdx) rowStatus = "running"

        return (
          <div key={stage.id} className={`agent-row ${rowStatus}`}>
            {rowStatus === "running" && <SpinnerIcon />}
            {rowStatus === "done" && <DotIcon color="rgba(34,197,94,0.75)" />}
            {rowStatus === "failed" && <DotIcon color="rgba(239,68,68,0.75)" />}
            {rowStatus === "pending" && <DotIcon color="var(--border2)" />}

            <div>
              <div style={{
                fontFamily: '"JetBrains Mono", monospace',
                fontSize: 10,
                letterSpacing: ".1em",
                color: rowStatus === "running" ? "var(--accent)" : rowStatus === "done" ? "#86efac" : rowStatus === "failed" ? "#fca5a5" : "var(--text3)",
              }}>
                {stage.label}
              </div>
              <div style={{
                fontFamily: '"JetBrains Mono", monospace',
                fontSize: 9,
                color: "var(--text3)",
                marginTop: 1,
              }}>
                {stage.desc}
              </div>
            </div>
          </div>
        )
      })}

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`} </style>
    </div>
  )
}
