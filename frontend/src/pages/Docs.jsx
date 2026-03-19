import { BookOpen, Terminal, Shield, Activity, FileCode } from 'lucide-react'

const apiBase = (import.meta.env.VITE_API_URL || 'http://localhost:8000/api').replace(/\/$/, '')

function Section({ icon: Icon, title, children }) {
  return (
    <section className="bg-gray-900 rounded-lg border border-gray-800 p-6">
      <div className="flex items-center gap-2 mb-4">
        <Icon className="w-5 h-5 text-primary-500" />
        <h2 className="text-lg font-medium">{title}</h2>
      </div>
      {children}
    </section>
  )
}

function CodeBlock({ children }) {
  return (
    <pre className="bg-gray-950 p-3 rounded-lg overflow-x-auto border border-gray-800">
      <code className="text-sm text-green-400">{children}</code>
    </pre>
  )
}

export default function Docs() {
  return (
    <div className="max-w-5xl mx-auto space-y-6">
      <div className="flex items-center gap-3 mb-2">
        <BookOpen className="w-7 h-7 text-primary-500" />
        <div>
          <h1 className="text-3xl font-semibold">Docs</h1>
          <p className="text-sm text-gray-400 mt-1">
            Open-ended vulnerability discovery, post-hoc classification, and proof-first validation.
          </p>
        </div>
      </div>

      <Section icon={Shield} title="How AutoPoV Works">
        <div className="space-y-3 text-sm text-gray-400 leading-6">
          <p>
            AutoPoV does not require predefined CWE input. A scan starts with broad discovery using static analyzers,
            heuristics, and AI agents.
          </p>
          <p>
            Candidate findings are then investigated to determine whether they are real. If a finding matches a known
            CWE or CVE, the system maps it during classification. If not, it can remain <span className="text-primary-400">UNCLASSIFIED</span>
            {' '}and still move forward to proof generation and validation.
          </p>
          <p>
            The final decision is proof-oriented: confirmed vulnerabilities are the ones the system can validate or
            exploit with observable evidence.
          </p>
        </div>
      </Section>

      <Section icon={Activity} title="API Reference">
        <div className="space-y-5 text-sm text-gray-400">
          <div>
            <h3 className="font-medium text-primary-400 mb-2">POST /api/scan/git</h3>
            <p className="mb-2">Scan a Git repository.</p>
            <CodeBlock>{`{
  "url": "https://github.com/user/repo.git",
  "branch": "main",
  "model": "anthropic/claude-opus-4.6"
}`}</CodeBlock>
          </div>

          <div>
            <h3 className="font-medium text-primary-400 mb-2">POST /api/scan/zip</h3>
            <p>Upload and scan a ZIP file using multipart form data with the file and optional model override.</p>
          </div>

          <div>
            <h3 className="font-medium text-primary-400 mb-2">POST /api/scan/paste</h3>
            <p className="mb-2">Scan pasted code.</p>
            <CodeBlock>{`{
  "code": "def vulnerable(): ...",
  "language": "python",
  "filename": "example.py",
  "model": "qwen3"
}`}</CodeBlock>
          </div>

          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <h3 className="font-medium text-blue-400 mb-1">GET /api/scan/{'{scan_id}'}</h3>
              <p>Get scan status and results.</p>
            </div>
            <div>
              <h3 className="font-medium text-blue-400 mb-1">GET /api/scan/{'{scan_id}'}/stream</h3>
              <p>Stream live logs via Server-Sent Events.</p>
            </div>
            <div>
              <h3 className="font-medium text-blue-400 mb-1">GET /api/history</h3>
              <p>Get scan history.</p>
            </div>
            <div>
              <h3 className="font-medium text-purple-400 mb-1">GET /api/report/{'{scan_id}'}</h3>
              <p>Download scan report as JSON or PDF.</p>
            </div>
          </div>

          <div className="pt-2 text-xs text-gray-500">
            Base URL: <span className="font-mono text-gray-300">{apiBase}</span>
          </div>
        </div>
      </Section>

      <Section icon={Terminal} title="CLI Reference">
        <div className="space-y-4 text-sm text-gray-400">
          <div>
            <h3 className="font-medium mb-2">Scan a repository</h3>
            <CodeBlock>autopov scan https://github.com/user/repo.git</CodeBlock>
          </div>
          <div>
            <h3 className="font-medium mb-2">Scan a local directory</h3>
            <CodeBlock>autopov scan /path/to/code --model anthropic/claude-opus-4.6</CodeBlock>
          </div>
          <div>
            <h3 className="font-medium mb-2">Scan pasted code</h3>
            <CodeBlock>cat vulnerable.py | autopov paste --language python</CodeBlock>
          </div>
          <div>
            <h3 className="font-medium mb-2">View scan results</h3>
            <CodeBlock>autopov results {'{scan_id}'} --output table</CodeBlock>
          </div>
        </div>
      </Section>

      <Section icon={FileCode} title="Discovery and Classification">
        <div className="space-y-3 text-sm text-gray-400 leading-6">
          <p>
            Discovery combines CodeQL, Semgrep, heuristic scouting, and optional AI scouting. These tools generate
            candidate findings without requiring the user to preselect CWE categories.
          </p>
          <p>
            Classification happens after discovery. Known issues can be mapped to CWE/CVE when the evidence supports it.
            Novel or unmapped issues remain unclassified and can still be investigated and proven.
          </p>
          <p>
            Proof generation and validation are the decisive stages. A finding is strongest when the system can produce
            a working exploit or another concrete confirmation signal.
          </p>
        </div>
      </Section>
    </div>
  )
}
