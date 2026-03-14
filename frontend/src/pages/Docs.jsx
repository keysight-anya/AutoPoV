import { FileText, Code, Terminal, Shield } from 'lucide-react'

function Docs() {
  const apiBase = (import.meta.env.VITE_API_URL || 'http://localhost:8000/api').replace(/\/$/, '')
  return (
    <div className="max-w-4xl mx-auto">
      {/* Header */}
      <div className="flex items-center space-x-3 mb-6">
        <FileText className="w-8 h-8 text-primary-500" />
        <h1 className="text-2xl font-bold">Documentation</h1>
      </div>

      <div className="space-y-8">
        {/* Overview */}
        <section className="bg-gray-900 rounded-lg border border-gray-800 p-6">
          <div className="flex items-center space-x-2 mb-4">
            <Shield className="w-5 h-5 text-primary-500" />
            <h2 className="text-lg font-medium">Overview</h2>
          </div>
          <p className="text-gray-400 leading-relaxed">
            AutoPoV is an autonomous vulnerability detection framework that combines static analysis 
            with AI-powered reasoning to identify and verify security vulnerabilities in code. It uses 
            LangGraph-based agents to orchestrate the detection workflow, from code ingestion to 
            Proof-of-Vulnerability (PoV) generation and execution.
          </p>
        </section>

        {/* API Reference */}
        <section className="bg-gray-900 rounded-lg border border-gray-800 p-6">
          <div className="flex items-center space-x-2 mb-4">
            <Code className="w-5 h-5 text-primary-500" />
            <h2 className="text-lg font-medium">API Reference</h2>
          </div>

          <div className="space-y-4">
            <div>
              <h3 className="font-medium text-green-400 mb-2">POST /api/scan/git</h3>
              <p className="text-sm text-gray-400 mb-2">Scan a Git repository</p>
              <pre className="bg-gray-950 p-3 rounded-lg overflow-x-auto">
                <code className="text-sm">
{`{
  "url": "https://github.com/user/repo.git",
  "branch": "main",
  "model": "openrouter/auto"
}`}
                </code>
              </pre>
            </div>

            <div>
              <h3 className="font-medium text-green-400 mb-2">POST /api/scan/zip</h3>
              <p className="text-sm text-gray-400 mb-2">Upload and scan a ZIP file</p>
              <p className="text-sm text-gray-500">Multipart form data with file and optional model override</p>
            </div>

            <div>
              <h3 className="font-medium text-green-400 mb-2">POST /api/scan/paste</h3>
              <p className="text-sm text-gray-400 mb-2">Scan pasted code</p>
              <pre className="bg-gray-950 p-3 rounded-lg overflow-x-auto">
                <code className="text-sm">
{`{
  "code": "def vulnerable(): ...",
  "language": "python",
  "model": "openrouter/auto"
}`}
                </code>
              </pre>
            </div>

            <div>
              <h3 className="font-medium text-blue-400 mb-2">GET /api/scan/&#123;scan_id&#125;</h3>
              <p className="text-sm text-gray-400">Get scan status and results</p>
            </div>

            <div>
              <h3 className="font-medium text-blue-400 mb-2">GET /api/scan/&#123;scan_id&#125;/stream</h3>
              <p className="text-sm text-gray-400">Stream live logs via Server-Sent Events</p>
            </div>

            <div>
              <h3 className="font-medium text-blue-400 mb-2">GET /api/history</h3>
              <p className="text-sm text-gray-400">Get scan history</p>
            </div>

            <div>
              <h3 className="font-medium text-purple-400 mb-2">GET /api/report/&#123;scan_id&#125;</h3>
              <p className="text-sm text-gray-400">Download scan report (JSON or PDF)</p>
            </div>
          </div>
        </section>

        {/* CLI Reference */}
        <section className="bg-gray-900 rounded-lg border border-gray-800 p-6">
          <div className="flex items-center space-x-2 mb-4">
            <Terminal className="w-5 h-5 text-primary-500" />
            <h2 className="text-lg font-medium">CLI Reference</h2>
          </div>

          <div className="space-y-4">
            <div>
              <h3 className="font-medium mb-2">Scan a repository</h3>
              <pre className="bg-gray-950 p-3 rounded-lg overflow-x-auto">
                <code className="text-sm text-green-400">
                  autopov scan https://github.com/user/repo.git
                </code>
              </pre>
            </div>

            <div>
              <h3 className="font-medium mb-2">Scan a local directory</h3>
              <pre className="bg-gray-950 p-3 rounded-lg overflow-x-auto">
                <code className="text-sm text-green-400">
                  autopov scan /path/to/code --model anthropic/claude-opus-4.6
                </code>
              </pre>
            </div>

            <div>
              <h3 className="font-medium mb-2">View scan results</h3>
              <pre className="bg-gray-950 p-3 rounded-lg overflow-x-auto">
                <code className="text-sm text-green-400">
                  autopov results &#123;scan_id&#125; --output table
                </code>
              </pre>
            </div>

            <div>
              <h3 className="font-medium mb-2">Generate API key</h3>
              <pre className="bg-gray-950 p-3 rounded-lg overflow-x-auto">
                <code className="text-sm text-green-400">
                  autopov keys generate --admin-key &#123;admin_key&#125;
                </code>
              </pre>
            </div>
          </div>
        </section>

        <section className="bg-gray-900 rounded-lg border border-gray-800 p-6">
          <h2 className="text-lg font-medium mb-4">Discovery and Classification</h2>
          <div className="space-y-3 text-sm text-gray-400">
            <p>The scanner does not require predefined CWE input. It performs open-ended discovery, investigates candidate issues, and then maps them to a known CWE/CVE only when the evidence supports that classification.</p>
            <p>If a real vulnerability does not cleanly match an existing taxonomy entry, it is preserved as an unclassified finding and the system can still attempt to generate and validate proof for it.</p>
          </div>
        </section>

        {/* Links */}
        <section className="bg-gray-900 rounded-lg border border-gray-800 p-6">
          <h2 className="text-lg font-medium mb-4">Links</h2>
          <div className="flex space-x-4">
            <a
              href={`${apiBase}/docs`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary-500 hover:text-primary-400"
            >
              Swagger UI →
            </a>
            <a
              href={`${apiBase}/openapi.json`}
              target="_blank"
              rel="noopener noreferrer"
              className="text-primary-500 hover:text-primary-400"
            >
              OpenAPI JSON →
            </a>
          </div>
        </section>
      </div>
    </div>
  )
}

export default Docs
