// frontend/src/pages/Docs.jsx
const apiBase = (import.meta.env.VITE_API_URL || 'http://localhost:8000/api').replace(/\/$/, '')

export default function Docs() {

  const monoStyle = { fontFamily: '"JetBrains Mono", monospace' }

  const sectionStyle = {
    background: 'var(--surface1)',
    border: '1px solid var(--border1)',
    borderLeft: '3px solid var(--accent)',
    padding: '20px 24px',
    marginBottom: 16,
  }

  const h2Style = {
    ...monoStyle,
    fontSize: 9,
    letterSpacing: '.16em',
    color: 'var(--text3)',
    marginBottom: 16,
  }

  const h3Style = {
    ...monoStyle,
    fontSize: 12,
    color: 'var(--accent)',
    marginBottom: 6,
    fontWeight: 600,
  }

  const h3BlueStyle = {
    ...h3Style,
    color: '#60a5fa',
  }

  const h3PurpleStyle = {
    ...h3Style,
    color: '#c084fc',
  }

  const bodyStyle = {
    fontSize: 12,
    color: 'var(--text2)',
    lineHeight: 1.7,
    marginBottom: 0,
  }

  const preStyle = {
    background: 'var(--surface2)',
    border: '1px solid var(--border1)',
    padding: '10px 14px',
    overflowX: 'auto',
    marginBottom: 0,
    marginTop: 6,
  }

  const codeStyle = {
    ...monoStyle,
    fontSize: 11,
    color: '#86efac',
  }

  const cweCardStyle = {
    background: 'var(--surface2)',
    border: '1px solid var(--border1)',
    padding: '14px 16px',
  }

  return (
    <div style={{ padding: 24, maxWidth: 760 }}>
      {/* Page label */}
      <div style={{ ...monoStyle, fontSize: 9, letterSpacing: '.18em', color: 'var(--text3)', marginBottom: 20 }}>
        [ DOCUMENTATION ]
      </div>

      {/* Overview */}
      <div style={sectionStyle}>
        <div style={h2Style}>OVERVIEW</div>
        <p style={bodyStyle}>
          AutoPoV is an autonomous vulnerability detection framework that combines static analysis
          with AI-powered reasoning to identify and verify security vulnerabilities in code. It uses
          LangGraph-based agents to orchestrate the detection workflow, from code ingestion to
          Proof-of-Vulnerability (PoV) generation and execution.
        </p>
      </div>

      {/* API Reference */}
      <div style={sectionStyle}>
        <div style={h2Style}>API REFERENCE</div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <div style={h3Style}>POST /api/scan/git</div>
            <p style={{ ...bodyStyle, marginBottom: 6 }}>Scan a Git repository</p>
            <pre style={preStyle}>
              <code style={codeStyle}>{`{
  "url": "https://github.com/user/repo.git",
  "branch": "main",
<<<<<<< HEAD
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
=======
  "model": "openai/gpt-4o",
  "cwes": ["CWE-89", "CWE-119"]
}`}</code>
            </pre>
          </div>

          <div>
            <div style={h3Style}>POST /api/scan/zip</div>
            <p style={{ ...bodyStyle, marginBottom: 4 }}>Upload and scan a ZIP file</p>
            <p style={{ ...bodyStyle, color: 'var(--text3)', fontSize: 11 }}>Multipart form data with file, model, and cwes fields</p>
          </div>
>>>>>>> origin/sandbox/ui-overhaul

          <div>
            <div style={h3Style}>POST /api/scan/paste</div>
            <p style={{ ...bodyStyle, marginBottom: 6 }}>Scan pasted code</p>
            <pre style={preStyle}>
              <code style={codeStyle}>{`{
  "code": "def vulnerable(): ...",
  "language": "python",
<<<<<<< HEAD
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
=======
  "model": "openai/gpt-4o",
  "cwes": ["CWE-89"]
}`}</code>
            </pre>
          </div>

          <div>
            <div style={h3BlueStyle}>GET /api/scan/&#123;scan_id&#125;</div>
            <p style={bodyStyle}>Get scan status and results</p>
>>>>>>> origin/sandbox/ui-overhaul
          </div>

<<<<<<< HEAD
        <section className="bg-gray-900 rounded-lg border border-gray-800 p-6">
          <h2 className="text-lg font-medium mb-4">Discovery and Classification</h2>
          <div className="space-y-3 text-sm text-gray-400">
            <p>The scanner does not require predefined CWE input. It performs open-ended discovery, investigates candidate issues, and then maps them to a known CWE/CVE only when the evidence supports that classification.</p>
            <p>If a real vulnerability does not cleanly match an existing taxonomy entry, it is preserved as an unclassified finding and the system can still attempt to generate and validate proof for it.</p>
=======
          <div>
            <div style={h3BlueStyle}>GET /api/scan/&#123;scan_id&#125;/stream</div>
            <p style={bodyStyle}>Stream live logs via Server-Sent Events</p>
>>>>>>> origin/sandbox/ui-overhaul
          </div>

          <div>
            <div style={h3BlueStyle}>GET /api/history</div>
            <p style={bodyStyle}>Get scan history</p>
          </div>

          <div>
            <div style={h3PurpleStyle}>GET /api/report/&#123;scan_id&#125;</div>
            <p style={bodyStyle}>Download scan report (JSON or PDF)</p>
          </div>
        </div>
      </div>

      {/* CLI Reference */}
      <div style={sectionStyle}>
        <div style={h2Style}>CLI REFERENCE</div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div>
            <div style={{ ...monoStyle, fontSize: 11, color: 'var(--text2)', marginBottom: 6, fontWeight: 600 }}>Scan a repository</div>
            <pre style={preStyle}>
              <code style={codeStyle}>autopov scan https://github.com/user/repo.git --model openai/gpt-4o</code>
            </pre>
          </div>

          <div>
            <div style={{ ...monoStyle, fontSize: 11, color: 'var(--text2)', marginBottom: 6, fontWeight: 600 }}>Scan a local directory</div>
            <pre style={preStyle}>
              <code style={codeStyle}>autopov scan /path/to/code --model anthropic/claude-3.5-sonnet</code>
            </pre>
          </div>

          <div>
            <div style={{ ...monoStyle, fontSize: 11, color: 'var(--text2)', marginBottom: 6, fontWeight: 600 }}>View scan results</div>
            <pre style={preStyle}>
              <code style={codeStyle}>autopov results &#123;scan_id&#125; --output table</code>
            </pre>
          </div>

          <div>
            <div style={{ ...monoStyle, fontSize: 11, color: 'var(--text2)', marginBottom: 6, fontWeight: 600 }}>Generate API key</div>
            <pre style={preStyle}>
              <code style={codeStyle}>autopov keys generate --admin-key &#123;admin_key&#125;</code>
            </pre>
          </div>
        </div>
      </div>

      {/* Supported CWEs */}
      <div style={sectionStyle}>
        <div style={h2Style}>SUPPORTED CWE CLASSES</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 10 }}>
          <div style={cweCardStyle}>
            <div style={{ ...monoStyle, fontSize: 12, color: '#f87171', marginBottom: 6, fontWeight: 600 }}>CWE-119</div>
            <div style={{ ...monoStyle, fontSize: 11, color: 'var(--text2)', marginBottom: 4 }}>Buffer Overflow</div>
            <div style={{ ...monoStyle, fontSize: 10, color: 'var(--text3)' }}>Improper restriction of operations within the bounds of a memory buffer</div>
          </div>

          <div style={cweCardStyle}>
            <div style={{ ...monoStyle, fontSize: 12, color: '#f87171', marginBottom: 6, fontWeight: 600 }}>CWE-89</div>
            <div style={{ ...monoStyle, fontSize: 11, color: 'var(--text2)', marginBottom: 4 }}>SQL Injection</div>
            <div style={{ ...monoStyle, fontSize: 10, color: 'var(--text3)' }}>Improper neutralization of special elements in SQL commands</div>
          </div>

          <div style={cweCardStyle}>
            <div style={{ ...monoStyle, fontSize: 12, color: 'var(--accent)', marginBottom: 6, fontWeight: 600 }}>CWE-416</div>
            <div style={{ ...monoStyle, fontSize: 11, color: 'var(--text2)', marginBottom: 4 }}>Use After Free</div>
            <div style={{ ...monoStyle, fontSize: 10, color: 'var(--text3)' }}>Use of memory after it has been freed</div>
          </div>

          <div style={cweCardStyle}>
            <div style={{ ...monoStyle, fontSize: 12, color: '#facc15', marginBottom: 6, fontWeight: 600 }}>CWE-190</div>
            <div style={{ ...monoStyle, fontSize: 11, color: 'var(--text2)', marginBottom: 4 }}>Integer Overflow</div>
            <div style={{ ...monoStyle, fontSize: 10, color: 'var(--text3)' }}>Integer overflow or wraparound</div>
          </div>
        </div>
      </div>

      {/* Links */}
      <div style={sectionStyle}>
        <div style={h2Style}>LINKS</div>
        <div style={{ display: 'flex', gap: 20 }}>
          <a
            href={`${apiBase}/docs`}
            target="_blank"
            rel="noopener noreferrer"
            style={{ ...monoStyle, fontSize: 11, color: 'var(--accent)', textDecoration: 'none' }}
          >
            Swagger UI →
          </a>
          <a
            href={`${apiBase}/openapi.json`}
            target="_blank"
            rel="noopener noreferrer"
            style={{ ...monoStyle, fontSize: 11, color: 'var(--accent)', textDecoration: 'none' }}
          >
            OpenAPI JSON →
          </a>
        </div>
      </div>
    </div>
  )
}
