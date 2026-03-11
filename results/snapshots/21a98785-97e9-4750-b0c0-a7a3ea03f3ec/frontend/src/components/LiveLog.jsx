import { useEffect, useRef } from 'react'
import { Terminal } from 'lucide-react'

function LiveLog({ logs }) {
  const logEndRef = useRef(null)

  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs])

  const formatLog = (log) => {
    // Extract timestamp if present
    const match = log.match(/^\[(.*?)\] (.*)$/)
    if (match) {
      return {
        timestamp: match[1],
        message: match[2]
      }
    }
    return { timestamp: null, message: log }
  }

  return (
    <div className="bg-gray-900 rounded-lg border border-gray-800 overflow-hidden">
      <div className="flex items-center space-x-2 px-4 py-3 border-b border-gray-800 bg-gray-850">
        <Terminal className="w-5 h-5 text-primary-500" />
        <span className="font-medium">Live Logs</span>
      </div>
      
      <div className="h-96 overflow-y-auto p-4 font-mono text-sm">
        {logs.length === 0 ? (
          <p className="text-gray-500 italic">Waiting for scan to start...</p>
        ) : (
          <div className="space-y-1">
            {logs.map((log, index) => {
              const { timestamp, message } = formatLog(log)
              return (
                <div key={index} className="log-entry flex space-x-3">
                  {timestamp && (
                    <span className="text-gray-500 text-xs shrink-0">
                      {new Date(timestamp).toLocaleTimeString()}
                    </span>
                  )}
                  <span className={`${
                    message.includes('Error') || message.includes('Failed')
                      ? 'text-red-400'
                      : message.includes('Success') || message.includes('confirmed')
                      ? 'text-green-400'
                      : message.includes('VULNERABILITY TRIGGERED')
                      ? 'text-red-500 font-bold'
                      : 'text-gray-300'
                  }`}>
                    {message}
                  </span>
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
