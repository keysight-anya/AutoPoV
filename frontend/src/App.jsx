import { Routes, Route } from 'react-router-dom'
import NavBar from './components/NavBar'
import Home from './pages/Home'
import ScanProgress from './pages/ScanProgress'
import Results from './pages/Results'
import History from './pages/History'
import Settings from './pages/Settings'
import Docs from './pages/Docs'
import Policy from './pages/Policy'
import Metrics from './pages/Metrics'

function App() {
  return (
    <div className="min-h-screen bg-gray-950 text-gray-100" style={{ fontFamily: '"JetBrains Mono", monospace' }}>
      <NavBar />
      {/* Thin violet glow under nav */}
      <div className="h-px bg-primary-600/10" />
      <main className="container mx-auto max-w-7xl px-6 py-10">
        <Routes>
          <Route path="/"                element={<Home />} />
          <Route path="/scan/:scanId"    element={<ScanProgress />} />
          <Route path="/results/:scanId" element={<Results />} />
          <Route path="/history"         element={<History />} />
          <Route path="/settings"        element={<Settings />} />
          <Route path="/docs"            element={<Docs />} />
          <Route path="/policy"          element={<Policy />} />
          <Route path="/metrics"         element={<Metrics />} />
        </Routes>
      </main>
    </div>
  )
}

export default App
