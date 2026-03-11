import { Routes, Route } from 'react-router-dom'
import NavBar from './components/NavBar'
import Home from './pages/Home'
import ScanProgress from './pages/ScanProgress'
import Results from './pages/Results'
import History from './pages/History'
import Settings from './pages/Settings'
import Docs from './pages/Docs'
import Policy from './pages/Policy'

function App() {
  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <NavBar />
      <main className="container mx-auto px-4 py-8">
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/scan/:scanId" element={<ScanProgress />} />
          <Route path="/results/:scanId" element={<Results />} />
          <Route path="/history" element={<History />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="/docs" element={<Docs />} />
          <Route path="/policy" element={<Policy />} />
        </Routes>
      </main>
    </div>
  )
}

export default App
