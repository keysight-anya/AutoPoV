// frontend/src/App.jsx
import { Routes, Route } from 'react-router-dom'
import AppShell from './components/AppShell'
import Home from './pages/Home'
import ScanProgress from './pages/ScanProgress'
import Results from './pages/Results'
import History from './pages/History'
import Settings from './pages/Settings'
import Docs from './pages/Docs'
import Policy from './pages/Policy'

function App() {
  return (
    <Routes>
      <Route element={<AppShell />}>
        <Route path="/"                  element={<Home />} />
        <Route path="/scan/:scanId"      element={<ScanProgress />} />
        <Route path="/results/:scanId"   element={<Results />} />
        <Route path="/history"           element={<History />} />
        <Route path="/settings"          element={<Settings />} />
        <Route path="/docs"              element={<Docs />} />
        <Route path="/policy"            element={<Policy />} />
      </Route>
    </Routes>
  )
}

export default App
