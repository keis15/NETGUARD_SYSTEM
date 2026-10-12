import { NavLink, Navigate, Route, Routes } from 'react-router-dom'
import { api } from './api.js'
import { Icon, StatusDot } from './components.jsx'
import { usePoll } from './hooks.js'
import Dashboard from './pages/Dashboard.jsx'
import Devices from './pages/Devices.jsx'
import NetworkScan from './pages/NetworkScan.jsx'
import WebsiteActivity from './pages/WebsiteActivity.jsx'
import AccessControl from './pages/AccessControl.jsx'
import Reports from './pages/Reports.jsx'
import Settings from './pages/Settings.jsx'

const NAV = [
  ['/', 'Dashboard', 'dashboard'],
  ['/devices', 'Devices', 'devices'],
  ['/scan', 'Network Scan', 'scan'],
  ['/activity', 'Website Activity', 'activity'],
  ['/access', 'Access Control', 'lock'],
  ['/reports', 'Reports', 'reports'],
  ['/settings', 'Settings', 'settings'],
]

export default function App() {
  const { data: scan, error } = usePoll(() => api.get('/scan/status'), 5000)
  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-logo"><Icon name="wifi" size={20} /></div>
          <div>
            <div className="brand-name">NetGuard</div>
            <div className="brand-sub">Home network monitor</div>
          </div>
        </div>
        {NAV.map(([to, label, icon]) => (
          <NavLink key={to} to={to} end={to === '/'} className="nav-link">
            <Icon name={icon} /> {label}
          </NavLink>
        ))}
        <div className="sidebar-foot">
          <div className="row">
            <StatusDot state={error ? 'err' : true} /> {error ? 'Backend offline' : 'Backend connected'}
          </div>
          {scan && (
            <div className="row">
              <StatusDot state={scan.running ? 'warn' : true} pulse={scan.running} />
              {scan.running ? 'Scanning…' : scan.auto_scan ? 'Auto-scan on' : 'Auto-scan off'}
            </div>
          )}
        </div>
      </aside>
      <main className="main">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/devices" element={<Devices />} />
          <Route path="/scan" element={<NetworkScan />} />
          <Route path="/activity" element={<WebsiteActivity />} />
          <Route path="/access" element={<AccessControl />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/settings" element={<Settings />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </main>
    </div>
  )
}
