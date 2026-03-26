import { useState, useEffect } from 'react'
import {
  Globe, Layers, Server, AlertTriangle, ShieldOff,
  Plus, RefreshCw, Search, ChevronDown
} from 'lucide-react'
import {
  BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend
} from 'recharts'

const defaultStatCards = [
  { label: 'Total Assets',          value: 0,  icon: Layers,      color: '#1d4ed8', bg: 'bg-blue-50'   },
  { label: 'Public Web Apps',       value: 0,   icon: Globe,       color: '#16a34a', bg: 'bg-green-50'  },
  { label: 'APIs',                   value: 0,   icon: Server,      color: '#7c3aed', bg: 'bg-purple-50' },
  { label: 'Servers',               value: 0,   icon: Server,      color: '#0891b2', bg: 'bg-cyan-50'   },
  { label: 'Expiring Certificates', value: 0,    icon: AlertTriangle,color:'#d97706', bg: 'bg-amber-50', alert: true },
  { label: 'High Risk Assets',      value: 0,   icon: ShieldOff,   color: '#dc2626', bg: 'bg-red-50',   critical: true },
]

const assetTypeDist = [
  { name: 'Web Apps',      value: 42,  color: '#3b82f6' },
  { name: 'APIs',          value: 26,  color: '#6366f1' },
  { name: 'Servers',       value: 37,  color: '#22c55e' },
  { name: 'Load Balancers',value: 11,  color: '#f59e0b' },
  { name: 'Other',         value: 12,  color: '#94a3b8' },
]

const riskDist = [
  { name: 'Critical', count: 5  },
  { name: 'High',     count: 9  },
  { name: 'Medium',   count: 34 },
  { name: 'Low',      count: 80 },
]

const certExpiry = [
  { label: '0–30 Days',  count: 3,  color: '#dc2626' },
  { label: '30–60 Days', count: 4,  color: '#f59e0b' },
  { label: '60–90 Days', count: 2,  color: '#22c55e' },
  { label: '>90 Days',   count: 84, color: '#3b82f6' },
]

const ipBreakdown = [
  { name: 'IPv4 86%', value: 86, color: '#1d4ed8' },
  { name: 'IPv6 14%', value: 14, color: '#60a5fa' },
]

const inventoryData = [
  { name: 'portal.company.com', url: 'https://portal.company.com', ipv4: '34.12.11.45', type: 'Web App', owner: 'IT',     risk: 'High',   cert: 'Valid',    keyLen: '2048-bit', scan: '2 hrs ago' },
  { name: 'api.company.com',    url: 'https://api.company.com',    ipv4: '34.12.11.90', type: 'API',     owner: 'DevOps', risk: 'Medium', cert: 'Expiring', keyLen: '4096-bit', scan: '5 hrs ago' },
  { name: 'vpn.company.com',    url: 'https://vpn.company.com',    ipv4: '34.55.90.21', type: 'Gateway', owner: 'IT',     risk: 'Critical',cert: 'Expired', keyLen: '1024-bit', scan: '1 hr ago'  },
  { name: 'mail.company.com',   url: 'https://mail.company.com',   ipv4: '35.11.44.10', type: 'Server',  owner: 'IT',     risk: 'Low',    cert: 'Valid',    keyLen: '3072-bit', scan: '1 day ago' },
  { name: 'app.company.com',    url: 'https://app.company.com',    ipv4: '34.77.21.12', type: 'Web App', owner: 'IT',     risk: 'Medium', cert: 'Valid',    keyLen: '2048-bit', scan: '5 days ago'},
]

const riskColor = { High: 'risk-high', Medium: 'risk-medium', Low: 'risk-low', Critical: 'risk-critical' }
const certColor  = { Valid: 'text-green-600', Expiring: 'text-amber-500', Expired: 'text-red-600' }

const recentActivity = [
  { icon: '⊗', text: 'Fail scan completed: 125 assets',       time: '10 min ago', color: 'text-red-500'   },
  { icon: '⚠', text: 'Weak cipher detected: vpn.company.com', time: '1 hr ago',   color: 'text-amber-500' },
  { icon: '⊠', text: 'Certificate expiring soon: api.company.com', time: '3 hrs ago', color: 'text-orange-500' },
  { icon: '✦', text: 'New asset discovered: dev-api.company.com',  time: '1 day ago',  color: 'text-blue-500'  },
  { icon: '⚙', text: 'NCKY asset & migrated',                 time: '2 days ago', color: 'text-green-500' },
]

export default function Home() {
  const [searchQuery, setSearchQuery] = useState('')
  const [statCards, setStatCards] = useState(defaultStatCards)

  useEffect(() => {
    // Fetch statistics from API
    fetch('http://localhost:8001/api/statistics')
      .then(res => res.json())
      .then(data => {
        if (data.success && data.assets) {
          const updatedCards = [...defaultStatCards]
          updatedCards[0].value = data.assets.total || 0  // Total Assets
          updatedCards[1].value = data.assets.web_apps || 0 // Public Web Apps
          updatedCards[2].value = data.assets.apis || 0     // APIs
          updatedCards[3].value = data.assets.servers || 0  // Servers
          updatedCards[4].value = data.findings?.expiring_certs || 0 // Expiring Certs
          updatedCards[5].value = data.findings?.by_severity?.high || 0  // High Risk
          setStatCards(updatedCards)
        }
      })
      .catch(err => console.error('Failed to fetch statistics:', err))
  }, [])

  return (
    <div className="space-y-5">
      {/* STAT CARDS */}
      <div className="grid grid-cols-6 gap-3">
        {statCards.map(({ label, value, icon: Icon, color, bg, alert, critical }) => (
          <div key={label}
            className={`stat-card glass-card rounded-xl p-4 cursor-pointer
              ${critical ? 'border-red-300 shadow-red-100' : 'border-amber-100'}
              ${alert ? 'border-amber-300' : ''}`}
          >
            <div className="flex items-start justify-between mb-2">
              <div className={`p-2 rounded-lg ${bg}`}>
                <Icon size={16} style={{ color }} />
              </div>
              {critical && <span className="w-2 h-2 bg-red-500 rounded-full badge-critical" />}
              {alert && <span className="w-2 h-2 bg-amber-500 rounded-full badge-critical" />}
            </div>
            <p className="font-display text-2xl font-bold" style={{ color }}>{value}</p>
            <p className="font-body text-xs text-gray-500 mt-0.5 leading-tight">{label}</p>
          </div>
        ))}
      </div>

      {/* CHARTS ROW */}
      <div className="grid grid-cols-4 gap-4">
        {/* Asset Type Distribution */}
        <div className="glass-card rounded-xl p-4 col-span-1">
          <h3 className="font-display text-xs font-semibold text-pnb-crimson uppercase tracking-wide mb-3">
            Asset Type Distribution
          </h3>
          <ResponsiveContainer width="100%" height={160}>
            <PieChart>
              <Pie data={assetTypeDist} dataKey="value" cx="50%" cy="50%" innerRadius={35} outerRadius={65}>
                {assetTypeDist.map((d, i) => <Cell key={i} fill={d.color} />)}
              </Pie>
              <Tooltip contentStyle={{ fontSize: 11 }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="space-y-1 mt-1">
            {assetTypeDist.map(d => (
              <div key={d.name} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-1.5">
                  <div className="w-2 h-2 rounded-sm" style={{ background: d.color }} />
                  <span className="font-body text-gray-600">{d.name}</span>
                </div>
                <span className="font-display font-bold text-gray-800">{d.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Asset Risk Distribution */}
        <div className="glass-card rounded-xl p-4 col-span-1">
          <h3 className="font-display text-xs font-semibold text-pnb-crimson uppercase tracking-wide mb-3">
            Asset Risk Distribution
          </h3>
          <div className="flex items-end gap-1 mb-2">
            <div className="w-8 h-14 bg-red-600 rounded-sm" title="Critical" />
            <div className="w-8 h-10 bg-orange-500 rounded-sm" title="High" />
            <div className="w-8 h-20 bg-amber-400 rounded-sm" title="Medium" />
            <div className="w-8 h-6 bg-green-500 rounded-sm" title="Low" />
          </div>
          <div className="flex justify-around text-xs font-body text-gray-500">
            {riskDist.map(r => <span key={r.name}>{r.name}</span>)}
          </div>
          {/* High risk badge */}
          <div className="mt-3 flex justify-center">
            <div className="bg-red-600 text-white font-display text-sm font-bold px-4 py-2 rounded-lg w-20 text-center">
              <div>11%</div>
              <div className="text-xs font-normal">High Risk</div>
            </div>
          </div>
        </div>

        {/* Certificate Expiry Timeline */}
        <div className="glass-card rounded-xl p-4 col-span-1">
          <h3 className="font-display text-xs font-semibold text-pnb-crimson uppercase tracking-wide mb-3">
            Certificate Expiry Timeline
          </h3>
          <div className="space-y-2">
            {certExpiry.map(c => (
              <div key={c.label} className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <div className="w-2.5 h-2.5 rounded-sm" style={{ background: c.color }} />
                  <span className="font-body text-xs text-gray-600">{c.label}</span>
                </div>
                <span className="font-display text-sm font-bold text-gray-800">{c.count}</span>
              </div>
            ))}
          </div>
          {/* Bar visual */}
          <div className="mt-3 h-3 rounded-full overflow-hidden flex">
            <div style={{ width: '3%',  background: '#dc2626' }} />
            <div style={{ width: '4%',  background: '#f59e0b' }} />
            <div style={{ width: '2%',  background: '#22c55e' }} />
            <div style={{ width: '91%', background: '#3b82f6' }} />
          </div>
        </div>

        {/* IP Version Breakdown */}
        <div className="glass-card rounded-xl p-4 col-span-1">
          <h3 className="font-display text-xs font-semibold text-pnb-crimson uppercase tracking-wide mb-3">
            IP Version Breakdown
          </h3>
          <ResponsiveContainer width="100%" height={120}>
            <PieChart>
              <Pie data={ipBreakdown} dataKey="value" cx="50%" cy="50%" outerRadius={50}>
                {ipBreakdown.map((d, i) => <Cell key={i} fill={d.color} />)}
              </Pie>
            </PieChart>
          </ResponsiveContainer>
          <div className="text-center -mt-4">
            <p className="font-display text-2xl font-bold text-blue-700">86%</p>
            <p className="font-body text-xs text-gray-500">IPv4</p>
          </div>
          <div className="flex justify-around text-xs mt-2">
            <span className="text-blue-700 font-semibold">■ IPv4 86%</span>
            <span className="text-blue-400 font-semibold">■ IPv6 14%</span>
          </div>
        </div>
      </div>

      {/* ASSET INVENTORY TABLE */}
      <div className="glass-card rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-5 py-3 border-b border-amber-100">
          <h3 className="font-display text-sm font-semibold text-pnb-crimson uppercase tracking-wide">
            Asset Inventory
          </h3>
          <div className="flex items-center gap-2">
            <button className="flex items-center gap-1.5 bg-amber-500 text-white text-xs font-display font-semibold
                               px-3 py-1.5 rounded-lg hover:bg-amber-600 transition-colors">
              <Plus size={12} /> Add Asset <ChevronDown size={12} />
            </button>
            <button className="flex items-center gap-1.5 bg-pnb-crimson text-white text-xs font-display font-semibold
                               px-3 py-1.5 rounded-lg hover:bg-red-800 transition-colors">
              <RefreshCw size={12} /> Scan All
            </button>
            <div className="relative">
              <Search size={12} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-400" />
              <input
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                placeholder="Search..."
                className="pl-8 pr-3 py-1.5 text-xs border border-amber-200 rounded-lg
                           bg-white font-body focus:outline-none focus:ring-1 focus:ring-amber-400 w-36"
              />
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-xs font-body">
            <thead>
              <tr className="bg-amber-50 border-b border-amber-100">
                {['Asset Name','URL','IPV4 Address','Type','Owner','Risk','Cert Status','Key Length','Last Scan'].map(h => (
                  <th key={h} className="px-3 py-2.5 text-left font-display font-semibold text-pnb-crimson text-xs tracking-wide">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {inventoryData
                .filter(r => r.name.includes(searchQuery) || r.type.toLowerCase().includes(searchQuery.toLowerCase()))
                .map((row, i) => (
                <tr key={i} className={i % 2 === 0 ? 'table-row-even' : 'table-row-odd'}>
                  <td className="px-3 py-2.5 text-blue-700 font-semibold">{row.name}</td>
                  <td className="px-3 py-2.5 text-blue-500 underline truncate max-w-32">{row.url}</td>
                  <td className="px-3 py-2.5 font-mono text-gray-700">{row.ipv4}</td>
                  <td className="px-3 py-2.5 text-gray-700">{row.type}</td>
                  <td className="px-3 py-2.5 text-gray-700">{row.owner}</td>
                  <td className="px-3 py-2.5">
                    <span className={`px-2 py-0.5 rounded text-white text-xs font-display font-semibold ${riskColor[row.risk]}`}>
                      {row.risk}
                    </span>
                  </td>
                  <td className={`px-3 py-2.5 font-semibold ${certColor[row.cert]}`}>
                    {row.cert === 'Valid' ? '✓ Valid' : row.cert === 'Expiring' ? '⚠ Expiring' : '✗ Expired'}
                  </td>
                  <td className="px-3 py-2.5 font-mono text-gray-700">{row.keyLen}</td>
                  <td className="px-3 py-2.5 text-gray-500">{row.scan}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* BOTTOM ROW: Nameservers + Crypto Overview + Activity */}
      <div className="grid grid-cols-3 gap-4">
        {/* Nameserver Records */}
        <div className="glass-card rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-amber-100 flex items-center justify-between">
            <h3 className="font-display text-xs font-semibold text-pnb-crimson uppercase tracking-wide">
              Nameserver Records
            </h3>
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-gray-500 font-body">Domain:</span>
              <span className="text-xs font-display font-semibold text-pnb-crimson">Company.Com</span>
              <button className="bg-amber-500 text-white text-xs font-display px-2 py-0.5 rounded ml-1">Resolve</button>
            </div>
          </div>
          <table className="w-full text-xs font-body">
            <thead>
              <tr className="bg-amber-50">
                {['Hostname','Type','IP Address','TTL'].map(h => (
                  <th key={h} className="px-3 py-2 text-left font-display font-semibold text-pnb-crimson">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[
                ['ns1.company.com','NS','192.0.2.10','3600'],
                ['ns2.company.com','NS','192.0.2.11','3600'],
                ['ns3.company.com','NS','192.0.2.12','3600'],
                ['www.company.com','A', '34.12.11.45','300'],
                ['mail.company.com','MX','35.11.44.10','300'],
              ].map(([h, t, ip, ttl], i) => (
                <tr key={i} className={i % 2 === 0 ? 'table-row-even' : 'table-row-odd'}>
                  <td className="px-3 py-1.5 font-mono text-gray-700">{h}</td>
                  <td className="px-3 py-1.5">
                    <span className="bg-blue-100 text-blue-700 text-xs font-display font-bold px-1.5 py-0.5 rounded">
                      {t}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 font-mono text-gray-700">{ip}</td>
                  <td className="px-3 py-1.5 text-gray-500">{ttl}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Crypto & Security Overview */}
        <div className="glass-card rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-amber-100">
            <h3 className="font-display text-xs font-semibold text-pnb-crimson uppercase tracking-wide">
              Crypto & Security Overview
            </h3>
          </div>
          <table className="w-full text-xs font-body">
            <thead>
              <tr className="bg-amber-50">
                {['Asset','Key Length','Cipher Suite','TLS'].map(h => (
                  <th key={h} className="px-3 py-2 text-left font-display font-semibold text-pnb-crimson">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {[
                ['portal.company.com','2038-bit','ECDHE-43A_AE3256-GCM','1.2'],
                ['api.company.com',   '4098-bit','TLS_AES_336-GCM-SHA394','1.3'],
                ['vpn.company.com',   '1024-bit','TLS_PR4_WITH_DES_CEC','1.0'],
                ['mail.company.com',  '3072-bit','ECDHE-ECDSA-AE3756-ECM','1.2'],
                ['app.company.com',   '2048-bit','TLS_AES_728-GCM_SNA256','1.3'],
              ].map(([a, kl, cs, tls], i) => (
                <tr key={i} className={i % 2 === 0 ? 'table-row-even' : 'table-row-odd'}>
                  <td className="px-3 py-1.5 text-gray-700 truncate max-w-20">{a.split('.')[0]}</td>
                  <td className="px-3 py-1.5">
                    <span className={`font-mono text-xs font-bold ${
                      kl.startsWith('1024') ? 'text-red-600' :
                      kl.startsWith('4') ? 'text-green-600' : 'text-blue-600'
                    }`}>{kl}</span>
                  </td>
                  <td className="px-3 py-1.5 font-mono text-gray-600 text-xs truncate max-w-28">
                    <span className={cs.includes('DES') ? 'bg-red-100 text-red-700 px-1 rounded' : ''}>
                      {cs.substring(0, 18)}…
                    </span>
                  </td>
                  <td className="px-3 py-1.5">
                    <span className={`font-display font-bold text-xs ${
                      tls === '1.3' ? 'text-green-600' : tls === '1.0' ? 'text-red-600' : 'text-amber-600'
                    }`}>{tls}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Recent Scans & Activity + Geographic */}
        <div className="glass-card rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-amber-100">
            <h3 className="font-display text-xs font-semibold text-pnb-crimson uppercase tracking-wide">
              Recent Scans & Activity
            </h3>
          </div>
          <div className="p-3 space-y-2">
            {recentActivity.map((a, i) => (
              <div key={i} className="flex items-start gap-2">
                <span className={`${a.color} text-sm flex-shrink-0 mt-0.5`}>{a.icon}</span>
                <div className="flex-1 min-w-0">
                  <p className="font-body text-xs text-gray-700 truncate">{a.text}</p>
                  <p className="font-body text-xs text-gray-400">{a.time}</p>
                </div>
              </div>
            ))}
          </div>
          {/* Geographic mini-map placeholder */}
          <div className="mx-3 mb-3 bg-slate-800 rounded-lg p-2 relative overflow-hidden">
            <p className="font-display text-xs text-amber-300 mb-1">Geographic Distribution</p>
            <div className="flex justify-around text-xs text-white">
              {['🇺🇸 USA','🇩🇪 Germany','🇸🇬 Singapore','🇮🇳 India'].map(g => (
                <span key={g} className="font-body opacity-80">{g}</span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
