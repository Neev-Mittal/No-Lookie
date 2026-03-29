import { useState, useEffect } from 'react'
import {
  Globe, Layers, Server, AlertTriangle, ShieldOff,
  Plus, RefreshCw, Search, ChevronDown
} from 'lucide-react'
import {
  BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer, Legend
} from 'recharts'

import dataAPI from '../dataAPI'

const ICON_MAP = {
  Layers, Globe, Server, AlertTriangle, ShieldOff
}

const riskColor = { High: 'risk-high', Medium: 'risk-medium', Low: 'risk-low', Critical: 'risk-critical', Unknown: 'bg-gray-500' }
const certColor  = { Valid: 'text-green-600', Expiring: 'text-amber-500', Expired: 'text-red-600', Unknown: 'text-gray-500' }

const recentActivity = [
  { icon: '⊗', text: 'Fail scan completed: 125 assets',       time: '10 min ago', color: 'text-red-500'   },
  { icon: '⚠', text: 'Weak cipher detected: vpn.pnb.bank.in', time: '1 hr ago',   color: 'text-amber-500' },
  { icon: '⊠', text: 'Certificate expiring soon: api.pnb.in', time: '3 hrs ago', color: 'text-orange-500' },
  { icon: '✦', text: 'New asset discovered: test.pnb.in',     time: '1 day ago',  color: 'text-blue-500'  },
  { icon: '⚙', text: 'NCKY asset migrated',                   time: '2 days ago', color: 'text-green-500' },
]

export default function Home() {
  const [searchQuery, setSearchQuery] = useState('')
  const [statCards, setStatCards] = useState([])
  const [assetTypeDist, setAssetTypeDist] = useState([])
  const [riskDist, setRiskDist] = useState([])
  const [certExpiry, setCertExpiry] = useState([])
  const [ipBreakdown, setIpBreakdown] = useState([])
  const [inventoryData, setInventoryData] = useState([])
  const [dnsRecords, setDnsRecords] = useState([])
  const [cryptoOverview, setCryptoOverview] = useState([])

  useEffect(() => {
    const fetchDashboardState = async () => {
      try {
        const res = await dataAPI.getDashboardData();
        if (res.success) {
          setStatCards(res.statCards.map(c => ({
            ...c, icon: ICON_MAP[c.icon] || Server
          })));
          setAssetTypeDist(res.assetTypeDist);
          setRiskDist(res.riskDist);
          setCertExpiry(res.certExpiry);
          setIpBreakdown(res.ipBreakdown);
        }

        const invRes = await dataAPI.getSubdomains();
        if (invRes.success && invRes.subdomains) {
          setInventoryData(invRes.subdomains.slice(0, 5).map(s => ({
            name: s.fqdn,
            url: `https://${s.fqdn}`,
            ipv4: s.ips?.[0] || '-',
            type: s.type === 'domain' ? 'Web App' : (s.type || 'Unknown'),
            owner: 'IT',
            risk: 'Medium',
            cert: 'Unknown',
            keyLen: '-',
            scan: new Date(s.resolvedAt).toLocaleDateString()
          })));
        }

        const extRes = await dataAPI.getHomepageExtras();
        if (extRes.success) {
          setDnsRecords(extRes.dnsRecords);
          setCryptoOverview(extRes.cryptoOverview);
        }
      } catch (err) {
        console.error('Failed fetching home dashboard stats:', err);
      }
    };
    fetchDashboardState();
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
        {/* Asset DNS Records */}
        <div className="glass-card rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-amber-100 flex items-center justify-between">
            <h3 className="font-display text-xs font-semibold text-pnb-crimson uppercase tracking-wide">
              Asset DNS Records
            </h3>
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-gray-500 font-body">Domain:</span>
              <span className="text-xs font-display font-semibold text-pnb-crimson">pnb.bank.in</span>
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
              {dnsRecords.map((r, i) => (
                <tr key={i} className={i % 2 === 0 ? 'table-row-even' : 'table-row-odd'}>
                  <td className="px-3 py-1.5 font-mono text-gray-700 truncate max-w-36" title={r.hostname}>
                    {r.hostname}
                  </td>
                  <td className="px-3 py-1.5">
                    <span className="bg-blue-100 text-blue-700 text-xs font-display font-bold px-1.5 py-0.5 rounded">
                      {r.type}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 font-mono text-gray-700">{r.ip}</td>
                  <td className="px-3 py-1.5 text-gray-500">{r.ttl}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Crypto & Security Overview */}
        <div className="glass-card rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-amber-100">
            <h3 className="font-display text-xs font-semibold text-pnb-crimson uppercase tracking-wide">
              Crypto &amp; Security Overview
            </h3>
          </div>
          <table className="w-full text-xs font-body">
            <thead>
              <tr className="bg-amber-50">
                {['Asset','Key','PQC Posture','TLS'].map(h => (
                  <th key={h} className="px-3 py-2 text-left font-display font-semibold text-pnb-crimson">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {cryptoOverview.map((row, i) => (
                <tr key={i} className={i % 2 === 0 ? 'table-row-even' : 'table-row-odd'}>
                  <td className="px-3 py-1.5 text-gray-700 truncate max-w-24" title={row.asset}>
                    {row.asset.split('.')[0]}
                  </td>
                  <td className="px-3 py-1.5">
                    <span className={`font-mono text-xs font-bold ${
                      row.keyLen === 'N/A' ? 'text-gray-400' :
                      row.keyLen.startsWith('1024') ? 'text-red-600' : 'text-blue-600'
                    }`}>{row.keyLen}</span>
                  </td>
                  <td className="px-3 py-1.5 font-mono text-gray-600 text-xs truncate max-w-28">
                    <span className={row.cipherIsWeak ? 'bg-red-100 text-red-700 px-1 rounded' : 'bg-green-100 text-green-700 px-1 rounded'}>
                      {row.cipher.length > 18 ? row.cipher.substring(0, 18) + '…' : row.cipher}
                    </span>
                  </td>
                  <td className="px-3 py-1.5">
                    <span className={`font-display font-bold text-xs ${row.tlsColor}`}>
                      {row.tls}
                    </span>
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
