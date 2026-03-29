import { useState, useEffect } from 'react'
import { Search, Plus, RefreshCw, Filter, Download, Eye } from 'lucide-react'
import { LoadingSpinner, ErrorAlert, DataEmpty } from '../components/DataLoaders.jsx'
import dataAPI from '../dataAPI.js'

const riskColors = { Critical:'risk-critical', High:'risk-high', Medium:'risk-medium', Low:'risk-low' }
const certIcons  = { Valid:'✓', Expiring:'⚠', Expired:'✗' }
const certColors = { Valid:'text-green-600', Expiring:'text-amber-500', Expired:'text-red-600' }

export default function AssetInventory() {
  const [assets, setAssets] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [search, setSearch]   = useState('')
  const [filter, setFilter]   = useState('All')
  const [selected, setSelected] = useState([])

  useEffect(() => {
    loadAssets()
  }, [])

  const loadAssets = async () => {
    setLoading(true)
    setError(null)
    const result = await dataAPI.getSubdomains(10000)
    
    if (result.success && result.subdomains.length > 0) {
      // Deduplicate by fqdn — same host on multiple ports should show as one entry
      const seenFqdns = new Set()
      const unique = result.subdomains.filter(a => {
        if (seenFqdns.has(a.fqdn)) return false
        seenFqdns.add(a.fqdn)
        return true
      })
      const transformedAssets = unique.map((a, i) => ({
        id: i + 1,
        name: a.fqdn,
        url: `https://${a.fqdn}`,
        ipv4: a.ips?.find(ip => ip.includes('.')) || '-',
        ipv6: a.ips?.find(ip => ip.includes(':')) || '-',
        type: a.type === 'domain' ? 'Web App' : (a.type || 'Unknown'),
        owner: 'IT',
        risk: 'Medium',
        cert: 'Unknown',
        keyLen: '-',
        pqc: false,
        lastScan: a.resolvedAt ? new Date(a.resolvedAt).toLocaleDateString() : 'Unknown',
      }))
      setAssets(transformedAssets)
    } else if (!result.success) {
      setError(result.error || 'Failed to load assets')
    }
    setLoading(false)
  }

  if (loading) return <LoadingSpinner />
  if (error) return <ErrorAlert error={error} onRetry={loadAssets} />
  if (assets.length === 0) return <DataEmpty message="No assets found" />

  const filtered = assets.filter(a => {
    const matchSearch = a.name.toLowerCase().includes(search.toLowerCase()) ||
                        a.type.toLowerCase().includes(search.toLowerCase())
    const matchFilter = filter === 'All' || a.risk === filter || a.type === filter
    return matchSearch && matchFilter
  })

  const toggleSelect = (id) =>
    setSelected(s => s.includes(id) ? s.filter(x => x !== id) : [...s, id])

  const toggleAll = () =>
    setSelected(s => s.length === filtered.length ? [] : filtered.map(a => a.id))

  return (
    <div className="space-y-4">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="font-display text-xl font-bold text-pnb-crimson">Asset Inventory</h1>
          <p className="font-body text-sm text-gray-600 mt-0.5">
            {assets.length} total assets across PNB infrastructure
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button className="flex items-center gap-1.5 text-xs font-display font-semibold
                             bg-white border border-amber-300 text-pnb-amber px-3 py-2 rounded-lg
                             hover:bg-amber-50 transition-colors">
            <Download size={13} /> Export
          </button>
          <button className="flex items-center gap-1.5 text-xs font-display font-semibold
                             bg-pnb-crimson text-white px-3 py-2 rounded-lg hover:bg-red-800 transition-colors">
            <Plus size={13} /> Add Asset
          </button>
        </div>
      </div>

      {/* Filters + Search */}
      <div className="glass-card rounded-xl p-4 flex items-center gap-4">
        <div className="relative flex-1 max-w-sm">
          <Search size={13} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search assets, URLs, types..."
            className="w-full pl-9 pr-4 py-2 text-sm border border-amber-200 rounded-lg
                       bg-white font-body focus:outline-none focus:ring-1 focus:ring-amber-400"
          />
        </div>

        <div className="flex items-center gap-1 font-display text-xs">
          {['All','Critical','High','Medium','Low','Web App','API','Server'].map(f => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-3 py-1.5 rounded-lg font-semibold transition-colors
                ${filter === f
                  ? 'bg-pnb-crimson text-white'
                  : 'bg-white border border-amber-200 text-pnb-amber hover:bg-amber-50'
                }`}
            >
              {f}
            </button>
          ))}
        </div>

        <button className="flex items-center gap-1.5 text-xs font-display font-semibold
                           text-pnb-amber border border-amber-300 bg-white px-3 py-2 rounded-lg
                           hover:bg-amber-50 transition-colors ml-auto">
          <RefreshCw size={12} /> Scan All
        </button>
      </div>

      {/* Table */}
      <div className="glass-card rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs font-body">
            <thead>
              <tr className="bg-gradient-to-r from-pnb-crimson to-red-800 text-white">
                <th className="px-3 py-3 text-left w-8">
                  <input
                    type="checkbox"
                    checked={selected.length === filtered.length && filtered.length > 0}
                    onChange={toggleAll}
                    className="accent-amber-400"
                  />
                </th>
                {['Asset Name','URL','IPV4 Address','IPV6 Address','Type','Owner','Risk','Cert Status','Key Length','PQC','Last Scan','Actions'].map(h => (
                  <th key={h} className="px-3 py-3 text-left font-display font-semibold tracking-wide">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map((row, i) => (
                <tr key={row.id}
                  className={`border-b border-amber-50 hover:bg-amber-50/50 transition-colors
                    ${i % 2 === 0 ? 'bg-white/80' : 'bg-amber-50/40'}`}
                >
                  <td className="px-3 py-2.5">
                    <input
                      type="checkbox"
                      checked={selected.includes(row.id)}
                      onChange={() => toggleSelect(row.id)}
                      className="accent-amber-400"
                    />
                  </td>
                  <td className="px-3 py-2.5 font-semibold text-blue-700 max-w-36 truncate">
                    {row.name}
                  </td>
                  <td className="px-3 py-2.5 text-blue-500 underline cursor-pointer max-w-36 truncate">
                    {row.url}
                  </td>
                  <td className="px-3 py-2.5 font-mono text-gray-700">{row.ipv4}</td>
                  <td className="px-3 py-2.5 font-mono text-gray-500 text-xs">{row.ipv6}</td>
                  <td className="px-3 py-2.5 text-gray-700">{row.type}</td>
                  <td className="px-3 py-2.5 text-gray-700">{row.owner}</td>
                  <td className="px-3 py-2.5">
                    <span className={`px-2 py-0.5 rounded text-white text-xs font-display font-bold ${riskColors[row.risk]}`}>
                      {row.risk}
                    </span>
                  </td>
                  <td className={`px-3 py-2.5 font-semibold ${certColors[row.cert]}`}>
                    {certIcons[row.cert]} {row.cert}
                  </td>
                  <td className={`px-3 py-2.5 font-mono font-bold ${
                    row.keyLen.startsWith('1024') ? 'text-red-600' :
                    row.keyLen.startsWith('4') ? 'text-green-600' : 'text-blue-600'
                  }`}>
                    {row.keyLen}
                  </td>
                  <td className="px-3 py-2.5 text-center">
                    <span className={`text-lg ${row.pqc ? 'text-green-500' : 'text-red-500'}`}>
                      {row.pqc ? '✓' : '✗'}
                    </span>
                  </td>
                  <td className="px-3 py-2.5 text-gray-500">{row.lastScan}</td>
                  <td className="px-3 py-2.5">
                    <button className="p-1 hover:bg-amber-100 rounded transition-colors">
                      <Eye size={13} className="text-pnb-amber" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Footer */}
        <div className="px-4 py-3 border-t border-amber-100 flex items-center justify-between bg-amber-50/30">
          <p className="font-body text-xs text-gray-500">
            Showing {filtered.length} of {assets.length} assets
            {selected.length > 0 && ` · ${selected.length} selected`}
          </p>
          <div className="flex items-center gap-2 font-display text-xs text-gray-500">
            <button className="px-2 py-1 border border-amber-200 rounded hover:bg-amber-50">← Prev</button>
            <span className="px-3 py-1 bg-pnb-crimson text-white rounded">1</span>
            <button className="px-2 py-1 border border-amber-200 rounded hover:bg-amber-50">Next →</button>
          </div>
        </div>
      </div>
    </div>
  )
}
