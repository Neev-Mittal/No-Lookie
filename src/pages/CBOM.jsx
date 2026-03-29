import { useState, useEffect } from 'react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'
import dataAPI from '../dataAPI'

export default function CBOM() {
  const [data, setData] = useState(null)

  useEffect(() => {
    dataAPI.getCBOMData().then(res => {
      if (res.success) setData(res)
    })
  }, [])

  if (!data) {
    return <div className="p-8 flex items-center justify-center min-h-[400px] text-pnb-crimson font-display font-semibold tracking-wide bg-amber-50/50 rounded-2xl border border-amber-200">Loading Cryptographic Bill of Materials...</div>
  }

  const { cipherData, caData, tlsData, keyLengthDist, appTable, stats } = data;
  return (
    <div className="space-y-4">
      {/* Header */}
      <h1 className="font-display text-xl font-bold text-pnb-crimson">
        Cryptographic Bill of Materials (CBOM)
      </h1>

      {/* Stat strip */}
      <div className="grid grid-cols-5 gap-3">
        {[
          { label: 'Total Applications', value: stats.totalApps, color: '#1d4ed8', bg: 'bg-blue-50' },
          { label: 'Sites Surveyed', value: stats.sitesSurveyed, color: '#7c3aed', bg: 'bg-purple-50' },
          { label: 'Active Certificates', value: stats.activeCerts, color: '#16a34a', bg: 'bg-green-50' },
          { label: 'Weak Cryptography', value: stats.weakCrypto, color: '#d97706', bg: 'bg-amber-50', alert: true },
          { label: 'Certificate Issues', value: stats.certIssues, color: '#dc2626', bg: 'bg-red-50', critical: true },
        ].map(({ label, value, color, bg, alert, critical }) => (
          <div key={label} className={`glass-card rounded-xl p-4 stat-card ${critical ? 'border-red-300' : alert ? 'border-amber-300' : 'border-amber-100'}`}>
            <p className="font-display text-2xl font-bold" style={{ color }}>{value}</p>
            <p className="font-body text-xs text-gray-500 mt-0.5">{label}</p>
            {(alert || critical) && (
              <div className={`mt-1 h-1 rounded-full ${critical ? 'bg-red-500' : 'bg-amber-400'} badge-critical`} />
            )}
          </div>
        ))}
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-3 gap-4">

        {/* Key Length Distribution */}
        <div className="glass-card rounded-xl p-4">
          <h3 className="font-display text-xs font-semibold text-pnb-crimson uppercase tracking-wide mb-3">
            Key Length Distribution
          </h3>
          <div className="flex items-end gap-2 h-32">
            {(keyLengthDist || []).map(({ len, count, color }) => {
              const maxCount = Math.max(1, ...keyLengthDist.map(k => k.count))
              const heightPct = Math.round((count / maxCount) * 100)
              return (
                <div key={len} className="flex flex-col items-center flex-1 h-full justify-end">
                  <span className="font-mono text-xs font-bold mb-0.5" style={{ color }}>{count}</span>
                  <div
                    className="w-full rounded-t transition-all"
                    style={{ height: `${heightPct}%`, background: color, minHeight: '4px' }}
                  />
                  <span className="font-mono text-xs text-gray-500 mt-1 truncate w-full text-center">{len}</span>
                </div>
              )
            })}
          </div>
        </div>

        {/* Cipher Usage */}
        <div className="glass-card rounded-xl p-4">
          <h3 className="font-display text-xs font-semibold text-pnb-crimson uppercase tracking-wide mb-3">
            Cipher Usage
          </h3>
          <div className="space-y-2">
            {cipherData.map(({ name, count, color }) => (
              <div key={name}>
                <div className="flex justify-between mb-0.5">
                  <span className="font-mono text-xs text-gray-600 truncate max-w-48">{name}</span>
                  <span className="font-display font-bold text-xs ml-2" style={{ color }}>{count}</span>
                </div>
                <div className="h-3 bg-gray-100 rounded overflow-hidden">
                  <div className="cipher-bar h-full" style={{ width: `${(count / Math.max(1, ...cipherData.map(c=>c.count))) * 100}%`, background: color }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Top Certificate Authorities */}
        <div className="glass-card rounded-xl p-4">
          <h3 className="font-display text-xs font-semibold text-pnb-crimson uppercase tracking-wide mb-3">
            Top Certificate Authorities
          </h3>
          <div className="space-y-2 mb-3">
            {caData.slice(0, 2).map(({ name, value, color }) => (
              <div key={name}>
                <div className="flex justify-between mb-0.5">
                  <span className="font-body text-xs text-gray-700">{name}</span>
                  <span className="font-display font-bold text-xs" style={{ color }}>{value}</span>
                </div>
                <div className="h-3 bg-gray-100 rounded overflow-hidden">
                  <div style={{ width: `${value}%`, background: color }} className="h-full rounded transition-all" />
                </div>
              </div>
            ))}
          </div>
          <div className="flex justify-center">
            <div className="space-y-1">
              {caData.slice(2).map(({ name, color }) => (
                <div key={name} className="flex items-center gap-1.5">
                  <div className="w-3 h-3 rounded-sm" style={{ background: color }} />
                  <span className="font-body text-xs text-gray-600">{name}</span>
                </div>
              ))}
              <div className="flex items-center gap-1.5">
                <div className="w-3 h-3 rounded-sm bg-gray-300" />
                <span className="font-body text-xs text-gray-600">16%</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom section */}
      <div className="grid grid-cols-3 gap-4">

        {/* Application table */}
        <div className="glass-card rounded-xl overflow-hidden col-span-2">
          <div className="px-4 py-3 border-b border-amber-100">
            <h3 className="font-display text-xs font-semibold text-pnb-crimson uppercase tracking-wide">
              Top Certificate Authorities — Application Detail
            </h3>
          </div>
          <table className="w-full text-xs font-body">
            <thead>
              <tr className="bg-amber-50">
                {['Application', 'Key Length', 'Cipher', 'Certificate Authority'].map(h => (
                  <th key={h} className="px-4 py-2.5 text-left font-display font-semibold text-pnb-crimson">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {appTable.map((r, i) => (
                <tr key={i} className={`border-b border-amber-50 hover:bg-amber-50/50 ${i % 2 === 0 ? 'bg-white/80' : 'bg-red-50/20'}`}>
                  <td className={`px-4 py-2.5 font-semibold ${i === 0 ? 'text-blue-700' : 'text-gray-700'}`}>{r.app}</td>
                  <td className={`px-4 py-2.5 font-mono font-bold ${r.keyLen.startsWith('1024') ? 'text-red-600' : 'text-blue-600'}`}>
                    {r.keyLen}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`font-mono text-xs px-2 py-0.5 rounded ${r.weak ? 'bg-red-100 text-red-700' : 'text-gray-700'}`}>
                      {r.cipher.substring(0, 28)}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-gray-700">{r.ca}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Encryption Protocols */}
        <div className="glass-card rounded-xl p-4">
          <h3 className="font-display text-xs font-semibold text-pnb-crimson uppercase tracking-wide mb-3">
            Encryption Protocols
          </h3>
          <ResponsiveContainer width="100%" height={140}>
            <PieChart>
              <Pie data={tlsData} dataKey="value" cx="50%" cy="50%" outerRadius={55} innerRadius={30}>
                {tlsData.map((d, i) => <Cell key={i} fill={d.color} />)}
              </Pie>
              <Tooltip contentStyle={{ fontSize: 11 }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="space-y-1 mt-2">
            {tlsData.map(({ name, value, color }) => (
              <div key={name} className="flex items-center justify-between">
                <div className="flex items-center gap-1.5">
                  <div className="w-3 h-3 rounded-sm" style={{ background: color }} />
                  <span className="font-body text-xs text-gray-600">{name}</span>
                </div>
                <span className="font-display font-bold text-xs" style={{ color }}>{value}%</span>
              </div>
            ))}
          </div>
          <div className="mt-3 p-2 bg-red-50 border border-red-200 rounded-lg">
            <p className="font-display text-xs text-red-700 font-semibold">⚠ TLS 1.1 Detected</p>
            <p className="font-body text-xs text-red-500 mt-0.5">Immediate upgrade recommended</p>
          </div>
        </div>
      </div>
    </div>
  )
}
