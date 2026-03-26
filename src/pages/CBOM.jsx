import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'

const cipherData = [
  { name: 'ECDHE-RSA-AES256-GGM-SHA384', count: 29, color: '#1d4ed8' },
  { name: 'ECDHE-ECDSA-AES256-GGM-SHA384', count: 23, color: '#2563eb' },
  { name: 'AES256-GGM-SHA384',              count: 19, color: '#3b82f6' },
  { name: 'AES128-GGM-SHA256',              count: 15, color: '#60a5fa' },
  { name: 'TLS_RSA_WITH_DES_CBC_SHA',       count: 9,  color: '#dc2626' },
]

const caData = [
  { name: 'DigiCert',     value: 39, color: '#1d4ed8' },
  { name: 'Thawte',       value: 39, color: '#7c3aed' },
  { name: "Let's Encrypt",value: 6,  color: '#16a34a' },
  { name: 'COMODO',       value: 6,  color: '#94a3b8' },
  { name: 'Other',        value: 10, color: '#f59e0b' },
]

const tlsData = [
  { name: 'TLS 1.3', value: 72, color: '#16a34a' },
  { name: 'TLS 1.2', value: 20, color: '#3b82f6' },
  { name: 'TLS 1.1', value: 8,  color: '#dc2626' },
]

const keyLengthDist = [
  { len: '4096', count: 27, color: '#16a34a' },
  { len: '3078', count: 18, color: '#22c55e' },
  { len: '2048', count: 32, color: '#3b82f6' },
  { len: '2044', count: 8,  color: '#f59e0b' },
  { len: '2',    count: 5,  color: '#dc2626' },
  { len: '27',   count: 3,  color: '#7c3aed' },
]

const appTable = [
  { app: 'portal.company.com', keyLen: '2048-Bit', cipher: 'ECDHE-RSA-AES256-GCM-SHA384',  ca: 'DigiCert', weak: false },
  { app: 'portal.company.com', keyLen: '1024-Bit', cipher: 'TLS_RSA_WITH-256CIESHA384',    ca: 'COMODO',   weak: true  },
  { app: 'vpn.company.com',    keyLen: '4096-Bit', cipher: 'TC5HE-RSA_AE556-CCM-SHA384',   ca: 'COMODO',   weak: false },
  { app: 'purn.company.com',   keyLen: '4096-Bit', cipher: 'TLS_RSA_AES256_GGM_SHA384',    ca: 'loopDot',  weak: false },
]

export default function CBOM() {
  return (
    <div className="space-y-4">
      {/* Header */}
      <h1 className="font-display text-xl font-bold text-pnb-crimson">
        Cryptographic Bill of Materials (CBOM)
      </h1>

      {/* Stat strip */}
      <div className="grid grid-cols-5 gap-3">
        {[
          { label: 'Total Applications', value: 17,  color: '#1d4ed8', bg: 'bg-blue-50'   },
          { label: 'Sites Surveyed',     value: 56,  color: '#7c3aed', bg: 'bg-purple-50' },
          { label: 'Active Certificates',value: 93,  color: '#16a34a', bg: 'bg-green-50'  },
          { label: 'Weak Cryptography',  value: 22,  color: '#d97706', bg: 'bg-amber-50', alert: true },
          { label: 'Certificate Issues', value: 7,   color: '#dc2626', bg: 'bg-red-50',   critical: true },
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
            {keyLengthDist.map(({ len, count, color }) => (
              <div key={len} className="flex flex-col items-center flex-1">
                <div
                  className="w-full rounded-t transition-all"
                  style={{ height: `${(count / 35) * 100}%`, background: color }}
                />
                <span className="font-mono text-xs text-gray-500 mt-1">{len}</span>
              </div>
            ))}
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
                  <div className="cipher-bar h-full" style={{ width: `${(count / 29) * 100}%`, background: color }} />
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
                {['Application','Key Length','Cipher','Certificate Authority'].map(h => (
                  <th key={h} className="px-4 py-2.5 text-left font-display font-semibold text-pnb-crimson">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {appTable.map((r, i) => (
                <tr key={i} className={`border-b border-amber-50 hover:bg-amber-50/50 ${i%2===0?'bg-white/80':'bg-red-50/20'}`}>
                  <td className={`px-4 py-2.5 font-semibold ${i===0?'text-blue-700':'text-gray-700'}`}>{r.app}</td>
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
