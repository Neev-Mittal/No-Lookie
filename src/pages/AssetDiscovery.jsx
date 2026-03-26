import { useState } from 'react'
import { Search, Calendar } from 'lucide-react'

// ── DATA ──────────────────────────────────────────────────────────────────────

const domainData = {
  New: [
    { detected:'03 Mar 2026', domain:'www.cos.pnb.bank.in',        registered:'17 Feb 2005', registrar:'National Internet Exchange of India', company:'PNB' },
    { detected:'17 Oct 2024', domain:'www2.pnbrrbkiosk.in',        registered:'22 Mar 2021', registrar:'National Internet Exchange of India', company:'PNB' },
    { detected:'17 Oct 2024', domain:'upload.pnbuniv.net.in',       registered:'22 Mar 2021', registrar:'National Internet Exchange of India', company:'PNB' },
    { detected:'17 Oct 2024', domain:'postman.pnb.bank.in',         registered:'22 Mar 2021', registrar:'National Internet Exchange of India', company:'PNB' },
    { detected:'17 Nov 2024', domain:'proxy.pnb.bank.in',           registered:'22 Mar 2021', registrar:'National Internet Exchange of India', company:'PNB' },
  ],
  'False Positive': [
    { detected:'15 Sep 2024', domain:'mirror.pnb-external.net',     registered:'10 Jan 2020', registrar:'GoDaddy LLC',                        company:'Third Party' },
    { detected:'20 Oct 2024', domain:'cdn.pnbservices.co',           registered:'05 Mar 2019', registrar:'Namecheap Inc',                      company:'Third Party' },
  ],
  Confirmed: [
    { detected:'01 Feb 2026', domain:'secure.pnb.bank.in',          registered:'10 Mar 2015', registrar:'National Internet Exchange of India', company:'PNB' },
    { detected:'10 Jan 2026', domain:'netbanking.pnb.bank.in',       registered:'01 Jun 2010', registrar:'National Internet Exchange of India', company:'PNB' },
  ],
}
domainData.All = [...domainData.New, ...domainData['False Positive'], ...domainData.Confirmed]

const sslData = {
  New: [
    { detected:'10 Mar 2026', sha:'b7563b983bfd217d471f607c9bbc509034a6', validFrom:'08 Feb 2026', common:'Generic Cert for WF Ovrd', company:'PNB', authority:'Symantac' },
    { detected:'10 Mar 2026', sha:'d8527f5c3e99b37164a8f3274a914506c94',  validFrom:'07 Feb 2026', common:'Generic Cert for WF Ovrd', company:'PNB', authority:'Digi-Cert' },
    { detected:'10 Mar 2026', sha:'Abe3195b86704f88cb75c7bcd11c69b9e493', validFrom:'06 Feb 2026', common:'Generic Cert for WF Ovrd', company:'PNB', authority:'Entrust' },
  ],
  'False/ignore': [
    { detected:'01 Mar 2026', sha:'fa92c1e4d3f0bcd8129aa74610e943f',      validFrom:'01 Jan 2026', common:'Proxy Cert Override',      company:'PNB', authority:'Let\'s Encrypt' },
  ],
  Confirmed: [],
}
sslData.All = [...sslData.New, ...sslData['False/ignore'], ...sslData.Confirmed]

const ipData = {
  New: [
    { detected:'05 Mar 2026', ip:'40.104.62.216',  ports:'80',     subnet:'103.107.224.0/22', asn:'AS9583', netname:'MSFT',             location:'-',            company:'Punjab National Bank' },
    { detected:'17 Oct 2024', ip:'40.101.72.212',  ports:'80',     subnet:'103.107.224.0/22', asn:'AS9583', netname:'-',                location:'India',        company:'Punjab National Bank' },
    { detected:'17 Oct 2024', ip:'402.10.1.1',     ports:'80',     subnet:'103.107.224.0/22', asn:'AS9583', netname:'-',                location:'-',            company:'Punjab National Bank' },
    { detected:'17 Oct 2024', ip:'103.25.151.22',  ports:'53,80',  subnet:'103.107.224.0/22', asn:'AS9583', netname:'Quantum-Link-Co',  location:'Nashik, India',company:'Punjab National Bank' },
    { detected:'17 Nov 2024', ip:'181.65.122.92',  ports:'80,443', subnet:'103.107.224.0/22', asn:'AS9583', netname:'E2E-Networks-IN', location:'Chennai, India',company:'Punjab National Bank' },
    { detected:'17 Nov 2024', ip:'20.153.63.72',   ports:'443',    subnet:'103.107.224.0/22', asn:'AS9583', netname:'-',                location:'Leh, India',   company:'Punjab National Bank' },
    { detected:'17 Nov 2024', ip:'21.151.42.188',  ports:'22',     subnet:'103.107.224.0/22', asn:'AS9583', netname:'-',                location:'India',        company:'Punjab National Bank' },
    { detected:'17 Nov 2024', ip:'402.11.22.153',  ports:'3997',   subnet:'103.107.224.0/22', asn:'AS9583', netname:'E2E-Networks-IN', location:'India',        company:'Punjab National Bank' },
  ],
  'False or ignore': [],
  Confirmed: [],
}
ipData.All = ipData.New

const softwareData = {
  New: [
    { detected:'05 Mar 2026', product:'http_server', version:'-',      type:'WebServer',  port:'443',  host:'49.51.98.173',  company:'PNB' },
    { detected:'17 Oct 2024', product:'http_server', version:'--',     type:'WebServer',  port:'587',  host:'49.52.123.215', company:'PNB' },
    { detected:'17 Oct 2024', product:'Apache',      version:'-',      type:'WebServer',  port:'443',  host:'40.59.99.173',  company:'PNB' },
    { detected:'17 Oct 2024', product:'IIS',         version:'10.0',   type:'WebServer',  port:'80',   host:'40.101.27.212', company:'PNB' },
    { detected:'17 Nov 2024', product:'Microsoft–IIS',version:'10.0',  type:'WebServer',  port:'80',   host:'401.10.274.14', company:'PNB' },
    { detected:'06 Mar 2026', product:'OpenResty',   version:'1.27.1.1',type:'Web Server',port:'2087', host:'66.68.262.93',  company:'PNB' },
  ],
  'False or ignore': [],
  Confirmed: [],
}
softwareData.All = softwareData.New

// ── COMPONENT ─────────────────────────────────────────────────────────────────

const TAB_CONFIG = {
  Domains:            { label: 'Domains (20)',           subTabs: ['New (5)', 'False Positive (10)', 'Confirmed (2)', 'All (3)'] },
  SSL:                { label: 'SSL (15)',               subTabs: ['New (3)', 'False/ignore (9)',    'Confirmed',     'All (3)'] },
  'IP Address/Subnets':{ label: 'IP Address/Subnets (34)',subTabs: ['New (15)','False or ignore (10)','Confirmed (9)','All (34)'] },
  Software:           { label: 'Software (52)',          subTabs: ['New (10)', 'False or ignore (6)', 'Confirmed (36)','All (52)'] },
}

function StatusBadge({ text }) {
  const color =
    text.includes('New')       ? 'bg-blue-500'   :
    text.includes('False')     ? 'bg-gray-500'    :
    text.includes('Confirmed') ? 'bg-green-600'   : 'bg-amber-500'
  return (
    <span className={`${color} text-white font-display text-xs font-bold px-3 py-1 rounded-full`}>
      {text}
    </span>
  )
}

export default function AssetDiscovery() {
  const [mainTab, setMainTab]   = useState('Domains')
  const [subTabIdx, setSubTabIdx] = useState(0)
  const [showGraph, setShowGraph] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [dateStart, setDateStart] = useState('')

  const subTabs = TAB_CONFIG[mainTab].subTabs
  const subKey  = subTabs[subTabIdx].split(' (')[0].replace(/\s*\(\d+\)/, '').trim()

  // ── Table content ────────────────────────────────────────────────────────
  const renderTable = () => {
    if (mainTab === 'Domains') {
      const rows = (domainData[subKey] || domainData.All)
      return (
        <table className="w-full text-xs font-body">
          <thead>
            <tr className="bg-gradient-to-r from-pnb-crimson to-red-800 text-white">
              {['Detection Date','Domain Name','Registration Date','Registrar','Company Name'].map(h => (
                <th key={h} className="px-4 py-3 text-left font-display font-semibold tracking-wide">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className={`border-b border-amber-50 hover:bg-amber-50 transition-colors ${i%2===0?'bg-white/80':'bg-red-50/20'}`}>
                <td className="px-4 py-3 text-gray-700">{r.detected}</td>
                <td className="px-4 py-3 text-blue-700 font-semibold">{r.domain}</td>
                <td className="px-4 py-3 text-gray-700">{r.registered}</td>
                <td className="px-4 py-3 text-gray-600">{r.registrar}</td>
                <td className="px-4 py-3 font-display font-bold text-pnb-crimson">{r.company}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )
    }

    if (mainTab === 'SSL') {
      const rows = (sslData[subKey] || sslData.All)
      return (
        <table className="w-full text-xs font-body">
          <thead>
            <tr className="bg-gradient-to-r from-pnb-crimson to-red-800 text-white">
              {['Detection Date','SSL SHA Fingerprint','Valid From','Common Name','Company Name','Certificate Authority'].map(h => (
                <th key={h} className="px-4 py-3 text-left font-display font-semibold tracking-wide">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className={`border-b border-amber-50 hover:bg-amber-50 transition-colors ${i%2===0?'bg-white/80':'bg-red-50/20'}`}>
                <td className="px-4 py-3 text-gray-700">{r.detected}</td>
                <td className="px-4 py-3 font-mono text-xs text-gray-600 max-w-48 truncate" title={r.sha}>{r.sha}</td>
                <td className="px-4 py-3 text-gray-700">{r.validFrom}</td>
                <td className="px-4 py-3 text-gray-700">{r.common}</td>
                <td className="px-4 py-3 font-display font-bold text-pnb-crimson">{r.company}</td>
                <td className="px-4 py-3">
                  <span className="bg-blue-100 text-blue-700 font-display font-bold text-xs px-2 py-0.5 rounded">
                    {r.authority}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )
    }

    if (mainTab === 'IP Address/Subnets') {
      const rows = (ipData[subKey] || ipData.All)
      return (
        <table className="w-full text-xs font-body">
          <thead>
            <tr className="bg-gradient-to-r from-pnb-crimson to-red-800 text-white">
              {['Detection Date','IP Address','Ports','Subnet','ASN','Netname','Location','Company'].map(h => (
                <th key={h} className="px-3 py-3 text-left font-display font-semibold tracking-wide">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className={`border-b border-amber-50 hover:bg-amber-50 transition-colors ${i%2===0?'bg-white/80':'bg-red-50/20'}`}>
                <td className="px-3 py-2.5 text-gray-700">{r.detected}</td>
                <td className="px-3 py-2.5 font-mono font-bold text-blue-700">{r.ip}</td>
                <td className="px-3 py-2.5">
                  <span className="bg-amber-100 text-amber-700 font-mono font-bold px-2 py-0.5 rounded">
                    {r.ports}
                  </span>
                </td>
                <td className="px-3 py-2.5 font-mono text-gray-600">{r.subnet}</td>
                <td className="px-3 py-2.5 font-display font-bold text-pnb-crimson">{r.asn}</td>
                <td className="px-3 py-2.5 text-gray-600">{r.netname}</td>
                <td className="px-3 py-2.5 text-gray-600">{r.location}</td>
                <td className="px-3 py-2.5 font-display font-semibold text-pnb-crimson">{r.company}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )
    }

    if (mainTab === 'Software') {
      const rows = (softwareData[subKey] || softwareData.All)
      return (
        <table className="w-full text-xs font-body">
          <thead>
            <tr className="bg-gradient-to-r from-pnb-crimson to-red-800 text-white">
              {['Detection Date','Product','Version','Type','Port','Host','Company Name'].map(h => (
                <th key={h} className="px-4 py-3 text-left font-display font-semibold tracking-wide">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i} className={`border-b border-amber-50 hover:bg-amber-50 transition-colors ${i%2===0?'bg-white/80':'bg-red-50/20'}`}>
                <td className="px-4 py-3 text-gray-700">{r.detected}</td>
                <td className="px-4 py-3 font-display font-bold text-pnb-crimson">{r.product}</td>
                <td className="px-4 py-3 font-mono text-gray-600">{r.version}</td>
                <td className="px-4 py-3 text-gray-700">{r.type}</td>
                <td className="px-4 py-3">
                  <span className="bg-purple-100 text-purple-700 font-mono font-bold px-2 py-0.5 rounded">
                    {r.port}
                  </span>
                </td>
                <td className="px-4 py-3 font-mono text-gray-700">{r.host}</td>
                <td className="px-4 py-3 font-display font-bold text-pnb-crimson">{r.company}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )
    }
  }

  // ── Network graph SVG (simplified interactive-looking) ───────────────────
  const GraphView = () => (
    <div className="glass-card rounded-xl p-4 relative overflow-hidden" style={{ height: 420 }}>
      <p className="font-display text-xs font-semibold text-pnb-crimson uppercase tracking-wide mb-3">
        Asset Relationship Graph
      </p>
      <svg width="100%" height="360" className="overflow-visible">
        {/* Edges */}
        {[
          [400,180, 200,100],[400,180, 600,100],[400,180, 250,260],
          [400,180, 550,260],[400,180, 150,200],[400,180, 650,200],
          [200,100, 100,60], [600,100, 700,60],
        ].map(([x1,y1,x2,y2], i) => (
          <line key={i} x1={x1} y1={y1} x2={x2} y2={y2}
            stroke="#22c55e" strokeWidth="1.5" opacity="0.6" />
        ))}
        {/* Hub node */}
        <circle cx="400" cy="180" r="22" fill="#92400e" />
        <text x="400" y="175" textAnchor="middle" fill="#fcd34d" fontSize="8" fontFamily="Oxanium">TAG</text>
        <text x="400" y="187" textAnchor="middle" fill="#fcd34d" fontSize="7" fontFamily="Oxanium">Scanning IP</text>

        {/* Domain nodes */}
        {[
          [200,100,'WWW','Domain: pltc.com.pk'],
          [600,100,'WWW','Domain: www.pepco-pbs.pk'],
          [250,260,'WWW','Domain: lesco.com.pk'],
          [550,260,'WWW','Domain: mepco.com.pk'],
          [150,200,'IP', '103.61.25.6'],
          [650,200,'IP', '78.154.234.148'],
          [100,60, 'SSL','SSL: #93..674'],
          [700,60, 'TAG','ETag: 162072031'],
        ].map(([cx,cy,type,label], i) => (
          <g key={i}>
            <circle cx={cx} cy={cy} r="18"
              fill={type==='WWW'?'#16a34a': type==='IP'?'#7c3aed': type==='SSL'?'#1d4ed8':'#92400e'}
              opacity="0.9"
            />
            <text x={cx} y={cy-3} textAnchor="middle" fill="white" fontSize="7" fontFamily="Oxanium" fontWeight="bold">{type}</text>
            <text x={cx} y={cy+11} textAnchor="middle" fill="white" fontSize="6" fontFamily="DM Sans">{label.substring(0,16)}</text>
          </g>
        ))}
      </svg>

      {/* Legend */}
      <div className="absolute bottom-4 left-4 flex items-center gap-4 text-xs font-body">
        {[['#16a34a','Domain'],['#1d4ed8','SSL'],['#7c3aed','IP'],['#92400e','Tag']].map(([c,l]) => (
          <div key={l} className="flex items-center gap-1">
            <div className="w-3 h-3 rounded-full" style={{background:c}} />
            <span className="text-gray-600">{l}</span>
          </div>
        ))}
      </div>
    </div>
  )

  // ── Search view ──────────────────────────────────────────────────────────
  const SearchView = () => (
    <div className="glass-card rounded-xl p-8 max-w-2xl mx-auto mt-4">
      <div className="relative mb-6">
        <Search size={16} className="absolute left-4 top-1/2 -translate-y-1/2 text-amber-500" />
        <input
          type="text"
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          placeholder="Search domain, URL, contact, IoC or other"
          className="w-full pl-11 pr-4 py-3 text-sm border-2 border-amber-300 rounded-xl
                     bg-amber-50 font-body text-pnb-crimson placeholder-amber-400
                     focus:outline-none focus:ring-2 focus:ring-amber-400"
        />
      </div>
      <div className="bg-amber-50 border border-amber-200 rounded-xl p-5">
        <div className="flex items-center gap-2 mb-3">
          <Calendar size={14} className="text-amber-600" />
          <span className="font-display text-sm font-semibold text-pnb-crimson">Time Period</span>
        </div>
        <p className="font-body text-xs text-gray-500 mb-3">Specify the Period for data</p>
        <div className="flex items-center gap-3">
          <input
            type="date" value={dateStart} onChange={e => setDateStart(e.target.value)}
            className="border border-amber-300 rounded-lg px-3 py-2 text-xs font-body focus:outline-none focus:ring-1 focus:ring-amber-400"
          />
          <span className="font-display text-pnb-amber font-bold">–</span>
          <input
            type="date"
            className="border border-amber-300 rounded-lg px-3 py-2 text-xs font-body focus:outline-none focus:ring-1 focus:ring-amber-400"
          />
        </div>
        <button className="mt-4 bg-gradient-to-r from-pnb-gold to-pnb-amber text-white font-display
                           font-semibold text-xs px-6 py-2 rounded-lg hover:from-pnb-amber hover:to-pnb-crimson
                           transition-all duration-300">
          Search
        </button>
      </div>
    </div>
  )

  return (
    <div className="space-y-4">
      {/* Page header */}
      <div className="flex items-center justify-between">
        <h1 className="font-display text-xl font-bold text-pnb-crimson">Asset Discovery</h1>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowGraph(!showGraph)}
            className={`font-display text-xs font-semibold px-4 py-2 rounded-lg transition-colors
              ${showGraph ? 'bg-pnb-crimson text-white' : 'bg-white border border-amber-300 text-pnb-amber hover:bg-amber-50'}`}
          >
            {showGraph ? '⊞ Table View' : '⬡ Graph View'}
          </button>
          <button
            onClick={() => setShowGraph('search')}
            className="font-display text-xs font-semibold px-4 py-2 rounded-lg bg-white border border-amber-300 text-pnb-amber hover:bg-amber-50 transition-colors"
          >
            <Search size={12} className="inline mr-1" />Search IoC
          </button>
        </div>
      </div>

      {/* Main tabs */}
      <div className="flex gap-2">
        {Object.keys(TAB_CONFIG).map(tab => (
          <button
            key={tab}
            onClick={() => { setMainTab(tab); setSubTabIdx(0) }}
            className={`font-display text-xs font-semibold px-5 py-2.5 rounded-xl transition-all duration-200
              ${mainTab === tab
                ? 'bg-gradient-to-r from-pnb-crimson to-red-700 text-white shadow-lg shadow-red-200'
                : 'bg-white/80 text-gray-600 hover:bg-amber-50 border border-amber-200'
              }`}
          >
            {TAB_CONFIG[tab].label}
          </button>
        ))}
      </div>

      {/* Sub tabs */}
      <div className="flex gap-2">
        {subTabs.map((st, idx) => (
          <button
            key={idx}
            onClick={() => setSubTabIdx(idx)}
            className={`font-display text-xs font-semibold px-4 py-2 rounded-lg transition-all
              ${subTabIdx === idx
                ? 'bg-amber-500 text-white'
                : 'bg-white/70 text-gray-600 hover:bg-amber-50 border border-amber-200'
              }`}
          >
            {st}
          </button>
        ))}
      </div>

      {/* Content */}
      {showGraph === 'search' ? (
        <SearchView />
      ) : showGraph ? (
        <GraphView />
      ) : (
        <div className="glass-card rounded-xl overflow-hidden">
          <div className="overflow-x-auto">
            {renderTable()}
          </div>
        </div>
      )}
    </div>
  )
}
