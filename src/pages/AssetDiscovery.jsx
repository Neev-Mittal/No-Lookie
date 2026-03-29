import { useState, useEffect } from 'react'
import { Search, Calendar } from 'lucide-react'
import dataAPI from '../dataAPI'

const BASE_TAB_CONFIG = {
  Domains:            { label: 'Domains',           subTabs: ['New', 'False Positive', 'Confirmed', 'All'] },
  SSL:                { label: 'SSL',               subTabs: ['New', 'False/ignore',    'Confirmed',     'All'] },
  'IP Address/Subnets':{ label: 'IP Address/Subnets',subTabs: ['New','False or ignore','Confirmed','All'] },
  Software:           { label: 'Software',          subTabs: ['New', 'False or ignore', 'Confirmed','All'] },
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

  const [domainData, setDomainData] = useState({ New: [], 'False Positive': [], Confirmed: [], All: [] })
  const [sslData, setSslData] = useState({ New: [], 'False/ignore': [], Confirmed: [], All: [] })
  const [ipData, setIpData] = useState({ New: [], 'False or ignore': [], Confirmed: [], All: [] })
  const [softwareData, setSoftwareData] = useState({ New: [], 'False or ignore': [], Confirmed: [], All: [] })

  useEffect(() => {
    const fetchDiscoveryData = async () => {
      try {
        const res = await dataAPI.getAssetDiscoveryData();
        if (res.success) {
          setDomainData(res.domainData);
          setSslData(res.sslData);
          setIpData(res.ipData);
          setSoftwareData(res.softwareData);
        }
      } catch (err) {
        console.error('Failed to fetch Asset Discovery Data', err);
      }
    };
    fetchDiscoveryData();
  }, [])

  const subTabs = BASE_TAB_CONFIG[mainTab].subTabs
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
        {Object.keys(BASE_TAB_CONFIG).map(tab => {
          let count = 0;
          if (tab === 'Domains') count = domainData.All?.length || 0;
          if (tab === 'SSL') count = sslData.All?.length || 0;
          if (tab === 'IP Address/Subnets') count = ipData.All?.length || 0;
          if (tab === 'Software') count = softwareData.All?.length || 0;
          
          return (
            <button
              key={tab}
              onClick={() => { setMainTab(tab); setSubTabIdx(0) }}
              className={`font-display text-xs font-semibold px-5 py-2.5 rounded-xl transition-all duration-200
                ${mainTab === tab
                  ? 'bg-gradient-to-r from-pnb-crimson to-red-700 text-white shadow-lg shadow-red-200'
                  : 'bg-white/80 text-gray-600 hover:bg-amber-50 border border-amber-200'
                }`}
            >
              {BASE_TAB_CONFIG[tab].label} ({count})
            </button>
          )
        })}
      </div>

      {/* Sub tabs */}
      <div className="flex gap-2">
        {subTabs.map((st, idx) => {
          let count = 0;
          const map = mainTab === 'Domains' ? domainData :
                     mainTab === 'SSL' ? sslData :
                     mainTab === 'IP Address/Subnets' ? ipData :
                     softwareData;
          count = map[st]?.length || 0;

          return (
            <button
              key={idx}
              onClick={() => setSubTabIdx(idx)}
              className={`font-display text-xs font-semibold px-4 py-2 rounded-lg transition-all
                ${subTabIdx === idx
                  ? 'bg-amber-500 text-white'
                  : 'bg-white/70 text-gray-600 hover:bg-amber-50 border border-amber-200'
                }`}
            >
              {st} ({count})
            </button>
          )
        })}
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
