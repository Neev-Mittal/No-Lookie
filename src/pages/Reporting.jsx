import { useState, useEffect } from 'react'
import dataAPI from '../dataAPI'
import {
  Users, Calendar, Search, Download,
  Mail, FolderOpen, Link2, Bell, Plus, ChevronDown
} from 'lucide-react'

const reportTypes = [
  { icon: Users,    label: 'Executives Reporting',  desc: 'Board-level risk summaries and KPIs' },
  { icon: Calendar, label: 'Scheduled Reporting',   desc: 'Automated periodic report delivery'  },
  { icon: Search,   label: 'On-Demand Reporting',   desc: 'Generate reports on request'         },
]

export default function Reporting() {
  const [active, setActive] = useState(null)
  const [stats, setStats] = useState(null)

  useEffect(() => {
    Promise.all([
      dataAPI.getDashboardData(),
      dataAPI.getCBOMData(),
      dataAPI.getPostureOfPQCData(),
      dataAPI.getCyberRatingData()
    ]).then(([dash, cbom, pqc, rating]) => {
      setStats({
        dash: dash.success ? dash : {},
        cbom: cbom.success ? cbom : {},
        pqc: pqc.success ? pqc : { summary: {} },
        rating: rating.success ? rating : {}
      })
    })
  }, [])

  if (active === null) {
    return <SelectionView setActive={setActive} />
  }
  if (active === 'scheduled') {
    return <ScheduledView setActive={setActive} />
  }
  if (active === 'ondemand') {
    return <OnDemandView setActive={setActive} />
  }
  return <ExecView setActive={setActive} stats={stats} />
}

// ── Landing selection ─────────────────────────────────────────────────────────
function SelectionView({ setActive }) {
  const cards = [
    {
      icon: Users, label: 'Executives Reporting', key: 'exec',
      desc: 'Board-level risk summaries, Q-VaR models, and KPI dashboards for CISO/CTO.',
      color: 'from-blue-600 to-blue-800',
    },
    {
      icon: Calendar, label: 'Scheduled Reporting', key: 'scheduled',
      desc: 'Automate periodic report generation and delivery to email or storage locations.',
      color: 'from-pnb-crimson to-red-900',
    },
    {
      icon: Search, label: 'On-Demand Reporting', key: 'ondemand',
      desc: 'Generate targeted reports on request for specific assets, incidents, or audits.',
      color: 'from-amber-500 to-amber-700',
    },
  ]

  return (
    <div className="space-y-5">
      <h1 className="font-display text-xl font-bold text-pnb-crimson">Reporting</h1>

      <div className="flex justify-center items-center min-h-80">
        <div className="grid grid-cols-3 gap-6 max-w-4xl w-full">
          {cards.map(({ icon: Icon, label, key, desc, color }) => (
            <button
              key={key}
              onClick={() => setActive(key)}
              className="group relative overflow-hidden rounded-3xl p-8 text-center
                         shadow-xl hover:shadow-2xl transition-all duration-300
                         hover:-translate-y-2 cursor-pointer"
            >
              {/* Background */}
              <div className={`absolute inset-0 bg-gradient-to-b ${color} opacity-90`} />
              {/* Oval outline */}
              <div className="absolute inset-4 border-2 border-white/20 rounded-2xl" />

              <div className="relative z-10">
                <div className="w-16 h-16 bg-white/20 rounded-2xl flex items-center justify-center mx-auto mb-4">
                  <Icon size={32} className="text-white" />
                </div>
                <p className="font-display text-lg font-bold text-white mb-2">{label}</p>
                <p className="font-body text-xs text-white/80">{desc}</p>
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Executive Reporting ───────────────────────────────────────────────────────
function ExecView({ setActive, stats }) {
  if (!stats) return <div className="p-8 text-pnb-crimson animate-pulse">Aggregating executive metrics...</div>

  const tiles = [
    { 
      title: 'Assets Discovery', 
      items: [
        `${stats.dash.statCards?.[0]?.value || 0} Total subdomains & IPs`,
        `${stats.dash.statCards?.[1]?.value || 0} Public Web Applications`
      ], 
      icon: '🔍', color: 'bg-blue-50 border-blue-200' 
    },
    { 
      title: 'Cyber Rating', 
      items: [
        `Consolidated Score: ${stats.rating.enterpriseScore || 0}`,
        `Current Tier: ${stats.rating.enterpriseTier || 'Unknown'}`
      ], 
      icon: '⭐', color: 'bg-amber-50 border-amber-200' 
    },
    { 
      title: 'Assets Inventory', 
      items: [
        `Active Certificates: ${stats.cbom.stats?.activeCerts || 0}`,
        `Weak Crypto Found: ${stats.cbom.stats?.weakCrypto || 0}`
      ], 
      icon: '🗂', color: 'bg-green-50 border-green-200' 
    },
    { 
      title: 'Posture of PQC', 
      items: [
        `Elite-PQC Ready: ${stats.pqc.summary?.pqcReadyPct || 0}%`,
        `Legacy Protocol Count: ${stats.pqc.summary?.legacyPct || 0}%`
      ], 
      icon: '🛡', color: 'bg-purple-50 border-purple-200' 
    },
    { 
      title: 'CBOM', 
      items: [
        `Total Assets Analyzed: ${stats.cbom.stats?.totalApps || 0}`,
        `Certificate/Cipher Issues: ${stats.cbom.stats?.certIssues || 0}`
      ], 
      icon: '📋', color: 'bg-orange-50 border-orange-200' 
    },
  ]

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <button onClick={() => setActive(null)}
          className="font-display text-xs text-pnb-amber hover:text-pnb-crimson">← Back</button>
        <h1 className="font-display text-xl font-bold text-pnb-crimson">Executive Reporting</h1>
      </div>

      <div className="grid grid-cols-3 gap-4">
        {tiles.map(({ title, items, icon, color }) => (
          <div key={title} className={`glass-card rounded-xl p-4 border ${color}`}>
            <div className="flex items-center gap-2 mb-2">
              <span className="text-xl">{icon}</span>
              <h3 className="font-display text-xs font-semibold text-gray-800">{title}</h3>
            </div>
            {items.map((item, i) => (
              <p key={i} className="font-body text-xs text-gray-600 mt-1">{item}</p>
            ))}
          </div>
        ))}

        {/* Download buttons */}
        <div className="glass-card rounded-xl p-4 border border-amber-200">
          <h3 className="font-display text-xs font-semibold text-pnb-crimson mb-3">Download Reports</h3>
          {['Executive Summary (PDF)','Risk Assessment (JSON)','Asset Inventory (CSV)','CBOM Report (CycloneDX)'].map(r => (
            <button key={r}
              className="w-full flex items-center justify-between text-xs font-body
                         py-2 px-3 mb-1.5 bg-white border border-amber-200 rounded-lg
                         hover:bg-amber-50 text-gray-700 transition-colors">
              {r} <Download size={12} className="text-pnb-amber" />
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}

// ── Scheduled Reporting ───────────────────────────────────────────────────────
function ScheduledView({ setActive }) {
  const [enabled, setEnabled] = useState(true)
  const [freq, setFreq]       = useState('Weekly')
  const [type, setType]       = useState('Executive Summary Report')
  const [assets, setAssets]   = useState('All Assets')

  const sections = ['Discovery', 'Inventory', 'CBOM', 'PQC Posture', 'Cyber Rating']
  const [checked, setChecked] = useState(new Set(sections))

  const toggleSection = s => {
    setChecked(prev => {
      const n = new Set(prev)
      n.has(s) ? n.delete(s) : n.add(s)
      return n
    })
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <button onClick={() => setActive(null)}
          className="font-display text-xs text-pnb-amber hover:text-pnb-crimson">← Back</button>
        <h1 className="font-display text-xl font-bold text-pnb-crimson">Schedule Reporting</h1>
      </div>

      <div className="glass-card rounded-2xl p-6 max-w-3xl mx-auto shadow-xl">
        {/* Header row */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-amber-100 rounded-xl"><Calendar size={20} className="text-pnb-amber" /></div>
            <h2 className="font-display text-lg font-bold text-pnb-crimson">Schedule Reporting</h2>
          </div>
          <div className="flex items-center gap-2">
            <span className="font-body text-xs text-gray-600">Enable Schedule</span>
            <button
              onClick={() => setEnabled(!enabled)}
              className={`relative w-12 h-6 rounded-full transition-colors ${enabled ? 'bg-amber-500' : 'bg-gray-300'}`}
            >
              <div className={`absolute top-1 w-4 h-4 bg-white rounded-full shadow transition-transform
                ${enabled ? 'translate-x-7' : 'translate-x-1'}`} />
            </button>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-8">
          {/* Left */}
          <div className="space-y-4">
            <div>
              <label className="font-display text-xs font-semibold text-gray-700 uppercase tracking-wide block mb-1.5">
                Report Type
              </label>
              <select value={type} onChange={e => setType(e.target.value)}
                className="w-full border border-amber-200 rounded-lg px-3 py-2 text-sm font-body
                           bg-white focus:outline-none focus:ring-1 focus:ring-amber-400">
                {['Executive Summary Report','Asset Discovery Report','CBOM Report','PQC Posture Report','Cyber Rating Report'].map(o => (
                  <option key={o}>{o}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="font-display text-xs font-semibold text-gray-700 uppercase tracking-wide block mb-1.5">
                Frequency
              </label>
              <select value={freq} onChange={e => setFreq(e.target.value)}
                className="w-full border border-amber-200 rounded-lg px-3 py-2 text-sm font-body
                           bg-white focus:outline-none focus:ring-1 focus:ring-amber-400">
                {['Daily','Weekly','Bi-Weekly','Monthly','Quarterly'].map(o => (
                  <option key={o}>{o}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="font-display text-xs font-semibold text-gray-700 uppercase tracking-wide block mb-1.5">
                Select Assets
              </label>
              <select value={assets} onChange={e => setAssets(e.target.value)}
                className="w-full border border-amber-200 rounded-lg px-3 py-2 text-sm font-body
                           bg-white focus:outline-none focus:ring-1 focus:ring-amber-400">
                {['All Assets','Web Applications','APIs','Servers','Gateways'].map(o => (
                  <option key={o}>{o}</option>
                ))}
              </select>
            </div>

            <div>
              <label className="font-display text-xs font-semibold text-gray-700 uppercase tracking-wide block mb-2">
                Include Sections
              </label>
              <div className="flex flex-wrap gap-2">
                {sections.map(s => (
                  <button key={s} onClick={() => toggleSection(s)}
                    className={`flex items-center gap-1.5 text-xs font-display font-semibold px-3 py-1.5 rounded-lg border transition-colors
                      ${checked.has(s) ? 'bg-amber-500 text-white border-amber-500' : 'bg-white text-gray-600 border-amber-200 hover:bg-amber-50'}`}>
                    {checked.has(s) && '✓'} {s}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {/* Right */}
          <div className="space-y-4">
            <div className="bg-amber-50 border border-amber-200 rounded-xl p-4">
              <div className="flex items-center gap-2 text-amber-600 mb-3">
                <Calendar size={14} />
                <span className="font-display text-xs font-semibold uppercase tracking-wide">Schedule Details</span>
              </div>
              <div className="space-y-3">
                <div>
                  <label className="font-body text-xs text-gray-600 block mb-1">Date</label>
                  <input type="date" defaultValue="2026-04-25"
                    className="w-full border border-amber-200 rounded-lg px-3 py-2 text-sm font-body
                               focus:outline-none focus:ring-1 focus:ring-amber-400" />
                </div>
                <div>
                  <label className="font-body text-xs text-gray-600 block mb-1">Time</label>
                  <select className="w-full border border-amber-200 rounded-lg px-3 py-2 text-sm font-body
                                    focus:outline-none focus:ring-1 focus:ring-amber-400">
                    {['09:00 AM (IST)','12:00 PM (IST)','06:00 PM (IST)'].map(o => <option key={o}>{o}</option>)}
                  </select>
                </div>
                <p className="font-body text-xs text-gray-500">Time Zone: Asia/Kolkata</p>
              </div>
            </div>

            <div className="bg-amber-50 border border-amber-200 rounded-xl p-4">
              <div className="flex items-center gap-2 text-amber-600 mb-3">
                <Mail size={14} />
                <span className="font-display text-xs font-semibold uppercase tracking-wide">Delivery Options</span>
              </div>
              {[
                { icon: Mail,       label: 'Email',           placeholder: 'executives@org.com', defaultOn: true },
                { icon: FolderOpen, label: 'Save to Location',placeholder: '/Reports/Quarterly/', defaultOn: true },
                { icon: Link2,      label: 'Download Link',   placeholder: '',                   defaultOn: false },
              ].map(({ icon: Icon, label, placeholder, defaultOn }) => {
                const [on, setOn] = useState(defaultOn)
                return (
                  <div key={label} className="flex items-center gap-2 mb-2">
                    <input type="checkbox" checked={on} onChange={() => setOn(!on)} className="accent-amber-500" />
                    <Icon size={13} className="text-gray-500" />
                    <span className="font-body text-xs text-gray-700 w-28">{label}</span>
                    {placeholder && on && (
                      <input placeholder={placeholder}
                        className="flex-1 border border-amber-200 rounded px-2 py-1 text-xs font-body
                                   focus:outline-none focus:ring-1 focus:ring-amber-400" />
                    )}
                  </div>
                )
              })}
            </div>

            <button className="w-full bg-gradient-to-r from-pnb-gold to-pnb-amber text-white font-display
                               font-bold py-3 rounded-xl hover:from-pnb-amber hover:to-pnb-crimson
                               transition-all duration-300 shadow-lg flex items-center justify-center gap-2">
              <Calendar size={14} /> Schedule Report →
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── On-Demand Reporting ───────────────────────────────────────────────────────
function OnDemandView({ setActive }) {
  const [selectedReport, setSelectedReport] = useState('')
  const [dropdownOpen, setDropdownOpen]     = useState(false)
  const [format, setFormat]                 = useState('PDF')
  const [includeCharts, setIncludeCharts]   = useState(true)
  const [pwProtect, setPwProtect]           = useState(false)
  const [emailEnabled, setEmailEnabled]     = useState(true)
  const [saveEnabled, setSaveEnabled]       = useState(true)

  const reportOpts = [
    { icon: '📊', label: 'Executive Reporting'      },
    { icon: '🔍', label: 'Assets Discovery'          },
    { icon: '🗂', label: 'Assets Inventory'          },
    { icon: '📋', label: 'CBOM'                      },
    { icon: '🛡', label: 'Posture of PQC'            },
    { icon: '⭐', label: 'Cyber Rating (Tiers 1 - 4)'},
  ]

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <button onClick={() => setActive(null)}
          className="font-display text-xs text-pnb-amber hover:text-pnb-crimson">← Back</button>
        <h1 className="font-display text-xl font-bold text-pnb-crimson">On-Demand Reporting</h1>
      </div>

      <div className="glass-card rounded-2xl p-6 max-w-3xl mx-auto shadow-xl">
        <div className="flex items-center gap-3 mb-6">
          <div className="p-2 bg-amber-100 rounded-xl"><Search size={20} className="text-pnb-amber" /></div>
          <div>
            <h2 className="font-display text-lg font-bold text-pnb-crimson">On-Demand Reporting</h2>
            <p className="font-body text-xs text-gray-500">Request reports as needed</p>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-8">
          {/* Report type selector */}
          <div>
            <label className="font-display text-xs font-semibold text-gray-700 uppercase tracking-wide block mb-2">
              Report Type
            </label>
            <div className="relative">
              <button
                onClick={() => setDropdownOpen(!dropdownOpen)}
                className="w-full flex items-center justify-between border border-amber-200 rounded-xl
                           px-4 py-2.5 bg-white text-sm font-body text-gray-700 hover:bg-amber-50 transition-colors"
              >
                {selectedReport || 'Select Report'}
                <ChevronDown size={14} className={`transition-transform ${dropdownOpen ? 'rotate-180' : ''}`} />
              </button>
              {dropdownOpen && (
                <div className="absolute z-20 top-full left-0 right-0 mt-1 bg-white border border-amber-200
                                rounded-xl shadow-xl overflow-hidden">
                  {reportOpts.map(({ icon, label }) => (
                    <button
                      key={label}
                      onClick={() => { setSelectedReport(label); setDropdownOpen(false) }}
                      className="w-full flex items-center gap-3 px-4 py-2.5 text-sm font-body text-gray-700
                                 hover:bg-amber-50 transition-colors text-left"
                    >
                      <span>{icon}</span> {label}
                    </button>
                  ))}
                </div>
              )}
            </div>
          </div>

          {/* Delivery options */}
          <div>
            <label className="font-display text-xs font-semibold text-gray-700 uppercase tracking-wide block mb-2">
              Delivery Options
            </label>
            <div className="space-y-3">
              {/* Email */}
              <div className={`flex items-center gap-2 p-3 rounded-xl border ${emailEnabled ? 'bg-amber-50 border-amber-200' : 'bg-gray-50 border-gray-200'}`}>
                <input type="checkbox" checked={emailEnabled} onChange={() => setEmailEnabled(!emailEnabled)} className="accent-amber-500" />
                <Mail size={13} className="text-gray-500" />
                <span className="font-body text-xs text-gray-700 flex-1">Send via Email</span>
                <button className={`relative w-10 h-5 rounded-full transition-colors ${emailEnabled ? 'bg-amber-500' : 'bg-gray-300'}`}
                  onClick={() => setEmailEnabled(!emailEnabled)}>
                  <div className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform ${emailEnabled ? 'translate-x-5' : 'translate-x-0.5'}`} />
                </button>
              </div>
              {emailEnabled && (
                <input placeholder="Enter Email Addresses"
                  className="w-full border border-amber-200 rounded-xl px-3 py-2 text-xs font-body
                             focus:outline-none focus:ring-1 focus:ring-amber-400" />
              )}

              {/* Save location */}
              <div className={`flex items-center gap-2 p-3 rounded-xl border ${saveEnabled ? 'bg-amber-50 border-amber-200' : 'bg-gray-50 border-gray-200'}`}>
                <input type="checkbox" checked={saveEnabled} onChange={() => setSaveEnabled(!saveEnabled)} className="accent-amber-500" />
                <FolderOpen size={13} className="text-gray-500" />
                <span className="font-body text-xs text-gray-700 flex-1">Save to Location</span>
                <button className={`relative w-10 h-5 rounded-full transition-colors ${saveEnabled ? 'bg-amber-500' : 'bg-gray-300'}`}
                  onClick={() => setSaveEnabled(!saveEnabled)}>
                  <div className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform ${saveEnabled ? 'translate-x-5' : 'translate-x-0.5'}`} />
                </button>
              </div>
              {saveEnabled && (
                <div className="flex items-center gap-1">
                  <input defaultValue="/Reports/OnDemand/"
                    className="flex-1 border border-amber-200 rounded-xl px-3 py-2 text-xs font-body
                               focus:outline-none focus:ring-1 focus:ring-amber-400" />
                  <button className="p-2 border border-amber-200 rounded-xl hover:bg-amber-50">
                    <FolderOpen size={13} className="text-amber-600" />
                  </button>
                </div>
              )}

              {/* Download link */}
              <div className="flex items-center gap-2 p-3 rounded-xl border bg-gray-50 border-gray-200">
                <input type="checkbox" className="accent-amber-500" />
                <Link2 size={13} className="text-gray-500" />
                <span className="font-body text-xs text-gray-700">Download Link</span>
              </div>

              {/* Slack */}
              <div className="flex items-center gap-2 p-3 rounded-xl border bg-gray-50 border-gray-200">
                <input type="checkbox" className="accent-amber-500" />
                <Bell size={13} className="text-gray-500" />
                <span className="font-body text-xs text-gray-700">Slack Notification</span>
              </div>
            </div>
          </div>
        </div>

        {/* Advanced Settings */}
        <div className="mt-6 bg-amber-50 border border-amber-200 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <span className="text-amber-600">⚙</span>
            <span className="font-display text-xs font-semibold text-gray-700 uppercase tracking-wide">Advanced Settings</span>
          </div>
          <div className="flex items-center gap-6 flex-wrap">
            <div>
              <label className="font-body text-xs text-gray-600 block mb-1">File Format</label>
              <select value={format} onChange={e => setFormat(e.target.value)}
                className="border border-amber-200 rounded-lg px-3 py-1.5 text-xs font-body focus:outline-none focus:ring-1 focus:ring-amber-400">
                {['PDF','JSON','CSV','XLSX','CycloneDX'].map(o => <option key={o}>{o}</option>)}
              </select>
            </div>

            <div className="flex items-center gap-2">
              <label className="font-body text-xs text-gray-600">Include Charts</label>
              <button onClick={() => setIncludeCharts(!includeCharts)}
                className={`relative w-10 h-5 rounded-full transition-colors ${includeCharts ? 'bg-amber-500' : 'bg-gray-300'}`}>
                <div className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform ${includeCharts ? 'translate-x-5' : 'translate-x-0.5'}`} />
              </button>
            </div>

            <div className="flex items-center gap-2">
              <label className="font-body text-xs text-gray-600">Password Protect</label>
              <button onClick={() => setPwProtect(!pwProtect)}
                className={`relative w-10 h-5 rounded-full transition-colors ${pwProtect ? 'bg-amber-500' : 'bg-gray-300'}`}>
                <div className={`absolute top-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform ${pwProtect ? 'translate-x-5' : 'translate-x-0.5'}`} />
              </button>
            </div>

            <button className="ml-auto bg-gradient-to-r from-pnb-gold to-pnb-amber text-white font-display
                               font-bold text-xs px-6 py-2.5 rounded-xl hover:from-pnb-amber hover:to-pnb-crimson
                               transition-all duration-300 shadow-lg flex items-center gap-2">
              <Download size={13} /> Generate Report
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
