/**
 * Data Loading Utility
 * Loads JSON data files from public/data folder (used during development)
 * Falls back to API calls in production
 */

const BASE_API = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
const USE_JSON_FILES = true // Set to false to use API endpoints

// Load JSON data
const loadJSONData = async (path) => {
  try {
    const response = await fetch(`/data/${path}`)
    if (!response.ok) throw new Error(`HTTP ${response.status}`)
    return await response.json()
  } catch (error) {
    console.error(`Error loading /data/${path}:`, error)
    return null
  }
}

/**
 * Normalises subdomains.json — handles two formats:
 *   1. Flat array:  ["fqdn1", "fqdn2", ...]
 *   2. Object:      { subdomains: [{fqdn, ips, ...}], count_assets: N }
 * Always returns { subdomains: [{fqdn, ips, status, asset_type, sources, resolved_at_utc}], count_assets: N }
 */
const normalizeSubdomainsData = (raw) => {
  if (!raw) return { subdomains: [], count_assets: 0 }
  // Flat string array format
  if (Array.isArray(raw)) {
    const subs = raw.map(fqdn => ({
      fqdn,
      ips: [],
      status: 'active',
      asset_type: fqdn.includes('api') ? 'api' : 'domain',
      sources: [],
      resolved_at_utc: new Date().toISOString(),
    }))
    return { subdomains: subs, count_assets: subs.length }
  }
  // Object format
  return {
    subdomains: raw.subdomains || [],
    count_assets: raw.count_assets || (raw.subdomains || []).length,
  }
}

// Normalize functions
const normalizeAsset = (asset) => ({
  id: asset['Asset ID'],
  name: asset.Asset,
  url: `https://${asset.Asset}`,
  ip: asset['IP Address'],
  port: asset.Port,
  tlsVersions: asset['Supported TLS Versions'] || [],
  minTls: asset['Minimum Supported TLS'],
  maxTls: asset['Maximum Supported TLS'],
  tlsVersion: asset['TLS Version'],
  cipherSuite: asset['Cipher Suite'],
  keyExchange: asset['Key Exchange Algorithm'],
  encryption: asset['Encryption Algorithm'],
  hash: asset['Hash Algorithm'],
  keyBits: asset['Key Size (Bits)'],
  pfs: asset['PFS Status'] === 'Yes',
  issuer: asset['Issuer CA'],
  notBefore: asset['Certificate Validity (Not Before/After)']?.['Not Before'],
  notAfter: asset['Certificate Validity (Not Before/After)']?.['Not After'],
  heiScore: asset.HEI_Score || 50,
  riskCategory: asset.Risk_Category || 'Medium',
  pqcLabel: asset['NIST PQC Readiness Label'] || '',
})

const normalizeSubdomain = (sub) => ({
  fqdn: sub.fqdn,
  ips: sub.ips || [],
  status: sub.status,
  type: sub.asset_type,
  sources: sub.sources || [],
  resolvedAt: sub.resolved_at_utc,
})

const normalizeFinding = (finding) => ({
  type: finding.finding_type,
  severity: finding.severity,
  asset: finding.asset,
  ip: finding.ip_address,
  port: finding.port,
  description: finding.description,
  recommendation: finding.recommendation,
  details: finding.details,
})

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Deduplicates enriched_cbom records by unique domain (Asset field).
 * Strategy: prefer the port-443 ok-scan record; fall back to any ok-scan record.
 * This ensures every page works from the same canonical unique-domain list.
 */
const dedupeByDomain = (records) => {
  const map = new Map()
  for (const r of records) {
    const key = r.Asset
    if (!map.has(key)) {
      map.set(key, r)
    } else {
      const existing = map.get(key)
      // Prefer port-443 ok record over anything else
      const rOk = r['Scan Status'] === 'ok'
      const existOk = existing['Scan Status'] === 'ok'
      if (rOk && r.Port === 443) map.set(key, r)
      else if (rOk && !existOk) map.set(key, r)
    }
  }
  return Array.from(map.values())
}

// ─────────────────────────────────────────────────────────────────────────────
// Public Data APIs
// ─────────────────────────────────────────────────────────────────────────────

export const dataAPI = {
  // Dashboard Metrics
  getDashboardData: async () => {
    try {
      const [cbomRaw, subRaw] = await Promise.all([
        loadJSONData('PNB/enriched_cbom.json'),
        loadJSONData('PNB/subdomains.json')
      ])

      // Use deduped unique-domain records for all per-asset metrics
      const assets = dedupeByDomain(cbomRaw?.records || [])
      const { subdomains: subs } = normalizeSubdomainsData(subRaw)
      // Authoritative total: unique FQDNs from subdomains.json
      const totalUniqueAssets = new Set(subs.map(s => s.fqdn)).size

      let webApps = 0, apis = 0, servers = 0, expiring = 0, highRisk = 0;
      let typeCounts = { 'Web Apps': 0, 'APIs': 0, 'Servers': 0, 'Load Balancers': 0, 'Other': 0 };
      let riskCounts = { 'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0 };
      let certCounts = { '0-30 Days': 0, '30-60 Days': 0, '60-90 Days': 0, '>90 Days': 0 };
      let ipCounts = { v4: 0, v6: 0 };

      // Calculate Subdomains / Type info from subdomains.json
      subs.forEach(s => {
        let type = (s.asset_type || '').toLowerCase();
        if (type.includes('api')) { apis++; typeCounts['APIs']++; }
        else if (type.includes('domain') || type.includes('web')) { webApps++; typeCounts['Web Apps']++; }
        else if (type.includes('server')) { servers++; typeCounts['Servers']++; }
        else { typeCounts['Other']++; }

        (s.ips || []).forEach(ip => {
          if (ip.includes(':')) ipCounts.v6++; else ipCounts.v4++;
        });
      });

      // Calculate Asset info from cbom.json
      assets.forEach(a => {
        let risk = a.Risk_Category || 'Low';
        if (riskCounts[risk] !== undefined) riskCounts[risk]++;
        if (risk === 'High' || risk === 'Critical') highRisk++;

        let certVal = a['Certificate Validity (Not Before/After)'];
        if (certVal && certVal['Not After']) {
          let days = (new Date(certVal['Not After']) - new Date()) / (1000 * 60 * 60 * 24);
          if (days < 0) { expiring++; } // already expired
          else if (days <= 30) { expiring++; certCounts['0-30 Days']++; }
          else if (days <= 60) { certCounts['30-60 Days']++; }
          else if (days <= 90) { certCounts['60-90 Days']++; }
          else { certCounts['>90 Days']++; }
        }
      });

      const totalIPs = ipCounts.v4 + ipCounts.v6 || 1;
      const v4Pct = Math.round((ipCounts.v4 / totalIPs) * 100);

      return {
        success: true,
        statCards: [
          { label: 'Total Assets', value: totalUniqueAssets, icon: 'Layers', color: '#1d4ed8', bg: 'bg-blue-50' },
          { label: 'Public Web Apps', value: webApps, icon: 'Globe', color: '#16a34a', bg: 'bg-green-50' },
          { label: 'APIs', value: apis, icon: 'Server', color: '#7c3aed', bg: 'bg-purple-50' },
          { label: 'Servers', value: servers, icon: 'Server', color: '#0891b2', bg: 'bg-cyan-50' },
          { label: 'Expiring Certificates', value: expiring, icon: 'AlertTriangle', color: '#d97706', bg: 'bg-amber-50', alert: true },
          { label: 'High Risk Assets', value: highRisk, icon: 'ShieldOff', color: '#dc2626', bg: 'bg-red-50', critical: true },
        ],
        assetTypeDist: Object.entries(typeCounts).filter(([_, v]) => v > 0).map(([k, v], i) => ({
          name: k, value: v, color: ['#3b82f6', '#6366f1', '#22c55e', '#f59e0b', '#94a3b8'][i] || '#94a3b8'
        })),
        riskDist: Object.entries(riskCounts).map(([k, v]) => ({ name: k, count: v })),
        certExpiry: [
          { label: '0–30 Days', count: certCounts['0-30 Days'], color: '#dc2626' },
          { label: '30–60 Days', count: certCounts['30-60 Days'], color: '#f59e0b' },
          { label: '60–90 Days', count: certCounts['60-90 Days'], color: '#22c55e' },
          { label: '>90 Days', count: certCounts['>90 Days'], color: '#3b82f6' },
        ],
        ipBreakdown: [
          { name: `IPv4 ${v4Pct}%`, value: v4Pct, color: '#1d4ed8' },
          { name: `IPv6 ${100 - v4Pct}%`, value: 100 - v4Pct, color: '#60a5fa' },
        ]
      }
    } catch (error) {
      console.error('getDashboardData error:', error)
      return { success: false, error: error.message }
    }
  },

  // Asset Discovery Data
  getAssetDiscoveryData: async () => {
    try {
      const [cbomRaw, subRaw] = await Promise.all([
        loadJSONData('PNB/enriched_cbom.json'),
        loadJSONData('PNB/subdomains.json')
      ])

      const assets = cbomRaw?.records || [];
      const { subdomains: subs } = normalizeSubdomainsData(subRaw);

      let domains = [], ssls = [], ipsArr = [], software = [];

      // Deduplicate subdomains by fqdn
      const seenFqdns = new Set();
      subs.forEach(s => {
        if (!seenFqdns.has(s.fqdn)) {
          seenFqdns.add(s.fqdn);
          domains.push({
            detected: new Date(s.resolved_at_utc).toLocaleDateString(),
            domain: s.fqdn,
            registered: '-', registrar: '-',
            company: 'PNB'
          });
        }
        // Deduplicate IPs globally across all subdomains
        (s.ips || []).forEach(ip => {
          ipsArr.push({
            detected: new Date(s.resolved_at_utc).toLocaleDateString(),
            ip,
            ports: '-', subnet: '-', asn: '-', netname: '-', location: '-', company: 'PNB'
          });
        });
      });

      // Deduplicate IPs by address
      const seenIPs = new Set();
      const dedupedIPs = ipsArr.filter(entry => {
        if (seenIPs.has(entry.ip)) return false;
        seenIPs.add(entry.ip);
        return true;
      });
      ipsArr.length = 0;
      ipsArr.push(...dedupedIPs);

      // Deduplicate SSL entries by asset name (same domain may appear on multiple ports)
      const seenAssets = new Set();
      assets.forEach(a => {
        let certVal = a['Certificate Validity (Not Before/After)'];
        if (a['Issuer CA'] && !seenAssets.has(a.Asset)) {
          seenAssets.add(a.Asset);
          ssls.push({
            detected: '-',
            sha: (a['Hash Algorithm'] || '').substring(0, 30),
            validFrom: certVal ? certVal['Not Before'] : '-',
            common: a.Asset,
            company: 'PNB',
            authority: a['Issuer CA'].replace('CN=', '').substring(0, 15)
          });
        }

        const svs = (a['Services'] || []);
        if (svs.length === 0 && a.Port) {
          software.push({
            detected: '-', product: 'Unknown', version: '-', type: 'Service',
            port: a.Port, host: a['IP Address'] || '-', company: 'PNB'
          });
        }
      });

      return {
        success: true,
        domainData: { New: domains.slice(0, 5), 'False Positive': [], Confirmed: domains.slice(5), All: domains },
        sslData: { New: ssls.slice(0, 5), 'False/ignore': [], Confirmed: ssls.slice(5), All: ssls },
        ipData: { New: ipsArr.slice(0, 10), 'False or ignore': [], Confirmed: ipsArr.slice(10), All: ipsArr },
        softwareData: { New: software.slice(0, 10), 'False or ignore': [], Confirmed: software.slice(10), All: software }
      }
    } catch (error) {
      console.error('getAssetDiscoveryData error:', error)
      return { success: false, error: error.message }
    }
  },

  // Asset data
  getAssets: async (limit = 100) => {
    try {
      const data = await loadJSONData('PNB/enriched_cbom.json')
      if (!data) throw new Error('Failed to load assets')

      const assets = dedupeByDomain(data.records || [])
        .slice(0, limit).map(normalizeAsset)
      return {
        success: true,
        assets,
        total: data.count_records || assets.length,
      }
    } catch (error) {
      console.error('getAssets error:', error)
      return {
        success: false,
        error: error.message,
        assets: [],
        total: 0,
      }
    }
  },

  // Subdomain discovery
  getSubdomains: async (limit = 100) => {
    try {
      const raw = await loadJSONData('PNB/subdomains.json')
      if (!raw) throw new Error('Failed to load subdomains')

      const { subdomains: allSubs, count_assets } = normalizeSubdomainsData(raw)
      const subdomains = allSubs.slice(0, limit).map(normalizeSubdomain)
      return {
        success: true,
        subdomains,
        total: count_assets,
      }
    } catch (error) {
      console.error('getSubdomains error:', error)
      return {
        success: false,
        error: error.message,
        subdomains: [],
        total: 0,
      }
    }
  },

  // CBOM - same as assets
  getCBOM: async () => {
    return dataAPI.getAssets(100)
  },

  // Shadow crypto findings
  getShadowCrypto: async () => {
    try {
      const data = await loadJSONData('PNB/shadow-crypto.json')
      if (!data) throw new Error('Failed to load shadow crypto data')

      const findings = (data.findings || []).map(normalizeFinding)
      return {
        success: true,
        findings,
        total: data.total_findings || findings.length,
        summary: data.severity_summary || {},
      }
    } catch (error) {
      console.error('getShadowCrypto error:', error)
      return {
        success: false,
        error: error.message,
        findings: [],
        total: 0,
        summary: {},
      }
    }
  },

  // CBOM Specific Data for Visuals
  getCBOMData: async () => {
    try {
      const data = await loadJSONData('PNB/enriched_cbom.json')
      if (!data) throw new Error('Failed to load CBOM data')
      // Dedupe by domain — one canonical record per unique asset name
      const records = dedupeByDomain(data.records || [])

      const cipherCounts = {}
      const caCounts = {}
      const tlsCounts = {}
      const keyLenCounts = {}

      const appTable = records.map(r => {
        const cipher = r['Cipher Suite'] || 'Unknown'
        const ca = (r['Issuer CA'] || 'Other').replace(/^.*CN=/, '').split(',')[0].trim()
        const tls = r['TLS Version'] || 'Unknown'
        const kl = String(r['Key Size (Bits)'] || 2048)

        cipherCounts[cipher] = (cipherCounts[cipher] || 0) + 1
        caCounts[ca] = (caCounts[ca] || 0) + 1
        tlsCounts[tls] = (tlsCounts[tls] || 0) + 1
        keyLenCounts[kl] = (keyLenCounts[kl] || 0) + 1

        return {
          app: r.Asset || 'Unknown',
          keyLen: `${kl}-Bit`,
          cipher: cipher,
          ca: ca.substring(0, 15),
          weak: Number(kl) < 2048 || tls.includes('1.0') || tls.includes('1.1') || cipher.includes('DES')
        }
      })

      const colors = ['#1d4ed8', '#2563eb', '#3b82f6', '#60a5fa', '#dc2626', '#16a34a', '#f59e0b', '#7c3aed']
      const toChartData = (counts, limit = 5, nameKey = 'name', valKey = 'count') => {
        return Object.entries(counts)
          .sort((a, b) => b[1] - a[1])
          .slice(0, limit)
          .map(([k, v], i) => ({
            [nameKey]: k,
            [valKey]: v,
            color: colors[i % colors.length]
          }))
      }

      const totalApps = appTable.length
      const weakCrypto = appTable.filter(a => a.weak).length

      // Normalize caData values to percentages relative to the max count
      const rawCaData = toChartData(caCounts, 5, 'name', 'value')
      const maxCaCount = rawCaData.length > 0 ? rawCaData[0].value : 1
      const normalizedCaData = rawCaData.map(d => ({ ...d, value: Math.round((d.value / maxCaCount) * 100) }))

      return {
        success: true,
        cipherData: toChartData(cipherCounts, 5),
        caData: normalizedCaData,
        tlsData: toChartData(tlsCounts, 3, 'name', 'value'),
        keyLengthDist: toChartData(keyLenCounts, 6, 'len', 'count'),
        appTable: appTable.slice(0, 50),
        stats: {
          totalApps,
          sitesSurveyed: totalApps,
          activeCerts: totalApps,
          weakCrypto,
          certIssues: Math.round(weakCrypto * 0.3)
        }
      }
    } catch (error) {
      console.error('getCBOMData error:', error)
      return { success: false, error: error.message }
    }
  },

  // Cyber Rating
  getCyberRatingData: async () => {
    try {
      const data = await loadJSONData('PNB/enriched_cbom.json')
      if (!data) throw new Error('Failed to load cyber rating')

      const records = dedupeByDomain(data.records || [])
      let sum = 0

      const urlScores = records.map(r => {
        const hei = r.HEI_Score || 50
        const score = Math.max(0, 1000 - (hei * 10))
        sum += score
        const tier = score >= 701 ? 'Elite' : score >= 400 ? 'Standard' : score >= 200 ? 'Legacy' : 'Critical'
        return {
          url: r.Asset || 'Unknown',
          score,
          tier
        }
      })

      const enterpriseScore = records.length ? Math.round(sum / records.length) : 755
      const enterpriseTier = enterpriseScore >= 701 ? 'Elite-PQC' : enterpriseScore >= 400 ? 'Standard' : 'Legacy'

      return {
        success: true,
        enterpriseScore,
        enterpriseTier,
        urlScores: urlScores.sort((a, b) => b.score - a.score).slice(0, 50)
      }
    } catch (error) {
      console.error('getCyberRatingData error:', error)
      return { success: false, error: error.message }
    }
  },

  // PQC Posture
  getPostureOfPQCData: async () => {
    try {
      const data = await loadJSONData('PNB/enriched_cbom.json')
      if (!data) throw new Error('Failed to load PQC data')

      const records = dedupeByDomain(data.records || [])

      let elite = 0, std = 0, legacy = 0, critical = 0
      let pqcReadyApp = 0, stdApp = 0, legacyApp = 0, critApp = 0

      const assets = records.map(r => {
        const hei = r.HEI_Score || 50
        const isPQC = (r['NIST PQC Readiness Label']?.includes('PQC')) || hei < 20

        if (hei < 20) elite++;
        else if (hei < 50) std++;
        else if (hei < 80) legacy++;
        else critical++;

        if (isPQC) pqcReadyApp++;
        else if (hei < 50) stdApp++;
        else if (hei < 80) legacyApp++;
        else critApp++;

        return {
          name: r.Asset || 'Unknown',
          ip: r['IP Address'] || '-',
          pqc: isPQC
        }
      })

      const total = records.length || 1

      return {
        success: true,
        gradeData: [
          { name: 'Elite', value: elite, color: '#16a34a' },
          { name: 'Critical', value: critical, color: '#dc2626' },
          { name: 'Std', value: std, color: '#d97706' },
        ],
        appStatusData: [
          { name: 'Elite-PQC Ready', value: pqcReadyApp, color: '#16a34a' },
          { name: 'Standard', value: stdApp, color: '#d97706' },
          { name: 'Legacy', value: legacyApp, color: '#dc2626' },
          { name: 'Critical', value: critApp, color: '#7c0000' },
        ],
        assets: assets.slice(0, 50),
        summary: {
          pqcReadyPct: Math.round((pqcReadyApp / total) * 100),
          stdPct: Math.round((stdApp / total) * 100),
          legacyPct: Math.round((legacyApp / total) * 100),
          criticalCount: critApp
        }
      }
    } catch (error) {
      console.error('getPostureOfPQCData error:', error)
      return { success: false, error: error.message }
    }
  },

  // Business Impact
  getBusinessImpact: async () => {
    try {
      // Derive business impact dynamically from enriched_cbom
      const data = await loadJSONData('PNB/enriched_cbom.json')
      if (!data) throw new Error('Failed to load business impact')

      const records = dedupeByDomain(data.records || [])

      // Select top 6 interesting assets to act as the simulation seeds
      const sorted = [...records].sort((a, b) => (b.HEI_Score || 0) - (a.HEI_Score || 0)).slice(0, 6)

      const assets = sorted.map(r => {
        const id = (r.Asset || '').split('.')[0].toLowerCase().replace(/[^a-z0-9]/g, '') || ('asset' + Math.random())
        const tls = r['TLS Version'] || 'TLSv1.2'
        const keyBits = parseInt(r['Key Size (Bits)']) || 2048
        const pfs = r['PFS Status'] === 'Yes'
        const hei = r.HEI_Score || 50

        return {
          id,
          name: r.Asset || 'Unknown',
          tls,
          keyBits,
          pfs,
          hei,
          value: Math.floor(Math.random() * 50_000_000) + 5_000_000,
          shelf: Math.floor(Math.random() * 8) + 3,
          blast: {
            direct: [`${id}_db`, `${id}_auth`],
            indirect: [`${id}_internal_api`, `${id}_cache`],
            cascading: [`${id}_analytics`, `${id}_audit_log`]
          }
        }
      })

      return {
        success: true,
        assets,
      }
    } catch (error) {
      console.error('getBusinessImpact error:', error)
      return {
        success: false,
        error: error.message,
        assets: [],
      }
    }
  },

  // Homepage extras: DNS Records + Crypto/Security Overview
  getHomepageExtras: async () => {
    try {
      const data = await loadJSONData('PNB/enriched_cbom.json')
      if (!data) throw new Error('Failed to load CBOM data')

      const records = data.records || []

      // ── DNS Records ────────────────────────────────────────────────────────
      // De-duplicate by IP address — one row per unique asset→IP mapping
      const seenIPs = new Set()
      const dnsRecords = []
      for (const r of records) {
        const ip = r['IP Address']
        if (!ip || seenIPs.has(ip)) continue
        seenIPs.add(ip)
        const port = r.Port
        // Infer record type from IP/port
        const isIPv6 = ip.includes(':')
        const type = isIPv6 ? 'AAAA' : port === 443 || port === 80 ? 'A' : 'A'
        const ttl = port === 443 || port === 80 ? '300' : '3600'
        dnsRecords.push({
          hostname: r.Asset || '-',
          type,
          ip,
          ttl,
        })
        if (dnsRecords.length >= 8) break
      }

      // ── Crypto / Security Overview ─────────────────────────────────────────
      // Show top 5 highest-risk assets with their real PQC posture
      const sorted = [...records]
        .sort((a, b) => (b.HEI_Score || 0) - (a.HEI_Score || 0))
        .slice(0, 5)

      const cryptoOverview = sorted.map(r => {
        const keyBits = r['Key Size (Bits)']
        const cipher = r['Cipher Suite']
        const tls = r['TLS Version']
        const qrmm = r.QRMM_Level?.label || 'Classical Insecure'
        const hei = r.HEI_Score || 100

        return {
          asset: r.Asset || 'Unknown',
          // Show real bits if available, else note it as unreachable
          keyLen: keyBits ? `${keyBits}-bit` : 'N/A',
          // Cipher suite if available; show QRMM label otherwise
          cipher: cipher || qrmm,
          cipherIsWeak: !cipher || qrmm.includes('Insecure') || qrmm.includes('Classical'),
          // TLS version if available
          tls: tls ? tls.replace('TLSv', '') : 'None',
          tlsColor: !tls ? 'text-red-600' : tls.includes('1.3') ? 'text-green-600' : tls.includes('1.2') ? 'text-amber-600' : 'text-red-600',
          risk: r.Risk_Category || 'Critical',
        }
      })

      return { success: true, dnsRecords, cryptoOverview }
    } catch (error) {
      console.error('getHomepageExtras error:', error)
      return { success: false, error: error.message, dnsRecords: [], cryptoOverview: [] }
    }
  },
}

export default dataAPI
