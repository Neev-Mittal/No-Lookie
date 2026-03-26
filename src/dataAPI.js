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
// Public Data APIs
// ─────────────────────────────────────────────────────────────────────────────

export const dataAPI = {
  // Asset data
  getAssets: async (limit = 100) => {
    try {
      const data = await loadJSONData('PNB/cbom.json')
      if (!data) throw new Error('Failed to load assets')
      
      const assets = (data.records || []).slice(0, limit).map(normalizeAsset)
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
      const data = await loadJSONData('PNB/subdomains.json')
      if (!data) throw new Error('Failed to load subdomains')
      
      const subdomains = (data.subdomains || []).slice(0, limit).map(normalizeSubdomain)
      return {
        success: true,
        subdomains,
        total: data.count_assets || subdomains.length,
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

  // PQC Posture
  getPostureOfPQC: async () => {
    try {
      const data = await loadJSONData('PNB/cbom.json')
      if (!data) throw new Error('Failed to load PQC data')
      
      const assets = (data.records || []).map(normalizeAsset)
      const pqcReady = assets.filter(a => a.pqcLabel.includes('PQC')).length
      
      return {
        success: true,
        assets,
        pqcReady,
        notReady: assets.length - pqcReady,
        total: assets.length,
      }
    } catch (error) {
      console.error('getPostureOfPQC error:', error)
      return {
        success: false,
        error: error.message,
        assets: [],
        pqcReady: 0,
        notReady: 0,
        total: 0,
      }
    }
  },

  // Cyber Rating
  getCyberRating: async () => {
    try {
      const data = await loadJSONData('PNB/enriched_cbom.json')
      if (!data) throw new Error('Failed to load cyber rating')
      
      const assets = (data.records || []).map(normalizeAsset)
      const avgScore = assets.length > 0
        ? assets.reduce((sum, a) => sum + (a.heiScore || 50), 0) / assets.length
        : 50
      
      const score = Math.round(avgScore * 10)
      const tier = score >= 701 ? 'Elite' : score >= 400 ? 'Standard' : score >= 200 ? 'Legacy' : 'Critical'
      
      return {
        success: true,
        assets,
        score,
        tier,
      }
    } catch (error) {
      console.error('getCyberRating error:', error)
      return {
        success: false,
        error: error.message,
        assets: [],
        score: 0,
        tier: 'Unknown',
      }
    }
  },

  // Business Impact
  getBusinessImpact: async () => {
    try {
      const data = await loadJSONData('simulation.json')
      if (!data) throw new Error('Failed to load business impact')
      
      const simulations = Array.isArray(data) ? data : [data]
      return {
        success: true,
        simulations,
      }
    } catch (error) {
      console.error('getBusinessImpact error:', error)
      return {
        success: false,
        error: error.message,
        simulations: [],
      }
    }
  },
}

export default dataAPI
