import { useMemo, useState } from 'react'
import {
  Chart as ChartJS,
  ArcElement,
  Tooltip,
  Legend,
  CategoryScale,
  LinearScale,
  BarElement,
} from 'chart.js'
import { Pie, Bar } from 'react-chartjs-2'
import './App.css'

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement)

const DEFAULT_PARSER_URL = 'http://localhost:8000/api/pcap/parse'
const DEFAULT_LLM_PROVIDER = 'openai'
const DEFAULT_LLM_MODEL = 'local-model'
const DEFAULT_LLM_ENDPOINTS = {
  openai: 'http://localhost:1234/v1/chat/completions',
  ollama: 'http://localhost:11434/api/chat',
}

const STORAGE_KEYS = {
  parserUrl: 'wireshark_agent_parser_url',
  llmProvider: 'wireshark_agent_llm_provider',
  llmEndpoint: 'wireshark_agent_llm_endpoint',
  llmModel: 'wireshark_agent_llm_model',
}

function getStoredValue(key, fallback) {
  if (typeof window === 'undefined') return fallback
  const saved = window.localStorage.getItem(key)
  return saved || fallback
}

function formatNumber(value) {
  if (value === null || value === undefined) return '—'
  return new Intl.NumberFormat().format(value)
}

function formatBytes(bytes) {
  if (bytes === null || bytes === undefined) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let value = Number(bytes)
  if (Number.isNaN(value)) return '—'
  let unitIndex = 0
  while (value >= 1024 && unitIndex < units.length - 1) {
    value /= 1024
    unitIndex += 1
  }
  return `${value.toFixed(value >= 10 || unitIndex === 0 ? 0 : 1)} ${units[unitIndex]}`
}

function extractProtocols(summary) {
  if (!summary) return []
  if (Array.isArray(summary.protocols)) return summary.protocols
  if (summary.protocols && typeof summary.protocols === 'object') {
    return Object.entries(summary.protocols).map(([name, count]) => ({ name, count }))
  }
  return []
}

function sliceList(items, limit = 8) {
  if (!Array.isArray(items)) return []
  return items.slice(0, limit)
}

function buildPrompt(analysis) {
  const summary = analysis?.summary || {}
  const protocols = extractProtocols(summary)
  const topTalkers = Array.isArray(summary.top_talkers) ? summary.top_talkers : []
  const alerts = Array.isArray(summary.alerts) ? summary.alerts : []
  const flows = Array.isArray(analysis?.flows) ? analysis.flows : []

  return [
    'You are a network traffic analyst. Provide a concise, actionable report based on this PCAP analysis.',
    '',
    'Summary:',
    `- Capture start: ${summary.capture_start || 'unknown'}`,
    `- Capture end: ${summary.capture_end || 'unknown'}`,
    `- Packet count: ${summary.packet_count ?? 'unknown'}`,
    `- Total bytes: ${summary.total_bytes ?? summary.bytes ?? 'unknown'}`,
    '',
    'Protocols:',
    ...sliceList(protocols, 10).map((item) => `- ${item.name}: ${item.count}`),
    '',
    'Top talkers:',
    ...sliceList(topTalkers, 10).map(
      (item) =>
        `- ${item.ip || item.host || 'unknown'} (${item.bytes ?? item.packets ?? 'n/a'})`
    ),
    '',
    'Alerts / anomalies:',
    ...sliceList(alerts, 12).map((item) => `- ${item}`),
    '',
    'Notable flows:',
    ...sliceList(flows, 12).map((flow) => {
      const src = flow.src || flow.source || 'unknown'
      const dst = flow.dst || flow.destination || 'unknown'
      const proto = flow.protocol || flow.proto || 'unknown'
      const bytes = flow.bytes ?? flow.total_bytes ?? 'n/a'
      return `- ${src} -> ${dst} (${proto}, ${bytes})`
    }),
    '',
    'Return:',
    '1) Executive summary (3-5 bullets)',
    '2) Key risks or anomalies',
    '3) Recommended next steps (Wireshark filters or validation steps)',
  ]
    .filter(Boolean)
    .join('\n')
}

async function parsePcap(file, parserUrl) {
  const formData = new FormData()
  formData.append('pcap', file)

  const response = await fetch(parserUrl, {
    method: 'POST',
    body: formData,
  })

  if (!response.ok) {
    const message = await response.text()
    throw new Error(message || `Parser error: ${response.status}`)
  }
  return response.json()
}

async function queryLlm({ provider, endpoint, model, prompt }) {
  if (provider === 'ollama') {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model,
        messages: [
          { role: 'system', content: 'You are a helpful network analyst.' },
          { role: 'user', content: prompt },
        ],
        stream: false,
      }),
    })
    if (!response.ok) {
      const message = await response.text()
      throw new Error(message || `LLM error: ${response.status}`)
    }
    const data = await response.json()
    return data?.message?.content || 'No response from LLM.'
  }

  const response = await fetch(endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      model,
      messages: [
        { role: 'system', content: 'You are a helpful network analyst.' },
        { role: 'user', content: prompt },
      ],
      temperature: 0.2,
    }),
  })

  if (!response.ok) {
    const message = await response.text()
    throw new Error(message || `LLM error: ${response.status}`)
  }
  const data = await response.json()
  return data?.choices?.[0]?.message?.content || 'No response from LLM.'
}

function App() {
  const [parserUrl, setParserUrl] = useState(
    getStoredValue(STORAGE_KEYS.parserUrl, DEFAULT_PARSER_URL)
  )
  const [llmProvider, setLlmProvider] = useState(
    getStoredValue(STORAGE_KEYS.llmProvider, DEFAULT_LLM_PROVIDER)
  )
  const [llmEndpoint, setLlmEndpoint] = useState(() => {
    const stored = getStoredValue(
      STORAGE_KEYS.llmEndpoint,
      DEFAULT_LLM_ENDPOINTS[DEFAULT_LLM_PROVIDER]
    )
    return stored
  })
  const [llmModel, setLlmModel] = useState(
    getStoredValue(STORAGE_KEYS.llmModel, DEFAULT_LLM_MODEL)
  )
  const [file, setFile] = useState(null)
  const [analysis, setAnalysis] = useState(null)
  const [llmReport, setLlmReport] = useState('')
  const [status, setStatus] = useState('idle')
  const [error, setError] = useState('')

  const protocols = useMemo(() => extractProtocols(analysis?.summary), [analysis])
  const topTalkers = useMemo(
    () => (Array.isArray(analysis?.summary?.top_talkers) ? analysis.summary.top_talkers : []),
    [analysis]
  )

  const protocolChart = useMemo(() => {
    if (!protocols.length) return null
    return {
      labels: protocols.map((item) => item.name),
      datasets: [
        {
          data: protocols.map((item) => item.count),
          backgroundColor: [
            '#0b4b60',
            '#f2a65a',
            '#2a9d8f',
            '#264653',
            '#e76f51',
            '#457b9d',
            '#9d4edd',
            '#e9c46a',
            '#1d3557',
            '#00b4d8',
          ],
          borderWidth: 0,
        },
      ],
    }
  }, [protocols])

  const talkersChart = useMemo(() => {
    if (!topTalkers.length) return null
    const trimmed = topTalkers.slice(0, 8)
    return {
      labels: trimmed.map((item) => item.ip || item.host || 'unknown'),
      datasets: [
        {
          label: 'Bytes',
          data: trimmed.map((item) => item.bytes ?? item.packets ?? 0),
          backgroundColor: '#0b4b60',
          borderRadius: 8,
        },
      ],
    }
  }, [topTalkers])

  const handleFileChange = (event) => {
    const nextFile = event.target.files?.[0] || null
    setFile(nextFile)
    setAnalysis(null)
    setLlmReport('')
    setError('')
  }

  const handleProviderChange = (event) => {
    const value = event.target.value
    setLlmProvider(value)
    const defaultEndpoint = DEFAULT_LLM_ENDPOINTS[value]
    setLlmEndpoint(defaultEndpoint)
    window.localStorage.setItem(STORAGE_KEYS.llmProvider, value)
    window.localStorage.setItem(STORAGE_KEYS.llmEndpoint, defaultEndpoint)
  }

  const persistSetting = (key, value) => {
    window.localStorage.setItem(key, value)
  }

  const handleAnalyze = async () => {
    if (!file) {
      setError('Please choose a PCAP file first.')
      return
    }
    setStatus('parsing')
    setError('')
    setAnalysis(null)
    setLlmReport('')

    try {
      const parsed = await parsePcap(file, parserUrl)
      setAnalysis(parsed)
      setStatus('reasoning')

      const prompt = buildPrompt(parsed)
      const report = await queryLlm({
        provider: llmProvider,
        endpoint: llmEndpoint,
        model: llmModel,
        prompt,
      })
      setLlmReport(report)
      setStatus('done')
    } catch (err) {
      setStatus('idle')
      setError(err?.message || 'Something went wrong.')
    }
  }

  return (
    <div className="page">
      <header className="hero">
        <div>
          <p className="eyebrow">Wireshark AI Agent</p>
          <h1>
            Analyze PCAPs, surface anomalies, and get actionable Wireshark filters in seconds.
          </h1>
          <p className="subtitle">
            Upload a capture, let the parser extract protocol details, and send a structured summary
            to your local LLM for fast, private analysis.
          </p>
          <div className="hero-actions">
            <button
              className="primary"
              onClick={handleAnalyze}
              disabled={status === 'parsing' || status === 'reasoning'}
            >
              {status === 'parsing'
                ? 'Parsing PCAP...'
                : status === 'reasoning'
                ? 'Querying LLM...'
                : 'Analyze PCAP'}
            </button>
            <label className="file-pill">
              <input type="file" accept=".pcap,.pcapng" onChange={handleFileChange} />
              {file ? file.name : 'Choose PCAP file'}
            </label>
          </div>
          {error && <div className="error">{error}</div>}
        </div>
        <div className="hero-card">
          <div className="card-title">System Configuration</div>
          <div className="field">
            <label>Parser API URL</label>
            <input
              value={parserUrl}
              onChange={(event) => setParserUrl(event.target.value)}
              onBlur={(event) => persistSetting(STORAGE_KEYS.parserUrl, event.target.value)}
              placeholder={DEFAULT_PARSER_URL}
            />
            <span className="hint">Expected: multipart upload with field `pcap`.</span>
          </div>
          <div className="field">
            <label>LLM Provider</label>
            <select value={llmProvider} onChange={handleProviderChange}>
              <option value="openai">OpenAI-compatible</option>
              <option value="ollama">Ollama</option>
            </select>
          </div>
          <div className="field">
            <label>LLM Endpoint</label>
            <input
              value={llmEndpoint}
              onChange={(event) => setLlmEndpoint(event.target.value)}
              onBlur={(event) => persistSetting(STORAGE_KEYS.llmEndpoint, event.target.value)}
              placeholder={DEFAULT_LLM_ENDPOINTS[llmProvider]}
            />
            <span className="hint">
              If this site is hosted on GitHub Pages (HTTPS), your LLM endpoint must also be HTTPS.
            </span>
          </div>
          <div className="field">
            <label>LLM Model</label>
            <input
              value={llmModel}
              onChange={(event) => setLlmModel(event.target.value)}
              onBlur={(event) => persistSetting(STORAGE_KEYS.llmModel, event.target.value)}
              placeholder="e.g. mistral, llama3, qwen"
            />
          </div>
          <div className="tags">
            <span>Local-first</span>
            <span>Private traffic</span>
            <span>GitHub Pages</span>
          </div>
        </div>
      </header>

      <section className="grid">
        <div className="panel">
          <div className="panel-header">Capture Summary</div>
          {analysis?.summary ? (
            <div className="stats">
              <div>
                <p>Packets</p>
                <h3>{formatNumber(analysis.summary.packet_count)}</h3>
              </div>
              <div>
                <p>Total bytes</p>
                <h3>{formatBytes(analysis.summary.total_bytes ?? analysis.summary.bytes)}</h3>
              </div>
              <div>
                <p>Capture window</p>
                <h3>
                  {analysis.summary.capture_start || '—'} → {analysis.summary.capture_end || '—'}
                </h3>
              </div>
              <div>
                <p>Unique hosts</p>
                <h3>{formatNumber(analysis.summary.unique_hosts)}</h3>
              </div>
            </div>
          ) : (
            <div className="empty-state">
              Upload a PCAP and run analysis to see the capture summary.
            </div>
          )}
        </div>

        <div className="panel">
          <div className="panel-header">Protocol Distribution</div>
          {protocolChart ? (
            <div className="chart-wrap">
              <Pie
                data={protocolChart}
                options={{
                  plugins: {
                    legend: {
                      position: 'bottom',
                      labels: { boxWidth: 12, color: '#1f3347' },
                    },
                  },
                }}
              />
            </div>
          ) : (
            <div className="empty-state">Protocol distribution will appear here.</div>
          )}
        </div>
      </section>

      <section className="grid">
        <div className="panel">
          <div className="panel-header">Top Talkers (Bytes)</div>
          {talkersChart ? (
            <div className="chart-wrap tall">
              <Bar
                data={talkersChart}
                options={{
                  indexAxis: 'y',
                  scales: {
                    x: { ticks: { color: '#1f3347' }, grid: { color: 'rgba(16,32,50,0.08)' } },
                    y: { ticks: { color: '#1f3347' }, grid: { display: false } },
                  },
                  plugins: {
                    legend: { display: false },
                  },
                }}
              />
            </div>
          ) : (
            <div className="empty-state">Top talkers will render once parsing finishes.</div>
          )}
        </div>

        <div className="panel">
          <div className="panel-header">Anomalies & Alerts</div>
          {analysis?.summary?.alerts?.length ? (
            <ul className="list">
              {analysis.summary.alerts.map((alert, index) => (
                <li key={`${alert}-${index}`}>{alert}</li>
              ))}
            </ul>
          ) : (
            <div className="empty-state">No anomalies reported yet.</div>
          )}
        </div>
      </section>

      <section className="panel wide">
        <div className="panel-header">AI Narrative Report</div>
        {llmReport ? (
          <div className="report">
            {llmReport.split('\n').map((line, index) => (
              <p key={`${line}-${index}`}>{line}</p>
            ))}
          </div>
        ) : (
          <div className="empty-state">
            The LLM report will appear here after the analysis completes.
          </div>
        )}
      </section>

      <section className="panel wide">
        <div className="panel-header">Raw JSON</div>
        {analysis ? (
          <pre className="code-block">{JSON.stringify(analysis, null, 2)}</pre>
        ) : (
          <div className="empty-state">Parser JSON output will be shown here.</div>
        )}
      </section>

      <footer className="footer">
        <p>
          Tip: For best results, keep your parser and LLM on the same machine. The frontend stays
          static for GitHub Pages, while analysis happens on your local endpoints.
        </p>
      </footer>
    </div>
  )
}

export default App
