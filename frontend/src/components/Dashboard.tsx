import React, { useEffect, useState, useRef } from 'react'

interface Props {
  clusterInfo: any
  attackHistory: any[]
  detectionEvents: any[]
  infrastructureItems: any[]
  orchestratorStatus: any
  events: any[]
  send: (data: any) => void
  fetchApi: (path: string) => Promise<any>
  remediationReady: boolean
  remediationSessions: any[]
  mitreAttack: any
}

const severityColors: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
}

const severityDescriptions: Record<string, { description: string; criteria: string[] }> = {
  critical: {
    description: 'Immediate, severe threat to cluster integrity',
    criteria: [
      'Results in node-level access or container escape',
      'Exposes cluster-admin credentials or privileges',
      'Provides unrestricted access to secrets across namespaces',
      'Enables full cluster control via RBAC abuse',
    ],
  },
  high: {
    description: 'Significant risk of data exposure or resource compromise',
    criteria: [
      'Enables lateral movement within the cluster',
      'Deploys unauthorized compute workloads (resource hijacking)',
      'Maps internal network topology for further attack',
      'Potentially intercepts network traffic between services',
    ],
  },
  medium: {
    description: 'Moderate risk, primarily information gathering',
    criteria: [
      'Collects configuration data and metadata',
      'Discovers service topology via DNS enumeration',
      'Does not directly escalate privileges or expose credentials',
    ],
  },
  low: {
    description: 'Minimal risk, informational only',
    criteria: [
      'No direct impact on cluster security',
      'Gathers basic cluster metadata',
    ],
  },
}

function SeverityTooltip({ severity }: { severity: string }) {
  const [show, setShow] = useState(false)
  const ref = useRef<HTMLDivElement>(null)
  const info = severityDescriptions[severity] || severityDescriptions.medium

  return (
    <div ref={ref} style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}>
      <span
        onMouseEnter={() => setShow(true)}
        onMouseLeave={() => setShow(false)}
        style={{
          width: 13, height: 13, borderRadius: '50%', display: 'inline-flex',
          alignItems: 'center', justifyContent: 'center', cursor: 'help',
          background: `${severityColors[severity] || '#64748b'}30`,
          color: severityColors[severity] || '#64748b',
          fontSize: 8, fontWeight: 700, lineHeight: 1, marginLeft: 3,
          transition: 'background 0.15s',
        }}
      >i</span>
      {show && (
        <>
          <div style={{
            position: 'fixed', zIndex: 1000,
            top: ref.current ? ref.current.getBoundingClientRect().top - 8 : 0,
            left: ref.current ? ref.current.getBoundingClientRect().right + 8 : 0,
            background: '#1e293b', border: '1px solid #334155', borderRadius: 8,
            padding: 10, width: 240,
            boxShadow: '0 8px 32px rgba(0,0,0,0.5)',
            pointerEvents: 'none',
          }}
            onMouseEnter={() => setShow(true)}
            onMouseLeave={() => setShow(false)}
          >
            <div style={{
              fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
              color: severityColors[severity] || '#94a3b8', marginBottom: 4,
              letterSpacing: 0.5,
            }}>{severity.toUpperCase()} — {info.description}</div>
            <div style={{ fontSize: 9, color: '#64748b', marginBottom: 4 }}>Determined by:</div>
            {info.criteria.map((c, i) => (
              <div key={i} style={{ fontSize: 9, color: '#94a3b8', padding: '1px 0', display: 'flex', gap: 4 }}>
                <span style={{ color: '#475569' }}>•</span>
                <span>{c}</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}

function InfoTooltip({ label, description }: { label: string; description: string }) {
  const [show, setShow] = useState(false)
  const ref = useRef<HTMLSpanElement>(null)

  return (
    <span ref={ref} style={{ position: 'relative', display: 'inline-flex', alignItems: 'center', marginLeft: 6 }}>
      <span
        onMouseEnter={() => setShow(true)}
        onMouseLeave={() => setShow(false)}
        style={{
          width: 13, height: 13, borderRadius: '50%', display: 'inline-flex',
          alignItems: 'center', justifyContent: 'center', cursor: 'help',
          background: '#1e293b', color: '#64748b',
          fontSize: 8, fontWeight: 700, lineHeight: 1,
        }}
      >i</span>
      {show && (
        <div style={{
          position: 'absolute', zIndex: 1000, bottom: 'calc(100% + 6px)', left: '50%',
          transform: 'translateX(-50%)',
          background: '#1e293b', border: '1px solid #334155', borderRadius: 6,
          padding: '6px 10px', width: 200,
          boxShadow: '0 4px 16px rgba(0,0,0,0.5)',
          pointerEvents: 'none', fontSize: 9, color: '#94a3b8', lineHeight: 1.4,
          whiteSpace: 'normal',
        }}>
          {description}
        </div>
      )}
    </span>
  )
}

export function Dashboard({
  clusterInfo, attackHistory, detectionEvents, infrastructureItems,
  orchestratorStatus, events, send, fetchApi,
  remediationReady, remediationSessions, mitreAttack,
}: Props) {
  const [attacks, setAttacks] = useState<any[]>([])
  const [clusterLoading, setClusterLoading] = useState(false)
  const [severityFilter, setSeverityFilter] = useState<string>('all')

  useEffect(() => {
    fetchApi('/api/health').then(d => d?.remediation_ready && setRemediationReady(true))
  }, [])

  // Poll cluster info every 10s via WebSocket
  useEffect(() => {
    if (!clusterInfo?.ready) return
    const interval = setInterval(() => {
      send({ type: 'get_cluster_info' })
    }, 10000)
    return () => clearInterval(interval)
  }, [clusterInfo?.ready, send])

  const [remediationReadyLocal, setRemediationReady] = useState(false)
  const [sessions, setSessions] = useState<any[]>([])
  const [orchStatus, setOrchStatus] = useState<any>(null)
  const [reportLoading, setReportLoading] = useState(false)
  const [expandedLogs, setExpandedLogs] = useState<Set<string>>(new Set())
  const [chatOpen, setChatOpen] = useState(false)
  const [chatMessages, setChatMessages] = useState<{role: string; content: string}[]>([])
  const [chatInput, setChatInput] = useState('')
  const [chatLoading, setChatLoading] = useState(false)
  const chatEndRef = useRef<HTMLDivElement>(null)

  const PREBUILT_PROMPTS = [
    { label: 'Summarize attacks', msg: 'Summarize all attack results, including which attacks were successful, which failed, and their severity levels.' },
    { label: 'Critical findings', msg: 'Show me all critical and high severity findings from the attacks and detection alerts.' },
    { label: 'MITRE coverage', msg: 'Analyze the MITRE ATT&CK coverage. Which tactics were covered? Which techniques were used?' },
    { label: 'Remediation actions', msg: 'What remediation actions were taken? List each session, what the agent did, and whether it succeeded.' },
    { label: 'Security assessment', msg: 'Give me a complete security assessment summary of this cluster based on all available data.' },
  ]

  const sendChat = async (msg: string) => {
    if (!msg.trim() || chatLoading) return
    const userMsg = { role: 'user', content: msg }
    setChatMessages(prev => [...prev, userMsg])
    setChatInput('')
    setChatLoading(true)
    try {
      const history = chatMessages.map(m => ({ role: m.role, content: m.content }))
      const res = await fetch('/api/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: msg, history }),
      })
      const data = await res.json()
      setChatMessages(prev => [...prev, { role: 'assistant', content: data.response || 'No response' }])
    } catch {
      setChatMessages(prev => [...prev, { role: 'assistant', content: 'Error communicating with the chatbot.' }])
    }
    setChatLoading(false)
  }

  useEffect(() => {
    chatEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [chatMessages])

  const generateReport = async () => {
    setReportLoading(true)
    try {
      const res = await fetch('/api/report')
      if (!res.ok) throw new Error('Report generation failed')
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `k8s-security-report-${Date.now()}.pdf`
      document.body.appendChild(a)
      a.click()
      a.remove()
      URL.revokeObjectURL(url)
    } catch (e) {
      console.error('Report error:', e)
      alert('Failed to generate report. Make sure attacks have been run and the cluster is ready.')
    }
    setReportLoading(false)
  }

  useEffect(() => {
    if (orchestratorStatus) setOrchStatus(orchestratorStatus)
  }, [orchestratorStatus])

  useEffect(() => {
    if (remediationSessions.length > 0) setSessions(remediationSessions)
  }, [remediationSessions])

  const deployCluster = async () => {
    setClusterLoading(true)
    try {
      const res = await fetch('/api/cluster/create-and-attack', { method: 'POST' })
      const data = await res.json()
      console.log('Cluster + attacks:', data)
    } catch {}
    setTimeout(async () => {
      const info = await fetchApi('/api/cluster/info')
      setClusterLoading(false)
      send({ type: 'get_cluster_info' })
    }, 5000)
  }

  const runningAttacks = attackHistory.filter(a => a?.status === 'running')
  const pendingAttacks = attackHistory.filter(a => a?.status === 'pending')
  const completedAttacks = attackHistory.filter(a => a?.status === 'completed')
  const failedAttacks = attackHistory.filter(a => a?.status === 'failed')
  const criticalAlerts = detectionEvents.filter(e => e?.severity === 'critical').length
  const highAlerts = detectionEvents.filter(e => e?.severity === 'high').length

  const boxStyle: React.CSSProperties = {
    background: '#0f172a', border: '1px solid #1e293b', borderRadius: 10, padding: 16,
  }
  const labelStyle: React.CSSProperties = {
    fontSize: 10, color: '#64748b', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6,
  }

  return (
    <div>
      {/* Top action bar */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 14, alignItems: 'center' }}>
        <button onClick={deployCluster} disabled={clusterLoading} style={{
          padding: '8px 18px', borderRadius: 8, border: 'none', cursor: 'pointer',
          fontSize: 12, fontWeight: 700,
          background: clusterLoading ? '#475569' : 'linear-gradient(135deg, #3b82f6, #2563eb)',
          color: '#fff',
        }}>
          {clusterLoading ? 'Deploying...' : '🚀 Deploy Cluster & Run Attacks'}
        </button>
        <button onClick={generateReport} disabled={reportLoading} style={{
          padding: '8px 16px', borderRadius: 8, border: '1px solid #334155', cursor: 'pointer',
          fontSize: 12, fontWeight: 600,
          background: reportLoading ? '#1e293b' : 'transparent',
          color: '#cbd5e1',
        }}>
          {reportLoading ? 'Generating...' : '📄 Generate Report'}
        </button>
        <span style={{ fontSize: 11, color: '#64748b' }}>
          {clusterInfo?.ready ? `${clusterInfo.node_count} nodes · ${clusterInfo.pod_count} pods` : 'No cluster'}
        </span>
        {orchStatus?.status === 'running' && (
          <span style={{ fontSize: 11, color: '#22c55e', display: 'flex', alignItems: 'center', gap: 4 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', animation: 'pulse 1s infinite' }} />
            Running attacks...
          </span>
        )}
      </div>

      {/* Stats row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 8, marginBottom: 14 }}>
        <div style={{ ...boxStyle, borderLeft: '3px solid #3b82f6', padding: '10px 14px' }}>
          <div style={labelStyle}>Cluster</div>
          <div style={{ fontSize: 22, fontWeight: 700 }}>
            {clusterInfo?.ready ? `${clusterInfo.node_count || 0}N` : '—'}
          </div>
          <div style={{ fontSize: 10, color: '#475569' }}>{clusterInfo?.pod_count || 0} pods</div>
        </div>
        <div style={{ ...boxStyle, borderLeft: '3px solid #f97316', padding: '10px 14px' }}>
          <div style={labelStyle}>Attacks</div>
          <div style={{ fontSize: 22, fontWeight: 700 }}>
            {attackHistory.length}
          </div>
          <div style={{ fontSize: 10, color: '#475569' }}>
            {runningAttacks.length} running · {completedAttacks.length} completed · {failedAttacks.length} failed
          </div>
        </div>
        <div style={{ ...boxStyle, borderLeft: '3px solid #ef4444', padding: '10px 14px' }}>
          <div style={labelStyle}>Alerts</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: criticalAlerts > 0 ? '#ef4444' : '#22c55e' }}>
            {criticalAlerts + highAlerts}
          </div>
          <div style={{ fontSize: 10, color: '#475569' }}>{criticalAlerts} critical</div>
        </div>
        <div style={{ ...boxStyle, borderLeft: '3px solid #8b5cf6', padding: '10px 14px' }}>
          <div style={labelStyle}>AI Remediation</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#a78bfa' }}>{sessions.length}</div>
          <div style={{ fontSize: 10, color: '#475569' }}>
            {remediationReadyLocal ? 'Claude ready' : 'No API key'}
          </div>
        </div>
      </div>

      {/* Main grid: MITRE + Attack progress + Events */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
        {/* MITRE ATT&CK Matrix */}
        <div style={boxStyle}>
          <div style={{ ...labelStyle, fontSize: 11, display: 'flex', alignItems: 'center' }}>
            MITRE ATT&CK Coverage
            <InfoTooltip label="MITRE" description="MITRE ATT&CK tactics covered by completed attacks. Click any box to open the MITRE page for that tactic. Boxes light up green once an attack for that tactic completes." />
          </div>
          {mitreAttack ? (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: 6 }}>
              {Object.entries(mitreAttack).map(([key, tactic]: [string, any]) => {
                const completedHere = attackHistory.filter(
                  (a: any) => (a.mitre_tactic || a.result?.mitre_tactic) === key && a.status === 'completed'
                ).length
                const tacticId = tactic.id || ''
                const mitreUrl = tacticId.startsWith('TA')
                  ? `https://attack.mitre.org/tactics/${tacticId}/`
                  : `https://attack.mitre.org/techniques/${tacticId}/`
                const isComplete = completedHere > 0
                return (
                  <a key={key} href={mitreUrl} target="_blank" rel="noopener noreferrer"
                     style={{ textDecoration: 'none', color: 'inherit', display: 'block' }}>
                    <div style={{
                      background: isComplete ? '#162032' : '#0f172a',
                      borderRadius: 6, padding: 8,
                      border: `1px solid ${isComplete ? '#166534' : '#1e293b'}`,
                      borderLeft: `3px solid ${isComplete ? '#22c55e' : '#1e293b'}`,
                      transition: 'all 0.3s ease',
                      opacity: isComplete ? 1 : 0.4,
                      cursor: 'pointer',
                    }}
                      onMouseEnter={e => { e.currentTarget.style.background = isComplete ? '#1e293b' : '#162032' }}
                      onMouseLeave={e => { e.currentTarget.style.background = isComplete ? '#162032' : '#0f172a' }}
                    >
                      <div style={{ fontSize: 9, color: isComplete ? '#22c55e' : '#334155' }}>{tactic.id}</div>
                      <div style={{ fontSize: 11, fontWeight: 600, marginTop: 1, color: isComplete ? '#e0e0e0' : '#334155' }}>
                        {tactic.name}
                      </div>
                    </div>
                  </a>
                )
              })}
            </div>
          ) : (
            <div style={{ color: '#475569', fontSize: 11, textAlign: 'center', padding: 16 }}>Loading MITRE ATT&CK coverage...</div>
          )}
        </div>

        {/* Attack Progress */}
        <div style={boxStyle}>
          <div style={{ ...labelStyle, fontSize: 11, display: 'flex', alignItems: 'center' }}>
            Attack Progress
            <InfoTooltip label="Attacks" description="Status of each executed attack — pending, running, completed, or failed. Severity badges with tooltips explain the risk level of each attack." />
          </div>
          {attackHistory.length === 0 ? (
            <div style={{ color: '#475569', fontSize: 11, textAlign: 'center', padding: 20 }}>
              Click "Deploy Cluster & Run Attacks" to start
            </div>
          ) : (
            <div style={{ maxHeight: 280, overflowY: 'auto' }}>
              {attackHistory.map((a: any, i: number) => (
                <div key={i} style={{
                  display: 'flex', alignItems: 'center', gap: 8, padding: '5px 0',
                  borderBottom: '1px solid #1e293b', fontSize: 11,
                }}>
                  <span style={{
                    width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                    background: a.status === 'completed' ? '#22c55e'
                      : a.status === 'running' ? '#3b82f6'
                      : a.status === 'failed' ? '#ef4444' : '#eab308',
                  }} />
                  <span style={{ flex: 1, color: '#cbd5e1' }}>{a.name || a.attack_id || 'Attack'}</span>
                  {a.severity && (
                    <span style={{
                      fontSize: 9, padding: '1px 6px', borderRadius: 3, display: 'inline-flex', alignItems: 'center', gap: 2,
                      background: severityColors[a.severity] + '20',
                      color: severityColors[a.severity],
                    }}>
                      {a.severity}
                      <SeverityTooltip severity={a.severity} />
                    </span>
                  )}
                  <span style={{
                    fontSize: 9, padding: '1px 6px', borderRadius: 3,
                    background: a.status === 'completed' ? '#052e16'
                      : a.status === 'running' ? '#1e3a5f'
                      : a.status === 'failed' ? '#450a0a' : '#451a03',
                    color: a.status === 'completed' ? '#22c55e'
                      : a.status === 'running' ? '#60a5fa'
                      : a.status === 'failed' ? '#ef4444' : '#f97316',
                  }}>{a.status || 'pending'}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Bottom row: Infrastructure + Alerts + Live feed */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
        {/* Infrastructure affected */}
        <div style={boxStyle}>
          <div style={{ ...labelStyle, display: 'flex', alignItems: 'center' }}>
            Affected Infrastructure
            <InfoTooltip label="Infrastructure" description="Kubernetes resources created or modified by attacks, including pods, secrets, ConfigMaps, and RBAC bindings." />
          </div>
          {infrastructureItems.length === 0 ? (
            <div style={{ color: '#475569', fontSize: 11, textAlign: 'center', padding: 16 }}>No infrastructure affected yet</div>
          ) : (
            <div style={{ maxHeight: 200, overflowY: 'auto' }}>
              {infrastructureItems.slice(0, 15).map((item: any, i: number) => (
                <div key={i} style={{
                  display: 'flex', gap: 6, padding: '4px 0', borderBottom: '1px solid #1e293b',
                  fontSize: 10, alignItems: 'center',
                }}>
                  <span style={{
                    fontSize: 9, padding: '1px 5px', borderRadius: 3,
                    background: '#1e293b', color: '#64748b', fontWeight: 600, flexShrink: 0,
                  }}>{item.resource_type}</span>
                  <span style={{ color: '#94a3b8', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {item.name}
                  </span>
                  <span style={{ color: '#475569', flexShrink: 0 }}>{item.namespace}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Detection alerts */}
        <div style={boxStyle}>
          <div style={{ ...labelStyle, display: 'flex', alignItems: 'center' }}>
            Detection Alerts
            <InfoTooltip label="Alerts" description="Security alerts generated by the detection monitor during attacks. Filter by severity to focus on critical or high-priority incidents." />
          </div>
          <div style={{ display: 'flex', gap: 6, marginBottom: 8 }}>
            {['all', 'critical', 'high', 'medium', 'low'].map(s => (
              <button key={s} onClick={() => setSeverityFilter(s)} style={{
                padding: '2px 8px', borderRadius: 4, border: '1px solid', cursor: 'pointer',
                fontSize: 9, fontWeight: 600, textTransform: 'capitalize',
                background: severityFilter === s ? (s === 'all' ? '#1e293b' : `${severityColors[s] || '#64748b'}20`) : 'transparent',
                color: severityFilter === s ? (s === 'all' ? '#cbd5e1' : severityColors[s] || '#94a3b8') : '#64748b',
                borderColor: severityFilter === s ? (s === 'all' ? '#334155' : severityColors[s] || '#334155') : '#1e293b',
              }}>{s === 'all' ? 'All' : s}</button>
            ))}
          </div>
          {(() => {
            const filtered = severityFilter === 'all'
              ? detectionEvents
              : detectionEvents.filter((e: any) => e.severity === severityFilter)
            return filtered.length === 0 ? (
              <div style={{ color: '#475569', fontSize: 11, textAlign: 'center', padding: 16 }}>No alerts yet</div>
            ) : (
              <div style={{ maxHeight: 160, overflowY: 'auto' }}>
                {filtered.slice(0, 15).map((e: any, i: number) => (
                <div key={i} style={{
                  display: 'flex', gap: 6, padding: '4px 0', borderBottom: '1px solid #1e293b',
                  fontSize: 10, alignItems: 'center',
                }}>
                  <span style={{
                    width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                    background: severityColors[e.severity] || '#64748b',
                  }} />
                  <span style={{ color: '#94a3b8', flex: 1 }}>{e.name}</span>
                  <span style={{
                    fontSize: 9, padding: '1px 5px', borderRadius: 3, display: 'inline-flex', alignItems: 'center', gap: 2,
                    background: severityColors[e.severity] + '20',
                    color: severityColors[e.severity],
                  }}>
                    {e.severity}
                    <SeverityTooltip severity={e.severity} />
                  </span>
                </div>
              ))}
            </div>
            )
          })()}
        </div>

        {/* Live event feed */}
        <div style={boxStyle}>
          <div style={{ ...labelStyle, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ display: 'flex', alignItems: 'center' }}>
              Live Event Feed
              <InfoTooltip label="Events" description="Real-time event stream of all platform activity — attack events, detection alerts, infrastructure changes, and remediation status updates." />
            </span>
            <span style={{ color: '#475569' }}>{events.length} events</span>
          </div>
          <div style={{ maxHeight: 200, overflowY: 'auto', fontSize: 10, fontFamily: '"JetBrains Mono", monospace' }}>
            {events.slice(0, 20).map((e: any, i: number) => {
              const colorMap: Record<string, string> = {
                attack_event: '#3b82f6', attack_started: '#8b5cf6', attack_completed: '#22c55e',
                detection_alert: '#f97316', infrastructure_affected: '#14b8a6',
                cluster_creating: '#eab308', cluster_ready: '#22c55e', cluster_error: '#ef4444',
                orchestrator_started: '#8b5cf6', orchestrator_completed: '#22c55e',
                remediation_queued: '#a78bfa', remediation_started: '#8b5cf6',
                remediation_completed: '#22c55e',
              }
              const color = colorMap[e.type] || '#64748b'
              const ts = e.receivedAt || Date.now()
              const time = new Date(ts).toLocaleTimeString('en-US', { hour12: false })
              return (
                <div key={i} style={{
                  padding: '2px 0', borderBottom: '1px solid #0f172a',
                  display: 'flex', gap: 6, color: '#94a3b8',
                }}>
                  <span style={{ color: '#475569', flexShrink: 0 }}>{time}</span>
                  <span style={{ color, flexShrink: 0 }}>[{e.type?.slice(0, 18)}]</span>
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {e.message || e.event?.message || ''}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* Attack Logs */}
      <div style={{ ...boxStyle, marginTop: 14 }}>
        <div style={{ ...labelStyle, fontSize: 11, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <span style={{ display: 'flex', alignItems: 'center' }}>
            Attack Logs
            <InfoTooltip label="Logs" description="Detailed logs for each attack, including terminal-style command blocks with kubectl commands and raw output. Click to expand/collapse." />
          </span>
          <span style={{ color: '#475569', fontSize: 10, fontWeight: 400 }}>
            {attackHistory.filter(a => (a.events?.length || 0) > 0).length} attacks with logs
          </span>
        </div>
        {attackHistory.filter(a => (a.events?.length || 0) > 0).length === 0 ? (
          <div style={{ color: '#475569', fontSize: 11, textAlign: 'center', padding: 20, fontFamily: '"JetBrains Mono", monospace' }}>
            No attack logs yet — deploy cluster and run attacks
          </div>
        ) : (
          <div>
            {attackHistory.filter(a => (a.events?.length || 0) > 0).map((attack: any) => {
              const hasLogs = (attack.events?.length || 0) > 0
              const key = attack.attack_id || attack.name
              const expanded = expandedLogs.has(key)
              if (!hasLogs) return null
              return (
                <div key={key} style={{
                  border: '1px solid #1e293b', borderRadius: 6, marginBottom: 6, overflow: 'hidden',
                }}>
                  <div
                    onClick={() => {
                      const next = new Set(expandedLogs)
                      if (expanded) next.delete(key); else next.add(key)
                      setExpandedLogs(next)
                    }}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 8, padding: '7px 10px',
                      background: '#162032', cursor: 'pointer', userSelect: 'none',
                      fontSize: 11,
                    }}
                  >
                    <span style={{
                      fontSize: 9, transition: 'transform 0.15s',
                      display: 'inline-block', transform: expanded ? 'rotate(90deg)' : 'none',
                      color: '#64748b',
                    }}>▶</span>
                    <span style={{
                      width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                      background: attack.status === 'completed' ? '#22c55e'
                        : attack.status === 'running' ? '#3b82f6'
                        : attack.status === 'failed' ? '#ef4444' : '#eab308',
                    }} />
                    <span style={{ color: '#cbd5e1', fontWeight: 600, flex: 1 }}>{attack.name || attack.attack_id}</span>
                    {attack.severity && (
                      <span style={{
                        fontSize: 9, padding: '1px 6px', borderRadius: 3,
                        background: severityColors[attack.severity] + '20',
                        color: severityColors[attack.severity],
                      }}>{attack.severity}</span>
                    )}
                    <span style={{
                      fontSize: 9, padding: '1px 6px', borderRadius: 3,
                      background: attack.status === 'completed' ? '#052e16'
                        : attack.status === 'running' ? '#1e3a5f'
                        : attack.status === 'failed' ? '#450a0a' : '#451a03',
                      color: attack.status === 'completed' ? '#22c55e'
                        : attack.status === 'running' ? '#60a5fa'
                        : attack.status === 'failed' ? '#ef4444' : '#f97316',
                    }}>{attack.status}</span>
                    <span style={{ fontSize: 9, color: '#475569' }}>{attack.events?.length || 0} events</span>
                  </div>
                  {expanded && (
                    <div style={{
                      background: '#0a0e17', padding: 8, maxHeight: 300, overflowY: 'auto',
                      fontSize: 10, fontFamily: '"JetBrains Mono", monospace', lineHeight: 1.6,
                    }}>
                      {(attack.events || []).map((evt: any, ei: number) => {
                        const typeColors: Record<string, string> = {
                          start: '#8b5cf6', info: '#3b82f6', success: '#22c55e',
                          warning: '#f97316', error: '#ef4444', complete: '#22c55e',
                          critical: '#ef4444', detected: '#ef4444',
                        }
                        const tc = typeColors[evt.event_type] || '#64748b'
                        const ts = evt.timestamp ? new Date(evt.timestamp * 1000).toLocaleTimeString('en-US', { hour12: false }) : ''
                        const dataStr = evt.data && Object.keys(evt.data).length > 0
                          ? JSON.stringify(evt.data, null, 1).slice(0, 400)
                          : null

                        // Render cmd events as terminal-style blocks
                        if (evt.event_type === 'cmd') {
                          const cmd = evt.data?.command || ''
                          const output = evt.data?.output || ''
                          return (
                            <div key={ei} style={{ padding: '2px 0', borderBottom: '1px solid #0f172a' }}>
                              <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
                                {ts && <span style={{ color: '#475569', flexShrink: 0 }}>{ts}</span>}
                                <span style={{ color: '#22c55e', flexShrink: 0, fontWeight: 600 }}>$</span>
                              </div>
                              <pre style={{
                                margin: '2px 0', padding: '6px 10px', background: '#0a0e17',
                                border: '1px solid #1a2e1a', borderRadius: 4,
                                color: '#22c55e', fontSize: 9.5, overflow: 'auto',
                                whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                                lineHeight: 1.5,
                              }}>{cmd}</pre>
                              {output && (
                                <pre style={{
                                  margin: '0 0 2px 0', padding: '4px 10px', background: '#0f172a',
                                  border: '1px solid #1e293b', borderRadius: 4,
                                  color: '#94a3b8', fontSize: 9, overflow: 'auto',
                                  whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                                  lineHeight: 1.4,
                                }}>{output}</pre>
                              )}
                            </div>
                          )
                        }

                        return (
                          <div key={ei} style={{ padding: '1px 0', borderBottom: '1px solid #0f172a' }}>
                            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                              {ts && <span style={{ color: '#475569', flexShrink: 0 }}>{ts}</span>}
                              <span style={{
                                color: tc, flexShrink: 0, fontWeight: 600,
                              }}>[{evt.event_type?.toUpperCase()}]</span>
                              <span style={{ color: '#94a3b8' }}>{evt.message}</span>
                            </div>
                            {dataStr && (
                              <pre style={{
                                margin: '2px 0 0 0', padding: '4px 8px', background: '#0f172a',
                                borderRadius: 3, color: '#64748b', fontSize: 9, overflow: 'auto',
                                whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                              }}>{dataStr}</pre>
                            )}
                          </div>
                        )
                      })}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Chat button */}
      <button onClick={() => setChatOpen(true)}
        style={{
          position: 'fixed', bottom: 20, right: 20, zIndex: 999,
          width: 48, height: 48, borderRadius: '50%', border: 'none', cursor: 'pointer',
          background: 'linear-gradient(135deg, #8b5cf6, #6d28d9)',
          color: '#fff', fontSize: 18, boxShadow: '0 4px 16px rgba(139,92,246,0.4)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
        }}
      >💬</button>

      {/* Chat panel */}
      {chatOpen && (
        <div style={{
          position: 'fixed', bottom: 80, right: 20, zIndex: 999,
          width: 380, height: 520, background: '#0f172a', borderRadius: 12,
          border: '1px solid #1e293b', boxShadow: '0 8px 40px rgba(0,0,0,0.6)',
          display: 'flex', flexDirection: 'column', overflow: 'hidden',
        }}>
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '10px 14px', borderBottom: '1px solid #1e293b',
            background: '#162032',
          }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: '#c4b5fd' }}>🤖 AI Security Chat</span>
            <button onClick={() => setChatOpen(false)}
              style={{ background: 'none', border: 'none', color: '#64748b', cursor: 'pointer', fontSize: 14 }}
            >✕</button>
          </div>

          {/* Prebuilt prompts */}
          <div style={{
            padding: '8px 10px', borderBottom: '1px solid #1e293b',
            display: 'flex', gap: 4, flexWrap: 'wrap',
          }}>
            {PREBUILT_PROMPTS.map((p, i) => (
              <button key={i} onClick={() => sendChat(p.msg)}
                style={{
                  padding: '4px 8px', borderRadius: 4, border: '1px solid #334155',
                  fontSize: 9, cursor: 'pointer', background: '#162032', color: '#94a3b8',
                  whiteSpace: 'nowrap',
                }}
              >{p.label}</button>
            ))}
          </div>

          {/* Messages */}
          <div style={{ flex: 1, overflowY: 'auto', padding: 10 }}>
            {chatMessages.length === 0 && (
              <div style={{ fontSize: 10, color: '#475569', textAlign: 'center', padding: 30, lineHeight: 1.8 }}>
                Ask me anything about the platform data.<br/>
                Try clicking one of the prompts above.
              </div>
            )}
            {chatMessages.map((m, i) => (
              <div key={i} style={{
                marginBottom: 10, padding: 10, borderRadius: 8,
                background: m.role === 'user' ? '#1e293b' : 'transparent',
                border: m.role === 'assistant' ? 'none' : 'none',
              }}>
                <div style={{ fontSize: 9, color: '#64748b', marginBottom: 4, fontWeight: 600 }}>
                  {m.role === 'user' ? 'You' : 'Claude'}
                </div>
                <div style={{
                  fontSize: 10.5, lineHeight: 1.6, color: '#cbd5e1',
                  whiteSpace: 'pre-wrap',
                }}>
                  {m.role === 'assistant' ? (
                    <span dangerouslySetInnerHTML={{ __html: m.content
                      .replace(/<table>/g, '<div style="overflow-x:auto;margin:6px 0"><table style="border-collapse:collapse;width:100%;font-size:9px">')
                      .replace(/<tr>/g, '<tr style="border-bottom:1px solid #1e293b">')
                      .replace(/<td>/g, '<td style="padding:4px 6px;color:#94a3b8">')
                      .replace(/<th>/g, '<th style="padding:4px 6px;color:#cbd5e1;font-weight:700;text-align:left">')
                      .replace(/<code>/g, '<code style="background:#1e293b;padding:1px 4px;border-radius:3px;font-size:9px;color:#22c55e">')
                      .replace(/<b>/g, '<b style="color:#e2e8f0">')
                    }} />
                  ) : (
                    m.content.split('\n').map((line, li) => {
                      return <div key={li} style={{ marginTop: line.trim() === '' ? 4 : 0 }}>{line}</div>
                    })
                  )}
                </div>
              </div>
            ))}
            {chatLoading && (
              <div style={{
                padding: 10, borderRadius: 8, background: '#0a0e17',
                border: '1px solid #162032', fontSize: 10, color: '#64748b',
              }}>
                <span style={{ animation: 'pulse 1s infinite' }}>Claude is thinking...</span>
              </div>
            )}
            <div ref={chatEndRef} />
          </div>

          {/* Input */}
          <div style={{
            padding: '8px 10px', borderTop: '1px solid #1e293b',
            display: 'flex', gap: 6,
          }}>
            <input
              value={chatInput}
              onChange={e => setChatInput(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && sendChat(chatInput)}
              placeholder="Ask about the security data..."
              style={{
                flex: 1, background: '#1e293b', border: '1px solid #334155', borderRadius: 6,
                padding: '7px 10px', fontSize: 10, color: '#cbd5e1', outline: 'none',
              }}
            />
            <button onClick={() => sendChat(chatInput)} disabled={chatLoading || !chatInput.trim()}
              style={{
                padding: '7px 12px', borderRadius: 6, border: 'none', cursor: 'pointer',
                fontSize: 10, fontWeight: 600,
                background: chatLoading ? '#334155' : '#8b5cf6', color: '#fff',
              }}
            >Send</button>
          </div>
        </div>
      )}
    </div>
  )
}
