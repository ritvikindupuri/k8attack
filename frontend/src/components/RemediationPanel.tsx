import React, { useEffect, useState, useRef } from 'react'

interface RemediationStep {
  thinking: string
  command: string | null
  command_output: string | null
  command_success: boolean | null
  timestamp: number
}

interface RemediationSession {
  session_id: string
  incident: any
  steps: RemediationStep[]
  status: string
  summary: string | null
  error: string | null
  created_at: number
  completed_at: number | null
}

interface Props {
  events: any[]
  fetchApi: (path: string) => Promise<any>
  send: (data: any) => void
  remediationSessions: RemediationSession[]
}

const pulseStyle = `
@keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.3; } }
@keyframes slideIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
`

export function RemediationPanel({ events, fetchApi, send, remediationSessions }: Props) {
  const [sessions, setSessions] = useState<RemediationSession[]>([])
  const [activeSession, setActiveSession] = useState<string | null>(null)
  const [streamTexts, setStreamTexts] = useState<Record<string, string>>({})
  const [pendingApprovals, setPendingApprovals] = useState<Record<string, { step_index: number; command: string }>>({})
  const streamRef = useRef<Record<string, string>>({})
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const style = document.createElement('style')
    style.textContent = pulseStyle
    document.head.appendChild(style)
    return () => { style.remove() }
  }, [])

  useEffect(() => {
    if (remediationSessions.length > 0) {
      setSessions(remediationSessions)
      if (!activeSession) {
        setActiveSession(remediationSessions[0].session_id)
      }
    }
  }, [remediationSessions])

  const processedEventIds = useRef<Set<number>>(new Set())

  useEffect(() => {
    for (const event of events) {
      const eventId = event.receivedAt || Date.now()
      if (processedEventIds.current.has(eventId)) continue
      processedEventIds.current.add(eventId)

      if (event.type === 'remediation_stream' && event.session_id) {
        streamRef.current[event.session_id] = (streamRef.current[event.session_id] || '') + (event.chunk || '')
        setStreamTexts({ ...streamRef.current })
      }

      if (event.type === 'remediation_approval_required' && event.session_id) {
        const key = `${event.session_id}:${event.step_index}`
        setPendingApprovals(prev => ({
          ...prev,
          [key]: { step_index: event.step_index, command: event.command },
        }))
      }
    }
  }, [events])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [sessions, streamTexts])

  const handleApproval = (sessionId: string, stepIndex: number, approved: boolean) => {
    send({
      type: 'remediation_approval',
      session_id: sessionId,
      step_index: stepIndex,
      approved,
    })
    const key = `${sessionId}:${stepIndex}`
    setPendingApprovals(prev => {
      const next = { ...prev }
      delete next[key]
      return next
    })
  }

  const active = sessions.find(s => s.session_id === activeSession)
  const streamText = activeSession ? (streamRef.current[activeSession] || '') : ''

  const renderThinking = (text: string) => {
    if (!text) return null
    const sectionRegex = /## (.+?)\n([\s\S]*?)(?=\n## |$)/g
    const sections: { header: string; body: string }[] = []
    let match
    while ((match = sectionRegex.exec(text)) !== null) {
      sections.push({ header: match[1].trim(), body: match[2].trim() })
    }
    if (sections.length === 0) {
      return <div style={{ color: '#94a3b8', lineHeight: 1.5 }}>{text}</div>
    }
    const sectionColors: Record<string, string> = {
      'Situation Assessment': '#60a5fa',
      'Risk Analysis': '#f97316',
      'Remediation Strategy': '#a78bfa',
      'Command Justification': '#fbbf24',
      'Verification Plan': '#34d399',
    }
    return sections.map((s, i) => {
      const color = sectionColors[s.header] || '#64748b'
      return (
        <div key={i} style={{
          marginBottom: 10, padding: 8, borderRadius: 6,
          background: `${color}06`, border: `1px solid ${color}20`,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: color, display: 'inline-block' }} />
            <span style={{ color, fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.5 }}>
              {s.header}
            </span>
          </div>
          <div style={{ color: '#cbd5e1', fontSize: 10.5, lineHeight: 1.5, whiteSpace: 'pre-wrap', paddingLeft: 12 }}>
            {s.body}
          </div>
        </div>
      )
    })
  }

  const boxStyle: React.CSSProperties = {
    background: '#0f172a', border: '1px solid #1e293b', borderRadius: 10, padding: 14,
  }

  return (
    <div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 14, alignItems: 'center' }}>
        <span style={{ fontSize: 11, color: '#64748b' }}>
          {sessions.length} session{sessions.length !== 1 ? 's' : ''}
        </span>
        <span style={{ fontSize: 10, color: '#f59e0b', background: '#451a03', padding: '2px 8px', borderRadius: 4 }}>
          Human approval required for each command
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: 14 }}>
        <div style={{ ...boxStyle, maxHeight: 'calc(100vh - 150px)', overflowY: 'auto', padding: 10 }}>
          <div style={{ fontSize: 10, fontWeight: 600, color: '#64748b', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 6 }}>
            Sessions
          </div>
          {sessions.length === 0 ? (
            <div style={{ fontSize: 11, color: '#475569', textAlign: 'center', padding: 16, lineHeight: 1.5 }}>
              Remediation sessions appear here automatically after attacks run.
            </div>
          ) : (
            sessions.map(s => (
              <div key={s.session_id} onClick={() => setActiveSession(s.session_id)} style={{
                padding: '7px 8px', borderRadius: 6, cursor: 'pointer', marginBottom: 3,
                background: activeSession === s.session_id ? '#1e293b' : 'transparent',
                border: '1px solid',
                borderColor: activeSession === s.session_id ? '#334155' : 'transparent',
                transition: 'all 0.1s',
              }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: '#e0e0e0', marginBottom: 2 }}>
                  {s.incident?.name || s.incident?.type || 'Remediation'}
                </div>
                <div style={{ display: 'flex', gap: 4, alignItems: 'center', fontSize: 10 }}>
                  <span style={{
                    width: 5, height: 5, borderRadius: '50%', display: 'inline-block',
                    background: s.status === 'completed' ? '#22c55e' : s.status === 'running' ? '#3b82f6' : s.status === 'failed' ? '#ef4444' : '#eab308',
                  }} />
                  <span style={{ color: '#64748b' }}>{s.status}</span>
                  <span style={{ color: '#475569', marginLeft: 'auto' }}>
                    {s.steps?.length || 0}cmds
                  </span>
                </div>
              </div>
            ))
          )}
        </div>

        <div style={{ ...boxStyle, maxHeight: 'calc(100vh - 150px)', overflowY: 'auto', padding: 14 }}>
          {!active ? (
            <div style={{ textAlign: 'center', padding: 40, color: '#475569', fontSize: 12 }}>
              Select a session or wait for attacks to trigger auto-remediation
            </div>
          ) : (
            <div style={{ animation: 'slideIn 0.2s ease' }}>
              <div style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                marginBottom: 14, paddingBottom: 10, borderBottom: '1px solid #1e293b',
              }}>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600 }}>
                    {active.incident?.name || active.incident?.type || 'Remediation Session'}
                  </div>
                  <div style={{ fontSize: 10, color: '#64748b', marginTop: 2 }}>
                    Agent: <span style={{ color: '#a78bfa', fontWeight: 600 }}>Claude Sonnet 4</span>
                    {' · '}{active.created_at ? new Date(active.created_at * 1000).toLocaleString() : ''}
                    {' · '}{active.steps?.length || 0} commands
                  </div>
                </div>
                <span style={{
                  fontSize: 10, padding: '3px 10px', borderRadius: 4,
                  background: active.status === 'completed' ? '#052e16' :
                    active.status === 'running' ? '#1e3a5f' :
                    active.status === 'failed' ? '#450a0a' : '#451a03',
                  color: active.status === 'completed' ? '#22c55e' :
                    active.status === 'running' ? '#60a5fa' :
                    active.status === 'failed' ? '#ef4444' : '#f97316',
                  fontWeight: 700, textTransform: 'uppercase',
                }}>{active.status}</span>
              </div>

              {active.steps?.map((step, i) => {
                const approvalKey = `${active.session_id}:${i}`
                const needsApproval = pendingApprovals[approvalKey]
                return (
                  <div key={i} style={{ marginBottom: 14 }}>
                    {step.thinking && (
                      <div style={{
                        background: '#1e1b4b', borderRadius: 8, padding: 12, marginBottom: 8,
                        border: '1px solid #2e1065',
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                          <span style={{ fontSize: 14 }}>🧠</span>
                          <span style={{
                            fontSize: 10, fontWeight: 700, color: '#8b5cf6',
                            textTransform: 'uppercase', letterSpacing: 0.5,
                          }}>
                            Agent Thinking — Step {i + 1}
                          </span>
                        </div>
                        {renderThinking(step.thinking)}
                      </div>
                    )}

                    {step.command && (
                      <div style={{
                        background: '#0c0a09', borderRadius: 8, border: '1px solid #292524',
                        overflow: 'hidden',
                      }}>
                        <div style={{
                          display: 'flex', alignItems: 'center', gap: 6,
                          padding: '8px 10px', background: '#1c1917',
                          borderBottom: '1px solid #292524',
                        }}>
                          <span style={{ fontSize: 12 }}>⚡</span>
                          <span style={{
                            fontSize: 10, fontWeight: 700, color: '#f97316',
                            textTransform: 'uppercase', letterSpacing: 0.5,
                          }}>
                            Command {i + 1}
                          </span>
                          {needsApproval && (
                            <span style={{
                              marginLeft: 'auto', fontSize: 9, color: '#f59e0b',
                              background: '#451a03', padding: '1px 6px', borderRadius: 3,
                              animation: 'pulse 1s infinite',
                            }}>
                              AWAITING APPROVAL
                            </span>
                          )}
                        </div>
                        <div style={{
                          padding: '8px 10px',
                          fontFamily: '"JetBrains Mono", "Fira Code", monospace',
                          fontSize: 11, color: '#fdba74',
                          whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                        }}>
                          $ {step.command}
                        </div>

                        {/* Human approval buttons */}
                        {needsApproval && (
                          <div style={{
                            display: 'flex', gap: 6, padding: '8px 10px',
                            borderTop: '1px solid #292524',
                          }}>
                            <button onClick={() => handleApproval(active.session_id, i, true)} style={{
                              padding: '5px 14px', borderRadius: 6, border: 'none', cursor: 'pointer',
                              fontSize: 10, fontWeight: 700,
                              background: '#22c55e', color: '#052e16',
                            }}>
                              ✓ Approve & Execute
                            </button>
                            <button onClick={() => handleApproval(active.session_id, i, false)} style={{
                              padding: '5px 14px', borderRadius: 6, border: '1px solid #7f1d1d', cursor: 'pointer',
                              fontSize: 10, fontWeight: 600,
                              background: 'transparent', color: '#ef4444',
                            }}>
                              ✕ Reject & Skip
                            </button>
                            <span style={{
                              fontSize: 9, color: '#f59e0b', display: 'flex', alignItems: 'center', marginLeft: 4,
                            }}>
                              ⏱ Auto-skip in 60s if no response
                            </span>
                          </div>
                        )}

                        {step.command_output !== null && (
                          <>
                            <div style={{
                              display: 'flex', alignItems: 'center', gap: 6,
                              padding: '6px 10px',
                              background: step.command_success ? '#052e16' : '#450a0a',
                              borderTop: '1px solid',
                              borderColor: step.command_success ? '#166534' : '#7f1d1d',
                            }}>
                              <span style={{
                                fontSize: 10, fontWeight: 700,
                                color: step.command_success ? '#22c55e' : '#ef4444',
                                textTransform: 'uppercase', letterSpacing: 0.5,
                              }}>
                                {step.command_success ? '✓ Output (success)' : '✗ Output (error)'}
                              </span>
                            </div>
                            <div style={{
                              padding: '8px 10px',
                              background: '#060912',
                              fontFamily: '"JetBrains Mono", "Fira Code", monospace',
                              fontSize: 10.5, color: step.command_success ? '#86efac' : '#fca5a5',
                              whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                              maxHeight: 200, overflowY: 'auto',
                            }}>
                              {step.command_output || '(no output)'}
                            </div>
                          </>
                        )}
                      </div>
                    )}
                  </div>
                )
              })}

              {active.status === 'running' && streamText && (
                <div style={{
                  background: '#1e1b4b', borderRadius: 8, padding: 12, marginBottom: 10,
                  border: '1px solid #2e1065',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                    <span style={{
                      width: 6, height: 6, borderRadius: '50%', background: '#8b5cf6',
                      display: 'inline-block', animation: 'pulse 0.8s infinite',
                    }} />
                    <span style={{
                      fontSize: 10, fontWeight: 700, color: '#8b5cf6',
                      textTransform: 'uppercase', letterSpacing: 0.5,
                    }}>
                      Agent Thinking in Real-Time
                    </span>
                  </div>
                  <div style={{
                    background: '#0f172a', padding: 8, borderRadius: 4, fontSize: 10.5,
                    maxHeight: 250, overflowY: 'auto', color: '#94a3b8', lineHeight: 1.5,
                    whiteSpace: 'pre-wrap',
                  }}>
                    {(() => {
                      const clean = streamText
                        .replace(/<\/?thinking>/g, '')
                        .replace(/<\/?command>/g, '')
                        .replace(/<\/?summary>/g, '')
                        .trim()
                      if (!clean) return <span style={{ color: '#475569', fontStyle: 'italic' }}>Claude is analyzing the incident...</span>
                      return clean.split('\n').map((line, j) => {
                        if (line.startsWith('## ')) return <div key={j} style={{ color: '#c4b5fd', fontWeight: 600, marginTop: 4 }}>{line}</div>
                        return <div key={j}>{line}</div>
                      })
                    })()}
                  </div>
                </div>
              )}

              {active.summary && (
                <div style={{
                  background: '#052e16', borderRadius: 8, padding: 12, marginBottom: 10,
                  border: '1px solid #166534',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                    <span style={{ fontSize: 14 }}>🛡️</span>
                    <span style={{
                      fontSize: 10, fontWeight: 700, color: '#22c55e',
                      textTransform: 'uppercase', letterSpacing: 0.5,
                    }}>
                      Remediation Summary
                    </span>
                  </div>
                  <div style={{ color: '#86efac', fontSize: 10.5, whiteSpace: 'pre-wrap', lineHeight: 1.5 }}>
                    {active.summary}
                  </div>
                </div>
              )}

              {active.error && (
                <div style={{
                  background: '#450a0a', borderRadius: 8, padding: 12,
                  border: '1px solid #7f1d1d',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                    <span style={{ fontSize: 14 }}>🚨</span>
                    <span style={{
                      fontSize: 10, fontWeight: 700, color: '#ef4444',
                      textTransform: 'uppercase', letterSpacing: 0.5,
                    }}>
                      Remediation Failed
                    </span>
                  </div>
                  <div style={{ color: '#fca5a5', fontSize: 10.5 }}>
                    {active.error}
                  </div>
                </div>
              )}

              <div ref={bottomRef} />
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
