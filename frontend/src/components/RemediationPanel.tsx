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

function ApprovalInput({ sessionId, stepIndex, onDecision }: {
  sessionId: string
  stepIndex: number
  onDecision: (approved: boolean) => void
}) {
  const [inputValue, setInputValue] = useState('')
  const [submitted, setSubmitted] = useState(false)

  const handleSubmit = (value: string) => {
    const trimmed = value.trim().toLowerCase()
    if (trimmed === 'allow' || trimmed === 'reject') {
      setSubmitted(true)
      onDecision(trimmed === 'allow')
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleSubmit(inputValue)
  }

  return (
    <div style={{
      display: 'flex', flexDirection: 'column', gap: 6,
      padding: '10px 12px', borderTop: '1px solid #292524',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontSize: 11, color: '#f59e0b', animation: 'pulse 1s infinite' }}>
          ●
        </span>
        <span style={{ fontSize: 12, color: '#fbbf24', fontWeight: 600 }}>
          HUMAN APPROVAL REQUIRED — Type <span style={{ color: '#22c55e' }}>allow</span> or <span style={{ color: '#ef4444' }}>reject</span> to continue
        </span>
      </div>
      <div style={{ display: 'flex', gap: 8 }}>
        <input
          type="text"
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={submitted}
          placeholder='Type "allow" to execute or "reject" to skip...'
          style={{
            flex: 1, padding: '6px 10px', borderRadius: 4, border: '1px solid #444',
            background: submitted ? '#1a1a2e' : '#0f172a', color: '#e0e0e0',
            fontSize: 13, fontFamily: '"JetBrains Mono", monospace', outline: 'none',
          }}
        />
        <button onClick={() => handleSubmit(inputValue)} disabled={submitted} style={{
          padding: '6px 16px', borderRadius: 4, border: 'none', cursor: submitted ? 'default' : 'pointer',
          fontSize: 12, fontWeight: 700, background: '#6366f1', color: '#e0e0e0',
          opacity: submitted ? 0.5 : 1,
        }}>
          Submit
        </button>
      </div>
      <div style={{ fontSize: 10, color: '#64748b' }}>
        Auto-skips after 60s if no response
      </div>
    </div>
  )
}

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

  const processedEventIds = useRef<Set<string>>(new Set())

  useEffect(() => {
    for (const event of events) {
      const eventKey = `${event.type}:${event.session_id || ''}:${event.step_index ?? ''}:${event.receivedAt || Date.now()}`
      if (processedEventIds.current.has(eventKey)) continue
      processedEventIds.current.add(eventKey)

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
      return <div style={{ color: '#94a3b8', lineHeight: 1.6, fontSize: 12.5 }}>{text}</div>
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
          marginBottom: 12, padding: '10px 12px', borderRadius: 8,
          background: `${color}06`, border: `1px solid ${color}20`,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, display: 'inline-block' }} />
            <span style={{ color, fontSize: 11, fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.5 }}>
              {s.header}
            </span>
          </div>
          <div style={{ color: '#cbd5e1', fontSize: 12.5, lineHeight: 1.7, whiteSpace: 'pre-wrap', paddingLeft: 14 }}>
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
      <div style={{ display: 'flex', gap: 12, marginBottom: 16, alignItems: 'center' }}>
        <span style={{ fontSize: 13, color: '#94a3b8' }}>
          {sessions.length} session{sessions.length !== 1 ? 's' : ''}
        </span>
        <span style={{ fontSize: 11, color: '#f59e0b', background: '#451a03', padding: '3px 10px', borderRadius: 4 }}>
          Human approval required for each command
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '220px 1fr', gap: 14 }}>
        <div style={{ ...boxStyle, maxHeight: 'calc(100vh - 150px)', overflowY: 'auto', padding: 12 }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: '#64748b', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 8 }}>
            Sessions
          </div>
          {sessions.length === 0 ? (
            <div style={{ fontSize: 13, color: '#475569', textAlign: 'center', padding: 20, lineHeight: 1.6 }}>
              Remediation sessions appear here automatically after attacks run.
            </div>
          ) : (
            sessions.map(s => (
              <div key={s.session_id} onClick={() => setActiveSession(s.session_id)} style={{
                padding: '8px 10px', borderRadius: 6, cursor: 'pointer', marginBottom: 4,
                background: activeSession === s.session_id ? '#1e293b' : 'transparent',
                border: '1px solid',
                borderColor: activeSession === s.session_id ? '#334155' : 'transparent',
                transition: 'all 0.1s',
              }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: '#e0e0e0', marginBottom: 3 }}>
                  {s.incident?.name || s.incident?.type || 'Remediation'}
                </div>
                <div style={{ display: 'flex', gap: 6, alignItems: 'center', fontSize: 11 }}>
                  <span style={{
                    width: 6, height: 6, borderRadius: '50%', display: 'inline-block',
                    background: s.status === 'completed' ? '#22c55e' : s.status === 'running' ? '#3b82f6' : s.status === 'failed' ? '#ef4444' : '#eab308',
                  }} />
                  <span style={{ color: '#94a3b8' }}>{s.status}</span>
                  <span style={{ color: '#64748b', marginLeft: 'auto' }}>
                    {s.steps?.length || 0}cmds
                  </span>
                </div>
              </div>
            ))
          )}
        </div>

        <div style={{ ...boxStyle, maxHeight: 'calc(100vh - 150px)', overflowY: 'auto', padding: 16 }}>
          {!active ? (
            <div style={{ textAlign: 'center', padding: 40, color: '#475569', fontSize: 13 }}>
              Select a session or wait for attacks to trigger auto-remediation
            </div>
          ) : (
            <div style={{ animation: 'slideIn 0.2s ease' }}>
              <div style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                marginBottom: 16, paddingBottom: 12, borderBottom: '1px solid #1e293b',
              }}>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 600 }}>
                    {active.incident?.name || active.incident?.type || 'Remediation Session'}
                  </div>
                  <div style={{ fontSize: 12, color: '#94a3b8', marginTop: 3 }}>
                    Agent: <span style={{ color: '#a78bfa', fontWeight: 600 }}>Claude Sonnet 4</span>
                    {' · '}{active.created_at ? new Date(active.created_at * 1000).toLocaleString() : ''}
                    {' · '}{active.steps?.length || 0} commands
                  </div>
                </div>
                <span style={{
                  fontSize: 11, padding: '4px 12px', borderRadius: 4,
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
                  <div key={i} style={{ marginBottom: 18 }}>
                    {step.thinking && (
                      <div style={{
                        background: '#1e1b4b', borderRadius: 8, padding: 14, marginBottom: 10,
                        border: '1px solid #2e1065',
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                          <span style={{ fontSize: 16 }}>🧠</span>
                          <span style={{
                            fontSize: 11, fontWeight: 700, color: '#8b5cf6',
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
                          display: 'flex', alignItems: 'center', gap: 8,
                          padding: '10px 12px', background: '#1c1917',
                          borderBottom: '1px solid #292524',
                        }}>
                          <span style={{ fontSize: 14 }}>⚡</span>
                          <span style={{
                            fontSize: 11, fontWeight: 700, color: '#f97316',
                            textTransform: 'uppercase', letterSpacing: 0.5,
                          }}>
                            Command {i + 1}
                          </span>
                          {needsApproval && (
                            <span style={{
                              marginLeft: 'auto', fontSize: 10, color: '#f59e0b',
                              background: '#451a03', padding: '2px 8px', borderRadius: 3,
                              animation: 'pulse 1s infinite',
                            }}>
                              AWAITING APPROVAL
                            </span>
                          )}
                        </div>
                        <div style={{
                          padding: '10px 12px',
                          fontFamily: '"JetBrains Mono", "Fira Code", monospace',
                          fontSize: 12, color: '#fdba74',
                          whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                        }}>
                          $ {step.command}
                        </div>

                        {/* Human approval text input */}
                        {needsApproval && (
                          <ApprovalInput
                            sessionId={active.session_id}
                            stepIndex={i}
                            onDecision={(approved) => handleApproval(active.session_id, i, approved)}
                          />
                        )}

                        {step.command_output !== null && (
                          <>
                            <div style={{
                              display: 'flex', alignItems: 'center', gap: 8,
                              padding: '8px 12px',
                              background: step.command_success ? '#052e16' : '#450a0a',
                              borderTop: '1px solid',
                              borderColor: step.command_success ? '#166534' : '#7f1d1d',
                            }}>
                              <span style={{
                                fontSize: 11, fontWeight: 700,
                                color: step.command_success ? '#22c55e' : '#ef4444',
                                textTransform: 'uppercase', letterSpacing: 0.5,
                              }}>
                                {step.command_success ? '✓ Output (success)' : '✗ Output (error)'}
                              </span>
                            </div>
                            <div style={{
                              padding: '10px 12px',
                              background: '#060912',
                              fontFamily: '"JetBrains Mono", "Fira Code", monospace',
                              fontSize: 12, color: step.command_success ? '#86efac' : '#fca5a5',
                              whiteSpace: 'pre-wrap', wordBreak: 'break-all',
                              maxHeight: 300, overflowY: 'auto',
                              lineHeight: 1.5,
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
                  background: '#1e1b4b', borderRadius: 8, padding: 14, marginBottom: 12,
                  border: '1px solid #2e1065',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                    <span style={{
                      width: 8, height: 8, borderRadius: '50%', background: '#8b5cf6',
                      display: 'inline-block', animation: 'pulse 0.8s infinite',
                    }} />
                    <span style={{
                      fontSize: 11, fontWeight: 700, color: '#8b5cf6',
                      textTransform: 'uppercase', letterSpacing: 0.5,
                    }}>
                      Agent Thinking in Real-Time
                    </span>
                  </div>
                  <div style={{
                    background: '#0f172a', padding: 10, borderRadius: 4, fontSize: 12.5,
                    maxHeight: 300, overflowY: 'auto', color: '#94a3b8', lineHeight: 1.7,
                    whiteSpace: 'pre-wrap',
                  }}>
                    {(() => {
                      const clean = streamText
                        .replace(/<\/?thinking>/g, '')
                        .replace(/<\/?command>/g, '')
                        .replace(/<\/?summary>/g, '')
                        .trim()
                      if (!clean) return <span style={{ color: '#475569', fontStyle: 'italic', fontSize: 13 }}>Claude is analyzing the incident...</span>
                      return clean.split('\n').map((line, j) => {
                        if (line.startsWith('## ')) return <div key={j} style={{ color: '#c4b5fd', fontWeight: 600, marginTop: 6, fontSize: 12 }}>{line}</div>
                        return <div key={j}>{line}</div>
                      })
                    })()}
                  </div>
                </div>
              )}

              {active.summary && (
                <div style={{
                  background: '#052e16', borderRadius: 8, padding: 14, marginBottom: 12,
                  border: '1px solid #166534',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                    <span style={{ fontSize: 16 }}>🛡️</span>
                    <span style={{
                      fontSize: 11, fontWeight: 700, color: '#22c55e',
                      textTransform: 'uppercase', letterSpacing: 0.5,
                    }}>
                      Remediation Summary
                    </span>
                  </div>
                  <div style={{ color: '#86efac', fontSize: 12.5, whiteSpace: 'pre-wrap', lineHeight: 1.7 }}>
                    {active.summary}
                  </div>
                </div>
              )}

              {active.error && (
                <div style={{
                  background: '#450a0a', borderRadius: 8, padding: 14, marginBottom: 12,
                  border: '1px solid #7f1d1d',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
                    <span style={{ fontSize: 16 }}>🚨</span>
                    <span style={{
                      fontSize: 11, fontWeight: 700, color: '#ef4444',
                      textTransform: 'uppercase', letterSpacing: 0.5,
                    }}>
                      Remediation Failed
                    </span>
                  </div>
                  <div style={{ color: '#fca5a5', fontSize: 12.5, lineHeight: 1.6 }}>
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
