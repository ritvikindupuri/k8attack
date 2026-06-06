import React, { useState, useEffect } from 'react'

interface Props {
  events: any[]
  fetchApi: (path: string) => Promise<any>
}

export function DetectionPanel({ events, fetchApi }: Props) {
  const [monitoring, setMonitoring] = useState(false)
  const [summary, setSummary] = useState<any>(null)

  useEffect(() => {
    fetchApi('/api/detection/summary').then(s => s && setSummary(s))
  }, [events.length])

  const toggleMonitoring = async () => {
    try {
      if (monitoring) {
        await fetch('/api/detection/stop', { method: 'POST' })
        setMonitoring(false)
      } else {
        await fetch('/api/detection/start', { method: 'POST' })
        setMonitoring(true)
      }
    } catch {}
  }

  const cardStyle: React.CSSProperties = {
    background: '#0f172a', border: '1px solid #1e293b', borderRadius: 12, padding: 20,
  }

  const severityColors: Record<string, string> = {
    critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
  }

  return (
    <div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button onClick={toggleMonitoring} style={{
          padding: '8px 16px', borderRadius: 8, border: 'none', cursor: 'pointer',
          fontSize: 12, fontWeight: 600,
          background: monitoring ? '#ef4444' : '#22c55e', color: '#fff',
        }}>
          {monitoring ? 'Stop Monitoring' : 'Start Monitoring'}
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16, marginBottom: 16 }}>
        <div style={cardStyle}>
          <h3 style={{ margin: '0 0 12px', fontSize: 14, fontWeight: 600, color: '#94a3b8' }}>ALERT SUMMARY</h3>
          {summary ? (
            <div style={{ display: 'grid', gap: 6 }}>
              {Object.entries(summary.alert_counts || {}).map(([id, info]: [string, any]) => (
                <div key={id} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                  padding: '6px 8px', borderRadius: 6, background: '#162032', fontSize: 11,
                }}>
                  <div>
                    <span style={{ color: '#e0e0e0' }}>{info.name}</span>
                    <span style={{
                      marginLeft: 6, fontSize: 10, padding: '1px 6px', borderRadius: 3,
                      background: severityColors[info.severity] + '20',
                      color: severityColors[info.severity],
                    }}>{info.severity}</span>
                  </div>
                  <span style={{ color: '#94a3b8', fontWeight: 600 }}>{info.count}</span>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ color: '#475569', fontSize: 12, textAlign: 'center', padding: 20 }}>
              No data yet
            </div>
          )}
        </div>

        <div style={cardStyle}>
          <h3 style={{ margin: '0 0 12px', fontSize: 14, fontWeight: 600, color: '#94a3b8' }}>SEVERITY BREAKDOWN</h3>
          {summary?.severity_summary ? (
            <div>
              {Object.entries(summary.severity_summary).map(([sev, count]: [string, any]) => (
                <div key={sev} style={{ marginBottom: 8 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, marginBottom: 4 }}>
                    <span style={{ color: severityColors[sev] || '#94a3b8', textTransform: 'capitalize' }}>{sev}</span>
                    <span style={{ color: '#94a3b8' }}>{count}</span>
                  </div>
                  <div style={{
                    height: 6, borderRadius: 3, background: '#1e293b', overflow: 'hidden',
                  }}>
                    <div style={{
                      width: `${Math.min((count / Math.max(Object.values(summary.severity_summary).reduce((a: number, b: any) => a + (typeof b === 'number' ? b : 0), 0), 1)) * 100, 100)}%`,
                      height: '100%', borderRadius: 3,
                      background: severityColors[sev] || '#64748b',
                      transition: 'width 0.3s',
                    }} />
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <div style={{ color: '#475569', fontSize: 12, textAlign: 'center', padding: 20 }}>
              No data yet
            </div>
          )}
        </div>
      </div>

      <div style={cardStyle}>
        <h3 style={{ margin: '0 0 12px', fontSize: 14, fontWeight: 600, color: '#94a3b8' }}>DETECTION EVENTS</h3>
        {events.length === 0 ? (
          <div style={{ color: '#475569', fontSize: 12, textAlign: 'center', padding: 20 }}>
            Start monitoring to see detection events.
          </div>
        ) : (
          <div style={{ maxHeight: 400, overflowY: 'auto' }}>
            {events.map((e: any, i: number) => (
              <div key={i} style={{
                padding: '8px 10px', fontSize: 11, borderBottom: '1px solid #1e293b',
                display: 'flex', gap: 8, alignItems: 'start',
              }}>
                <span style={{
                  width: 8, height: 8, borderRadius: '50%', display: 'inline-block', flexShrink: 0, marginTop: 3,
                  background: severityColors[e.severity] || '#64748b',
                }} />
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 600, color: '#e0e0e0' }}>{e.name}</span>
                    <span style={{ color: '#475569', fontSize: 10 }}>
                      {e.timestamp ? new Date(e.timestamp * 1000).toLocaleTimeString() : ''}
                    </span>
                  </div>
                  <div style={{ color: '#64748b', marginTop: 2 }}>{e.description}</div>
                  <div style={{ color: '#475569', fontSize: 10, marginTop: 2 }}>
                    MITRE: {e.mitre?.tactic} · {e.mitre?.technique} |
                    Count: {e.count}
                  </div>
                  {e.details && (
                    <div style={{ color: '#475569', fontSize: 10, marginTop: 2 }}>
                      {Object.entries(e.details).map(([k, v]) => (
                        <span key={k} style={{ marginRight: 8 }}>{k}: {String(v).slice(0, 40)}</span>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
