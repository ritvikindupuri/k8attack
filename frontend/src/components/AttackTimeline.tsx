import React from 'react'

interface Props {
  history: any[]
}

const severityColors: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
}

export function AttackTimeline({ history }: Props) {
  const cardStyle: React.CSSProperties = {
    background: '#0f172a', border: '1px solid #1e293b', borderRadius: 12, padding: 20,
  }

  if (history.length === 0) {
    return (
      <div style={cardStyle}>
        <div style={{ textAlign: 'center', padding: 40, color: '#475569', fontSize: 13 }}>
          No attacks have been executed yet. Go to the Attacks tab to launch one.
        </div>
      </div>
    )
  }

  return (
    <div style={cardStyle}>
      <h3 style={{ margin: '0 0 16px', fontSize: 14, fontWeight: 600, color: '#94a3b8' }}>ATTACK TIMELINE</h3>
      <div style={{ position: 'relative' }}>
        <div style={{
          position: 'absolute', left: 15, top: 0, bottom: 0, width: 2,
          background: 'linear-gradient(to bottom, #3b82f6, #ef4444)',
        }} />
        {history.map((attack: any, i: number) => (
          <div key={i} style={{ position: 'relative', paddingLeft: 40, paddingBottom: 20 }}>
            <div style={{
              position: 'absolute', left: 8, top: 4, width: 16, height: 16, borderRadius: '50%',
              background: attack.status === 'completed' ? '#22c55e' : attack.status === 'failed' ? '#ef4444' : '#3b82f6',
              border: '2px solid #0f172a',
            }} />
            <div style={{
              background: '#162032', borderRadius: 8, padding: 12, border: '1px solid #1e293b',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                <span style={{ fontSize: 13, fontWeight: 600 }}>{attack.name}</span>
                <div style={{ display: 'flex', gap: 6 }}>
                  <span style={{
                    fontSize: 10, padding: '2px 8px', borderRadius: 4,
                    background: severityColors[attack.severity] + '20',
                    color: severityColors[attack.severity],
                  }}>{attack.severity}</span>
                  <span style={{
                    fontSize: 10, padding: '2px 8px', borderRadius: 4,
                    background: attack.status === 'completed' ? '#052e16' : '#451a03',
                    color: attack.status === 'completed' ? '#22c55e' : '#ef4444',
                  }}>{attack.status}</span>
                </div>
              </div>
              <div style={{ fontSize: 11, color: '#64748b' }}>
                MITRE: {attack.mitre_tactic} · {attack.mitre_techniques?.map((t: any) => t.id).join(', ') || 'N/A'}
              </div>
              {attack.infrastructure_affected && attack.infrastructure_affected.length > 0 && (
                <div style={{ marginTop: 8, fontSize: 11, color: '#94a3b8' }}>
                  <span style={{ color: '#64748b' }}>Infrastructure: </span>
                  {attack.infrastructure_affected.map((inf: any, j: number) => (
                    <span key={j} style={{ marginRight: 8 }}>
                      [{inf.resource_type}:{inf.name}]
                    </span>
                  ))}
                </div>
              )}
              {attack.start_time && (
                <div style={{ marginTop: 4, fontSize: 10, color: '#475569' }}>
                  {new Date(attack.start_time * 1000).toLocaleTimeString()}
                  {attack.end_time ? ` · Duration: ${(attack.end_time - attack.start_time).toFixed(1)}s` : ''}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
