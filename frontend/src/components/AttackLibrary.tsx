import React, { useEffect, useState } from 'react'

interface Props {
  send: (data: any) => void
  fetchApi: (path: string) => Promise<any>
  attackStatus: Record<string, any>
}

const severityColors: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
}

export function AttackLibrary({ send, fetchApi, attackStatus }: Props) {
  const [attacks, setAttacks] = useState<any[]>([])
  const [running, setRunning] = useState<string | null>(null)
  const [result, setResult] = useState<any>(null)

  useEffect(() => {
    fetchApi('/api/attacks').then(d => d?.attacks && setAttacks(d.attacks))
  }, [])

  const runAttack = async (attackId: string) => {
    setRunning(attackId)
    setResult(null)
    try {
      const res = await fetch(`/api/attacks/run/${attackId}`, { method: 'POST' })
      const data = await res.json()
      if (data.execution_id) {
        const poll = setInterval(async () => {
          const r = await fetchApi(`/api/attacks/result/${data.execution_id}`)
          if (r?.result?.status === 'completed' || r?.result?.status === 'failed') {
            setResult(r.result)
            setRunning(null)
            clearInterval(poll)
          }
        }, 1000)
        setTimeout(() => { clearInterval(poll); setRunning(null) }, 60000)
      }
    } catch {
      setRunning(null)
    }
  }

  const cardStyle: React.CSSProperties = {
    background: '#0f172a', border: '1px solid #1e293b', borderRadius: 12, padding: 20,
  }

  return (
    <div>
      <div style={{ ...cardStyle, marginBottom: 16 }}>
        <h3 style={{ margin: '0 0 16px', fontSize: 14, fontWeight: 600, color: '#94a3b8' }}>ATTACK LIBRARY</h3>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(320px, 1fr))', gap: 12 }}>
          {attacks.map((attack: any, i: number) => (
            <div key={i} style={{
              background: '#162032', borderRadius: 10, padding: 16, border: '1px solid #1e293b',
              transition: 'all 0.2s',
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: 8 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>{attack.name}</div>
                  <div style={{ fontSize: 11, color: '#64748b', lineHeight: 1.4 }}>{attack.description}</div>
                </div>
                <span style={{
                  fontSize: 10, fontWeight: 600, padding: '2px 8px', borderRadius: 4,
                  background: severityColors[attack.severity] + '20',
                  color: severityColors[attack.severity],
                  textTransform: 'uppercase', marginLeft: 8, flexShrink: 0,
                }}>{attack.severity}</span>
              </div>

              <div style={{ fontSize: 10, color: '#475569', marginBottom: 8 }}>
                <span style={{ color: '#64748b' }}>MITRE: </span>
                {attack.mitre_tactic} · {attack.mitre_techniques?.map((t: any) => t.id).join(', ')}
              </div>

              <button onClick={() => runAttack(attack.id)} disabled={running === attack.id} style={{
                width: '100%', padding: '6px 12px', borderRadius: 6, border: 'none', cursor: 'pointer',
                fontSize: 11, fontWeight: 600,
                background: running === attack.id ? '#475569' : '#3b82f6',
                color: '#fff',
              }}>
                {running === attack.id ? 'Executing...' : 'Execute Attack'}
              </button>
            </div>
          ))}
        </div>
      </div>

      {result && (
        <div style={cardStyle}>
          <h3 style={{ margin: '0 0 12px', fontSize: 14, fontWeight: 600, color: '#94a3b8' }}>ATTACK RESULT</h3>
          <div style={{
            background: '#162032', borderRadius: 8, padding: 16, border: '1px solid #1e293b',
            marginBottom: 12,
          }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <span style={{ fontSize: 14, fontWeight: 600 }}>{result.name}</span>
              <span style={{
                fontSize: 11, padding: '2px 10px', borderRadius: 4,
                background: result.status === 'completed' ? '#052e16' : '#451a03',
                color: result.status === 'completed' ? '#22c55e' : '#ef4444',
              }}>{result.status.toUpperCase()}</span>
            </div>
            {result.infrastructure_affected && result.infrastructure_affected.length > 0 && (
              <div style={{ marginTop: 12 }}>
                <div style={{ fontSize: 11, color: '#64748b', marginBottom: 4 }}>AFFECTED INFRASTRUCTURE:</div>
                {result.infrastructure_affected.map((inf: any, i: number) => (
                  <div key={i} style={{ fontSize: 11, padding: '4px 0', color: '#94a3b8' }}>
                    [{inf.resource_type}] {inf.name} ({inf.namespace})
                  </div>
                ))}
              </div>
            )}
          </div>
          <div style={{ maxHeight: 300, overflowY: 'auto' }}>
            {result.events?.map((e: any, i: number) => (
              <div key={i} style={{
                padding: '6px 8px', fontSize: 11, borderBottom: '1px solid #1e293b',
                display: 'flex', gap: 8,
              }}>
                <span style={{
                  color: e.event_type === 'success' ? '#22c55e' : e.event_type === 'error' ? '#ef4444'
                    : e.event_type === 'detected' ? '#f97316' : '#94a3b8',
                  flexShrink: 0,
                }}>[{e.event_type}]</span>
                <span style={{ color: '#cbd5e1' }}>{e.message}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
