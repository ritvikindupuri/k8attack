import React, { useEffect, useState } from 'react'

interface Props {
  fetchApi: (path: string) => Promise<any>
}

const tacticColors: Record<string, string> = {
  TA0001: '#3b82f6', TA0002: '#8b5cf6', TA0003: '#ec4899', TA0004: '#ef4444',
  TA0005: '#f97316', TA0006: '#eab308', TA0007: '#22c55e', TA0008: '#14b8a6',
  TA0009: '#06b6d4', TA0040: '#6366f1',
}

export function MitreMatrix({ fetchApi }: Props) {
  const [mitre, setMitre] = useState<any>(null)

  useEffect(() => {
    fetchApi('/api/attacks/mitre').then(d => d?.mitre_attack && setMitre(d.mitre_attack))
  }, [])

  const cardStyle: React.CSSProperties = {
    background: '#0f172a', border: '1px solid #1e293b', borderRadius: 12, padding: 20,
  }

  if (!mitre) {
    return (
      <div style={cardStyle}>
        <div style={{ textAlign: 'center', padding: 40, color: '#475569', fontSize: 13 }}>
          Loading MITRE ATT&CK mapping...
        </div>
      </div>
    )
  }

  return (
    <div style={cardStyle}>
      <h3 style={{ margin: '0 0 4px', fontSize: 14, fontWeight: 600, color: '#94a3b8' }}>
        MITRE ATT&CK for Kubernetes
      </h3>
      <p style={{ fontSize: 11, color: '#475569', margin: '0 0 16px' }}>
        Mapping of K8s attacks to the MITRE ATT&CK framework
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: 12 }}>
        {Object.entries(mitre).map(([key, tactic]: [string, any]) => (
          <div key={key} style={{
            background: '#162032', borderRadius: 10, border: `1px solid ${tacticColors[tactic.id] || '#1e293b'}40`,
            overflow: 'hidden',
          }}>
            <div style={{
              padding: '10px 14px',
              background: `${tacticColors[tactic.id] || '#1e293b'}20`,
              borderBottom: `1px solid ${tacticColors[tactic.id] || '#1e293b'}40`,
            }}>
              <div style={{ fontSize: 10, color: tacticColors[tactic.id], textTransform: 'uppercase', letterSpacing: 1 }}>
                {tactic.id}
              </div>
              <div style={{ fontSize: 14, fontWeight: 600, marginTop: 2 }}>{tactic.name}</div>
            </div>
            <div style={{ padding: '8px 14px 12px' }}>
              {tactic.techniques?.map((tech: any, i: number) => (
                <div key={i} style={{
                  padding: '6px 0', borderBottom: i < tactic.techniques.length - 1 ? '1px solid #1e293b' : 'none',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontSize: 11, color: '#e0e0e0', fontWeight: 500 }}>{tech.name}</span>
                    <span style={{
                      fontSize: 10, padding: '1px 6px', borderRadius: 3,
                      background: '#1e293b', color: '#64748b',
                    }}>{tech.id}</span>
                  </div>
                  <div style={{ fontSize: 10, color: '#64748b', marginTop: 2 }}>{tech.k8s_technique}</div>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
