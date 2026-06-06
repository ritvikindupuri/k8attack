import React from 'react'

interface Props {
  items: any[]
}

const resourceIcons: Record<string, string> = {
  pod: 'P', secret: 'S', configmap: 'C', service_endpoint: 'E',
  cluster_role_binding: 'R', node_filesystem: 'F', host_network: 'N',
  network_range: 'N',
}

const resourceColors: Record<string, string> = {
  pod: '#3b82f6', secret: '#ef4444', configmap: '#eab308',
  service_endpoint: '#22c55e', cluster_role_binding: '#f97316',
  node_filesystem: '#8b5cf6', host_network: '#ec4899', network_range: '#14b8a6',
}

export function InfrastructureView({ items }: Props) {
  const cardStyle: React.CSSProperties = {
    background: '#0f172a', border: '1px solid #1e293b', borderRadius: 12, padding: 20,
  }

  if (items.length === 0) {
    return (
      <div style={cardStyle}>
        <div style={{ textAlign: 'center', padding: 40, color: '#475569', fontSize: 13 }}>
          No infrastructure affected yet. Execute attacks to see affected resources.
        </div>
      </div>
    )
  }

  return (
    <div style={cardStyle}>
      <h3 style={{ margin: '0 0 4px', fontSize: 14, fontWeight: 600, color: '#94a3b8' }}>
        AFFECTED INFRASTRUCTURE
      </h3>
      <p style={{ fontSize: 11, color: '#475569', margin: '0 0 16px' }}>
        Resources compromised or interacted with during attacks
      </p>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 8 }}>
        {items.map((item: any, i: number) => {
          const icon = resourceIcons[item.resource_type] || '?'
          const color = resourceColors[item.resource_type] || '#64748b'
          return (
            <div key={i} style={{
              background: '#162032', borderRadius: 8, padding: 12, border: `1px solid ${color}30`,
              display: 'flex', gap: 10,
            }}>
              <div style={{
                width: 32, height: 32, borderRadius: 6, display: 'flex',
                alignItems: 'center', justifyContent: 'center',
                background: `${color}20`, color, fontSize: 14, fontWeight: 'bold', flexShrink: 0,
              }}>{icon}</div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 13, fontWeight: 600, color: '#e0e0e0' }}>{item.name}</div>
                <div style={{ fontSize: 11, color: '#64748b' }}>
                  {item.resource_type} · {item.namespace}
                </div>
                {item.details && Object.keys(item.details).length > 0 && (
                  <div style={{ marginTop: 4, fontSize: 10, color: '#475569' }}>
                    {Object.entries(item.details).slice(0, 3).map(([k, v]: [string, any]) => (
                      <div key={k}>
                        {k}: {typeof v === 'string' ? (v.length > 50 ? v.slice(0, 50) + '...' : v) : JSON.stringify(v).slice(0, 50)}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
