import React, { useState } from 'react'

interface Props {
  clusterInfo: any
  send: (data: any) => void
  fetchApi: (path: string) => Promise<any>
}

export function ClusterView({ clusterInfo, send, fetchApi }: Props) {
  const [loading, setLoading] = useState<string | null>(null)

  const doAction = async (action: string, apiPath: string) => {
    setLoading(action)
    try {
      if (action === 'create') {
        await fetch('/api/cluster/create', { method: 'POST' })
      } else if (action === 'delete') {
        await fetch('/api/cluster/delete', { method: 'POST' })
      } else if (action === 'setup') {
        await fetch('/api/cluster/setup-scenarios', { method: 'POST' })
      }
      setTimeout(async () => {
        const info = await fetchApi('/api/cluster/info')
        send({ type: 'get_cluster_info' })
      }, 2000)
    } catch {}
    setLoading(null)
  }

  const cardStyle: React.CSSProperties = {
    background: '#0f172a', border: '1px solid #1e293b', borderRadius: 12, padding: 20, marginBottom: 16,
  }

  const btnStyle = (color: string): React.CSSProperties => ({
    padding: '8px 16px', borderRadius: 8, border: 'none', cursor: 'pointer',
    fontSize: 12, fontWeight: 600, background: color, color: '#fff',
    opacity: loading ? 0.6 : 1,
  })

  return (
    <div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button style={btnStyle('#3b82f6')} onClick={() => doAction('create', '/api/cluster/create')}
          disabled={loading === 'create'}>
          {loading === 'create' ? 'Creating...' : 'Create Kind Cluster'}
        </button>
        <button style={btnStyle('#ef4444')} onClick={() => doAction('delete', '/api/cluster/delete')}
          disabled={loading === 'delete'}>
          {loading === 'delete' ? 'Deleting...' : 'Delete Cluster'}
        </button>
        <button style={btnStyle('#f97316')} onClick={() => doAction('setup', '/api/cluster/setup-scenarios')}
          disabled={loading === 'setup'}>
          {loading === 'setup' ? 'Setting up...' : 'Setup Vulnerable Configs'}
        </button>
      </div>

      <div style={cardStyle}>
        <h3 style={{ margin: '0 0 12px', fontSize: 14, fontWeight: 600, color: '#94a3b8' }}>CLUSTER STATUS</h3>
        {!clusterInfo ? (
          <div style={{ color: '#475569', fontSize: 12, textAlign: 'center', padding: 20 }}>
            No cluster connected. Create one above.
          </div>
        ) : clusterInfo.error ? (
          <div style={{ color: '#ef4444', fontSize: 12 }}>
            Error: {clusterInfo.error}
          </div>
        ) : (
          <div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12, marginBottom: 16 }}>
              <div style={{ background: '#162032', borderRadius: 8, padding: 12, textAlign: 'center' }}>
                <div style={{ fontSize: 24, fontWeight: 700 }}>{clusterInfo.node_count || 0}</div>
                <div style={{ fontSize: 11, color: '#64748b' }}>Nodes</div>
              </div>
              <div style={{ background: '#162032', borderRadius: 8, padding: 12, textAlign: 'center' }}>
                <div style={{ fontSize: 24, fontWeight: 700 }}>{clusterInfo.pod_count || 0}</div>
                <div style={{ fontSize: 11, color: '#64748b' }}>Pods</div>
              </div>
              <div style={{ background: '#162032', borderRadius: 8, padding: 12, textAlign: 'center' }}>
                <div style={{ fontSize: 24, fontWeight: 700 }}>{clusterInfo.service_count || 0}</div>
                <div style={{ fontSize: 11, color: '#64748b' }}>Services</div>
              </div>
            </div>

            {clusterInfo.nodes && clusterInfo.nodes.length > 0 && (
              <div style={{ marginBottom: 16 }}>
                <h4 style={{ margin: '0 0 8px', fontSize: 12, color: '#64748b' }}>NODES</h4>
                {clusterInfo.nodes.map((n: any, i: number) => (
                  <div key={i} style={{
                    background: '#162032', borderRadius: 8, padding: 12, marginBottom: 8,
                    border: '1px solid #1e293b',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: 13, fontWeight: 600 }}>{n.name}</span>
                      <span style={{
                        fontSize: 11, padding: '2px 8px', borderRadius: 4,
                        background: n.status === 'Ready' ? '#052e16' : '#451a03',
                        color: n.status === 'Ready' ? '#22c55e' : '#f97316',
                      }}>{n.status}</span>
                    </div>
                    <div style={{ fontSize: 11, color: '#64748b', marginTop: 4 }}>
                      {n.os} · {n.arch} · K8s {n.kubelet}
                    </div>
                    <div style={{ fontSize: 11, color: '#64748b', marginTop: 2 }}>
                      CPU: {n.capacity?.cpu || '?'} · Memory: {n.capacity?.memory || '?'}
                    </div>
                  </div>
                ))}
              </div>
            )}

            {clusterInfo.pods && clusterInfo.pods.length > 0 && (
              <div>
                <h4 style={{ margin: '0 0 8px', fontSize: 12, color: '#64748b' }}>PODS</h4>
                <div style={{ maxHeight: 300, overflowY: 'auto' }}>
                  <table style={{ width: '100%', fontSize: 11, borderCollapse: 'collapse' }}>
                    <thead>
                      <tr style={{ color: '#64748b', textAlign: 'left' }}>
                        <th style={{ padding: '4px 8px' }}>Name</th>
                        <th style={{ padding: '4px 8px' }}>Namespace</th>
                        <th style={{ padding: '4px 8px' }}>Status</th>
                        <th style={{ padding: '4px 8px' }}>Node</th>
                        <th style={{ padding: '4px 8px' }}>IP</th>
                      </tr>
                    </thead>
                    <tbody>
                      {clusterInfo.pods.map((p: any, i: number) => (
                        <tr key={i} style={{ borderTop: '1px solid #1e293b' }}>
                          <td style={{ padding: '4px 8px', color: '#e0e0e0' }}>{p.name}</td>
                          <td style={{ padding: '4px 8px', color: '#94a3b8' }}>{p.namespace}</td>
                          <td style={{ padding: '4px 8px' }}>
                            <span style={{
                              color: p.status === 'Running' ? '#22c55e' : p.status === 'Pending' ? '#eab308' : '#94a3b8',
                            }}>{p.status}</span>
                          </td>
                          <td style={{ padding: '4px 8px', color: '#94a3b8' }}>{p.node || '—'}</td>
                          <td style={{ padding: '4px 8px', color: '#94a3b8' }}>{p.ip || '—'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
