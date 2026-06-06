import React, { useEffect, useRef } from 'react'

interface Props {
  events: any[]
}

export function RealTimeLog({ events }: Props) {
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = 0
    }
  }, [events.length])

  const getEventColor = (type: string): string => {
    const colors: Record<string, string> = {
      attack_event: '#3b82f6',
      attack_started: '#8b5cf6',
      attack_completed: '#22c55e',
      attack_failed: '#ef4444',
      detection_alert: '#f97316',
      infrastructure_affected: '#14b8a6',
      cluster_ready: '#22c55e',
      cluster_creating: '#eab308',
      cluster_error: '#ef4444',
      cluster_deleted: '#64748b',
      monitor_started: '#22c55e',
      monitor_stopped: '#ef4444',
      connected: '#22c55e',
      cluster_info: '#94a3b8',
      info: '#64748b',
      success: '#22c55e',
      error: '#ef4444',
      warning: '#f97316',
      detected: '#ef4444',
    }
    return colors[type] || '#64748b'
  }

  const formatTimestamp = (ts: number): string => {
    if (!ts) return ''
    const d = new Date(ts)
    return d.toLocaleTimeString('en-US', { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0')
  }

  return (
    <div style={{
      background: '#060912', border: '1px solid #1e293b', borderRadius: 12,
      padding: 16, fontFamily: '"JetBrains Mono", "Fira Code", monospace', fontSize: 11,
    }}>
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        marginBottom: 12, color: '#64748b', fontSize: 11,
      }}>
        <span style={{ fontWeight: 600 }}>LIVE EVENT LOG</span>
        <span>{events.length} events · auto-scroll</span>
      </div>
      <div ref={containerRef} style={{
        maxHeight: 'calc(100vh - 200px)', overflowY: 'auto',
      }}>
        {events.length === 0 && (
          <div style={{ color: '#475569', padding: 20, textAlign: 'center' }}>
            Waiting for events...
          </div>
        )}
        {events.map((event: any, i: number) => {
          const ts = event.receivedAt || event.timestamp || event.data?.timestamp
          const color = getEventColor(event.type)
          return (
            <div key={i} style={{
              display: 'flex', gap: 10, padding: '3px 0',
              borderBottom: '1px solid #0f172a',
              lineHeight: 1.5,
            }}>
              <span style={{ color: '#475569', flexShrink: 0, width: 80 }}>
                {ts ? formatTimestamp(typeof ts === 'number' ? ts : ts * 1000) : ''}
              </span>
              <span style={{ color, flexShrink: 0, width: 90 }}>
                [{event.type || 'event'}]
              </span>
              <span style={{ color: '#94a3b8', wordBreak: 'break-all', flex: 1 }}>
                {event.message || event.event?.message || ''}
                {event.data?.pod ? ` (pod: ${event.data.pod})` : ''}
                {event.data?.namespace ? ` [${event.data.namespace}]` : ''}
                {event.event?.data?.exec_output ? ` → ${event.event.data.exec_output.slice(0, 60)}` : ''}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
