import { useEffect, useRef, useState, useCallback } from 'react'

type MessageHandler = (data: any) => void

export function useWebSocket(url: string) {
  const ws = useRef<WebSocket | null>(null)
  const [connected, setConnected] = useState(false)
  const handlers = useRef<Map<string, MessageHandler[]>>(new Map())
  const reconnectTimer = useRef<ReturnType<typeof setTimeout>>()
  const mountedRef = useRef(true)

  const on = useCallback((event: string, handler: MessageHandler) => {
    if (!handlers.current.has(event)) {
      handlers.current.set(event, [])
    }
    handlers.current.get(event)!.push(handler)
    return () => {
      const h = handlers.current.get(event)
      if (h) {
        const idx = h.indexOf(handler)
        if (idx >= 0) h.splice(idx, 1)
      }
    }
  }, [])

  const send = useCallback((data: any) => {
    if (ws.current?.readyState === WebSocket.OPEN) {
      ws.current.send(JSON.stringify(data))
    }
  }, [])

  useEffect(() => {
    mountedRef.current = true
    let running = true

    const connect = () => {
      if (!running) return
      const socket = new WebSocket(url)
      ws.current = socket

      socket.onopen = () => {
        if (!running) { socket.close(); return }
        setConnected(true)
      }

      socket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          const type = data.type || 'message'
          const typeHandlers = handlers.current.get(type) || []
          typeHandlers.forEach(fn => fn(data))
          const allHandlers = handlers.current.get('*') || []
          allHandlers.forEach(fn => fn(data))
        } catch { }
      }

      socket.onclose = () => {
        setConnected(false)
        if (running && mountedRef.current) {
          reconnectTimer.current = setTimeout(connect, 3000)
        }
      }

      socket.onerror = () => {
        socket.close()
      }
    }

    connect()

    return () => {
      running = false
      mountedRef.current = false
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      ws.current?.close()
    }
  }, [url])

  return { connected, send, on, ws: ws.current }
}
