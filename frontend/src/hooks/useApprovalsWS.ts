import { useState, useEffect, useRef } from "react";
import { getWsUrl } from "../config";

export interface ApprovalRequest {
  approval_id: string;
  agent_id: string;
  action: string;
  parameters: Record<string, any>;
  risk_level: string;
  reason: string;
}

export function useApprovalsWS() {
  const [queue, setQueue] = useState<ApprovalRequest[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    const connect = () => {
      const ws = new WebSocket(getWsUrl("/api/v1/ws/approvals"));
      wsRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
        console.log("Connected to approvals WebSocket");
      };

      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          const { event: eventType, data } = payload;

          if (eventType === "new_approval_request") {
            setQueue((prev) => {
              if (prev.some((item) => item.approval_id === data.approval_id)) {
                return prev;
              }
              return [...prev, data];
            });
          } else if (eventType === "approval_resolved") {
            setQueue((prev) => prev.filter((item) => item.approval_id !== data.approval_id));
          }
        } catch (err) {
          console.error("Error parsing WebSocket message:", err);
        }
      };

      ws.onclose = () => {
        setConnected(false);
        console.log("Disconnected from approvals WebSocket. Reconnecting in 3s...");
        setTimeout(connect, 3000);
      };

      ws.onerror = (error) => {
        console.error("WebSocket error:", error);
      };
    };

    connect();

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const removeApproval = (approvalId: string) => {
    setQueue((prev) => prev.filter((item) => item.approval_id !== approvalId));
  };

  return { queue, connected, removeApproval };
}
