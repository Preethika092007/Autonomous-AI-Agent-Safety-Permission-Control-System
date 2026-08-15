import { useState, useEffect } from "react";
import axios from "axios";
import { getApiUrl } from "../config";

export interface HealthStatus {
  status: string;
  timestamp: string;
  services: {
    database: string;
    redis: string;
    authentication: string;  // Phase 2: "enabled" | "disabled"
  };
}

export function useHealth(intervalMs = 5000) {
  const [health, setHealth] = useState<HealthStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchHealth = async () => {
    try {
      const response = await axios.get<HealthStatus>(getApiUrl("/api/v1/health"));
      setHealth(response.data);
      setError(null);
    } catch (err: any) {
      setError(err.message || "Failed to fetch health status");
      setHealth({
        status: "disconnected",
        timestamp: new Date().toISOString(),
        services: { database: "disconnected", redis: "disconnected", authentication: "unknown" }
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHealth();
    const interval = setInterval(fetchHealth, intervalMs);
    return () => clearInterval(interval);
  }, [intervalMs]);

  return { health, loading, error, refetch: fetchHealth };
}
