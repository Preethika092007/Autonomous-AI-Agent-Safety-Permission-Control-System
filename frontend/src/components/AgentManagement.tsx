import { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { Users, ToggleLeft, ToggleRight, ShieldAlert, CheckCircle2, RotateCcw } from "lucide-react";
import { getApiUrl } from "../config";

interface AgentInfo {
  id: string;
  name: string;
  role: string;
  is_active: boolean;
  created_at: string;
  active_credential_id: string | null;
}

export function AgentManagement() {
  const { token, operator } = useAuth();
  const [agents, setAgents] = useState<AgentInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [newKey, setNewKey] = useState<{ agent_id: string, key: string } | null>(null);

  const fetchAgents = async () => {
    try {
      const res = await fetch(getApiUrl("/api/v1/agents/"), {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (!res.ok) throw new Error("Failed to fetch agents");
      const data = await res.json();
      setAgents(data);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (token && operator?.role === "admin") {
      fetchAgents();
    }
  }, [token, operator]);

  const handleToggleStatus = async (agentId: string, currentStatus: boolean) => {
    try {
      const res = await fetch(getApiUrl(`/api/v1/agents/${agentId}/status`), {
        method: "PATCH",
        headers: { 
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}` 
        },
        body: JSON.stringify({ is_active: !currentStatus })
      });
      if (!res.ok) throw new Error("Failed to update status");
      await fetchAgents();
    } catch (err: any) {
      alert(err.message);
    }
  };

  const handleRotateKey = async (agentId: string) => {
    if (!confirm(`Are you sure you want to rotate the key for ${agentId}? The old key will immediately stop working.`)) return;
    
    try {
      const res = await fetch(getApiUrl(`/api/v1/agents/${agentId}/rotate-key`), {
        method: "POST",
        headers: { Authorization: `Bearer ${token}` }
      });
      if (!res.ok) throw new Error("Failed to rotate key");
      const data = await res.json();
      setNewKey({ agent_id: agentId, key: data.api_key });
      await fetchAgents();
    } catch (err: any) {
      alert(err.message);
    }
  };

  if (operator?.role !== "admin") {
    return (
      <div className="glass-panel p-6 rounded-2xl flex flex-col items-center justify-center text-center py-12">
        <ShieldAlert className="w-12 h-12 text-amber-500 mb-4" />
        <h2 className="text-xl font-bold text-white mb-2">Access Denied</h2>
        <p className="text-gray-400 max-w-md">You need Administrator privileges to manage agents and credentials.</p>
      </div>
    );
  }

  if (loading) return <div className="p-6 text-gray-400">Loading agents...</div>;
  if (error) return <div className="p-6 text-red-400">Error: {error}</div>;

  return (
    <div className="glass-panel rounded-2xl overflow-hidden flex flex-col h-full border border-gray-800 shadow-xl shadow-black/50">
      <div className="bg-gray-900/50 px-5 py-4 border-b border-gray-800 flex items-center justify-between sticky top-0 backdrop-blur-md z-10">
        <div className="flex items-center gap-2">
          <Users className="w-5 h-5 text-indigo-400" />
          <h2 className="font-semibold text-gray-100 tracking-wide flex items-center gap-2">
            Agent Management
            <span className="bg-indigo-500/20 text-indigo-400 text-[10px] font-bold px-2 py-0.5 rounded-full uppercase tracking-wider">
              {agents.length} Registered
            </span>
          </h2>
        </div>
      </div>

      <div className="p-5 flex-1 overflow-y-auto min-h-[300px] max-h-[500px] bg-black/20">
        {newKey && (
          <div className="mb-6 bg-green-500/10 border border-green-500/20 p-4 rounded-xl">
            <h3 className="text-green-400 font-bold mb-2 flex items-center gap-2">
              <CheckCircle2 className="w-5 h-5" />
              New Key Generated for {newKey.agent_id}
            </h3>
            <p className="text-sm text-gray-300 mb-2">Please copy this key now. It will not be shown again.</p>
            <div className="bg-black/50 p-3 rounded font-mono text-sm text-green-300 break-all select-all border border-green-500/10">
              {newKey.key}
            </div>
            <button 
              onClick={() => setNewKey(null)}
              className="mt-3 text-xs text-green-400 hover:text-green-300 underline"
            >
              Dismiss
            </button>
          </div>
        )}

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {agents.map(agent => (
            <div key={agent.id} className="bg-gray-900/50 border border-gray-800 p-4 rounded-xl hover:border-gray-700 transition-colors">
              <div className="flex justify-between items-start mb-3">
                <div>
                  <h3 className="font-bold text-white text-lg">{agent.name}</h3>
                  <p className="text-xs text-gray-400 font-mono mt-1">{agent.id}</p>
                </div>
                <span className={`px-2 py-1 rounded text-[10px] font-bold uppercase ${
                  agent.is_active ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                }`}>
                  {agent.is_active ? 'Active' : 'Disabled'}
                </span>
              </div>
              
              <div className="text-sm text-gray-400 mb-4">
                <p>Role: <span className="text-gray-300">{agent.role}</span></p>
                <p>Active Key: {agent.active_credential_id ? (
                  <span className="text-gray-300 font-mono text-xs">{agent.active_credential_id.substring(0, 8)}...</span>
                ) : (
                  <span className="text-red-400 text-xs">None</span>
                )}</p>
              </div>

              <div className="flex items-center gap-2 pt-3 border-t border-gray-800">
                <button
                  onClick={() => handleToggleStatus(agent.id, agent.is_active)}
                  className={`flex-1 flex items-center justify-center gap-1.5 py-1.5 px-3 rounded text-xs font-medium transition-colors ${
                    agent.is_active 
                      ? 'bg-red-500/10 text-red-400 hover:bg-red-500/20 border border-red-500/20' 
                      : 'bg-green-500/10 text-green-400 hover:bg-green-500/20 border border-green-500/20'
                  }`}
                >
                  {agent.is_active ? <ToggleLeft className="w-3.5 h-3.5" /> : <ToggleRight className="w-3.5 h-3.5" />}
                  {agent.is_active ? 'Disable' : 'Enable'}
                </button>
                <button
                  onClick={() => handleRotateKey(agent.id)}
                  className="flex-1 flex items-center justify-center gap-1.5 bg-gray-800 hover:bg-gray-700 text-gray-300 py-1.5 px-3 rounded text-xs font-medium transition-colors border border-gray-700"
                >
                  <RotateCcw className="w-3.5 h-3.5" />
                  Rotate Key
                </button>
              </div>
            </div>
          ))}
        </div>
        {agents.length === 0 && (
          <div className="text-center py-12 text-gray-500 text-sm">
            No agents registered yet.
          </div>
        )}
      </div>
    </div>
  );
}
