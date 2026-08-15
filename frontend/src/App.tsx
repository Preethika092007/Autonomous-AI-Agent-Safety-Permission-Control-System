import { useState, useMemo, Fragment, useEffect } from "react";
import { useHealth } from "./hooks/useHealth";
import { useAuditLogs } from "./hooks/useAuditLogs";
import { useApprovalsWS } from "./hooks/useApprovalsWS";
import { ApprovalQueue } from "./components/ApprovalQueue";
import { LoginModal } from "./components/LoginModal";
import { AgentManagement } from "./components/AgentManagement";
import { ModelGovernance } from "./components/ModelGovernance";
import { SecurityDashboard } from "./components/SecurityDashboard";
import { LandingPage } from "./components/LandingPage";
import { useAuth } from "./context/AuthContext";
import { 
  Activity, Database, Cpu, Lock, Unlock, Clock, ShieldAlert,
  Search, RefreshCw, AlertTriangle, Users, LogOut, Home
} from "lucide-react";
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell, CartesianGrid } from "recharts";


export default function App() {
  const { health } = useHealth();
  const { logs, loading: logsLoading, refetch: refetchLogs } = useAuditLogs();
  const { queue, connected: wsConnected, removeApproval } = useApprovalsWS();
  const { token, operator, logout } = useAuth();

  const [searchAgent, setSearchAgent] = useState("");
  const [selectedRisk, setSelectedRisk] = useState("ALL");
  const [expandedLogId, setExpandedLogId] = useState<string | null>(null);
  const [showLoginModal, setShowLoginModal] = useState(false);
  const [activeTab, setActiveTab] = useState<"landing" | "dashboard" | "agents" | "governance" | "security">(
    token ? "dashboard" : "landing"
  );

  // Automatically route to dashboard on login, or home on logout
  useEffect(() => {
    if (token) {
      setActiveTab("dashboard");
    } else {
      setActiveTab("landing");
    }
  }, [token]);

  // Filter audit logs based on agent search and risk level dropdown selections
  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      const matchesAgent = log.agent_id.toLowerCase().includes(searchAgent.toLowerCase());
      const matchesRisk = selectedRisk === "ALL" || log.risk_level.toUpperCase() === selectedRisk;
      return matchesAgent && matchesRisk;
    });
  }, [logs, searchAgent, selectedRisk]);

  // Aggregate dashboard stats
  const metrics = useMemo(() => {
    const allowed = logs.filter((l) => l.decision === "allow").length;
    const blocked = logs.filter((l) => l.decision === "block").length;
    const pending = queue.length;
    const total = logs.length + pending;
    return { total, allowed, blocked, pending };
  }, [logs, queue]);

  // Format Recharts data
  const chartData = useMemo(() => {
    return [
      { name: "Allowed Actions", count: metrics.allowed, color: "#10b981" },
      { name: "Blocked Actions", count: metrics.blocked, color: "#ef4444" },
      { name: "Pending Approvals", count: metrics.pending, color: "#f59e0b" }
    ];
  }, [metrics]);

  const toggleExpandLog = (id: string) => {
    setExpandedLogId(expandedLogId === id ? null : id);
  };

  return (
    <div className="min-h-screen bg-[#07080d] text-gray-100 flex flex-col font-sans">
      {/* Upper Navigation Header */}
      <header className="glass-panel sticky top-0 z-50 px-6 py-4 flex flex-wrap items-center justify-between border-b border-gray-800">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 bg-indigo-600 rounded-xl flex items-center justify-center shadow-lg shadow-indigo-500/20">
            <ShieldAlert className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold tracking-tight bg-gradient-to-r from-white via-gray-200 to-gray-500 bg-clip-text text-transparent">
              AURA Firewall Dashboard
            </h1>
            <p className="text-xs text-gray-400">Autonomous AI Agent Safety & Permission Middleware</p>
          </div>
        </div>

        {/* Real-time Status Badges */}
        <div className="flex items-center gap-4 mt-2 sm:mt-0">
          <div className="flex items-center gap-2 bg-black/40 px-3 py-1.5 rounded-full border border-gray-800 text-xs">
            <span className={`w-2.5 h-2.5 rounded-full ${wsConnected ? "bg-green-500 animate-pulse" : "bg-red-500"}`} />
            <span className="text-gray-300">WebSocket: {wsConnected ? "Connected" : "Offline"}</span>
          </div>

          <div className="flex items-center gap-2 bg-black/40 px-3 py-1.5 rounded-full border border-gray-800 text-xs">
            <Database className="w-3.5 h-3.5 text-gray-400" />
            <span className="text-gray-300">
              Database: <span className={health?.services?.database === "healthy" ? "text-green-500 font-medium" : "text-amber-500 font-medium"}>
                {health?.services?.database === "healthy" ? "Online" : "Offline"}
              </span>
            </span>
          </div>

          <div className="flex items-center gap-2 bg-black/40 px-3 py-1.5 rounded-full border border-gray-800 text-xs">
            <Cpu className="w-3.5 h-3.5 text-gray-400" />
            <span className="text-gray-300">
              Redis: <span className={health?.services?.redis === "healthy" ? "text-green-500 font-medium" : "text-amber-500 font-medium"}>
                {health?.services?.redis === "healthy" ? "Online" : "Offline"}
              </span>
            </span>
          </div>

          <div className="flex items-center gap-2 bg-black/40 px-3 py-1.5 rounded-full border border-gray-800 text-xs">
            <Lock className="w-3.5 h-3.5 text-gray-400" />
            <span className="text-gray-300">
              Auth: <span className={health?.services?.authentication === "enabled" ? "text-green-500 font-medium" : "text-amber-500 font-medium"}>
                {health?.services?.authentication === "enabled" ? "On" : "Off"}
              </span>
            </span>
          </div>

          <button 
            onClick={refetchLogs}
            className="p-1.5 rounded-lg hover:bg-gray-800 border border-gray-800 transition-colors"
            title="Refresh logs"
          >
            <RefreshCw className="w-4 h-4 text-gray-400" />
          </button>

          {/* Navigation Tabs */}
          <div className="flex items-center gap-1.5 bg-black/40 p-1.5 rounded-xl border border-gray-800/80">
            <button
              onClick={() => setActiveTab("landing")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                activeTab === "landing" ? "bg-indigo-600 text-white" : "text-gray-400 hover:text-gray-200 hover:bg-gray-800/50"
              }`}
            >
              <Home className="w-3.5 h-3.5" /> Home
            </button>
            
            <button
              onClick={() => setActiveTab("dashboard")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                activeTab === "dashboard" ? "bg-indigo-600 text-white" : "text-gray-400 hover:text-gray-200 hover:bg-gray-800/50"
              }`}
            >
              <Activity className="w-3.5 h-3.5" /> Dashboard
            </button>

            {token && (
              <>
                <button
                  onClick={() => setActiveTab("agents")}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                    activeTab === "agents" ? "bg-indigo-600 text-white" : "text-gray-400 hover:text-gray-200 hover:bg-gray-800/50"
                  }`}
                >
                  <Users className="w-3.5 h-3.5" /> Agents
                </button>
                <button
                  onClick={() => setActiveTab("governance")}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                    activeTab === "governance" ? "bg-indigo-600 text-white" : "text-gray-400 hover:text-gray-200 hover:bg-gray-800/50"
                  }`}
                >
                  <Database className="w-3.5 h-3.5" /> Governance
                </button>
                <button
                  onClick={() => setActiveTab("security")}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                    activeTab === "security" ? "bg-indigo-600 text-white" : "text-gray-400 hover:text-gray-200 hover:bg-gray-800/50"
                  }`}
                >
                  <ShieldAlert className="w-3.5 h-3.5" /> SecOps
                </button>
              </>
            )}
          </div>

          {/* Operator Auth */}
          {token ? (
            <div className="flex items-center gap-3 border-l border-gray-800 pl-4">
              <span className="text-xs text-gray-400 hidden md:inline">
                Logged in as <span className="text-white font-bold">{operator?.username}</span>
              </span>
              <button
                onClick={() => { logout(); setActiveTab("landing"); }}
                className="p-2 text-gray-400 hover:text-white rounded-lg hover:bg-gray-800 transition-colors border border-transparent hover:border-gray-800"
                title="Log Out"
              >
                <LogOut className="w-4 h-4" />
              </button>
            </div>
          ) : (
            <div className="border-l border-gray-800 pl-4">
              <button
                onClick={() => setShowLoginModal(true)}
                className="flex items-center gap-1.5 bg-indigo-600 hover:bg-indigo-700 text-white px-3.5 py-2 rounded-xl text-xs font-semibold transition shadow-lg shadow-indigo-500/20 hover:scale-[1.02]"
              >
                <Lock className="w-3.5 h-3.5" /> Operator Login
              </button>
            </div>
          )}
        </div>
      </header>

      {showLoginModal && <LoginModal onClose={() => setShowLoginModal(false)} />}

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-6 space-y-6">
        
        {activeTab === "landing" ? (
          <LandingPage 
            onLaunchDashboard={() => setActiveTab("dashboard")} 
            onOpenLogin={() => setShowLoginModal(true)} 
            isAuthenticated={!!token} 
          />
        ) : activeTab === "agents" ? (
          <div className="animate-scale-in">
            <AgentManagement />
          </div>
        ) : activeTab === "governance" ? (
          <div className="animate-scale-in">
            <ModelGovernance />
          </div>
        ) : activeTab === "security" ? (
          <div className="animate-scale-in">
            <SecurityDashboard />
          </div>
        ) : (
          <div className="animate-scale-in space-y-6">
            {/* Card Row Metrics */}
            <section className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <div className="glass-panel p-5 rounded-2xl relative overflow-hidden">
            <div className="flex justify-between items-start">
              <div>
                <span className="text-gray-400 text-xs font-semibold uppercase tracking-wider">Total Evaluated</span>
                <h3 className="text-3xl font-bold mt-1 text-white">{metrics.total}</h3>
              </div>
              <div className="p-2 rounded-xl bg-indigo-500/10 text-indigo-400 border border-indigo-500/10">
                <Activity className="w-5 h-5" />
              </div>
            </div>
            <div className="text-[10px] text-indigo-400/80 mt-3 flex items-center gap-1">
              <span>Dynamic API intercepts</span>
            </div>
          </div>

          <div className="glass-panel p-5 rounded-2xl relative overflow-hidden">
            <div className="flex justify-between items-start">
              <div>
                <span className="text-gray-400 text-xs font-semibold uppercase tracking-wider">Allowed Actions</span>
                <h3 className="text-3xl font-bold mt-1 text-green-500">{metrics.allowed}</h3>
              </div>
              <div className="p-2 rounded-xl bg-green-500/10 text-green-400 border border-green-500/10">
                <Unlock className="w-5 h-5" />
              </div>
            </div>
            <div className="text-[10px] text-green-400/80 mt-3 flex items-center gap-1">
              <span>Passed safety validation</span>
            </div>
          </div>

          <div className="glass-panel p-5 rounded-2xl relative overflow-hidden">
            <div className="flex justify-between items-start">
              <div>
                <span className="text-gray-400 text-xs font-semibold uppercase tracking-wider">Blocked Actions</span>
                <h3 className="text-3xl font-bold mt-1 text-red-500">{metrics.blocked}</h3>
              </div>
              <div className="p-2 rounded-xl bg-red-500/10 text-red-400 border border-red-500/10">
                <Lock className="w-5 h-5" />
              </div>
            </div>
            <div className="text-[10px] text-red-400/80 mt-3 flex items-center gap-1">
              <span>Policy & ML rule intercepts</span>
            </div>
          </div>

          <div className="glass-panel p-5 rounded-2xl relative overflow-hidden">
            <div className="flex justify-between items-start">
              <div>
                <span className="text-gray-400 text-xs font-semibold uppercase tracking-wider">Pending Review</span>
                <h3 className="text-3xl font-bold mt-1 text-amber-500">{metrics.pending}</h3>
              </div>
              <div className="p-2 rounded-xl bg-amber-500/10 text-amber-400 border border-amber-500/10">
                <Clock className="w-5 h-5" />
              </div>
            </div>
            <div className="text-[10px] text-amber-400/80 mt-3 flex items-center gap-1">
              <span>Waiting human override</span>
            </div>
          </div>
        </section>

        {/* Dashboard Panels */}
        <div className="grid gap-6 lg:grid-cols-3">
          
          {/* Left Column: Analytics Chart & Audit Logs */}
          <div className="lg:col-span-2 space-y-6">
            
            {/* Analytics Telemetry Chart */}
            <article className="glass-panel p-5 rounded-2xl border border-gray-800">
              <h3 className="text-lg font-bold mb-4 flex items-center gap-2">
                <Activity className="w-4 h-4 text-indigo-400" />
                Firewall Traffic Breakdown
              </h3>
              <div className="h-60 w-full">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={chartData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1f2231" vertical={false} />
                    <XAxis dataKey="name" stroke="#6b7280" fontSize={11} tickLine={false} />
                    <YAxis stroke="#6b7280" fontSize={11} tickLine={false} allowDecimals={false} />
                    <Tooltip 
                      cursor={{ fill: "rgba(255, 255, 255, 0.02)" }}
                      contentStyle={{ background: "#11131c", border: "1px solid #1f2231", borderRadius: "12px", fontSize: "12px" }}
                    />
                    <Bar dataKey="count" radius={[8, 8, 0, 0]} maxBarSize={60}>
                      {chartData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </article>

            {/* Historical Audit Logs Stream */}
            <article className="glass-panel p-5 rounded-2xl border border-gray-800">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-4">
                <h3 className="text-lg font-bold flex items-center gap-2">
                  <Activity className="w-4 h-4 text-indigo-400" />
                  Access Audit Logs
                </h3>

                {/* Filter Controls */}
                <div className="flex flex-wrap gap-2 items-center">
                  <div className="relative">
                    <Search className="w-3.5 h-3.5 text-gray-400 absolute left-3 top-1/2 -translate-y-1/2" />
                    <input
                      type="text"
                      placeholder="Search Agent..."
                      value={searchAgent}
                      onChange={(e) => setSearchAgent(e.target.value)}
                      className="bg-black/55 text-xs text-gray-200 pl-8 pr-3 py-1.5 rounded-lg border border-gray-800 focus:outline-none focus:border-indigo-600 transition-colors w-40"
                    />
                  </div>

                  <select
                    value={selectedRisk}
                    onChange={(e) => setSelectedRisk(e.target.value)}
                    className="bg-black/55 text-xs text-gray-200 px-3 py-1.5 rounded-lg border border-gray-800 focus:outline-none focus:border-indigo-600 transition-colors cursor-pointer"
                  >
                    <option value="ALL">All Risks</option>
                    <option value="LOW">Low</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="HIGH">High</option>
                  </select>
                </div>
              </div>

              {/* Data Table */}
              <div className="overflow-x-auto">
                {logsLoading ? (
                  <div className="text-center py-10 text-gray-400 text-sm">Loading logs...</div>
                ) : filteredLogs.length === 0 ? (
                  <div className="text-center py-10 text-gray-400 text-sm">No matching audit logs found.</div>
                ) : (
                  <table className="w-full text-left text-xs border-collapse">
                    <thead>
                      <tr className="border-b border-gray-800 text-gray-400 font-semibold uppercase tracking-wider">
                        <th className="py-3 px-3">Agent</th>
                        <th className="py-3 px-3">Action</th>
                        <th className="py-3 px-3">Decision</th>
                        <th className="py-3 px-3">Risk Level</th>
                        <th className="py-3 px-3 text-right">Time</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800/40">
                      {filteredLogs.map((log) => {
                        const isExpanded = expandedLogId === log.id;
                        return (
                          <Fragment key={log.id}>
                            <tr 
                              onClick={() => toggleExpandLog(log.id)}
                              className="hover:bg-white/[0.02] cursor-pointer transition-colors duration-150"
                            >
                              <td className="py-3.5 px-3 font-semibold text-gray-200">{log.agent_id}</td>
                              <td className="py-3.5 px-3">
                                <span className="font-mono text-[10px] bg-black/40 px-2 py-0.5 rounded border border-gray-800/80 text-purple-400">
                                  {log.action}
                                </span>
                              </td>
                              <td className="py-3.5 px-3">
                                <span className={`font-semibold inline-flex items-center gap-1.5 ${
                                  log.decision === "allow" ? "text-green-500" : "text-red-500"
                                }`}>
                                  <span className={`w-1.5 h-1.5 rounded-full ${
                                    log.decision === "allow" ? "bg-green-500" : "bg-red-500"
                                  }`} />
                                  {log.decision.toUpperCase()}
                                </span>
                              </td>
                              <td className="py-3.5 px-3">
                                <span className={`font-semibold px-2 py-0.5 rounded text-[10px] ${
                                  log.risk_level === "high" 
                                    ? "bg-red-500/10 text-red-500 border border-red-500/20" 
                                    : log.risk_level === "medium"
                                      ? "bg-amber-500/10 text-amber-500 border border-amber-500/20"
                                      : "bg-green-500/10 text-green-500 border border-green-500/20"
                                }`}>
                                  {log.risk_level.toUpperCase()}
                                </span>
                              </td>
                              <td className="py-3.5 px-3 text-right text-gray-500 font-mono">
                                {new Date(log.requested_at).toLocaleTimeString()}
                              </td>
                            </tr>
                            {/* Collapsible Row for SHAP Details */}
                            {isExpanded && (
                              <tr>
                                <td colSpan={5} className="bg-black/30 px-5 py-4 text-xs text-gray-300">
                                  <div className="grid gap-3 sm:grid-cols-2">
                                    <div>
                                      <span className="text-[10px] text-gray-500 font-mono block uppercase mb-1">
                                        Evaluation Trace:
                                      </span>
                                      <div className="grid grid-cols-2 gap-x-2 gap-y-1 mb-3 bg-black/40 p-2.5 rounded border border-gray-800/80 text-[10px] font-mono text-gray-400">
                                        <div>Request ID:</div>
                                        <div className="truncate text-indigo-400">{log.request_id || "N/A"}</div>
                                        <div>Model Version:</div>
                                        <div className="text-white">{log.model_version || "N/A"}</div>
                                        <div>Feature Schema:</div>
                                        <div className="text-white">{log.feature_schema_version ? `v${log.feature_schema_version}` : "N/A"}</div>
                                        <div>Policy Version:</div>
                                        <div className="text-white">{log.policy_version || "N/A"}</div>
                                      </div>

                                      <span className="text-[10px] text-gray-500 font-mono block uppercase mb-1">
                                        Action Parameters:
                                      </span>
                                      <pre className="bg-black/60 p-2.5 rounded border border-gray-800 text-[10px] font-mono max-h-32 overflow-y-auto text-gray-400">
                                        {JSON.stringify(log.parameters, null, 2)}
                                      </pre>
                                    </div>
                                    <div>
                                      <span className="text-[10px] text-gray-500 font-mono block uppercase mb-1">
                                        SHAP Threat Explanation & Override details:
                                      </span>
                                      <div className="bg-indigo-500/5 p-3 rounded-xl border border-indigo-500/15 text-gray-300 flex items-start gap-2.5">
                                        <AlertTriangle className="w-4 h-4 text-indigo-400 shrink-0 mt-0.5" />
                                        <div>{log.reason}</div>
                                      </div>

                                      <span className="text-[10px] text-gray-500 font-mono block uppercase mt-3 mb-1">
                                        Evaluated At:
                                      </span>
                                      <span className="font-mono text-gray-400">
                                        {log.evaluation_timestamp 
                                          ? new Date(log.evaluation_timestamp).toLocaleString() 
                                          : new Date(log.evaluated_at).toLocaleString()}
                                      </span>
                                    </div>
                                  </div>
                                </td>
                              </tr>
                            )}
                          </Fragment>
                        );
                      })}
                    </tbody>
                  </table>
                )}
              </div>
            </article>
          </div>
          {/* Right Column: Live Human Approval Queue */}
          <div className="lg:col-span-1">
            <ApprovalQueue queue={queue} onResolve={removeApproval} />
          </div>

        </div>
        </div>
        )}
      </main>

      <footer className="py-6 text-center text-xs text-gray-600 border-t border-gray-900 mt-12 bg-black/10">
        <p>&copy; {new Date().getFullYear()} Autonomous Agent Safety Middleware Systems. Local ML Engine (XGBoost/SHAP) Active.</p>
      </footer>
    </div>
  );
}
