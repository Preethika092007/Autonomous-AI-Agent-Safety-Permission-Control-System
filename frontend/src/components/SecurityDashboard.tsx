import React, { useState, useEffect } from "react";
import { useAuth } from "../context/AuthContext";
import { useSecurity } from "../hooks/useSecurity";
import type { VerifyReport } from "../hooks/useSecurity";
import { useIncidents } from "../hooks/useIncidents";
import {
  Shield,
  Lock,
  Unlock,
  ShieldAlert,
  List,
  FileText,
  CheckCircle,
  AlertOctagon,
  Activity,
  RefreshCw,
  Search,
  PlusCircle,
  AlertTriangle,
  UserPlus
} from "lucide-react";

export function SecurityDashboard() {
  const { operator } = useAuth();
  const isAdmin = operator?.role === "admin";

  const {
    lockdownEnabled,
    auditEvents,
    auditMetadata,
    loading: secLoading,
    fetchStatus,
    triggerLockdown,
    releaseLockdown,
    verifyAuditLogs,
    exportAuditLogs,
    quarantineAgent
  } = useSecurity();

  const {
    incidents,
    loading: incLoading,
    fetchIncidents,
    createIncident,
    updateIncident,
    resolveIncident
  } = useIncidents();

  // Verification results state
  const [verifyReport, setVerifyReport] = useState<VerifyReport | null>(null);
  const [verifyError, setVerifyError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);

  // Quarantine form state
  const [quarantineAgentId, setQuarantineAgentId] = useState("");
  const [quarantineIncidentId, setQuarantineIncidentId] = useState("");
  const [quarantineSuccess, setQuarantineSuccess] = useState<string | null>(null);
  const [quarantineError, setQuarantineError] = useState<string | null>(null);

  // New incident form state
  const [showNewIncidentModal, setShowNewIncidentModal] = useState(false);
  const [newIncTitle, setNewIncTitle] = useState("");
  const [newIncDesc, setNewIncDesc] = useState("");
  const [newIncSeverity, setNewIncSeverity] = useState("medium");
  const [newIncAgent, setNewIncAgent] = useState("");
  const [newIncModel, setNewIncModel] = useState("");
  const [newIncPolicy, setNewIncPolicy] = useState("");

  // Filter logs state
  const [filterSeverity, setFilterSeverity] = useState("");
  const [filterEventType, setFilterEventType] = useState("");
  const [filterAgentId, setFilterAgentId] = useState("");
  const [filterIncidentId, setFilterIncidentId] = useState("");
  const [filterPage] = useState(1);

  // Incident resolution state
  const [resolvingIncidentId, setResolvingIncidentId] = useState<string | null>(null);
  const [resolutionNotes, setResolutionNotes] = useState("");

  // Incident assignment state
  const [assigningIncidentId, setAssigningIncidentId] = useState<string | null>(null);
  const [assignOperatorVal, setAssignOperatorVal] = useState("");

  // Initial loads
  useEffect(() => {
    fetchStatus();
    fetchIncidents();
    handleSearchAudit();
  }, []);

  const handleSearchAudit = () => {
    exportAuditLogs({
      severity: filterSeverity || undefined,
      event_type: filterEventType || undefined,
      agent_id: filterAgentId || undefined,
      incident_id: filterIncidentId || undefined,
      page: filterPage,
      limit: 100
    });
  };

  const handleTriggerLockdown = async () => {
    if (!window.confirm("CRITICAL WARNING: Are you sure you want to trigger a global system lockdown? This will block all evaluate-action operations.")) return;
    try {
      await triggerLockdown();
      alert("Global system lockdown active!");
    } catch (e: any) {
      alert("Failed to trigger lockdown: " + e.message);
    }
  };

  const handleReleaseLockdown = async () => {
    if (!window.confirm("Are you sure you want to release the global system lockdown?")) return;
    try {
      await releaseLockdown();
      alert("Lockdown released. Safety systems restored.");
    } catch (e: any) {
      alert("Failed to release lockdown: " + e.message);
    }
  };

  const handleVerifyChain = async () => {
    setVerifying(true);
    setVerifyReport(null);
    setVerifyError(null);
    try {
      const res = await verifyAuditLogs();
      setVerifyReport(res);
    } catch (e: any) {
      setVerifyError(e.response?.data?.detail?.message || e.message || "Audit chain verification failed");
    } finally {
      setVerifying(false);
    }
  };

  const handleQuarantine = async (e: React.FormEvent) => {
    e.preventDefault();
    setQuarantineSuccess(null);
    setQuarantineError(null);
    if (!quarantineAgentId || !quarantineIncidentId) {
      setQuarantineError("Please provide both Agent ID and linked Incident ID.");
      return;
    }
    try {
      await quarantineAgent(quarantineAgentId, quarantineIncidentId);
      setQuarantineSuccess(`Agent '${quarantineAgentId}' successfully quarantined. Key revoked.`);
      setQuarantineAgentId("");
      setQuarantineIncidentId("");
    } catch (err: any) {
      setQuarantineError(err.message || "Quarantine action failed.");
    }
  };

  const handleCreateIncident = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await createIncident({
        title: newIncTitle,
        description: newIncDesc,
        severity: newIncSeverity,
        affected_agent_id: newIncAgent || undefined,
        affected_model_version: newIncModel || undefined,
        affected_policy_version: newIncPolicy || undefined
      });
      setShowNewIncidentModal(false);
      setNewIncTitle("");
      setNewIncDesc("");
      setNewIncSeverity("medium");
      setNewIncAgent("");
      setNewIncModel("");
      setNewIncPolicy("");
      alert("Incident successfully reported.");
    } catch (err: any) {
      alert("Failed to create incident: " + err.message);
    }
  };

  const handleResolveIncidentSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!resolvingIncidentId) return;
    try {
      await resolveIncident(resolvingIncidentId, resolutionNotes);
      setResolvingIncidentId(null);
      setResolutionNotes("");
      alert("Incident resolved.");
    } catch (err: any) {
      alert("Failed to resolve incident: " + err.message);
    }
  };

  const handleAssignIncidentSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!assigningIncidentId || !assignOperatorVal) return;
    try {
      await updateIncident(assigningIncidentId, { assigned_to: assignOperatorVal });
      setAssigningIncidentId(null);
      setAssignOperatorVal("");
      alert("Incident assigned successfully.");
    } catch (err: any) {
      alert("Failed to assign incident: " + err.message);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto p-4 md:p-6 bg-slate-900 text-slate-100 min-h-screen">
      {/* Header Banner */}
      <div className="flex flex-col md:flex-row justify-between items-start md:items-center bg-slate-800/80 border border-slate-700/50 p-6 rounded-2xl backdrop-blur gap-4">
        <div>
          <h1 className="text-3xl font-extrabold tracking-tight bg-gradient-to-r from-red-400 via-pink-400 to-indigo-400 bg-clip-text text-transparent flex items-center gap-3">
            <Shield className="h-8 w-8 text-red-400" />
            Security Operations & Audit
          </h1>
          <p className="text-slate-400 mt-1">
            Real-time incident governance, agent quarantines, global lockdown triggers, and cryptographic audit chains.
          </p>
        </div>
        
        {/* Global Lockdown Toggle Banner */}
        <div className="flex items-center gap-3 bg-slate-900/60 p-3 rounded-xl border border-slate-700/60">
          <span className="text-sm font-semibold uppercase tracking-wider text-slate-400">Lockdown Status:</span>
          {lockdownEnabled ? (
            <div className="flex items-center gap-2 px-3 py-1 bg-red-950/80 text-red-400 border border-red-500/50 rounded-full text-xs font-bold uppercase animate-pulse">
              <Lock className="h-3 w-3" /> Enabled (Fails Closed)
            </div>
          ) : (
            <div className="flex items-center gap-2 px-3 py-1 bg-emerald-950/80 text-emerald-400 border border-emerald-500/50 rounded-full text-xs font-bold uppercase">
              <Unlock className="h-3 w-3" /> Inactive (Healthy)
            </div>
          )}

          {isAdmin && (
            <button
              onClick={lockdownEnabled ? handleReleaseLockdown : handleTriggerLockdown}
              className={`ml-2 px-4 py-1.5 rounded-lg text-xs font-bold tracking-wider uppercase transition duration-150 ${
                lockdownEnabled
                  ? "bg-emerald-600 hover:bg-emerald-700 text-white shadow-lg shadow-emerald-900/40"
                  : "bg-red-600 hover:bg-red-700 text-white shadow-lg shadow-red-900/40"
              }`}
            >
              {lockdownEnabled ? "Unlock System" : "LOCKDOWN"}
            </button>
          )}
        </div>
      </div>

      {/* Grid: Quarantine Form + Audit integrity checks */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        
        {/* Containment & Quarantine Container */}
        <div className="bg-slate-800/60 border border-slate-700/50 rounded-2xl p-6 backdrop-blur space-y-4">
          <h2 className="text-xl font-bold flex items-center gap-2 text-rose-400">
            <ShieldAlert className="h-5 w-5" /> Agent Quarantine Control
          </h2>
          <p className="text-sm text-slate-400">
            Deactivate a suspicious or compromised agent immediately. This revokes all active API keys and blocks future /evaluate-action execution.
          </p>

          <form onSubmit={handleQuarantine} className="space-y-4">
            <div>
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1">Suspicious Agent ID</label>
              <input
                type="text"
                value={quarantineAgentId}
                onChange={(e) => setQuarantineAgentId(e.target.value)}
                placeholder="e.g. rogue-researcher"
                className="w-full bg-slate-900/80 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-red-500"
              />
            </div>
            <div>
              <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1">Linked Operational Incident ID</label>
              <select
                value={quarantineIncidentId}
                onChange={(e) => setQuarantineIncidentId(e.target.value)}
                className="w-full bg-slate-900/80 border border-slate-700 rounded-xl px-4 py-2.5 text-sm text-slate-100 focus:outline-none focus:border-red-500"
              >
                <option value="">-- Select Linked Incident --</option>
                {incidents.filter(i => i.status !== "resolved" && i.status !== "closed").map(inc => (
                  <option key={inc.incident_id} value={inc.incident_id}>
                    [{inc.severity.toUpperCase()}] {inc.title} ({inc.incident_id.substring(0,8)})
                  </option>
                ))}
              </select>
            </div>
            {quarantineError && (
              <div className="p-3 bg-red-950/60 text-red-400 border border-red-800/40 rounded-xl text-xs flex items-center gap-2">
                <AlertOctagon className="h-4 w-4 shrink-0" /> {quarantineError}
              </div>
            )}
            {quarantineSuccess && (
              <div className="p-3 bg-emerald-950/60 text-emerald-400 border border-emerald-800/40 rounded-xl text-xs flex items-center gap-2">
                <CheckCircle className="h-4 w-4 shrink-0" /> {quarantineSuccess}
              </div>
            )}
            <button
              type="submit"
              disabled={!isAdmin}
              className="w-full bg-red-950/80 text-red-400 border border-red-500/50 hover:bg-red-900/80 px-4 py-2.5 rounded-xl font-bold uppercase text-xs tracking-wider transition disabled:opacity-40"
            >
              Trigger Agent Quarantine
            </button>
          </form>
        </div>

        {/* Cryptographic Audit Verification */}
        <div className="bg-slate-800/60 border border-slate-700/50 rounded-2xl p-6 backdrop-blur space-y-4 flex flex-col justify-between">
          <div>
            <h2 className="text-xl font-bold flex items-center gap-2 text-indigo-400">
              <Activity className="h-5 w-5" /> Cryptographic Integrity Audit
            </h2>
            <p className="text-sm text-slate-400">
              Verify the entire security logs database sequence. Compares the hash of each record concatenated with its predecessor to detect external db injection or modification.
            </p>
          </div>

          <div className="bg-slate-900/60 border border-slate-700/60 p-4 rounded-xl min-h-[120px] flex flex-col justify-center items-center gap-2">
            {verifying ? (
              <div className="flex flex-col items-center gap-2">
                <RefreshCw className="h-6 w-6 text-indigo-400 animate-spin" />
                <span className="text-xs text-slate-400">Recalculating hash chain signatures...</span>
              </div>
            ) : verifyReport ? (
              <div className="text-center space-y-2 w-full">
                {verifyReport.valid ? (
                  <div className="text-emerald-400 font-bold flex items-center justify-center gap-1">
                    <CheckCircle className="h-5 w-5" /> LOG INTEGRITY CONFIRMED
                  </div>
                ) : (
                  <div className="text-red-400 font-bold flex items-center justify-center gap-1 animate-bounce">
                    <AlertTriangle className="h-5 w-5" /> TAMPER WARNING DETECTED
                  </div>
                )}
                <div className="grid grid-cols-2 gap-2 text-xs text-slate-400 max-w-xs mx-auto">
                  <div className="text-right font-medium">Checked:</div>
                  <div className="text-left text-slate-200">{verifyReport.events_checked} events</div>
                  <div className="text-right font-medium">Timestamp:</div>
                  <div className="text-left text-slate-200">{new Date(verifyReport.verified_at).toLocaleTimeString()}</div>
                  {!verifyReport.valid && (
                    <>
                      <div className="text-right font-medium text-red-400">Corrupted ID:</div>
                      <div className="text-left text-red-300 font-mono">{verifyReport.first_invalid_event_id?.substring(0,8) || "N/A"}</div>
                    </>
                  )}
                </div>
              </div>
            ) : verifyError ? (
              <div className="text-center text-red-400 text-xs font-medium space-y-1">
                <AlertOctagon className="h-6 w-6 text-red-400 mx-auto" />
                <p>Verify Failed: {verifyError}</p>
              </div>
            ) : (
              <span className="text-xs text-slate-500 italic">No verification report generated yet.</span>
            )}
          </div>

          <button
            onClick={handleVerifyChain}
            className="w-full bg-slate-900 border border-slate-700 hover:bg-slate-800 text-slate-200 px-4 py-2.5 rounded-xl font-bold uppercase text-xs tracking-wider transition"
          >
            Verify Log Chain Signatures
          </button>
        </div>
      </div>

      {/* Incidents Management Section */}
      <div className="bg-slate-800/60 border border-slate-700/50 rounded-2xl p-6 backdrop-blur space-y-4">
        <div className="flex justify-between items-center">
          <h2 className="text-xl font-bold flex items-center gap-2 text-pink-400">
            <List className="h-5 w-5" /> Operational Incidents Governance
          </h2>
          <button
            onClick={() => setShowNewIncidentModal(true)}
            className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 transition"
          >
            <PlusCircle className="h-4 w-4" /> Declare Incident
          </button>
        </div>

        {incLoading ? (
          <div className="text-center text-xs text-slate-400 py-6">Loading incident registry...</div>
        ) : incidents.length === 0 ? (
          <div className="text-center text-xs text-slate-500 italic py-6">No incident records logged.</div>
        ) : (
          <div className="overflow-x-auto rounded-xl border border-slate-700/50 bg-slate-900/50">
            <table className="w-full border-collapse text-left text-sm">
              <thead className="bg-slate-900/80 text-xs uppercase tracking-wider text-slate-400 border-b border-slate-700/50">
                <tr>
                  <th className="p-4">Incident ID</th>
                  <th className="p-4">Title & Description</th>
                  <th className="p-4">Severity</th>
                  <th className="p-4">Status</th>
                  <th className="p-4">Ownership</th>
                  <th className="p-4 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800">
                {incidents.map((inc) => (
                  <tr key={inc.incident_id} className="hover:bg-slate-800/30">
                    <td className="p-4 font-mono text-xs text-slate-300">
                      {inc.incident_id.substring(0, 8)}...
                    </td>
                    <td className="p-4">
                      <div className="font-bold text-slate-200">{inc.title}</div>
                      <div className="text-xs text-slate-400 line-clamp-2 mt-0.5">{inc.description}</div>
                      {inc.resolution_notes && (
                        <div className="mt-1.5 p-2 bg-slate-950/40 border border-slate-800/80 rounded text-xs text-slate-400">
                          <span className="font-bold text-emerald-400">Resolution:</span> {inc.resolution_notes}
                        </div>
                      )}
                    </td>
                    <td className="p-4">
                      <span className={`px-2.5 py-0.5 rounded-full text-xs font-bold uppercase ${
                        inc.severity === "critical" ? "bg-red-950/80 text-red-400 border border-red-500/30" :
                        inc.severity === "high" ? "bg-orange-950/80 text-orange-400 border border-orange-500/30" :
                        inc.severity === "medium" ? "bg-yellow-950/80 text-yellow-400 border border-yellow-500/30" :
                        "bg-slate-850/80 text-slate-300 border border-slate-700/30"
                      }`}>
                        {inc.severity}
                      </span>
                    </td>
                    <td className="p-4">
                      <span className={`px-2 py-0.5 rounded-full text-xs font-bold ${
                        inc.status === "resolved" || inc.status === "closed" ? "bg-emerald-950/85 text-emerald-400 border border-emerald-500/30" :
                        inc.status === "contained" ? "bg-cyan-950/85 text-cyan-400 border border-cyan-500/30" :
                        "bg-blue-950/85 text-blue-400 border border-blue-500/30"
                      }`}>
                        {inc.status}
                      </span>
                    </td>
                    <td className="p-4 text-xs text-slate-300">
                      <div><span className="text-slate-500">By:</span> {inc.created_by}</div>
                      <div><span className="text-slate-500">Assign:</span> {inc.assigned_to || <span className="italic text-yellow-500/70">Unassigned</span>}</div>
                    </td>
                    <td className="p-4 text-right space-y-1.5">
                      {inc.status !== "resolved" && inc.status !== "closed" && (
                        <div className="flex flex-col items-end gap-1.5">
                          {/* Assignment (Only admin) */}
                          {isAdmin && (
                            <button
                              onClick={() => {
                                setAssigningIncidentId(inc.incident_id);
                                setAssignOperatorVal(inc.assigned_to || "");
                              }}
                              className="text-indigo-400 hover:text-indigo-300 text-xs font-semibold flex items-center gap-0.5"
                            >
                              <UserPlus className="h-3.5 w-3.5" /> Assign
                            </button>
                          )}
                          
                          {/* Resolution */}
                          <button
                            onClick={() => {
                              setResolvingIncidentId(inc.incident_id);
                              setResolutionNotes("");
                            }}
                            className="bg-emerald-600 hover:bg-emerald-700 text-white px-2.5 py-1 rounded-lg text-xs font-bold transition"
                          >
                            Resolve
                          </button>
                        </div>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Compliance Event Audit log exporter */}
      <div className="bg-slate-800/60 border border-slate-700/50 rounded-2xl p-6 backdrop-blur space-y-4">
        <h2 className="text-xl font-bold flex items-center gap-2 text-indigo-400">
          <FileText className="h-5 w-5" /> Compliance Audit Trail Exporter
        </h2>
        <p className="text-sm text-slate-400">
          Search and query cryptographically chained security logs. Chronologically exports audit records matching policy filters.
        </p>

        {/* Filters */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 bg-slate-900/60 border border-slate-700/50 p-4 rounded-xl">
          <div>
            <label className="block text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1">Severity</label>
            <select
              value={filterSeverity}
              onChange={(e) => setFilterSeverity(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs focus:outline-none"
            >
              <option value="">All</option>
              <option value="info">Info</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="critical">Critical</option>
            </select>
          </div>
          <div>
            <label className="block text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1">Event Type</label>
            <input
              type="text"
              value={filterEventType}
              placeholder="e.g. emergency_lockdown"
              onChange={(e) => setFilterEventType(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-600 focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1">Agent ID</label>
            <input
              type="text"
              value={filterAgentId}
              placeholder="Filter by agent..."
              onChange={(e) => setFilterAgentId(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-600 focus:outline-none"
            />
          </div>
          <div>
            <label className="block text-[10px] font-bold uppercase tracking-wider text-slate-400 mb-1">Incident ID</label>
            <input
              type="text"
              value={filterIncidentId}
              placeholder="Filter by incident..."
              onChange={(e) => setFilterIncidentId(e.target.value)}
              className="w-full bg-slate-900 border border-slate-700 rounded-lg px-2.5 py-1.5 text-xs text-slate-100 placeholder-slate-600 focus:outline-none"
            />
          </div>
        </div>

        <div className="flex justify-end gap-3">
          <button
            onClick={handleSearchAudit}
            className="bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-xl text-xs font-bold flex items-center gap-1.5 transition"
          >
            <Search className="h-4 w-4" /> Filter Trail
          </button>
        </div>

        {/* Audit Log Table list */}
        {secLoading ? (
          <div className="text-center text-xs text-slate-400 py-6">Exporting logs...</div>
        ) : auditEvents.length === 0 ? (
          <div className="text-center text-xs text-slate-500 italic py-6">No matching logs fetched.</div>
        ) : (
          <div className="space-y-2">
            <div className="text-right text-xs text-slate-400">
              Chained Count: <span className="font-semibold text-slate-200">{auditMetadata?.total_records || auditEvents.length}</span> records
            </div>
            
            <div className="overflow-x-auto rounded-xl border border-slate-700/50 bg-slate-900/50 max-h-[400px]">
              <table className="w-full border-collapse text-left text-sm">
                <thead className="bg-slate-900/80 text-xs uppercase tracking-wider text-slate-400 border-b border-slate-700/50 sticky top-0">
                  <tr>
                    <th className="p-3">Time</th>
                    <th className="p-3">Event Type</th>
                    <th className="p-3">Severity</th>
                    <th className="p-3">Description</th>
                    <th className="p-3">Audit Signatures (SHA256)</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-slate-800">
                  {auditEvents.map((evt) => (
                    <tr key={evt.event_id} className="hover:bg-slate-800/35">
                      <td className="p-3 text-xs text-slate-400 whitespace-nowrap">
                        {new Date(evt.timestamp).toLocaleString()}
                      </td>
                      <td className="p-3 text-xs font-bold text-slate-300">{evt.event_type}</td>
                      <td className="p-3 text-xs">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                          evt.severity === "critical" ? "bg-red-950 text-red-400 border border-red-500/20" :
                          evt.severity === "high" ? "bg-orange-950 text-orange-400 border border-orange-500/20" :
                          "bg-slate-800 text-slate-300"
                        }`}>
                          {evt.severity}
                        </span>
                      </td>
                      <td className="p-3 text-xs text-slate-300">{evt.description}</td>
                      <td className="p-3 font-mono text-[10px] text-indigo-400 space-y-0.5 whitespace-nowrap max-w-[200px] truncate">
                        <div><span className="text-slate-500">Prev:</span> {evt.previous_event_hash.substring(0,12)}...</div>
                        <div><span className="text-slate-500">Hash:</span> {evt.event_hash.substring(0,12)}...</div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* MODAL: Declare Incident */}
      {showNewIncidentModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-700/60 p-6 rounded-2xl w-full max-w-lg space-y-4 shadow-2xl">
            <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2 border-b border-slate-800 pb-3">
              <PlusCircle className="text-indigo-400" /> Declare New Operational Incident
            </h3>
            
            <form onSubmit={handleCreateIncident} className="space-y-4">
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1">Incident Title</label>
                <input
                  type="text"
                  required
                  value={newIncTitle}
                  onChange={(e) => setNewIncTitle(e.target.value)}
                  placeholder="e.g. Rogue XGBoost prediction anomalies"
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-2 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1">Detailed Description</label>
                <textarea
                  required
                  rows={3}
                  value={newIncDesc}
                  onChange={(e) => setNewIncDesc(e.target.value)}
                  placeholder="Describe the operational incident or suspected attack vector..."
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-2 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1">Severity</label>
                  <select
                    value={newIncSeverity}
                    onChange={(e) => setNewIncSeverity(e.target.value)}
                    className="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-2 text-sm text-slate-100 focus:outline-none"
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1">Affected Agent ID (Optional)</label>
                  <input
                    type="text"
                    value={newIncAgent}
                    onChange={(e) => setNewIncAgent(e.target.value)}
                    placeholder="e.g. research-002"
                    className="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-2 text-sm text-slate-100 placeholder-slate-600 focus:outline-none"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1">Affected Model Version (Optional)</label>
                  <input
                    type="text"
                    value={newIncModel}
                    onChange={(e) => setNewIncModel(e.target.value)}
                    placeholder="e.g. v20260813-09"
                    className="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-2 text-sm text-slate-100 placeholder-slate-600 focus:outline-none"
                  />
                </div>
                <div>
                  <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1">Affected Policy Version (Optional)</label>
                  <input
                    type="text"
                    value={newIncPolicy}
                    onChange={(e) => setNewIncPolicy(e.target.value)}
                    placeholder="e.g. 1.0.0"
                    className="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-2 text-sm text-slate-100 placeholder-slate-600 focus:outline-none"
                  />
                </div>
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setShowNewIncidentModal(false)}
                  className="bg-slate-800 hover:bg-slate-700 text-slate-350 px-4 py-2 rounded-xl text-xs font-bold transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2 rounded-xl text-xs font-bold transition"
                >
                  Submit Incident
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: Resolve Incident */}
      {resolvingIncidentId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-700/60 p-6 rounded-2xl w-full max-w-md space-y-4 shadow-2xl">
            <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2 border-b border-slate-800 pb-3">
              <CheckCircle className="text-emerald-400" /> Resolve Security Incident
            </h3>
            
            <form onSubmit={handleResolveIncidentSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1">Resolution Summary & Notes</label>
                <textarea
                  required
                  rows={4}
                  value={resolutionNotes}
                  onChange={(e) => setResolutionNotes(e.target.value)}
                  placeholder="Detail the analysis findings, containment actions, and resolution steps..."
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-2 text-sm text-slate-100 placeholder-slate-650 focus:outline-none focus:border-emerald-500"
                />
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setResolvingIncidentId(null)}
                  className="bg-slate-800 hover:bg-slate-700 text-slate-350 px-4 py-2 rounded-xl text-xs font-bold transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-emerald-600 hover:bg-emerald-700 text-white px-5 py-2 rounded-xl text-xs font-bold transition"
                >
                  Resolve Incident
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* MODAL: Assign Incident */}
      {assigningIncidentId && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/80 backdrop-blur-sm p-4">
          <div className="bg-slate-900 border border-slate-700/60 p-6 rounded-2xl w-full max-w-md space-y-4 shadow-2xl">
            <h3 className="text-lg font-bold text-slate-100 flex items-center gap-2 border-b border-slate-800 pb-3">
              <UserPlus className="text-indigo-400" /> Assign Incident Ownership
            </h3>
            
            <form onSubmit={handleAssignIncidentSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-bold uppercase tracking-wider text-slate-400 mb-1">Assigned Operator Username</label>
                <input
                  type="text"
                  required
                  value={assignOperatorVal}
                  onChange={(e) => setAssignOperatorVal(e.target.value)}
                  placeholder="e.g. admin"
                  className="w-full bg-slate-950 border border-slate-700 rounded-xl px-4 py-2 text-sm text-slate-100 placeholder-slate-600 focus:outline-none focus:border-indigo-500"
                />
              </div>

              <div className="flex justify-end gap-3 pt-3 border-t border-slate-800">
                <button
                  type="button"
                  onClick={() => setAssigningIncidentId(null)}
                  className="bg-slate-800 hover:bg-slate-700 text-slate-350 px-4 py-2 rounded-xl text-xs font-bold transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="bg-indigo-600 hover:bg-indigo-700 text-white px-5 py-2 rounded-xl text-xs font-bold transition"
                >
                  Assign Operator
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
}
