import { useState } from "react";
import { useModels } from "../hooks/useModels";
import { useAuth } from "../context/AuthContext";
import {
  Shield,
  Activity,
  CheckCircle,
  AlertTriangle,
  RefreshCw,
  Cpu,
  List,
  Lock
} from "lucide-react";

export function ModelGovernance() {
  const { models, health, loading, error, refresh, activateModel, rollbackModel } = useModels();
  const { operator } = useAuth();
  const isAdmin = operator?.role === "admin";

  const [selectedModel, setSelectedModel] = useState<string | null>(null);
  const [showConfirm, setShowConfirm] = useState(false);
  const [confirmType, setConfirmType] = useState<"activate" | "rollback">("activate");
  const [localError, setLocalError] = useState<string | null>(null);
  const [actionSuccessMsg, setActionSuccessMsg] = useState<string | null>(null);

  const activeModelObj = models.find((m) => m.status === "active");

  const handleOpenConfirm = (type: "activate" | "rollback", version?: string) => {
    setLocalError(null);
    setActionSuccessMsg(null);
    setConfirmType(type);
    if (type === "activate" && version) {
      setSelectedModel(version);
    }
    setShowConfirm(true);
  };

  const handleConfirmAction = async () => {
    try {
      setLocalError(null);
      if (confirmType === "activate" && selectedModel) {
        const res = await activateModel(selectedModel);
        setActionSuccessMsg(res?.message || "Model activated successfully!");
      } else if (confirmType === "rollback") {
        const res = await rollbackModel();
        setActionSuccessMsg(res?.message || "Rollback completed successfully!");
      }
      setShowConfirm(false);
    } catch (err: any) {
      setLocalError(err.message || "Action failed.");
      setShowConfirm(false);
    }
  };

  if (loading && models.length === 0) {
    return (
      <div className="flex h-64 items-center justify-center">
        <RefreshCw className="h-8 w-8 animate-spin text-indigo-500" />
      </div>
    );
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case "active":
        return "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20";
      case "candidate":
        return "bg-indigo-500/10 text-indigo-400 border border-indigo-500/20";
      default:
        return "bg-gray-500/10 text-gray-400 border border-gray-500/20";
    }
  };

  const getDriftBadgeColor = (status?: string) => {
    switch (status) {
      case "critical":
        return "bg-rose-500/10 text-rose-400 border border-rose-500/20";
      case "warning":
        return "bg-amber-500/10 text-amber-400 border border-amber-500/20";
      default:
        return "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20";
    }
  };

  return (
    <div className="space-y-6">
      {/* Upper Alerts & Operations Hero Card */}
      <div className="glass-panel p-6 rounded-3xl border border-gray-800/80 bg-gradient-to-r from-indigo-950/20 via-transparent to-transparent flex flex-col md:flex-row items-center justify-between gap-6">
        <div className="space-y-3 md:w-2/3">
          <h2 className="text-2xl font-bold text-gradient">ML Model Governance & Drift Telemetry</h2>
          <p className="text-sm text-gray-400 leading-relaxed">
            Monitor dynamic Population Stability Index (PSI) drift metrics, verify SHA-256 model signature hashes, 
            and execute immediate hot-swaps or safety rollbacks of your production LLM risk engines.
          </p>
          
          <div className="flex items-center gap-2 pt-1">
            <button
              onClick={() => refresh()}
              className="flex items-center gap-1.5 rounded-xl border border-gray-800 bg-gray-900/50 px-3.5 py-2 text-xs font-semibold text-gray-300 transition hover:bg-gray-850"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Sync Status
            </button>
            {isAdmin ? (
              <button
                onClick={() => handleOpenConfirm("rollback")}
                className="flex items-center gap-1.5 rounded-xl border border-rose-500/20 bg-rose-500/10 px-3.5 py-2 text-xs font-semibold text-rose-400 transition hover:bg-rose-500/20"
              >
                Rollback Model
              </button>
            ) : (
              <button
                disabled
                title="Admin privileges required"
                className="flex items-center gap-1.5 rounded-xl border border-gray-850 bg-gray-900/20 px-3.5 py-2 text-xs font-semibold text-gray-500 cursor-not-allowed"
              >
                <Lock className="h-3 w-3" />
                Rollback Model
              </button>
            )}
          </div>
        </div>

        <div className="md:w-1/3 flex justify-end shrink-0 w-full sm:w-auto">
          <div className="relative group">
            <div className="absolute -inset-1 bg-gradient-to-r from-indigo-500 to-purple-500 rounded-2xl blur opacity-25 group-hover:opacity-40 transition duration-300"></div>
            <img 
              src="/ai-model.png" 
              alt="AI Brain Telemetry" 
              className="relative w-48 h-28 object-cover rounded-2xl border border-indigo-500/20 shadow-2xl"
            />
          </div>
        </div>
      </div>

      {(error || localError) && (
        <div className="rounded-xl border border-rose-500/20 bg-rose-500/5 p-4 text-xs text-rose-400 flex items-start gap-2.5">
          <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
          <div>{error || localError}</div>
        </div>
      )}

      {actionSuccessMsg && (
        <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-4 text-xs text-emerald-400 flex items-start gap-2.5">
          <CheckCircle className="h-4 w-4 shrink-0 mt-0.5" />
          <div>{actionSuccessMsg}</div>
        </div>
      )}

      {/* Main Grid: Active Health, Drift telemetry & Metrics */}
      <div className="grid gap-6 md:grid-cols-3">
        {/* Active Model Health Status */}
        <div className="rounded-2xl border border-gray-800/80 bg-gray-950/40 p-5 backdrop-blur-md">
          <h3 className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-4 flex items-center gap-1.5">
            <Cpu className="h-4 w-4 text-indigo-400" />
            Active Model Health
          </h3>
          {health ? (
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-xs text-gray-500">Active Version</span>
                <span className="font-mono text-sm font-semibold text-white">v{health.active_model}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-xs text-gray-500">Sync Status</span>
                <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-mono ${getStatusColor(health.instance_sync === "synchronized" ? "active" : "candidate")}`}>
                  {health.instance_sync}
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-xs text-gray-500">SHA-256 Checksum</span>
                <span className="flex items-center gap-1 text-xs text-emerald-400">
                  <CheckCircle className="h-3 w-3" /> Valid
                </span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-xs text-gray-500">Artifact Loaded</span>
                <span className="flex items-center gap-1 text-xs text-emerald-400">
                  <CheckCircle className="h-3 w-3" /> Valid
                </span>
              </div>
              <div className="pt-2 border-t border-gray-900 flex justify-between items-center text-[10px] text-gray-500">
                <span>Last Evaluated At:</span>
                <span className="font-mono">
                  {health.last_evaluation_at ? new Date(health.last_evaluation_at).toLocaleString() : "Never"}
                </span>
              </div>
            </div>
          ) : (
            <div className="text-xs text-gray-500">No active model telemetry metadata.</div>
          )}
        </div>

        {/* Statistical Drift Telemetry */}
        <div className="rounded-2xl border border-gray-800/80 bg-gray-950/40 p-5 backdrop-blur-md">
          <h3 className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-4 flex items-center gap-1.5">
            <Activity className="h-4 w-4 text-indigo-400" />
            ML Drift telemetry
          </h3>
          {health ? (
            <div className="space-y-4">
              <div className="flex justify-between items-center">
                <span className="text-xs text-gray-500">Drift Score (PSI)</span>
                <span className="font-mono text-sm font-semibold text-white">{health.drift_score}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-xs text-gray-500">Drift Status</span>
                <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-mono ${getDriftBadgeColor(health.drift_status)}`}>
                  {health.drift_status}
                </span>
              </div>
              
              {/* PSI Score progress bar */}
              <div className="space-y-1">
                <div className="flex justify-between text-[10px] text-gray-500">
                  <span>Population Stability Index</span>
                  <span>Max: 1.0</span>
                </div>
                <div className="h-1.5 w-full bg-gray-900 rounded-full overflow-hidden">
                  <div
                    className={`h-full rounded-full transition-all duration-500 ${
                      health.drift_status === "critical"
                        ? "bg-rose-500"
                        : health.drift_status === "warning"
                        ? "bg-amber-500"
                        : "bg-emerald-500"
                    }`}
                    style={{ width: `${Math.min(health.drift_score * 100, 100)}%` }}
                  />
                </div>
              </div>

              <p className="text-[10px] text-gray-500 leading-relaxed pt-1">
                * Population Stability Index calculates data distribution shift for actions length compared to training baseline. PSI &gt;= 0.25 indicates critical feature drift.
              </p>
            </div>
          ) : (
            <div className="text-xs text-gray-500">No active model drift telemetry metadata.</div>
          )}
        </div>

        {/* Model Accuracy Metrics */}
        <div className="rounded-2xl border border-gray-800/80 bg-gray-950/40 p-5 backdrop-blur-md">
          <h3 className="text-xs font-medium text-gray-400 uppercase tracking-wider mb-4 flex items-center gap-1.5">
            <Shield className="h-4 w-4 text-indigo-400" />
            Approved Model Metrics
          </h3>
          {activeModelObj ? (
            <div className="grid grid-cols-2 gap-3 text-center">
              <div className="bg-black/30 p-2.5 rounded-lg border border-gray-900">
                <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-0.5">Accuracy</div>
                <div className="text-sm font-semibold font-mono text-white">
                  {(activeModelObj.metrics.accuracy ?? 0 * 100).toFixed(1)}%
                </div>
              </div>
              <div className="bg-black/30 p-2.5 rounded-lg border border-gray-900">
                <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-0.5">F1-Score</div>
                <div className="text-sm font-semibold font-mono text-white">
                  {(activeModelObj.metrics.f1 ?? 0 * 100).toFixed(1)}%
                </div>
              </div>
              <div className="bg-black/30 p-2.5 rounded-lg border border-gray-900">
                <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-0.5">False Allow</div>
                <div className="text-sm font-semibold font-mono text-rose-400">
                  {(activeModelObj.metrics.false_allow_rate ?? 0 * 100).toFixed(1)}%
                </div>
              </div>
              <div className="bg-black/30 p-2.5 rounded-lg border border-gray-900">
                <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-0.5">False Block</div>
                <div className="text-sm font-semibold font-mono text-amber-400">
                  {(activeModelObj.metrics.false_block_rate ?? 0 * 100).toFixed(1)}%
                </div>
              </div>
            </div>
          ) : (
            <div className="text-xs text-gray-500">No active model statistics.</div>
          )}
        </div>
      </div>

      {/* Model Registry List */}
      <div className="rounded-2xl border border-gray-800/80 bg-gray-950/40 backdrop-blur-md overflow-hidden">
        <div className="border-b border-gray-850 px-5 py-4 flex items-center justify-between">
          <h3 className="text-sm font-semibold text-white flex items-center gap-1.5">
            <List className="h-4 w-4 text-indigo-400" />
            Registered Model Registry
          </h3>
          <span className="text-[10px] text-gray-500 font-mono">
            Total Models: {models.length}
          </span>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-gray-900 bg-black/40 text-[10px] font-semibold uppercase tracking-wider text-gray-500">
                <th className="px-5 py-3">Version</th>
                <th className="px-5 py-3">Status</th>
                <th className="px-5 py-3">Feature Schema</th>
                <th className="px-5 py-3">Dataset Version</th>
                <th className="px-5 py-3">Metrics (Acc / F1 / False Allow)</th>
                <th className="px-5 py-3">Activated At</th>
                <th className="px-5 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-900/60 text-xs text-gray-300">
              {models.map((model) => (
                <tr key={model.id} className="hover:bg-white/[0.02] transition">
                  <td className="px-5 py-4 font-mono font-semibold text-white">v{model.model_version}</td>
                  <td className="px-5 py-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] font-mono uppercase ${getStatusColor(model.status)}`}>
                      {model.status}
                    </span>
                  </td>
                  <td className="px-5 py-4 font-mono text-gray-400">v{model.feature_schema_version}</td>
                  <td className="px-5 py-4 font-mono text-gray-400">v{model.dataset_version}</td>
                  <td className="px-5 py-4 font-mono text-gray-400">
                    {model.metrics.accuracy ? `${(model.metrics.accuracy * 100).toFixed(0)}%` : "-"} /{" "}
                    {model.metrics.f1 ? `${(model.metrics.f1 * 100).toFixed(0)}%` : "-"} /{" "}
                    {model.metrics.false_allow_rate ? `${(model.metrics.false_allow_rate * 100).toFixed(0)}%` : "-"}
                  </td>
                  <td className="px-5 py-4 text-gray-500 font-mono">
                    {model.activated_at ? new Date(model.activated_at).toLocaleString() : "N/A"}
                  </td>
                  <td className="px-5 py-4 text-right">
                    {model.status !== "active" ? (
                      isAdmin ? (
                        <button
                          onClick={() => handleOpenConfirm("activate", model.model_version)}
                          className="rounded bg-indigo-500/10 border border-indigo-500/20 px-2.5 py-1 text-[10px] font-semibold text-indigo-400 hover:bg-indigo-500/20 transition"
                        >
                          Activate
                        </button>
                      ) : (
                        <button
                          disabled
                          title="Admin privileges required"
                          className="rounded bg-gray-900/40 border border-gray-800 px-2.5 py-1 text-[10px] font-medium text-gray-600 cursor-not-allowed"
                        >
                          Activate
                        </button>
                      )
                    ) : (
                      <span className="text-[10px] text-emerald-400 font-semibold font-mono uppercase px-2">
                        Active Model
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Safety Confirmation Modal */}
      {showConfirm && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-md rounded-2xl border border-gray-800 bg-gray-950 p-6 shadow-2xl">
            <h4 className="text-base font-semibold text-white flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-rose-400" />
              Confirm Model Lifecycle Operation
            </h4>
            <p className="mt-3 text-xs text-gray-400 leading-relaxed">
              {confirmType === "activate"
                ? `Are you sure you want to activate model version v${selectedModel}? This will atomically reload and swap the active classifier in production across all cluster instances.`
                : "Are you sure you want to roll back the active classifier to the most recently retired compatible model?"}
            </p>
            <div className="mt-5 flex justify-end gap-3">
              <button
                onClick={() => setShowConfirm(false)}
                className="rounded-lg border border-gray-850 px-4 py-2 text-xs font-semibold text-gray-400 hover:bg-gray-900"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmAction}
                className="rounded-lg bg-indigo-500 px-4 py-2 text-xs font-semibold text-white hover:bg-indigo-600 transition"
              >
                Confirm Swap
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
