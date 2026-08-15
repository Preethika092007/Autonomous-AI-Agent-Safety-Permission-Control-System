import React, { useState } from "react";
import axios from "axios";
import { Check, X, ShieldAlert, User, Terminal } from "lucide-react";
import type { ApprovalRequest } from "../hooks/useApprovalsWS";
import { useAuth } from "../context/AuthContext";
import { getApiUrl } from "../config";


interface ApprovalQueueProps {
  queue: ApprovalRequest[];
  onResolve?: (approvalId: string) => void;
}

export const ApprovalQueue: React.FC<ApprovalQueueProps> = ({ queue, onResolve }) => {
  const [processingId, setProcessingId] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { token } = useAuth();

  const handleResolve = async (approvalId: string, status: "approved" | "rejected") => {
    setProcessingId(approvalId);
    setError(null);
    try {
      await axios.post(getApiUrl("/api/v1/approve-action"), {
        approval_id: approvalId,
        status: status
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (onResolve) {
        onResolve(approvalId);
      }
    } catch (err: any) {
      setError(err.response?.data?.detail || err.message || "Failed to resolve approval request");
    } finally {
      setProcessingId(null);
    }
  };

  if (queue.length === 0) {
    return (
      <div className="glass-panel rounded-2xl p-8 flex flex-col items-center justify-center text-gray-400 border border-gray-800">
        <div className="w-16 h-16 bg-gray-900 rounded-full flex items-center justify-center mb-4">
          <Check className="w-8 h-8 text-green-500" />
        </div>
        <p className="font-semibold text-lg text-gray-200">Approval Queue Clean</p>
        <p className="text-sm mt-1">No pending AI agent actions require human review.</p>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="text-xl font-bold flex items-center gap-2">
          <ShieldAlert className="text-amber-500 w-6 h-6 animate-pulse" />
          Pending Approvals
          <span className="text-xs bg-amber-500/20 text-amber-500 font-semibold px-2.5 py-0.5 rounded-full">
            {queue.length} Required
          </span>
        </h3>
        {error && <span className="text-xs text-red-500">{error}</span>}
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        {queue.map((req) => (
          <div
            key={req.approval_id}
            className="glass-panel border-l-4 border-l-amber-500 rounded-2xl p-5 hover:border-l-amber-400 transition-all duration-300 relative overflow-hidden group shadow-lg"
          >
            {/* Card Background Glow */}
            <div className="absolute -top-10 -right-10 w-24 h-24 bg-amber-500/5 rounded-full blur-2xl group-hover:bg-amber-500/10 transition-all duration-300" />

            <div className="flex justify-between items-start mb-3">
              <div>
                <span className="text-xs font-semibold px-2 py-1 rounded bg-amber-500/10 text-amber-500 uppercase tracking-wider">
                  {req.risk_level} Risk
                </span>
              </div>
              <div className="text-[10px] text-gray-500 font-mono">
                ID: {req.approval_id.substring(0, 8)}...
              </div>
            </div>

            <div className="space-y-2 mb-4">
              <div className="flex items-center gap-2 text-sm">
                <User className="w-4 h-4 text-gray-400" />
                <span className="text-gray-400">Agent:</span>
                <span className="font-semibold text-gray-200">{req.agent_id}</span>
              </div>

              <div className="flex items-center gap-2 text-sm">
                <Terminal className="w-4 h-4 text-gray-400" />
                <span className="text-gray-400">Action:</span>
                <span className="font-mono text-xs bg-black/40 px-2 py-0.5 rounded border border-gray-800 text-purple-400 break-all">
                  {req.action}
                </span>
              </div>

              <div className="mt-2 text-xs bg-black/20 p-2.5 rounded-lg border border-gray-800 text-gray-300">
                <span className="font-medium text-amber-500 block mb-1">Threat Explanation:</span>
                {req.reason}
              </div>

              {req.parameters && Object.keys(req.parameters).length > 0 && (
                <div className="mt-2">
                  <span className="text-[10px] text-gray-500 block mb-1 font-mono uppercase tracking-wider">Parameters:</span>
                  <pre className="text-[10px] bg-black/60 p-2 rounded text-gray-400 overflow-x-auto font-mono max-h-24">
                    {JSON.stringify(req.parameters, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            <div className="flex gap-2">
              <button
                onClick={() => handleResolve(req.approval_id, "approved")}
                disabled={processingId !== null}
                className="flex-1 bg-green-600 hover:bg-green-500 text-white font-semibold text-sm py-2 px-3 rounded-xl flex items-center justify-center gap-1.5 transition-colors duration-200 disabled:opacity-50"
              >
                <Check className="w-4 h-4" />
                Approve
              </button>
              <button
                onClick={() => handleResolve(req.approval_id, "rejected")}
                disabled={processingId !== null}
                className="flex-1 bg-red-600 hover:bg-red-500 text-white font-semibold text-sm py-2 px-3 rounded-xl flex items-center justify-center gap-1.5 transition-colors duration-200 disabled:opacity-50"
              >
                <X className="w-4 h-4" />
                Reject
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
