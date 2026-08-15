import { useState } from "react";
import { 
  ShieldCheck, Terminal, Cpu, Database, 
  Lock, ArrowRight, Zap, CheckCircle2, RefreshCw
} from "lucide-react";

interface LandingPageProps {
  onLaunchDashboard: () => void;
  onOpenLogin: () => void;
  isAuthenticated: boolean;
}

export function LandingPage({ onLaunchDashboard, onOpenLogin, isAuthenticated }: LandingPageProps) {
  // Sandbox state
  const [selectedAgent, setSelectedAgent] = useState<"research_bot" | "dev_bot" | "ops_bot">("research_bot");
  const [sandboxAction, setSandboxAction] = useState("read_file");
  const [sandboxParam, setSandboxParam] = useState("scientific_paper.pdf");
  const [sandboxResult, setSandboxResult] = useState<{
    status: "idle" | "evaluating" | "done";
    decision: "allow" | "block" | "require_human_approval";
    risk: "low" | "medium" | "high";
    reason: string;
  }>({
    status: "idle",
    decision: "allow",
    risk: "low",
    reason: ""
  });

  const handleTestSandbox = () => {
    setSandboxResult(prev => ({ ...prev, status: "evaluating" }));
    
    setTimeout(() => {
      // Determinstic evaluation logic matching policy/model logic
      if (sandboxAction === "execute_bash" && sandboxParam.includes("rm -rf")) {
        setSandboxResult({
          status: "done",
          decision: "block",
          risk: "high",
          reason: "OperationsAgent: Blocked dangerous shell command execution. Attempted path traversal or root deletion."
        });
      } else if (sandboxAction === "execute_db" && sandboxParam.includes("DROP")) {
        setSandboxResult({
          status: "done",
          decision: "block",
          risk: "high",
          reason: "OperationsAgent: Blocked hard database drop queries. Query signature matches critical risk rules."
        });
      } else if (sandboxAction === "restart_service" && sandboxParam === "postgres") {
        setSandboxResult({
          status: "done",
          decision: "require_human_approval",
          risk: "medium",
          reason: "OperationsAgent: Service restarts require multi-signature operator review before dispatch."
        });
      } else if (sandboxAction === "execute_bash" && selectedAgent === "research_bot") {
        setSandboxResult({
          status: "done",
          decision: "block",
          risk: "medium",
          reason: "ResearchAgent: Role policy violation. Research bots are restricted from executing shell binaries."
        });
      } else if (sandboxAction === "write_config" && selectedAgent === "dev_bot") {
        setSandboxResult({
          status: "done",
          decision: "block",
          risk: "high",
          reason: "DeveloperAgent: Suspicious parameters. Modified system credentials matched abnormal threat signature."
        });
      } else {
        setSandboxResult({
          status: "done",
          decision: "allow",
          risk: "low",
          reason: "Safe action. Parameters matched normal semantic bounds and role permissions."
        });
      }
    }, 800);
  };

  const getDecisionColor = (decision: string) => {
    switch (decision) {
      case "allow": return "text-green-400 border-green-500/20 bg-green-500/5";
      case "block": return "text-red-400 border-red-500/20 bg-red-500/5";
      default: return "text-amber-400 border-amber-500/20 bg-amber-500/5";
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case "low": return "bg-green-500/20 text-green-400";
      case "medium": return "bg-amber-500/20 text-amber-400";
      default: return "bg-red-500/20 text-red-400";
    }
  };

  return (
    <div 
      className="space-y-24 pb-20 bg-cover bg-center relative rounded-3xl overflow-hidden border border-gray-800/40"
      style={{ 
        backgroundImage: "linear-gradient(to bottom, rgba(3, 4, 8, 0.9) 0%, rgba(3, 4, 8, 0.98) 100%), url('/hero-bg.png')" 
      }}
    >
      {/* 1. Hero Section */}
      <section className="relative pt-12 flex flex-col items-center text-center max-w-4xl mx-auto space-y-8 px-6 animate-fade-in-up">
        <div className="absolute top-0 w-72 h-72 bg-indigo-500/10 rounded-full blur-3xl -z-10" />
        <div className="absolute right-0 w-72 h-72 bg-purple-500/10 rounded-full blur-3xl -z-10" />

        <div className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-indigo-500/20 bg-indigo-500/5 text-xs text-indigo-300 font-semibold shadow-inner">
          <Zap className="w-3.5 h-3.5" /> Phase 7 Production Hardened
        </div>

        <h1 className="text-4xl sm:text-6xl font-extrabold tracking-tight text-white leading-tight">
          Secure and Audit Your <br />
          <span className="text-gradient">Autonomous AI Agents</span>
        </h1>

        <p className="text-lg text-gray-400 max-w-2xl">
          AURA Firewall is a premium, real-time safety and permission middleware for LLM-driven agents. 
          Interdict harmful commands, enforce role permissions, and trace decisions dynamically.
        </p>

        <div className="flex flex-col sm:flex-row items-center gap-4 justify-center w-full">
          <button 
            onClick={onLaunchDashboard}
            className="w-full sm:w-auto flex items-center justify-center gap-2 bg-indigo-600 hover:bg-indigo-500 text-white font-semibold px-8 py-4 rounded-xl transition shadow-lg shadow-indigo-600/30 hover:scale-[1.02]"
          >
            Launch Console <ArrowRight className="w-4 h-4" />
          </button>
          
          {!isAuthenticated && (
            <button 
              onClick={onOpenLogin}
              className="w-full sm:w-auto flex items-center justify-center gap-2 bg-gray-900 hover:bg-gray-800 border border-gray-800 text-gray-200 font-semibold px-8 py-4 rounded-xl transition hover:border-gray-700"
            >
              <Lock className="w-4 h-4" /> Operator Sign In
            </button>
          )}
        </div>
      </section>

      {/* 2. Interactive Agent Sandbox Playground */}
      <section className="max-w-5xl mx-auto px-6 animate-fade-in-up delay-75">
        <div className="glass-panel rounded-3xl overflow-hidden border border-gray-800/80">
          <div className="border-b border-gray-800 bg-gray-950/60 p-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <h2 className="text-xl font-bold flex items-center gap-2">
                <Terminal className="w-5 h-5 text-indigo-400" /> Interactive Intercept Sandbox
              </h2>
              <p className="text-sm text-gray-400 mt-1">Simulate agent actions and watch how the safety middleware evaluates requests in real-time.</p>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-2.5 h-2.5 rounded-full bg-green-500 animate-pulse" />
              <span className="text-xs text-gray-400 font-mono">Status: Live Filter Active</span>
            </div>
          </div>

          <div className="grid md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-gray-800/80">
            {/* Input Form */}
            <div className="p-6 space-y-6">
              <div className="space-y-2">
                <label className="text-xs text-gray-400 font-bold uppercase tracking-wider">Select Agent Identity</label>
                <div className="grid grid-cols-3 gap-2">
                  {[
                    { id: "research_bot", label: "Research Bot", role: "ResearchAgent" },
                    { id: "dev_bot", label: "Developer Bot", role: "DeveloperAgent" },
                    { id: "ops_bot", label: "Ops Bot", role: "OperationsAgent" }
                  ].map(agent => (
                    <button
                      key={agent.id}
                      onClick={() => {
                        setSelectedAgent(agent.id as any);
                        if (agent.id === "research_bot") {
                          setSandboxAction("read_file");
                          setSandboxParam("scientific_paper.pdf");
                        } else if (agent.id === "dev_bot") {
                          setSandboxAction("write_config");
                          setSandboxParam("max_connections=500");
                        } else {
                          setSandboxAction("restart_service");
                          setSandboxParam("postgres");
                        }
                      }}
                      className={`p-3 rounded-xl border text-center transition flex flex-col items-center justify-center ${
                        selectedAgent === agent.id 
                          ? "border-indigo-600 bg-indigo-500/5 text-white" 
                          : "border-gray-800 text-gray-400 hover:border-gray-700"
                      }`}
                    >
                      <span className="text-xs font-bold">{agent.label}</span>
                      <span className="text-[10px] text-gray-500 mt-0.5">{agent.role}</span>
                    </button>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-xs text-gray-400 font-bold uppercase tracking-wider">Action Name</label>
                  <select 
                    value={sandboxAction} 
                    onChange={(e) => setSandboxAction(e.target.value)}
                    className="w-full bg-gray-950 border border-gray-800 rounded-xl p-3 text-sm text-white focus:outline-none focus:border-indigo-600"
                  >
                    <option value="read_file">read_file</option>
                    <option value="write_file">write_file</option>
                    <option value="write_config">write_config</option>
                    <option value="execute_bash">execute_bash</option>
                    <option value="execute_db">execute_db</option>
                    <option value="restart_service">restart_service</option>
                  </select>
                </div>

                <div className="space-y-2">
                  <label className="text-xs text-gray-400 font-bold uppercase tracking-wider">Parameters</label>
                  <input
                    type="text"
                    value={sandboxParam}
                    onChange={(e) => setSandboxParam(e.target.value)}
                    placeholder="e.g. rm -rf /"
                    className="w-full bg-gray-950 border border-gray-800 rounded-xl p-3 text-sm text-white focus:outline-none focus:border-indigo-600"
                  />
                </div>
              </div>

              <button
                onClick={handleTestSandbox}
                disabled={sandboxResult.status === "evaluating"}
                className="w-full flex items-center justify-center gap-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-indigo-600/50 text-white font-semibold py-3.5 rounded-xl transition"
              >
                {sandboxResult.status === "evaluating" ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" /> Evaluating...
                  </>
                ) : (
                  <>
                    <ShieldCheck className="w-4 h-4" /> Evaluate Safety
                  </>
                )}
              </button>
            </div>

            {/* Sandbox Evaluation Output */}
            <div className="p-6 bg-gray-950/20 flex flex-col justify-center">
              {sandboxResult.status === "idle" ? (
                <div className="text-center py-12 space-y-3">
                  <ShieldCheck className="w-12 h-12 text-gray-600 mx-auto" />
                  <p className="text-sm text-gray-500 font-mono">Configure the parameters on the left and test the firewall response.</p>
                </div>
              ) : sandboxResult.status === "evaluating" ? (
                <div className="text-center py-12 space-y-3 animate-pulse">
                  <RefreshCw className="w-10 h-10 text-indigo-500 mx-auto animate-spin" />
                  <p className="text-sm text-indigo-400 font-mono">Running ML threat classifier & policy checks...</p>
                </div>
              ) : (
                <div className="space-y-6">
                  <div className="flex items-center justify-between border-b border-gray-800 pb-4">
                    <span className="text-xs text-gray-400 font-bold uppercase">Decision Verdict</span>
                    <span className={`px-3 py-1 rounded-full border text-xs font-mono font-bold uppercase tracking-wider ${getDecisionColor(sandboxResult.decision)}`}>
                      {sandboxResult.decision}
                    </span>
                  </div>

                  <div className="flex items-center justify-between border-b border-gray-800 pb-4">
                    <span className="text-xs text-gray-400 font-bold uppercase">Risk Category</span>
                    <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono uppercase tracking-wider ${getRiskColor(sandboxResult.risk)}`}>
                      {sandboxResult.risk}
                    </span>
                  </div>

                  <div className="space-y-2">
                    <span className="text-xs text-gray-400 font-bold uppercase block">Threat Explanation</span>
                    <div className="p-4 rounded-2xl bg-gray-950 border border-gray-800/80 font-mono text-xs leading-relaxed text-gray-300">
                      {sandboxResult.reason}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </section>

      {/* 3. Core Capabilities Grid */}
      <section className="max-w-6xl mx-auto px-6 space-y-12 animate-fade-in-up delay-100">
        <div className="text-center max-w-xl mx-auto space-y-3">
          <h2 className="text-2xl sm:text-3xl font-extrabold text-white">Full-Spectrum Agent Governance</h2>
          <p className="text-sm text-gray-400">Our unified platform addresses security, compliance, and ML model drift directly at runtime.</p>
        </div>

        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
          {[
            {
              icon: <Cpu className="w-5 h-5 text-indigo-400" />,
              title: "ML Threat Classifier",
              desc: "Predict agent action risk levels using XGBoost and SentenceTransformer token embeddings."
            },
            {
              icon: <ShieldCheck className="w-5 h-5 text-green-400" />,
              title: "Granular Role Policy",
              desc: "Enforce RBAC policies based on agent roles (ResearchAgent, DeveloperAgent, OperationsAgent)."
            },
            {
              icon: <Lock className="w-5 h-5 text-purple-400" />,
              title: "Identity Verification",
              desc: "Ensure every request is authenticated via cryptographically generated SHA256 API key credentials."
            },
            {
              icon: <Database className="w-5 h-5 text-amber-400" />,
              title: "Auditable Logs",
              desc: "Maintain a SHA256 hash-chained immutable audit log of all decisions to prevent tamper vectors."
            }
          ].map((cap, i) => (
            <div key={i} className="glass-panel p-6 rounded-2xl border border-gray-800/80 flex flex-col justify-between space-y-4 shadow-sm hover-card-glow cursor-pointer transition">
              <div className="p-3 bg-gray-950 rounded-xl border border-gray-800/50 w-fit">
                {cap.icon}
              </div>
              <div className="space-y-1.5">
                <h4 className="font-bold text-white text-base">{cap.title}</h4>
                <p className="text-xs text-gray-400 leading-relaxed">{cap.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* 4. Enterprise Compliance & Auditing */}
      <section className="max-w-5xl mx-auto px-6 animate-fade-in-up delay-150">
        <div className="glass-panel p-8 rounded-3xl flex flex-col md:flex-row items-center gap-8 border border-gray-800/80 bg-gradient-to-r from-gray-950/20 via-transparent to-transparent">
          <div className="space-y-4 md:w-3/5">
            <h3 className="text-2xl font-bold text-gradient">Audit Trail Integrity & Compliance</h3>
            <p className="text-sm text-gray-400 leading-relaxed">
              Every action evaluated by the AURA Firewall is logged into a SHA256 hash-chain (similar to a blockchain ledger). 
              Any administrative attempt to delete, modify, or insert raw SQL records breaks the cryptographic hash-chain signature, 
              instantly alerting operators via the SecOps incident dashboard.
            </p>
            <div className="grid grid-cols-2 gap-3 pt-2">
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-green-400" />
                <span className="text-xs text-gray-300 font-medium">SOC2 Compliant Ledger</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle2 className="w-4 h-4 text-green-400" />
                <span className="text-xs text-gray-300 font-medium">Immutable Chain Signatures</span>
              </div>
            </div>
          </div>

          <div className="md:w-2/5 w-full bg-gray-950 rounded-2xl border border-gray-800 p-6 space-y-4 font-mono text-[10px] text-gray-400">
            <div className="flex items-center justify-between border-b border-gray-800 pb-2">
              <span className="text-indigo-400">AUDIT_LEDGER_CHAIN</span>
              <span className="text-gray-500">v1.0.0</span>
            </div>
            <div className="space-y-2">
              <div className="p-2 rounded bg-gray-900/50 border border-gray-800">
                <span className="text-gray-500 block">RECORD_INDEX: #112</span>
                <span className="text-green-400 block">HASH: 4a2d9f...ea7f2c4</span>
                <span className="text-gray-400 block">STATUS: VERIFIED (MATCH)</span>
              </div>
              <div className="p-2 rounded bg-gray-900/50 border border-gray-800">
                <span className="text-gray-500 block">RECORD_INDEX: #113</span>
                <span className="text-green-400 block">HASH: 8d9441...baaa883</span>
                <span className="text-gray-400 block">STATUS: VERIFIED (MATCH)</span>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
