import { useState } from "react";
import { useAuth } from "../context/AuthContext";
import { Lock, AlertCircle, X } from "lucide-react";
import { getApiUrl } from "../config";

export function LoginModal({ onClose }: { onClose: () => void }) {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const formData = new URLSearchParams();
      formData.append("username", username);
      formData.append("password", password);

      const res = await fetch(getApiUrl("/api/v1/operator/login"), {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: formData,
      });

      if (!res.ok) {
        throw new Error("Invalid username or password");
      }

      const data = await res.json();
      
      // Fetch operator profile to complete login
      const profileRes = await fetch(getApiUrl("/api/v1/operator/me"), {
        headers: { Authorization: `Bearer ${data.access_token}` }
      });
      
      if (!profileRes.ok) throw new Error("Failed to fetch profile");
      const profile = await profileRes.json();

      login(data.access_token, profile);
      onClose();
    } catch (err: any) {
      setError(err.message || "Failed to log in");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-[#0f111a] border border-gray-800 rounded-2xl w-full max-w-sm shadow-2xl relative overflow-hidden">
        <button 
          onClick={onClose}
          className="absolute top-4 right-4 text-gray-400 hover:text-white"
        >
          <X className="w-5 h-5" />
        </button>
        
        <div className="p-6">
          <div className="flex items-center gap-3 mb-6">
            <div className="p-2 bg-indigo-500/20 rounded-lg text-indigo-400">
              <Lock className="w-6 h-6" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">Operator Login</h2>
              <p className="text-sm text-gray-400">Sign in to manage firewall</p>
            </div>
          </div>

          {error && (
            <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 rounded-lg flex items-center gap-2 text-red-400 text-sm">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Username</label>
              <input
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                className="w-full bg-black/50 border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors"
                placeholder="admin"
                required
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Password</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full bg-black/50 border border-gray-700 rounded-lg px-4 py-2 text-white focus:outline-none focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-colors"
                placeholder="••••••••"
                required
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="w-full bg-indigo-600 hover:bg-indigo-700 text-white font-medium py-2 px-4 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed mt-2"
            >
              {loading ? "Authenticating..." : "Sign In"}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
