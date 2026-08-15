import { createContext, useContext, useState, useEffect, type ReactNode } from "react";
import { getApiUrl } from "../config";

interface Operator {
  id: string;
  username: string;
  role: string;
}

interface AuthContextType {
  token: string | null;
  operator: Operator | null;
  login: (token: string, operator: Operator) => void;
  logout: () => void;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const [operator, setOperator] = useState<Operator | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Check for existing token
    const storedToken = localStorage.getItem("operator_token");
    if (storedToken) {
      setToken(storedToken);
      // Fetch operator profile
      fetch(getApiUrl("/api/v1/operator/me"), {
        headers: { Authorization: `Bearer ${storedToken}` }
      })
      .then(res => res.ok ? res.json() : null)
      .then(data => {
        if (data) {
          setOperator(data);
        } else {
          localStorage.removeItem("operator_token");
          setToken(null);
        }
      })
      .catch(() => {
        localStorage.removeItem("operator_token");
        setToken(null);
      })
      .finally(() => setIsLoading(false));
    } else {
      setIsLoading(false);
    }
  }, []);

  const login = (newToken: string, newOp: Operator) => {
    localStorage.setItem("operator_token", newToken);
    setToken(newToken);
    setOperator(newOp);
  };

  const logout = () => {
    localStorage.removeItem("operator_token");
    setToken(null);
    setOperator(null);
  };

  return (
    <AuthContext.Provider value={{ token, operator, login, logout, isLoading }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
