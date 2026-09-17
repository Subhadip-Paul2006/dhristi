// Drishti v0.1 — auth context and session management | 11-Jul-2026
/** Auth context — real multi-user sessions. No hardcoded demo login: the user
 * signs in (or up). The access token lives only in the API client's memory; the
 * refresh token is persisted, so a page refresh restores the session (the client
 * mints a fresh access token from the stored refresh token on load). */
import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, registerLogout, setTokens, hasSession, restoreSession } from "./api/client";
import type { Me } from "./api/types";

interface AuthState {
  ready: boolean;
  user: Me | null;
  login: (email: string, password: string) => Promise<void>;
  register: (body: {
    name: string;
    email: string;
    password: string;
    org_name: string;
  }) => Promise<void>;
  logout: () => void;
  refreshMe: () => Promise<void>;
}

const AuthContext = createContext<AuthState>({
  ready: false,
  user: null,
  login: async () => {},
  register: async () => {},
  logout: () => {},
  refreshMe: async () => {},
});

export function AuthProvider({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(false);
  const [user, setUser] = useState<Me | null>(null);

  useEffect(() => {
    // if the API client's refresh-once fails, drop the session
    registerLogout(() => {
      setTokens(null);
      setUser(null);
    });
    
    if (hasSession()) {
      // On a reload the access token is gone; mint a new one from the persisted
      // refresh token before loading the current user.
      restoreSession()
        .then((ok) => (ok ? api.me().then(setUser) : setTokens(null)))
        .catch(() => setTokens(null))
        .finally(() => setReady(true));
    } else {
      setReady(true);
    }
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const tokens = await api.login(email, password);
    setTokens(tokens);
    setUser(await api.me());
  }, []);

  const register = useCallback(
    async (body: { name: string; email: string; password: string; org_name: string }) => {
      const out = await api.register(body);
      setTokens({
        access_token: out.access_token,
        refresh_token: out.refresh_token,
        token_type: out.token_type,
      });
      setUser(await api.me());
    },
    [],
  );

  const logout = useCallback(() => {
    setTokens(null);
    setUser(null);
  }, []);

  const refreshMe = useCallback(async () => {
    setUser(await api.me());
  }, []);

  return (
    <AuthContext.Provider value={{ ready, user, login, register, logout, refreshMe }}>
      {children}
    </AuthContext.Provider>
  );
}

export const useAuth = () => useContext(AuthContext);
