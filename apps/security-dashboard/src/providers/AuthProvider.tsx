"use client";

import { createContext, useContext, type ReactNode } from "react";

import type { DashboardRole } from "@/lib/auth/rbac";

interface AuthContextValue {
  subject: string;
  email: string;
  roles: DashboardRole[];
}

const AuthContext = createContext<AuthContextValue | null>(null);

export interface AuthProviderProps {
  children: ReactNode;
  principal: AuthContextValue;
}

export function AuthProvider({ children, principal }: AuthProviderProps) {
  return <AuthContext.Provider value={principal}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}
