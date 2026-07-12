export type DashboardRole = "viewer" | "analyst" | "admin";

export type DashboardFeature =
  | "zero-trust-graph"
  | "threat-hunting"
  | "k8s-compliance";

export interface AuthenticatedPrincipal {
  subject: string;
  email: string;
  roles: DashboardRole[];
  issuer: string;
  authProtocol: "oidc" | "saml";
  sessionId: string;
  issuedAt: number;
  expiresAt: number;
}

export const SESSION_COOKIE_NAME = "neuromesh_session";

export const FEATURE_ROUTE_MAP: Record<DashboardFeature, string> = {
  "zero-trust-graph": "/dashboard/zero-trust-graph",
  "threat-hunting": "/dashboard/threat-hunting",
  "k8s-compliance": "/dashboard/k8s-compliance",
};

const roleFeatureAccess: Record<DashboardRole, readonly DashboardFeature[]> = {
  viewer: ["zero-trust-graph"],
  analyst: ["zero-trust-graph", "threat-hunting"],
  admin: ["zero-trust-graph", "threat-hunting", "k8s-compliance"],
};

export function resolveFeatureFromPath(pathname: string): DashboardFeature | null {
  const entry = Object.entries(FEATURE_ROUTE_MAP).find(([, route]) =>
    pathname.startsWith(route),
  );
  return entry ? (entry[0] as DashboardFeature) : null;
}

export function isAuthorizedForFeature(
  principal: AuthenticatedPrincipal,
  feature: DashboardFeature,
): boolean {
  return principal.roles.some((role) => roleFeatureAccess[role].includes(feature));
}

export function isAuthorizedForPath(
  principal: AuthenticatedPrincipal,
  pathname: string,
): boolean {
  const feature = resolveFeatureFromPath(pathname);
  if (!feature) {
    return principal.roles.includes("admin");
  }
  return isAuthorizedForFeature(principal, feature);
}

export function auditAccessDecision(input: {
  principal: AuthenticatedPrincipal;
  pathname: string;
  allowed: boolean;
  requestId: string;
}): void {
  const payload = {
    event: "dashboard.rbac.decision",
    requestId: input.requestId,
    subject: input.principal.subject,
    roles: input.principal.roles,
    pathname: input.pathname,
    allowed: input.allowed,
    timestamp: new Date().toISOString(),
  };

  console.warn(JSON.stringify(payload));
}
