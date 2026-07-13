import { NextResponse, type NextRequest } from "next/server";

import {
  auditAccessDecision,
  isAuthorizedForPath,
  SESSION_COOKIE_NAME,
} from "@/lib/auth/rbac";
import {
  getOidcLoginUrl,
  getSamlLoginUrl,
  verifySessionToken,
} from "@/lib/auth/session";

const DASHBOARD_PREFIX = "/dashboard";

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  if (!pathname.startsWith(DASHBOARD_PREFIX)) {
    return NextResponse.next();
  }

  const requestId = crypto.randomUUID();
  const sessionToken = request.cookies.get(SESSION_COOKIE_NAME)?.value;

  if (!sessionToken) {
    return redirectToIdentityProvider(request);
  }

  const principal = await verifySessionToken(sessionToken);
  if (!principal) {
    const response = redirectToIdentityProvider(request);
    response.cookies.delete(SESSION_COOKIE_NAME);
    return response;
  }

  const allowed = isAuthorizedForPath(principal, pathname);
  auditAccessDecision({ principal, pathname, allowed, requestId });

  if (!allowed) {
    const forbiddenUrl = request.nextUrl.clone();
    forbiddenUrl.pathname = "/forbidden";
    forbiddenUrl.searchParams.set("from", pathname);
    return NextResponse.redirect(forbiddenUrl);
  }

  const response = NextResponse.next();
  response.headers.set("x-neuromesh-request-id", requestId);
  response.headers.set("x-neuromesh-subject", principal.subject);
  return response;
}

function redirectToIdentityProvider(request: NextRequest): NextResponse {
  const returnTo = request.nextUrl.pathname;
  const protocol = process.env.NEUROMESH_AUTH_PROTOCOL ?? "oidc";
  const loginUrl =
    protocol === "saml" ? getSamlLoginUrl(returnTo) : getOidcLoginUrl(returnTo);

  return NextResponse.redirect(loginUrl);
}

export const config = {
  matcher: ["/dashboard/:path*"],
};
