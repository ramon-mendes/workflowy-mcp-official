import { NextRequest, NextResponse } from "next/server";
import { getIssuer } from "../../lib/oauth";

export const runtime = "nodejs";

export async function GET(request: NextRequest): Promise<NextResponse> {
  const issuer = getIssuer(request.url);

  return NextResponse.json({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    registration_endpoint: `${issuer}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    scopes_supported: ["workflowy"],
    service_documentation: `${issuer}/`,
  });
}
