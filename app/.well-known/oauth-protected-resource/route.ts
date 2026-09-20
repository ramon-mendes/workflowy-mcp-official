import { NextRequest, NextResponse } from "next/server";
import { getIssuer, getMcpResource } from "../../lib/oauth";

export const runtime = "nodejs";

export async function GET(request: NextRequest): Promise<NextResponse> {
  const issuer = getIssuer(request.url);
  const resource = getMcpResource(request.url);

  return NextResponse.json({
    resource,
    authorization_servers: [issuer],
    bearer_methods_supported: ["header"],
    scopes_supported: ["workflowy"],
    resource_documentation: `${issuer}/`,
  });
}
