import { NextRequest, NextResponse } from "next/server";
import { getIssuer, registerOAuthClient } from "../../lib/oauth";

export const runtime = "nodejs";

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
}

function isValidRedirectUri(value: string): boolean {
  try {
    const parsed = new URL(value);
    return parsed.protocol === "https:" || parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1";
  } catch {
    return false;
  }
}

function corsHeaders(): HeadersInit {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "content-type, authorization",
  };
}

export async function OPTIONS(): Promise<Response> {
  return new Response(null, { status: 204, headers: corsHeaders() });
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  let body: Record<string, unknown>;
  try {
    body = (await request.json()) as Record<string, unknown>;
  } catch {
    return NextResponse.json({ error: "invalid_client_metadata" }, { status: 400, headers: corsHeaders() });
  }

  const redirectUris = asStringArray(body.redirect_uris);
  if (redirectUris.length === 0 || redirectUris.some((uri) => !isValidRedirectUri(uri))) {
    return NextResponse.json({ error: "invalid_redirect_uri" }, { status: 400, headers: corsHeaders() });
  }

  const grantTypes = asStringArray(body.grant_types);
  const responseTypes = asStringArray(body.response_types);
  const scope = typeof body.scope === "string" && body.scope.trim() ? body.scope.trim() : "workflowy";
  const clientName = typeof body.client_name === "string" ? body.client_name.slice(0, 200) : undefined;

  if (grantTypes.length > 0 && !grantTypes.includes("authorization_code")) {
    return NextResponse.json({ error: "invalid_client_metadata" }, { status: 400, headers: corsHeaders() });
  }

  if (responseTypes.length > 0 && !responseTypes.includes("code")) {
    return NextResponse.json({ error: "invalid_client_metadata" }, { status: 400, headers: corsHeaders() });
  }

  const client = await registerOAuthClient({
    clientName,
    redirectUris,
    grantTypes,
    responseTypes,
    scope,
  });

  const issuer = getIssuer(request.url);
  return NextResponse.json(
    {
      client_id: client.client_id,
      client_id_issued_at: Math.floor(Date.now() / 1000),
      client_name: client.client_name ?? undefined,
      redirect_uris: client.redirect_uris,
      grant_types: grantTypes.length ? grantTypes : ["authorization_code"],
      response_types: responseTypes.length ? responseTypes : ["code"],
      scope: client.scope ?? "workflowy",
      token_endpoint_auth_method: "none",
      authorization_endpoint: `${issuer}/oauth/authorize`,
      token_endpoint: `${issuer}/oauth/token`,
    },
    { status: 201, headers: corsHeaders() },
  );
}
