import { NextRequest, NextResponse } from "next/server";
import {
  exchangeAuthorizationCode,
  getMcpResource,
  getRequestedResource,
  isAllowedResource,
} from "../../lib/oauth";

export const runtime = "nodejs";

function corsHeaders(): HeadersInit {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "content-type, authorization",
    "Cache-Control": "no-store",
    Pragma: "no-cache",
  };
}

function errorResponse(
  error: string,
  status: number,
  description?: string,
): NextResponse {
  return NextResponse.json(
    description ? { error, error_description: description } : { error },
    { status, headers: corsHeaders() },
  );
}

export async function OPTIONS(): Promise<Response> {
  return new Response(null, { status: 204, headers: corsHeaders() });
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  let form: URLSearchParams;
  try {
    const raw = await request.text();
    form = new URLSearchParams(raw);
  } catch {
    return errorResponse("invalid_request", 400, "Unable to parse request body");
  }

  const grantType = form.get("grant_type") ?? "";
  if (grantType !== "authorization_code") {
    return errorResponse(
      "unsupported_grant_type",
      400,
      "Only authorization_code is supported",
    );
  }

  const code = form.get("code") ?? "";
  const clientId = form.get("client_id") ?? "";
  const redirectUri = form.get("redirect_uri") ?? "";
  const codeVerifier = form.get("code_verifier") ?? "";

  if (!code || !clientId || !redirectUri || !codeVerifier) {
    return errorResponse(
      "invalid_request",
      400,
      "code, client_id, redirect_uri, and code_verifier are required",
    );
  }

  const resource = getRequestedResource(form.get("resource"), request.url);
  if (!isAllowedResource(resource, request.url)) {
    return errorResponse(
      "invalid_target",
      400,
      `resource must be ${getMcpResource(request.url)}`,
    );
  }

  const result = await exchangeAuthorizationCode({
    code,
    clientId,
    redirectUri,
    codeVerifier,
    resource,
  });

  if (!result) {
    return errorResponse(
      "invalid_grant",
      400,
      "Authorization code is invalid, expired, already used, or PKCE verification failed",
    );
  }

  return NextResponse.json(
    {
      access_token: result.accessToken,
      token_type: "Bearer",
      expires_in: result.expiresIn,
      scope: result.scope,
    },
    { status: 200, headers: corsHeaders() },
  );
}
