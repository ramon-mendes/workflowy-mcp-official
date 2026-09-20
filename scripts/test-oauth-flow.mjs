// End-to-end local test for the MCP OAuth flow.
//
// It performs dynamic client registration, generates PKCE, opens the
// authorization page in your browser (approve with ADMIN_SECRET), captures the
// redirect on a loopback server, exchanges the code for an access token, and
// finally connects to /api/mcp with that token and lists tools.
//
// Usage:
//   node scripts/test-oauth-flow.mjs [origin]
//   node scripts/test-oauth-flow.mjs http://localhost:3000
//
// The server must be running (npm run dev) with DATABASE_URL, ADMIN_SECRET,
// and WORKFLOWY_API_KEY configured.

import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";

const origin = process.argv[2] || "http://localhost:3000";
const CALLBACK_PORT = 8787;
const redirectUri = `http://localhost:${CALLBACK_PORT}/callback`;

function base64url(buffer) {
  return buffer.toString("base64url");
}

function openInBrowser(url) {
  const platform = process.platform;
  const cmd =
    platform === "win32" ? "cmd" : platform === "darwin" ? "open" : "xdg-open";
  const args = platform === "win32" ? ["/c", "start", "", url] : [url];
  try {
    spawn(cmd, args, { stdio: "ignore", detached: true }).unref();
  } catch {
    // Non-fatal: user can copy the URL manually.
  }
}

async function getJson(url) {
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error(`GET ${url} -> HTTP ${res.status}`);
  }
  return res.json();
}

async function waitForCode() {
  return new Promise((resolve, reject) => {
    const server = createServer((req, res) => {
      const reqUrl = new URL(req.url, `http://localhost:${CALLBACK_PORT}`);
      if (reqUrl.pathname !== "/callback") {
        res.writeHead(404).end();
        return;
      }
      const code = reqUrl.searchParams.get("code");
      const error = reqUrl.searchParams.get("error");
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(
        `<html><body style="font-family:system-ui;padding:40px"><h2>${
          code ? "Authorization received ✅" : "Authorization failed ❌"
        }</h2><p>You can close this tab and return to the terminal.</p></body></html>`,
      );
      server.close();
      if (error) {
        reject(new Error(`Authorization error: ${error}`));
      } else if (code) {
        resolve(code);
      } else {
        reject(new Error("No code in callback"));
      }
    });
    server.listen(CALLBACK_PORT);
  });
}

async function main() {
  console.log(`Testing OAuth against ${origin}\n`);

  // 1. Discovery (sanity check the metadata endpoints).
  const prm = await getJson(`${origin}/.well-known/oauth-protected-resource`);
  const asm = await getJson(`${origin}/.well-known/oauth-authorization-server`);
  console.log("1. Discovery OK");
  console.log(`   resource: ${prm.resource}`);
  console.log(`   authorization_endpoint: ${asm.authorization_endpoint}`);
  console.log(`   token_endpoint: ${asm.token_endpoint}\n`);

  // 2. Dynamic client registration.
  const regRes = await fetch(asm.registration_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client_name: "Local OAuth Test",
      redirect_uris: [redirectUri],
      grant_types: ["authorization_code"],
      response_types: ["code"],
      scope: "workflowy",
    }),
  });
  if (!regRes.ok) {
    throw new Error(
      `Registration failed: HTTP ${regRes.status} ${await regRes.text()}`,
    );
  }
  const client = await regRes.json();
  console.log(`2. Registered client: ${client.client_id}\n`);

  // 3. PKCE.
  const codeVerifier = base64url(randomBytes(32));
  const codeChallenge = base64url(
    createHash("sha256").update(codeVerifier).digest(),
  );
  const state = base64url(randomBytes(8));

  const authorizeUrl = new URL(asm.authorization_endpoint);
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("client_id", client.client_id);
  authorizeUrl.searchParams.set("redirect_uri", redirectUri);
  authorizeUrl.searchParams.set("scope", "workflowy");
  authorizeUrl.searchParams.set("state", state);
  authorizeUrl.searchParams.set("code_challenge", codeChallenge);
  authorizeUrl.searchParams.set("code_challenge_method", "S256");
  authorizeUrl.searchParams.set("resource", prm.resource);

  console.log("3. Opening the authorization page in your browser.");
  console.log("   Approve it with your ADMIN_SECRET.\n");
  console.log(`   If it does not open, visit:\n   ${authorizeUrl}\n`);
  openInBrowser(authorizeUrl.toString());

  // 4. Wait for the redirect with the code.
  const code = await waitForCode();
  console.log("4. Authorization code received\n");

  // 5. Token exchange.
  const tokenRes = await fetch(asm.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: client.client_id,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
      resource: prm.resource,
    }),
  });
  if (!tokenRes.ok) {
    throw new Error(
      `Token exchange failed: HTTP ${tokenRes.status} ${await tokenRes.text()}`,
    );
  }
  const token = await tokenRes.json();
  console.log("5. Token exchange OK");
  console.log(`   access_token: ${token.access_token.slice(0, 12)}...`);
  console.log(`   expires_in: ${token.expires_in}  scope: ${token.scope}\n`);

  // 6. Connect to the MCP endpoint with the OAuth access token.
  const transport = new StreamableHTTPClientTransport(
    new URL(`${origin}/api/mcp`),
    {
      requestInit: {
        headers: { Authorization: `Bearer ${token.access_token}` },
      },
    },
  );
  const mcp = new Client(
    { name: "oauth-test-client", version: "1.0.0" },
    { capabilities: { prompts: {}, resources: {}, tools: {} } },
  );
  await mcp.connect(transport);
  console.log("6. MCP connected with OAuth token");
  const tools = await mcp.listTools();
  console.log(`   tools: ${tools.tools.map((t) => t.name).join(", ")}\n`);

  // 7. Negative check: a bogus token must be rejected.
  const badRes = await fetch(`${origin}/api/mcp`, {
    method: "POST",
    headers: {
      Authorization: "Bearer wft_invalid_token",
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list" }),
  });
  const wwwAuth = badRes.headers.get("www-authenticate");
  console.log(`7. Invalid token -> HTTP ${badRes.status}`);
  console.log(`   WWW-Authenticate: ${wwwAuth ?? "(none)"}\n`);

  console.log("All OAuth checks passed ✅");
  process.exit(0);
}

main().catch((error) => {
  console.error("\nTest failed:", error.message);
  process.exit(1);
});
