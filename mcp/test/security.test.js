import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { createLocalJWKSet, exportJWK, generateKeyPair, SignJWT } from "jose";
import { z } from "zod";
import {
  ALL_CLASSIFIED_TOOLS,
  JwtOAuthVerifier,
  SCOPES,
  installToolSecurity,
  oauthConfigFromEnv,
  protectedResourceMetadata,
  toolSecurityPolicy
} from "../security.js";

const issuer = "https://tenant.example.com/";
const resource = "https://mcp.example.com";
const audience = resource;
const subject = "auth0|private-user-1";

test("every tool registration has an explicit annotation policy", () => {
  const source = fs.readFileSync(new URL("../server.js", import.meta.url), "utf8");
  const names = [...source.matchAll(/server\.tool\("([^"]+)"/g)].map((match) => match[1]);
  const unique = [...new Set(names)];
  const missing = unique.filter((name) => !ALL_CLASSIFIED_TOOLS.has(name));
  const extra = [...ALL_CLASSIFIED_TOOLS].filter((name) => !unique.includes(name));
  assert.equal(names.length, 138);
  assert.equal(unique.length, 137);
  assert.equal(unique.length, ALL_CLASSIFIED_TOOLS.size);
  assert.deepEqual(missing, []);
  assert.deepEqual(extra, []);
});

test("known safe tools are read-only, private, and non-destructive", () => {
  for (const name of ["get_focus_status", "get_window_whisper", "list_diary_books", "list_diary_entries", "read_diary_entry", "get_companion_actions"]) {
    assert.deepEqual(toolSecurityPolicy(name), {
      name,
      scopes: [SCOPES.read],
      annotations: { readOnlyHint: true, destructiveHint: false, openWorldHint: false, idempotentHint: true }
    });
  }
});

test("destructive and open-world actions are labeled conservatively", () => {
  assert.equal(toolSecurityPolicy("delete_diary_book").annotations.destructiveHint, true);
  assert.equal(toolSecurityPolicy("send_phone_command").annotations.destructiveHint, true);
  assert.equal(toolSecurityPolicy("xhs_comment").annotations.openWorldHint, true);
  assert.equal(toolSecurityPolicy("get_weather_state").annotations.readOnlyHint, true);
  assert.equal(toolSecurityPolicy("get_weather_state").annotations.openWorldHint, true);
});

test("OAuth environment configuration is fail-closed", () => {
  assert.throws(() => oauthConfigFromEnv({}), /OAUTH_ISSUER/);
  assert.throws(() => oauthConfigFromEnv({ OAUTH_ISSUER: issuer, MCP_RESOURCE_URL: resource }), /OAUTH_ALLOWED_SUBJECTS/);
  const config = oauthConfigFromEnv({
    OAUTH_ISSUER: issuer,
    MCP_RESOURCE_URL: resource,
    OAUTH_AUDIENCE: audience,
    OAUTH_ALLOWED_SUBJECTS: subject
  });
  assert.equal(config.issuer, issuer);
  assert.equal(config.resource, resource);
  assert.deepEqual(config.allowedSubjects, [subject]);
});

test("protected resource metadata advertises the issuer and all scopes", () => {
  const metadata = protectedResourceMetadata({ resource, issuer });
  assert.equal(metadata.resource, resource);
  assert.deepEqual(metadata.authorization_servers, [issuer]);
  assert.deepEqual(new Set(metadata.scopes_supported), new Set(Object.values(SCOPES)));
});

test("JWT verifier checks signature, issuer, audience, expiry, scopes, and subject", async () => {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const publicJwk = await exportJWK(publicKey);
  publicJwk.kid = "test-key";
  publicJwk.alg = "RS256";
  publicJwk.use = "sig";
  const localJwks = createLocalJWKSet({ keys: [publicJwk] });
  const discovery = {
    issuer,
    authorization_endpoint: `${issuer}authorize`,
    token_endpoint: `${issuer}oauth/token`,
    jwks_uri: `${issuer}.well-known/jwks.json`,
    code_challenge_methods_supported: ["S256"]
  };
  const verifier = new JwtOAuthVerifier({ issuer, resource, audience, allowedSubjects: [subject], discoveryUrl: `${issuer}.well-known/openid-configuration` }, {
    fetchImpl: async () => new Response(JSON.stringify(discovery), { status: 200, headers: { "Content-Type": "application/json" } }),
    jwksFactory: () => localJwks
  });
  const sign = (claims = {}) => new SignJWT({ scope: SCOPES.read, ...claims })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" })
    .setIssuer(issuer)
    .setAudience(audience)
    .setSubject(subject)
    .setIssuedAt()
    .setExpirationTime("5m")
    .sign(privateKey);

  const token = await sign();
  const auth = await verifier.verifyAccessToken(token);
  assert.equal(auth.extra.subject, subject);
  assert.deepEqual(auth.scopes, [SCOPES.read]);
  assert.equal(auth.resource.href.replace(/\/$/, ""), resource);

  const wrongAudience = await new SignJWT({ scope: SCOPES.read })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" }).setIssuer(issuer).setAudience("https://other.example.com")
    .setSubject(subject).setIssuedAt().setExpirationTime("5m").sign(privateKey);
  await assert.rejects(() => verifier.verifyAccessToken(wrongAudience), /aud|audience/i);

  const wrongIssuer = await new SignJWT({ scope: SCOPES.read })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" }).setIssuer("https://wrong.example.com/").setAudience(audience)
    .setSubject(subject).setIssuedAt().setExpirationTime("5m").sign(privateKey);
  await assert.rejects(() => verifier.verifyAccessToken(wrongIssuer), /iss|issuer/i);

  const expired = await new SignJWT({ scope: SCOPES.read })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" }).setIssuer(issuer).setAudience(audience)
    .setSubject(subject).setIssuedAt(Math.floor(Date.now() / 1000) - 120).setExpirationTime(Math.floor(Date.now() / 1000) - 60).sign(privateKey);
  await assert.rejects(() => verifier.verifyAccessToken(expired), /exp|expired/i);

  const noScopes = await new SignJWT({})
    .setProtectedHeader({ alg: "RS256", kid: "test-key" }).setIssuer(issuer).setAudience(audience)
    .setSubject(subject).setIssuedAt().setExpirationTime("5m").sign(privateKey);
  await assert.rejects(() => verifier.verifyAccessToken(noScopes), /scope/i);

  const wrongUser = await new SignJWT({ scope: SCOPES.read })
    .setProtectedHeader({ alg: "RS256", kid: "test-key" }).setIssuer(issuer).setAudience(audience)
    .setSubject("auth0|someone-else").setIssuedAt().setExpirationTime("5m").sign(privateKey);
  await assert.rejects(() => verifier.verifyAccessToken(wrongUser), /subject/i);
});

test("tool descriptors include annotations and OAuth security schemes", async () => {
  const server = new McpServer({ name: "test", version: "1.0.0" });
  installToolSecurity(server, { resourceMetadataUrl: `${resource}/.well-known/oauth-protected-resource` });
  server.tool("get_focus_status", "Read focus status", { device_id: z.string().default("android-phone") }, async () => ({ content: [{ type: "text", text: "ok" }] }));

  const listHandler = server.server._requestHandlers.get("tools/list");
  const listed = await listHandler({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }, {});
  const tool = listed.tools[0];
  assert.equal(tool.annotations.readOnlyHint, true);
  assert.equal(tool.annotations.destructiveHint, false);
  assert.equal(tool.annotations.openWorldHint, false);
  assert.deepEqual(tool.securitySchemes, [{ type: "oauth2", scopes: [SCOPES.read] }]);
  assert.deepEqual(tool._meta.securitySchemes, tool.securitySchemes);

  const handler = server._registeredTools.get_focus_status.handler;
  const missingAuth = await handler({ device_id: "android-phone" }, {});
  assert.equal(missingAuth.isError, true);
  assert.ok(missingAuth._meta["mcp/www_authenticate"]);
  const missingScope = await handler({ device_id: "android-phone" }, { authInfo: { scopes: [SCOPES.write], extra: { subject }, expiresAt: Math.floor(Date.now() / 1000) + 60 } });
  assert.equal(missingScope.isError, true);
  assert.match(missingScope._meta["mcp/www_authenticate"][0], /insufficient_scope/);
  const allowed = await handler({ device_id: "android-phone" }, { authInfo: { scopes: [SCOPES.read], extra: { subject }, expiresAt: Math.floor(Date.now() / 1000) + 60 } });
  assert.equal(allowed.content[0].text, "ok");
});
