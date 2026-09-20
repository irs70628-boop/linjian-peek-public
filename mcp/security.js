import { createRemoteJWKSet, jwtVerify } from "jose";

export const SCOPES = Object.freeze({
  read: "zhangxinchuang.read",
  write: "zhangxinchuang.write",
  control: "zhangxinchuang.control",
  destructive: "zhangxinchuang.destructive"
});

const READ_ONLY_TOOLS = new Set([
  "get_wallet_state", "get_wallet_month_state", "list_wallet_months", "list_wallet_pending", "list_wallet_approvals",
  "list_companion_wallet_requests", "list_wallet_request_results", "get_wallet_rules", "get_takeout_state",
  "list_takeout_cards", "list_takeout_meals", "suggest_takeout_options", "get_takeout_checkout_status",
  "linjian_status", "get_focus_status", "latest_screen", "get_window_whisper", "get_companion_actions",
  "get_activity_events", "get_phone_state", "get_screen_nodes", "get_life_state",
  "get_guardian_calendar", "list_guardian_days", "list_diary_books", "list_diary_entries", "read_diary_entry",
  "read_diary_entry_with_annotations", "list_diary_annotations", "search_diary_entries", "get_senses_state",
  "get_guidian_state", "get_care_policy", "get_care_history", "get_last_visit", "get_visit_history",
  "get_visit_stats", "active_care_check", "get_weather_state", "list_known_apps", "get_screen_break_state",
  "get_lock_state", "list_lockable_apps", "list_screen_break_apps", "get_screen_break_release_requests"
]);

const REVERSIBLE_WRITE_TOOLS = new Set([
  "set_window_whisper", "add_activity_event", "add_guardian_calendar_event", "add_guardian_day", "update_guardian_day",
  "create_diary_book", "rename_diary_book", "update_diary_book_cover", "write_diary_entry", "add_diary_annotation",
  "mark_diary_annotations_seen", "update_diary_entry", "set_care_policy",
  "set_takeout_budget", "set_takeout_preferences", "add_takeout_card", "save_takeout_card", "update_takeout_card",
  "remember_takeout_meal", "remember_current_takeout_meal", "create_takeout_plan", "copy_takeout_note"
]);

const REVERSIBLE_CONTROL_TOOLS = new Set([
  "set_guidian_config", "mark_guidian_returned", "save_known_app", "add_locked_app", "remove_locked_app",
  "add_screen_break_app", "draft_xhs_comment", "peek_screen"
]);

const DESTRUCTIVE_TOOLS = new Set([
  "wallet_takeout_action", "add_wallet_record", "edit_wallet_record", "delete_wallet_record", "submit_wallet_approval",
  "submit_companion_wallet_request", "decide_wallet_approval", "save_wallet_request_result",
  "save_user_wallet_request_result", "update_wallet_request_result", "confirm_wallet_record", "set_wallet_rules",
  "wallet_approval_request", "delete_takeout_card", "remove_takeout_card", "takeout_wallet_request",
  "open_takeout_link", "open_takeout_plan", "record_takeout_order", "prepare_takeout_checkout",
  "auto_takeout_checkout", "cancel_takeout_checkout", "start_focus_mode", "end_focus_mode", "set_focus_plan",
  "reply_focus_request", "approve_focus_unlock", "deny_focus_unlock", "tap_text", "input_text", "xhs_comment",
  "send_visible_comment_after_confirmation", "delete_guardian_day", "delete_diary_annotation", "delete_diary_entry",
  "delete_diary_book", "record_care_event", "record_visit", "care_action", "trigger_guidian",
  "send_weather_notification", "send_phone_command", "open_app", "phone_home", "phone_back", "phone_recents",
  "phone_screen_off", "send_notification", "set_alarm", "run_sequence", "run_preset", "screen_break_app",
  "temporary_screen_break_release", "end_screen_break", "extend_screen_break", "deny_screen_break_release_request",
  "lock_app", "unlock_app", "temporary_unlock_app", "extend_lock", "deny_unlock_request",
  "set_emergency_passphrase", "set_screen_break_passphrase"
]);

const OPEN_WORLD_TOOLS = new Set([
  "get_weather_state", "send_weather_notification", "draft_xhs_comment", "xhs_comment", "send_visible_comment_after_confirmation",
  "open_takeout_link", "open_takeout_plan", "prepare_takeout_checkout", "auto_takeout_checkout"
]);

export const ALL_CLASSIFIED_TOOLS = new Set([
  ...READ_ONLY_TOOLS,
  ...REVERSIBLE_WRITE_TOOLS,
  ...REVERSIBLE_CONTROL_TOOLS,
  ...DESTRUCTIVE_TOOLS
]);

export function toolSecurityPolicy(name) {
  if (!ALL_CLASSIFIED_TOOLS.has(name)) {
    throw new Error(`Missing explicit security classification for MCP tool: ${name}`);
  }
  const readOnly = READ_ONLY_TOOLS.has(name);
  const destructive = DESTRUCTIVE_TOOLS.has(name);
  const control = REVERSIBLE_CONTROL_TOOLS.has(name) || destructive;
  const scope = readOnly ? SCOPES.read : destructive ? SCOPES.destructive : control ? SCOPES.control : SCOPES.write;
  return {
    name,
    scopes: [scope],
    annotations: {
      readOnlyHint: readOnly,
      destructiveHint: destructive,
      openWorldHint: OPEN_WORLD_TOOLS.has(name),
      ...(readOnly ? { idempotentHint: true } : {})
    }
  };
}

export function protectedResourceMetadata({ resource, issuer, documentationUrl = "" }) {
  return {
    resource,
    authorization_servers: [issuer],
    scopes_supported: Object.values(SCOPES),
    bearer_methods_supported: ["header"],
    ...(documentationUrl ? { resource_documentation: documentationUrl } : {})
  };
}

function splitCsv(value = "") {
  return String(value || "").split(",").map((part) => part.trim()).filter(Boolean);
}

function normalizeIssuer(value = "") {
  const raw = String(value || "").trim();
  if (!raw) throw new Error("OAUTH_ISSUER is required");
  const url = new URL(raw);
  if (url.protocol !== "https:") throw new Error("OAUTH_ISSUER must use HTTPS");
  return url.href.endsWith("/") ? url.href : `${url.href}/`;
}

function normalizedResource(value = "") {
  const raw = String(value || "").trim();
  if (!raw) throw new Error("MCP_RESOURCE_URL or RENDER_EXTERNAL_URL is required");
  const url = new URL(raw);
  if (url.protocol !== "https:") throw new Error("MCP_RESOURCE_URL must use HTTPS");
  url.hash = "";
  return url.href.replace(/\/$/, "");
}

function tokenScopes(payload) {
  if (Array.isArray(payload.scp)) return payload.scp.map(String);
  if (typeof payload.scope === "string") return payload.scope.split(/\s+/).filter(Boolean);
  if (Array.isArray(payload.permissions)) return payload.permissions.map(String);
  return [];
}

export function oauthConfigFromEnv(env = process.env) {
  const issuer = normalizeIssuer(env.OAUTH_ISSUER || "");
  const resource = normalizedResource(env.MCP_RESOURCE_URL || env.RENDER_EXTERNAL_URL || "");
  const audience = String(env.OAUTH_AUDIENCE || resource).trim();
  const allowedSubjects = splitCsv(env.OAUTH_ALLOWED_SUBJECTS);
  if (!audience) throw new Error("OAUTH_AUDIENCE is required");
  if (!allowedSubjects.length) throw new Error("OAUTH_ALLOWED_SUBJECTS must contain at least one stable OAuth subject (sub)");
  return {
    issuer,
    resource,
    audience,
    allowedSubjects,
    discoveryUrl: new URL(".well-known/openid-configuration", issuer).href,
    documentationUrl: String(env.MCP_RESOURCE_DOCUMENTATION_URL || "").trim()
  };
}

export class JwtOAuthVerifier {
  constructor(config, { fetchImpl = fetch, jwksFactory = (url) => createRemoteJWKSet(url) } = {}) {
    this.config = config;
    this.fetchImpl = fetchImpl;
    this.jwksFactory = jwksFactory;
    this.discoveryPromise = null;
    this.jwks = null;
  }

  async discovery() {
    if (!this.discoveryPromise) {
      this.discoveryPromise = this.fetchImpl(this.config.discoveryUrl, {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(8000)
      }).then(async (response) => {
        if (!response.ok) throw new Error(`OAuth discovery failed with HTTP ${response.status}`);
        const metadata = await response.json();
        if (metadata.issuer !== this.config.issuer) throw new Error("OAuth discovery issuer mismatch");
        if (!Array.isArray(metadata.code_challenge_methods_supported) || !metadata.code_challenge_methods_supported.includes("S256")) {
          throw new Error("OAuth provider discovery must advertise PKCE S256");
        }
        if (!metadata.authorization_endpoint || !metadata.token_endpoint || !metadata.jwks_uri) {
          throw new Error("OAuth discovery is missing authorization_endpoint, token_endpoint, or jwks_uri");
        }
        const jwksUrl = new URL(metadata.jwks_uri);
        if (jwksUrl.protocol !== "https:") throw new Error("OAuth jwks_uri must use HTTPS");
        return metadata;
      }).catch((error) => {
        this.discoveryPromise = null;
        throw error;
      });
    }
    return this.discoveryPromise;
  }

  async verifyAccessToken(token) {
    const metadata = await this.discovery();
    if (!this.jwks) this.jwks = this.jwksFactory(new URL(metadata.jwks_uri));
    const { payload, protectedHeader } = await jwtVerify(token, this.jwks, {
      issuer: this.config.issuer,
      audience: this.config.audience,
      algorithms: ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]
    });
    const subject = String(payload.sub || "").trim();
    if (!subject || !this.config.allowedSubjects.includes(subject)) throw new Error("OAuth subject is not authorized for this private MCP server");
    if (!Number.isFinite(payload.exp)) throw new Error("OAuth access token must contain exp");
    const scopes = tokenScopes(payload);
    if (!scopes.length) throw new Error("OAuth access token contains no scopes");
    return {
      token,
      clientId: String(payload.azp || payload.client_id || protectedHeader.kid || "chatgpt-oauth-client"),
      scopes,
      expiresAt: payload.exp,
      resource: new URL(this.config.resource),
      extra: { subject, issuer: payload.iss, audience: payload.aud }
    };
  }
}

export function createBearerMiddleware({ verifier, resourceMetadataUrl, allowUnauthenticated = false }) {
  return async (req, res, next) => {
    const challenge = (error = "invalid_token", description = "A valid user authorization is required") => {
      const value = authChallenge(resourceMetadataUrl, [], error, description);
      res.setHeader("WWW-Authenticate", value);
      return res.status(401).json({ error, error_description: description });
    };
    try {
      const header = String(req.headers.authorization || "");
      if (!header && allowUnauthenticated) return next();
      const match = header.match(/^Bearer\s+(.+)$/i);
      if (!match) return challenge("invalid_token", "Missing or malformed Authorization bearer token");
      const auth = await verifier.verifyAccessToken(match[1]);
      if (!Number.isFinite(auth.expiresAt) || auth.expiresAt <= Date.now() / 1000) {
        return challenge("invalid_token", "The access token is expired or has no valid expiration");
      }
      req.auth = auth;
      return next();
    } catch (error) {
      return challenge("invalid_token", String(error?.message || "Access token validation failed").slice(0, 240));
    }
  };
}

function authChallenge(resourceMetadataUrl, scopes, error = "insufficient_scope", description = "A valid user authorization is required") {
  const scopePart = scopes.length ? `, scope="${scopes.join(" ")}"` : "";
  return `Bearer resource_metadata="${resourceMetadataUrl}"${scopePart}, error="${error}", error_description="${description}"`;
}

function authErrorResult(resourceMetadataUrl, scopes, error, description) {
  return {
    isError: true,
    content: [{ type: "text", text: `Authorization required: ${description}` }],
    _meta: { "mcp/www_authenticate": [authChallenge(resourceMetadataUrl, scopes, error, description)] }
  };
}

export function installToolSecurity(server, { resourceMetadataUrl }) {
  const lowLevel = server.server;
  const originalSetRequestHandler = lowLevel.setRequestHandler.bind(lowLevel);
  lowLevel.setRequestHandler = (schema, handler) => originalSetRequestHandler(schema, async (request, extra) => {
    const result = await handler(request, extra);
    if (Array.isArray(result?.tools)) {
      result.tools = result.tools.map((tool) => ({
        ...tool,
        securitySchemes: tool?._meta?.securitySchemes || []
      }));
    }
    return result;
  });

  server.tool = (name, ...args) => {
    const callback = args.at(-1);
    if (typeof callback !== "function") throw new Error(`Tool ${name} is missing a callback`);
    const configParts = args.slice(0, -1);
    const description = typeof configParts[0] === "string" ? configParts.shift() : undefined;
    const inputSchema = configParts[0] && typeof configParts[0] === "object" ? configParts.shift() : undefined;
    if (configParts.length) throw new Error(`Unsupported legacy tool registration for ${name}`);
    const policy = toolSecurityPolicy(name);
    const securitySchemes = [{ type: "oauth2", scopes: policy.scopes }];
    return server.registerTool(name, {
      description,
      inputSchema,
      annotations: policy.annotations,
      _meta: { securitySchemes }
    }, async (toolArgs, extra) => {
      const auth = extra?.authInfo;
      if (!auth) return authErrorResult(resourceMetadataUrl, policy.scopes, "invalid_token", "No validated access token was provided");
      const missing = policy.scopes.filter((scope) => !auth.scopes?.includes(scope));
      if (missing.length) return authErrorResult(resourceMetadataUrl, policy.scopes, "insufficient_scope", `Missing required scope: ${missing.join(" ")}`);
      if (!auth.extra?.subject) return authErrorResult(resourceMetadataUrl, policy.scopes, "invalid_token", "The access token did not resolve to an authorized user identity");
      return callback(toolArgs, extra);
    });
  };
}

export function annotationReport() {
  return [...ALL_CLASSIFIED_TOOLS].sort().map((name) => toolSecurityPolicy(name));
}
