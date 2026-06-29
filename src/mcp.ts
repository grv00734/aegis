/**
 * MCP (Model Context Protocol) security.
 *
 * MCP traffic is JSON-RPC 2.0. When an agent calls a tool (`tools/call`), the
 * arguments can carry confidential data — those are already deep-scrubbed by the
 * passthrough path. This module adds a tool **deny-list**: dangerous or
 * unapproved tools (e.g. shell execution, file deletion) can be blocked outright,
 * which is the control enterprise buyers ask for around MCP.
 */
export interface McpRequest {
  jsonrpc?: string;
  method?: string;
  params?: { name?: string; arguments?: unknown } & Record<string, unknown>;
}

export function isMcp(body: unknown): body is McpRequest {
  return (
    !!body &&
    typeof body === "object" &&
    (body as McpRequest).jsonrpc === "2.0" &&
    typeof (body as McpRequest).method === "string"
  );
}

/** The tool name for a `tools/call`, else undefined. */
export function mcpToolName(body: unknown): string | undefined {
  if (isMcp(body) && body.method === "tools/call") return body.params?.name;
  return undefined;
}

/** Returns the denied tool name if this request calls a denied tool, else null. */
export function mcpDenied(body: unknown, denied: string[] | undefined): string | null {
  if (!denied || denied.length === 0) return null;
  const name = mcpToolName(body);
  return name && denied.includes(name) ? name : null;
}
