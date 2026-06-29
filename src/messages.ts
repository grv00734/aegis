/**
 * Format-aware request scrubbing. We only rewrite the fields that carry
 * user/assistant content (prompts, messages, system text) so that structural
 * fields like `model` or `max_tokens` are left untouched.
 *
 * For unknown shapes we fall back to scrubbing every string in the body, which
 * is safe but coarser.
 */
import type { RouteFormat, RawMatch } from "./types.js";
import type { Scrubber } from "./scrub/index.js";
import { Vault } from "./scrub/placeholders.js";

export interface RequestScrubResult {
  body: unknown;
  matches: RawMatch[];
}

type Json = unknown;
/** Optional post-scrub text transform (prompt optimization). */
export type TextTransform = (s: string) => string;

function scrubString(s: unknown, scrubber: Scrubber, vault: Vault, sink: RawMatch[], opt?: TextTransform): unknown {
  if (typeof s !== "string") return s;
  const { text, matches } = scrubber.scrub(s, vault);
  sink.push(...matches);
  return opt ? opt(text) : text;
}

/** Scrub a content value that may be a plain string or an array of typed blocks. */
function scrubContent(content: Json, scrubber: Scrubber, vault: Vault, sink: RawMatch[], opt?: TextTransform): Json {
  if (typeof content === "string") return scrubString(content, scrubber, vault, sink, opt);
  if (Array.isArray(content)) {
    return content.map((block) => {
      if (block && typeof block === "object" && "text" in block) {
        const b = block as Record<string, unknown>;
        return { ...b, text: scrubString(b.text, scrubber, vault, sink, opt) };
      }
      return block;
    });
  }
  return content;
}

function scrubDeep(value: Json, scrubber: Scrubber, vault: Vault, sink: RawMatch[], opt?: TextTransform): Json {
  if (typeof value === "string") return scrubString(value, scrubber, vault, sink, opt);
  if (Array.isArray(value)) return value.map((v) => scrubDeep(v, scrubber, vault, sink, opt));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      out[k] = scrubDeep(v, scrubber, vault, sink, opt);
    }
    return out;
  }
  return value;
}

export function scrubRequestBody(
  body: Json,
  format: RouteFormat,
  scrubber: Scrubber,
  vault: Vault,
  opt?: TextTransform,
): RequestScrubResult {
  const sink: RawMatch[] = [];

  if (!body || typeof body !== "object") {
    return { body, matches: sink };
  }

  if (format === "anthropic" || format === "openai") {
    const b = { ...(body as Record<string, unknown>) };

    // System prompt (Anthropic supports string or block array).
    if ("system" in b) b.system = scrubContent(b.system, scrubber, vault, sink, opt);

    // Messages array shared by both formats.
    if (Array.isArray(b.messages)) {
      b.messages = (b.messages as Json[]).map((msg) => {
        if (msg && typeof msg === "object" && "content" in msg) {
          const m = msg as Record<string, unknown>;
          return { ...m, content: scrubContent(m.content, scrubber, vault, sink, opt) };
        }
        return msg;
      });
    }

    // OpenAI "responses" API uses `input` instead of `messages`.
    if ("input" in b) b.input = scrubContent(b.input, scrubber, vault, sink, opt);

    return { body: b, matches: sink };
  }

  if (format === "gemini") {
    // Google Gemini/Vertex: { contents: [{ parts: [{ text }] }], systemInstruction: { parts } }
    const b = { ...(body as Record<string, unknown>) };
    if (Array.isArray(b.contents)) {
      b.contents = (b.contents as Json[]).map((c) => {
        if (c && typeof c === "object" && "parts" in c) {
          const cc = c as Record<string, unknown>;
          return { ...cc, parts: scrubContent(cc.parts, scrubber, vault, sink, opt) };
        }
        return c;
      });
    }
    if (b.systemInstruction && typeof b.systemInstruction === "object" && "parts" in (b.systemInstruction as object)) {
      const si = b.systemInstruction as Record<string, unknown>;
      b.systemInstruction = { ...si, parts: scrubContent(si.parts, scrubber, vault, sink, opt) };
    }
    return { body: b, matches: sink };
  }

  // Unknown shape (Bedrock, Cohere, internal company agents, …): scrub every
  // string we can find. Safe by default — over-redacts rather than leaks.
  return { body: scrubDeep(body, scrubber, vault, sink, opt), matches: sink };
}
