/**
 * Server-Sent-Events restorer.
 *
 * Streamed responses arrive as many tiny text deltas. A placeholder we injected
 * (e.g. `[[REDACTED:EMAIL:1]]`) may be echoed by the model and split across
 * several deltas. We therefore buffer a small tail ("carry") that could be the
 * beginning of a placeholder, only releasing text once we know it is not part
 * of an incomplete token. Released text has its placeholders restored and is
 * re-emitted as well-formed SSE with correct JSON escaping.
 *
 * Restoration only ever puts real values back into the response stream that is
 * returned to the *local* client — nothing here touches the upstream request.
 */
import type { RouteFormat } from "./types.js";
import { Vault } from "./scrub/placeholders.js";

const OPEN = "[[REDACTED:";

/**
 * Index from which the suffix of `s` must be held because it could be (part of)
 * an unfinished placeholder. Returns `s.length` when nothing needs holding.
 */
export function carryIndex(s: string): number {
  // 1) A started-but-unclosed placeholder: hold from its opening bracket.
  let i = s.indexOf(OPEN);
  while (i !== -1) {
    const close = s.indexOf("]]", i + OPEN.length);
    if (close === -1) return i;
    i = s.indexOf(OPEN, close + 2);
  }
  // 2) A trailing fragment that is a prefix of the opening marker (e.g. "[[RED").
  const maxP = Math.min(OPEN.length - 1, s.length);
  for (let p = maxP; p > 0; p--) {
    if (s.endsWith(OPEN.slice(0, p))) return s.length - p;
  }
  return s.length;
}

export class SseRestorer {
  private raw = "";
  private carry = "";
  private lastIndex = 0;
  private format: Exclude<RouteFormat, "passthrough"> = "anthropic";

  constructor(private vault: Vault) {}

  feed(chunk: string): string {
    // No redactions and no key -> no tokens can exist -> pass through.
    if (!this.vault.active) return chunk;

    this.raw += chunk;
    let out = "";
    let idx: number;
    while ((idx = this.raw.indexOf("\n\n")) !== -1) {
      const block = this.raw.slice(0, idx);
      this.raw = this.raw.slice(idx + 2);
      out += this.processBlock(block);
    }
    return out;
  }

  end(): string {
    if (!this.vault.active) return this.raw;
    const flushed = this.flushCarry();
    const tail = this.raw;
    this.raw = "";
    return flushed + tail;
  }

  private processBlock(block: string): string {
    const lines = block.split("\n");
    let eventName: string | null = null;
    const dataParts: string[] = [];
    for (const line of lines) {
      if (line.startsWith("event:")) eventName = line.slice(6).trim();
      else if (line.startsWith("data:")) dataParts.push(line.slice(5).replace(/^ /, ""));
    }

    if (dataParts.length === 0) return block + "\n\n";
    const dataStr = dataParts.join("\n");

    if (dataStr === "[DONE]") {
      this.format = "openai";
      return this.flushCarry() + block + "\n\n";
    }

    let obj: any;
    try {
      obj = JSON.parse(dataStr);
    } catch {
      return block + "\n\n"; // not JSON we understand
    }

    // --- Anthropic shape ---
    if (obj && typeof obj.type === "string") {
      this.format = "anthropic";
      if (obj.type === "content_block_start" && typeof obj.index === "number") {
        this.lastIndex = obj.index;
        return block + "\n\n";
      }
      if (
        obj.type === "content_block_delta" &&
        obj.delta?.type === "text_delta" &&
        typeof obj.delta.text === "string"
      ) {
        if (typeof obj.index === "number") this.lastIndex = obj.index;
        const restored = this.consume(obj.delta.text);
        if (restored === "") return "";
        obj.delta.text = restored;
        return emit(eventName, obj);
      }
      if (
        obj.type === "content_block_stop" ||
        obj.type === "message_delta" ||
        obj.type === "message_stop"
      ) {
        return this.flushCarry() + block + "\n\n";
      }
      return block + "\n\n";
    }

    // --- OpenAI shape ---
    if (Array.isArray(obj?.choices)) {
      this.format = "openai";
      const choice = obj.choices[0];
      const delta = choice?.delta;
      if (delta && typeof delta.content === "string") {
        const restored = this.consume(delta.content);
        if (restored === "" && choice.finish_reason == null) return "";
        delta.content = restored;
        return emit(eventName, obj);
      }
      if (choice?.finish_reason != null) {
        return this.flushCarry() + emit(eventName, obj);
      }
      return emit(eventName, obj);
    }

    return block + "\n\n";
  }

  /** Append text to the carry, release the safe portion with placeholders restored. */
  private consume(text: string): string {
    const combined = this.carry + text;
    const ci = carryIndex(combined);
    const safe = combined.slice(0, ci);
    this.carry = combined.slice(ci);
    return this.vault.restore(safe);
  }

  /** Emit whatever is held in the carry as a synthetic text delta. */
  private flushCarry(): string {
    if (this.carry === "") return "";
    const restored = this.vault.restore(this.carry);
    this.carry = "";
    if (restored === "") return "";

    if (this.format === "openai") {
      return emit(null, { choices: [{ index: 0, delta: { content: restored } }] });
    }
    return emit("content_block_delta", {
      type: "content_block_delta",
      index: this.lastIndex,
      delta: { type: "text_delta", text: restored },
    });
  }
}

function emit(eventName: string | null, obj: unknown): string {
  let s = "";
  if (eventName) s += `event: ${eventName}\n`;
  s += `data: ${JSON.stringify(obj)}\n\n`;
  return s;
}
