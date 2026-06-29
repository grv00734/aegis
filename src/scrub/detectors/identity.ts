import type { Detector, RawMatch } from "../../types.js";
import { runPatterns, type PatternSpec } from "./util.js";

/**
 * Context-aware PII that plain field-regex misses: person names, postal
 * addresses, dates of birth, IBANs and passport numbers. This narrows the gap
 * with NER-based tools (Presidio/GLiNER) while staying 100% local and offline.
 *
 * Names use a bundled common-given-name list plus surrounding context (a
 * capitalised surname, an honorific, or a "name:" label) to keep false
 * positives low without a model. For higher recall you can additionally wire a
 * local ONNX NER model via `makeNerDetector` (see ner.ts) — also offline.
 */

// A compact set of common given names (many locales). Extend via config if needed.
const GIVEN_NAMES = new Set(
  (
    "james john robert michael william david richard joseph thomas charles christopher daniel matthew anthony " +
    "mark donald steven andrew paul joshua kenneth kevin brian george edward ronald timothy jason jeffrey ryan " +
    "jacob gary nicholas eric jonathan stephen larry justin scott brandon benjamin samuel gregory alexander patrick " +
    "mary patricia jennifer linda elizabeth barbara susan jessica sarah karen nancy lisa margaret betty sandra " +
    "ashley kimberly emily donna michelle carol amanda dorothy melissa deborah stephanie rebecca laura sharon cynthia " +
    "kathleen amy angela shirley anna brenda pamela emma nicole helen samantha katherine christine debra rachel " +
    "carolyn janet maria olivia liam noah ava sophia isabella mia amelia harper evelyn a, " + // 'a, ' guards trailing split
    "mohammed ahmed ali fatima aisha omar yusuf ibrahim hassan khan priya raj amit anil sunil deepak rahul neha " +
    "wei li chen zhang liu yang huang zhao chloe lucas mateo santiago sofia camila valentina diego carlos juan jose " +
    "luis miguel antonio francisco manuel pedro pablo sergei dmitri ivan olga natasha yuki haruto sakura hiroshi"
  )
    .split(/\s+/)
    .map((n) => n.replace(/,$/, ""))
    .filter((n) => n.length > 1),
);

const PATTERNS: PatternSpec[] = [
  // Honorific + capitalised name(s): "Dr. Jane Doe", "Mr Smith"
  {
    type: "PERSON_NAME",
    severity: "medium",
    source: "\\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Sir|Madam)\\.?\\s+[A-Z][a-z]+(?:\\s+[A-Z][a-z]+)?\\b",
  },
  // "name: Jane Doe" / "full name - John Smith"
  {
    type: "PERSON_NAME",
    severity: "medium",
    source: "(?:full\\s+)?name\\s*[:\\-]\\s*([A-Z][a-z]+(?:\\s+[A-Z][a-z]+){1,2})",
    flags: "i",
    group: 1,
  },
  // US-style street address
  {
    type: "STREET_ADDRESS",
    severity: "medium",
    source:
      "\\b\\d{1,5}\\s+(?:[A-Z][a-zA-Z]+\\.?\\s){1,3}(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Ter|Circle|Cir|Highway|Hwy)\\b\\.?",
  },
  // Date of birth (labelled, to avoid matching arbitrary dates)
  {
    type: "DATE_OF_BIRTH",
    severity: "high",
    source: "(?:DOB|D\\.O\\.B\\.?|date\\s+of\\s+birth)\\s*[:\\-]?\\s*(\\d{1,2}[\\/\\-.]\\d{1,2}[\\/\\-.]\\d{2,4})",
    flags: "i",
    group: 1,
  },
  // Organization (company suffixes) — closes part of the NER gap locally
  {
    type: "ORGANIZATION",
    severity: "medium",
    source: "\\b[A-Z][A-Za-z0-9&.\\- ]{1,40}?\\s(?:Inc|LLC|Ltd|Corp|Corporation|GmbH|PLC|LLP|Co)\\b\\.?",
  },
  // Location as "City, ST 12345"
  {
    type: "LOCATION",
    severity: "low",
    source: "\\b[A-Z][a-zA-Z]+(?:\\s[A-Z][a-zA-Z]+){0,2},\\s[A-Z]{2}\\s\\d{5}(?:-\\d{4})?\\b",
  },
  // IBAN
  { type: "IBAN", severity: "high", source: "\\b[A-Z]{2}\\d{2}[A-Z0-9]{11,30}\\b" },
  // Passport (labelled)
  {
    type: "PASSPORT",
    severity: "high",
    source: "passport\\s*(?:no\\.?|number|#)?\\s*[:#]?\\s*([A-Z0-9]{6,9})",
    flags: "i",
    group: 1,
  },
];

/** "Firstname Lastname" where Firstname is a known given name. */
function detectKnownNames(text: string): RawMatch[] {
  const out: RawMatch[] = [];
  const re = /\b([A-Z][a-z]+)\s+([A-Z][a-z]+)\b/g;
  for (const m of text.matchAll(re)) {
    const first = (m[1] ?? "").toLowerCase();
    if (GIVEN_NAMES.has(first)) {
      const start = m.index ?? 0;
      out.push({
        start,
        end: start + m[0].length,
        value: m[0],
        type: "PERSON_NAME",
        category: "pii",
        severity: "medium",
      });
    }
  }
  return out;
}

export const identityDetector: Detector = {
  name: "identity",
  category: "pii",
  run(text: string): RawMatch[] {
    return [...runPatterns(text, PATTERNS, "pii"), ...detectKnownNames(text)];
  },
};
