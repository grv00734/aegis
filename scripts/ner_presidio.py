#!/usr/bin/env python3
"""
Local NER bridge for Aegis's `nerCommand` hook.

Reads text on stdin and prints a JSON array of entities that Aegis maps to
NER_<TYPE> detections, e.g.:  [{"start": 10, "end": 18, "type": "PERSON"}]

Runs entirely on this machine (no cloud). Uses Microsoft Presidio if installed;
otherwise tries GLiNER; otherwise fails open (prints []), so the regex/dictionary
detectors still run.

Setup (one of):
  pip install "presidio-analyzer" && python -m spacy download en_core_web_lg
  pip install gliner

Wire it up in aegis.config.json:
  "nerCommand": "python3 scripts/ner_presidio.py"
"""
import sys
import json


def via_presidio(text):
    from presidio_analyzer import AnalyzerEngine  # type: ignore

    analyzer = AnalyzerEngine()
    results = analyzer.analyze(text=text, language="en")
    return [
        {"start": r.start, "end": r.end, "type": r.entity_type}
        for r in results
        if r.score >= 0.5
    ]


def via_gliner(text):
    from gliner import GLiNER  # type: ignore

    model = GLiNER.from_pretrained("urchade/gliner_small")
    labels = ["person", "organization", "location", "email", "phone number", "address"]
    ents = model.predict_entities(text, labels)
    return [
        {"start": e["start"], "end": e["end"], "type": e["label"].upper().replace(" ", "_")}
        for e in ents
    ]


def main():
    text = sys.stdin.read()
    if not text.strip():
        print("[]")
        return
    for backend in (via_presidio, via_gliner):
        try:
            print(json.dumps(backend(text)))
            return
        except Exception:
            continue
    print("[]")  # fail open


if __name__ == "__main__":
    main()
