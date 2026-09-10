#!/usr/bin/env python3
"""Content gate: does the deliverable actually say anything?

The first version asked `if "# Findings" not in text`. That is substring
matching wearing a structure check's clothes, and it passed two things it
should have refused:

    "# Findings\\n# Evidence\\n# Next steps\\n" + "x"*200   headings, no content
    "I will write the # Findings ... later."               headings in prose

Both are the failure this gate exists to prevent in miniature: verifying
that a name appears rather than that the content is right, through brittle
string matching. So the file is parsed as structure. A section counts only
when its heading starts a line, and each section must carry real prose of
its own. Repeated filler is not prose, which is what the distinct-character
floor catches.

The target path and the required sections live in config.json, and the path
is resolved from the lab root rather than the caller's working directory, so
the verdict cannot change with who invoked it.

This is a Stop-style gate: it exits 1 on failure, not 2.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _lib import LAB, load_config, resolve, verdict  # noqa: E402

cfg = load_config()
spec = cfg["deliverable"]

target = resolve(spec["path"], LAB)
required = spec["required_sections"]
min_chars = spec["min_section_chars"]
min_distinct = spec["min_distinct_chars"]

if not os.path.exists(target):
    verdict("fail", f"{os.path.relpath(target, LAB)} does not exist")

with open(target, encoding="utf-8", errors="replace") as f:
    text = f.read()

# split into sections on real headings only: '#' at the start of a line
sections, current = {}, None
for line in text.splitlines():
    m = re.match(r"^#{1,6}\s+(.*?)\s*$", line)
    if m:
        current = m.group(1).strip().lower()
        sections[current] = []
    elif current is not None:
        sections[current].append(line)

missing = [h for h in required if h.lower() not in sections]
if missing:
    verdict("fail", f"missing section heading(s) at line start: {', '.join(missing)}")

thin = []
for h in required:
    body = "\n".join(sections[h.lower()]).strip()
    if len(body) < min_chars or len(set(body.replace(" ", ""))) < min_distinct:
        thin.append(f"{h} ({len(body)} chars)")
if thin:
    verdict("fail", f"section(s) present but without real content: {', '.join(thin)}")

verdict("pass", f"{len(required)} required sections present, each with substance")
