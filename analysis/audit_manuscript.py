"""Manuscript number audit (Step 26).

1. Every results macro used in the text must be defined in paper/results_macros.tex (generated from CSVs).
2. Lists macros that are defined but unused.
3. Lists every other number with 2+ significant digits in the text, so it can be checked by hand
   against its source (protocol constants, scenario parameters, or quotes from the source paper).
Output: results/manuscript_audit.txt
"""
import glob
import os
import re

ROOT = os.path.join(os.path.dirname(__file__), "..")
P = os.path.join(ROOT, "paper")
defs = set(re.findall(r"newcommand\{\\([A-Za-z]+)\}", open(os.path.join(P, "results_macros.tex"), encoding="utf-8").read()))
used, literal = set(), []
for f in sorted(glob.glob(os.path.join(P, "sec_*.tex"))):
    txt = open(f, encoding="utf-8").read()
    used |= set(re.findall(r"\\([A-Za-z]+)", txt)) & defs
    for i, line in enumerate(txt.splitlines(), 1):
        clean = re.sub(r"\\[A-Za-z]+|\{[^{}]*\}|\$[^$]*\$", " ", line)
        for m in re.finditer(r"(?<![A-Za-z\-])\d+(?:\.\d+)?(?:\s?(?:%|ms|s|KB|MB|B|\\times|x))?", clean):
            if len(re.sub(r"\D", "", m.group())) >= 2:
                literal.append(f"{os.path.basename(f)}:{i}: {m.group().strip()}")
out = [f"results macros defined: {len(defs)}; used in text: {len(used)}", "unused: " + ", ".join(sorted(defs - used)), "",
       "literal numbers to verify manually:"] + literal
open(os.path.join(ROOT, "results", "manuscript_audit.txt"), "w", encoding="utf-8").write("\n".join(out) + "\n")
print("\n".join(out[:3]))
print(len(literal), "literal numbers listed")
