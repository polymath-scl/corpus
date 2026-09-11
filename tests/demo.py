#!/usr/bin/env python3
"""Build a small worked example corpus and walk through it.

Creates a throwaway corpus in a temporary folder, with throwaway signing keys,
populated with a handful of records from the pilot problem, then demonstrates
search, display, and how verification status is computed rather than claimed.

    python3 tests/demo.py

Nothing is written outside the temporary folder, which is left in place at the
end so you can poke at it.
"""
import importlib.machinery
import importlib.util
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "polymath"
spec = importlib.util.spec_from_loader(
    "pm", importlib.machinery.SourceFileLoader("pm", str(SCRIPT)))
pm = importlib.util.module_from_spec(spec); spec.loader.exec_module(pm)

tmp = Path(tempfile.mkdtemp(prefix="polymath-demo-"))
root = tmp / "corpus"
for d in ("people", "records", "artifacts", "transcripts", "LICENSES"):
    (root / d).mkdir(parents=True)
subprocess.run(["git", "-C", str(root), "init", "-q"], check=True)

keys = {}
for who, role, name in (("danny", "admin", "Danny Calegari"),
                        ("student", "member", "A Graduate Student"),
                        ("postdoc", "member", "A Postdoc")):
    k = tmp / f"id_{who}"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", who, "-f", str(k)],
                   check=True)
    keys[who] = k
    pub = (tmp / f"id_{who}.pub").read_text().strip()
    (root / "people" / f"{who}.toml").write_text(
        f'name = "{name}"\nrole = "{role}"\nadmitted_by = "danny"\n'
        f'key_confirmed_out_of_band = "demo corpus"\nkeys = ["{pub}"]\n', encoding="utf-8")

def put(author, rtype, title, body, links=None, **extra):
    rec = pm._template(rtype, author)
    rec["title"] = title; rec["body"] = body; rec["links"] = links or []
    rec.update(extra)
    rec = pm._finalise(rec, keys[author])
    d = root / "records" / "2026" / "09"; d.mkdir(parents=True, exist_ok=True)
    (d / f"{rec['id']}.json").write_text(
        json.dumps(rec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return rec

goal = put("danny", "question",
    "Is scl rational in closed surface groups?",
    "For G the fundamental group of a closed surface of genus at least 2, and g in [G,G], "
    "is scl(g) always rational? Rationality is known in free groups by linear programming "
    "over the space of admissible surfaces. The obstacle in the surface group case is that "
    "the corresponding polyhedron is not evidently finite-sided.")

sub = put("danny", "question",
    "Does the LP argument localise along a separating curve?",
    "If a closed surface group splits as an amalgam over an infinite cyclic subgroup, can "
    "the rationality argument be run on each factor and glued?",
    links=[{"rel": "depends_on", "target": goal["id"]}])

obs = put("student", "obstruction",
    "Gluing LPs along a separating curve loses finiteness",
    "The two factor polyhedra are finite-sided, but the gluing condition is an equality of "
    "boundary winding numbers, and imposing it introduces infinitely many faces in the "
    "limit. So the naive amalgam argument does not give rationality.",
    what_was_tried="Split along a separating simple closed curve; write the admissible "
                   "surface as a union of two pieces; set up the LP for each factor "
                   "separately and impose matching of boundary data as a linear condition.",
    links=[{"rel": "answers", "target": sub["id"]}])

spec_q = put("postdoc", "question",
    "Which rationals occur as scl in the free group of rank 2?",
    "The scl spectrum of F_2. Note that scl is defined on the commutator subgroup, or more "
    "generally on formal sums of cyclically reduced chains with trivial homology class -- "
    "equal numbers of a and A, and of b and B. Known: every nontrivial element of the "
    "commutator subgroup of a free group has scl at least 1/2 (Duncan-Howie). Question: "
    "which rationals above that gap are realised, and with which denominators?")

claim = put("postdoc", "claim",
    "scl of the commutator abAB is 1/2 in F_2",
    "For F_2 = <a,b> and w = [a,b] = abAB, scl(w) = 1/2. The upper bound comes from the "
    "once-punctured torus that w bounds; the lower bound is the Duncan-Howie gap. This is "
    "classical, and is here as the smallest honest worked example of a two-sided certificate.",
    links=[{"rel": "cites", "target": spec_q["id"]}])

cert = root / "artifacts" / "commutator-certificate.json"
cert.write_text(json.dumps({
    "element": "abAB",
    "in_commutator_subgroup": True,
    "exponent_sums": {"a": 0, "b": 0},
    "claimed_scl": "1/2",
    "upper_bound_certificate": {
        "kind": "admissible surface",
        "surface": "once-punctured torus",
        "euler_characteristic": -1,
        "boundary_components": 1,
        "degree": 1,
        "bound": "-chi^-(S) / (2n) = 1/2"
    },
    "lower_bound_certificate": {
        "kind": "gap theorem, not an explicit quasimorphism",
        "source": "Duncan-Howie: scl >= 1/2 on the commutator subgroup of a free group",
        "bound": "1/2",
        "note": "An explicit extremal quasimorphism realising this bound would be a "
                "stronger certificate, and is exactly the kind of artifact this record "
                "type is for. It is deliberately not fabricated here."
    }
}, indent=2) + "\n", encoding="utf-8")

art = put("postdoc", "artifact",
    "Two-sided certificate for scl(abAB) = 1/2",
    "Matching upper and lower bounds. All values are exact rationals: any floating point "
    "solution must be rounded and re-verified exactly before it counts.",
    file={"path": "commutator-certificate.json", "sha256": pm.file_hash(cert)},
    links=[{"rel": "supports", "target": claim["id"]}])

verdict = put("danny", "verdict",
    "Arithmetic in the abAB certificate checks out",
    "Checked in exact rational arithmetic: the word has exponent sum zero in both "
    "generators, so scl is defined on it; -chi^-/(2n) = 1/2 for the stated surface; the "
    "quoted gap is 1/2. Note carefully what this does NOT say. It does not say the surface "
    "described is admissible for this word, and it does not say the cited gap theorem "
    "applies as stated. A machine result covers the arithmetic only.",
    checked=[{"path": "commutator-certificate.json", "sha256": pm.file_hash(cert)}],
    links=[{"rel": "supports", "target": claim["id"]}])


def run(*args):
    print(f"\n$ polymath {' '.join(args)}")
    print("-" * 72)
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(root), *args],
                       capture_output=True, text=True)
    print(r.stdout.rstrip() or r.stderr.rstrip())

print("=" * 72)
print(f"Demo corpus: {root}")
print("=" * 72)
run("validate")
run("search", "scl", "rational")
run("search", "separating", "curve")
run("show", claim["id"])
run("graph", obs["id"])

print("\n" + "=" * 72)
print("Verification status is COMPUTED, never written down by an author:")
print("=" * 72)
c = pm.Corpus(root)
print(f"  claim {claim['id'][:12]}  ->  {pm.verification_status(c, claim['id'])}")
print("\nThere is a machine result, but no independent statement review yet, so the")
print("claim is not verified. Adding one from a third person:")
review = put("student", "statement_review",
    "The certificate is about the element the claim names, and scl is defined on it",
    "Checked that the word in the certificate file is abAB as written in the claim; that it "
    "lies in the commutator subgroup, so scl is defined on it at all; that the once-punctured "
    "torus really is admissible for it of degree 1; and that the gap theorem is quoted in the "
    "right direction. This is the check no machine performs.",
    reviews=verdict["id"])
c = pm.Corpus(root)
print(f"  claim {claim['id'][:12]}  ->  {pm.verification_status(c, claim['id'])}")
run("validate")
print(f"\nThe demo corpus is left at {root} -- delete it when you are done.")
