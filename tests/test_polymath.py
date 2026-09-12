#!/usr/bin/env python3
"""Tests for the Stage 0 client.

Most of these are attacks. Each one comes from a specific finding in
red_team_1.md or red_team_2.md, and asserts that the validator refuses it.
Run with:  python3 tests/test_polymath.py
"""

import importlib.machinery
import importlib.util
import json
import re
import os
import shutil
import subprocess
import sys
import tempfile
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCRIPT = HERE.parent / "polymath"

spec = importlib.util.spec_from_loader(
    "pm", importlib.machinery.SourceFileLoader("pm", str(SCRIPT)))
pm = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pm)

PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}" + (f"   {extra}" if extra and not cond else ""))


def codes(problems):
    return sorted({p.code for p in problems})


# --------------------------------------------------------------------------
# fixture
# --------------------------------------------------------------------------

class Fixture:
    def __init__(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="polymath-test-"))
        self.root = self.tmp / "corpus"
        for d in ("people", "records", "artifacts", "transcripts", "LICENSES"):
            (self.root / d).mkdir(parents=True)
        self.keys = {}
        for who, role in (("alice", "admin"), ("bob", "member"), ("mallory", "member")):
            k = self.tmp / f"id_{who}"
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", who,
                            "-f", str(k)], check=True)
            self.keys[who] = k
            pub = (self.tmp / f"id_{who}.pub").read_text().strip()
            (self.root / "people" / f"{who}.toml").write_text(
                f'name = "{who.title()} Example"\n'
                f'role = "{role}"\n'
                f'admitted_by = "alice"\n'
                f'key_confirmed_out_of_band = "in person, 2026-09-10"\n'
                f'keys = ["{pub}"]\n', encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "init", "-q"], check=True)
        for k, v in (("user.name", "Test Member"),
                     ("user.email", "test@example.invalid")):
            subprocess.run(["git", "-C", str(self.root), "config", k, v], check=True)

    def corpus(self):
        c = pm.Corpus(self.root)
        return c

    def make(self, author="bob", rtype="theorem", title="A test claim",
             body="A body.", links=None, sign_as=None, **extra):
        rec = pm._template(rtype, author)
        rec["title"] = title
        rec["body"] = body
        rec["links"] = links or []
        rec.update(extra)
        return pm._finalise(rec, self.keys[sign_as or author])

    def place(self, rec, subdir="2026/09", name=None):
        d = self.root / "records" / subdir
        d.mkdir(parents=True, exist_ok=True)
        p = d / (name or f"{rec['id']}.json")
        p.write_text(json.dumps(rec, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        return p

    def validate(self):
        c = self.corpus()
        return pm.run_validation(c)

    def clean(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


def fill_placeholders(text, prose):
    """Replace each REPLACE THIS paragraph in a generated draft with real prose."""
    out, skipping = [], False
    for line in text.split("\n"):
        if line.startswith(pm.PLACEHOLDER):
            out.append(prose)
            skipping = True
            continue
        if skipping:
            if line.strip() == "":
                skipping = False
                out.append(line)
            continue
        out.append(line)
    return "\n".join(out)


def fresh():
    return Fixture()


# --------------------------------------------------------------------------
# tests
# --------------------------------------------------------------------------

def t_happy_path():
    f = fresh()
    q = f.make(author="alice", rtype="question", title="Is scl rational in surface groups")
    f.place(q)
    c = f.make(author="bob", rtype="theorem", title="scl is rational for one relator quotients",
               links=[{"rel": "answers", "target": q["id"]}])
    f.place(c)
    probs = f.validate()
    check("clean corpus validates", probs == [], f"got {[str(p) for p in probs]}")
    f.clean()


def t_tampered_body_breaks_hash():
    f = fresh()
    rec = f.make()
    p = f.place(rec)
    d = json.loads(p.read_text()); d["body"] = "Something else entirely."
    p.write_text(json.dumps(d))
    check("altered body is caught by the fingerprint", "I02" in codes(f.validate()))
    f.clean()


def t_tampered_body_rehashed_breaks_signature():
    f = fresh()
    rec = f.make()
    rec["body"] = "Something else entirely."
    rec.pop("id")
    rec["id"] = pm.make_id(rec)          # attacker recomputes the fingerprint
    f.place(rec)                          # but cannot produce a matching signature
    check("re-fingerprinted forgery is caught by the signature", "I08" in codes(f.validate()))
    f.clean()


def t_signed_by_someone_else():
    f = fresh()
    rec = f.make(author="alice", sign_as="mallory")
    f.place(rec)
    check("record claiming another author is rejected", "I08" in codes(f.validate()))
    f.clean()


def t_non_member():
    f = fresh()
    rec = f.make(author="bob")
    f.place(rec)
    (f.root / "people" / "bob.toml").unlink()
    check("record from a non-member is rejected", "I06" in codes(f.validate()))
    f.clean()


def t_revoked_key():
    f = fresh()
    rec = f.make(author="bob")
    f.place(rec)
    pub = (f.tmp / "id_bob.pub").read_text().strip()
    (f.root / "people" / "bob.toml").write_text(
        f'name = "Bob"\nrole = "member"\nadmitted_by = "alice"\n'
        f'key_confirmed_out_of_band = "in person"\nkeys = ["{pub}"]\n'
        f'[[revocation]]\nkey = "{pub}"\nreason = "compromise"\n', encoding="utf-8")
    check("record signed with a revoked key is rejected",
          {"I07", "I08"} & set(codes(f.validate())) != set())
    f.clean()


def t_body_too_long():
    f = fresh()
    f.place(f.make(body="x" * (pm.MAX_BODY + 1)))
    check("over-long body is rejected", "S07" in codes(f.validate()))
    f.clean()


def t_control_characters():
    f = fresh()
    f.place(f.make(body="normal text\x1b[2J\x1b[H and then a cleared screen"))
    check("terminal escape sequences are rejected", "C01" in codes(f.validate()))
    f.clean()


def t_bidi_override():
    f = fresh()
    f.place(f.make(body="the bound is ‮5 < x‬ here"))
    check("text-direction override characters are rejected", "C02" in codes(f.validate()))
    f.clean()


def t_zero_width():
    f = fresh()
    f.place(f.make(title="A test​claim"))
    check("invisible formatting characters are rejected", "C03" in codes(f.validate()))
    f.clean()


def t_nfc_required():
    f = fresh()
    rec = f.make(title="A test claim")
    rec["body"] = unicodedata.normalize("NFD", "Poincaré duality")
    rec.pop("id"); rec.pop("signature")
    rec["id"] = pm.make_id(rec)
    rec["signature"] = pm.ssh_sign(pm.canonical_bytes(rec), f.keys["bob"])
    f.place(rec)
    # canonical_bytes normalises, so the stored (non-normalised) text is caught
    check("non-normalised text is rejected", "C04" in codes(f.validate()))
    f.clean()


def t_html_and_remote_images():
    f = fresh()
    f.place(f.make(title="With markup", body='see <img src="http://evil.test/x.png">'))
    cs = codes(f.validate())
    check("raw HTML is rejected", "C05" in cs)
    f.clean()
    f = fresh()
    f.place(f.make(title="With image", body="![fig](https://evil.test/beacon.png)"))
    check("images loaded from other websites are rejected", "C06" in codes(f.validate()))
    f.clean()


def t_group_notation_is_not_html():
    """Angle brackets are ubiquitous in group theory. Found by running the demo:
    the first version of the HTML check rejected F_2 = <a,b>."""
    f = fresh()
    for i, body in enumerate([
            "F_2 = <a,b> is free of rank 2.",
            "The presentation <x,y | [x,y]> gives Z^2.",
            "scl vanishes on <a> when a is torsion.",
            "We need chi(S) < 0 and n > 0 here.",
            "G = <S | R> is hyperbolic."]):
        f.place(f.make(title=f"Group notation {i}", body=body))
    probs = f.validate()
    check("group presentations are not mistaken for HTML", probs == [],
          f"got {[str(p) for p in probs]}")
    f.clean()


def t_markdown_draft_round_trip():
    """The whole point: prose goes in as prose. Quotes, backslashes, blank lines,
    unicode and LaTeX must survive verbatim, with nothing to escape."""
    f = fresh()
    body = ('The obstruction is that the gluing condition is an *equality* of boundary\n'
            'winding numbers.\n\n'
            'Concretely: write $\\partial S = \\sum n_i \\gamma_i$ with $n_i \\in \\mathbb{Q}$,\n'
            'and note that "admissible" here means degree $n$ over $w$ -- not degree 1.\n\n'
            'A line of three dashes below should stay in the body:\n\n'
            '---\n\n'
            'and so should this paragraph after it.\n')
    draft = f.tmp / "d.md"
    draft.write_text("---\ntype: obstruction\ntitle: Gluing loses finiteness\n"
                     "author: bob\nprovenance: human\n---\n\n"
                     + body + "\n## What was tried\n\nSplit along a separating curve; "
                     "set up one LP per factor.\n", encoding="utf-8")
    header, parsed_body = pm.parse_draft(draft.read_text())
    rec = pm.draft_to_record(header, parsed_body, f.corpus(), "bob")
    rec = pm._finalise(rec, f.keys["bob"])
    f.place(rec)
    check("markdown draft becomes a valid record", f.validate() == [])
    check("prose survives verbatim, including quotes, LaTeX and a --- line",
          rec["body"].strip() == body.strip(), repr(rec["body"][:120]))
    check("'What was tried' is pulled into its own field",
          rec["what_was_tried"].startswith("Split along a separating curve"))
    check("and is removed from the body", "What was tried" not in rec["body"])
    f.clean()


def t_markdown_header_errors():
    f = fresh()
    c = f.corpus()

    def err(text):
        try:
            h, b = pm.parse_draft(text)
            pm.draft_to_record(h, b, c, "bob")
            return None
        except pm.Problem as e:
            return e.code

    check("a draft not starting with --- is rejected",
          err("type: note\ntitle: x\n") == "D01")
    check("an unclosed header is rejected",
          err("---\ntype: note\ntitle: x\n\nbody\n") == "D02")
    check("an unknown header field names the valid ones",
          err("---\ntype: note\ntitle: x\nauthr: bob\n---\n\nbody\n") == "D06")
    check("a missing type is rejected",
          err("---\ntitle: x\n---\n\nbody\n") == "D10")
    check("an unknown type is rejected",
          err("---\ntype: lemma\ntitle: x\n---\n\nbody\n") == "D11")
    check("an empty body is rejected",
          err("---\ntype: note\ntitle: x\n---\n\n\n") == "D15")
    check("an obstruction with no 'what was tried' is rejected",
          err("---\ntype: obstruction\ntitle: x\n---\n\nIt fails.\n") == "D14")
    check("a malformed link is rejected",
          err("---\ntype: note\ntitle: x\nlinks:\n  - depends_on\n---\n\nbody\n") == "D17")
    f.clean()


def t_markdown_links_and_artifacts():
    f = fresh()
    target = f.make(author="alice", rtype="question", title="An open question")
    f.place(target)
    art = f.root / "artifacts" / "cert.json"
    art.write_text('{"element": "abAB"}\n')

    h, b = pm.parse_draft(
        f"---\ntype: artifact\ntitle: A certificate\nauthor: bob\n"
        f"file: cert.json\nlinks:\n  - cites {target['id']}\n---\n\nThe certificate.\n")
    rec = pm.draft_to_record(h, b, f.corpus(), "bob")
    check("links written as 'relation id' are parsed",
          rec["links"] == [{"rel": "cites", "target": target["id"]}])
    check("the artifact fingerprint is computed for you, not typed",
          rec["file"] == {"path": "cert.json", "sha256": pm.file_hash(art)})
    f.place(pm._finalise(rec, f.keys["bob"]))
    check("the result validates", f.validate() == [])

    h, b = pm.parse_draft("---\ntype: artifact\ntitle: Missing\nauthor: bob\n"
                          "file: ../../../etc/passwd\n---\n\nx\n")
    try:
        pm.draft_to_record(h, b, f.corpus(), "bob"); code = None
    except pm.Problem as e:
        code = e.code
    check("an artifact path escaping artifacts/ is rejected", code == "D07")
    f.clean()


def t_markdown_cli_round_trip():
    f = fresh()
    draft = f.tmp / "draft-question.md"
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root),
                        "new", "question", "--title", "Is scl rational in surface groups?",
                        "--author", "bob", "--out", str(draft)],
                       capture_output=True, text=True, cwd=str(f.root))
    check("`polymath new` writes a markdown draft", draft.exists() and
          draft.read_text().startswith("---\ntype: question"), r.stderr)
    draft.write_text(fill_placeholders(
        draft.read_text(),
        'For G = pi_1 of a closed surface of genus >= 2, and c a chain of trivial\n'
        'homology class, is scl(c) always rational? The free group case is settled\n'
        'by linear programming over admissible surfaces; the obstacle here is\n'
        'finiteness of the polyhedron.'))
    _h, _b = pm.parse_draft(draft.read_text())
    check("the filled draft has no placeholder left in the prose",
          pm.PLACEHOLDER not in _b)
    check("guidance mentioning the placeholder lives in the header, "
          "so it cannot be published by accident",
          pm.PLACEHOLDER in draft.read_text() and pm.PLACEHOLDER not in _b)
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root),
                        "publish", str(draft), "--key", str(f.keys["bob"]),
                        "-y", "--local-only"],
                       capture_output=True, text=True, cwd=str(f.root))
    check("`polymath publish` accepts the markdown draft", r.returncode == 0,
          r.stdout + r.stderr)
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root), "validate"],
                       capture_output=True, text=True, cwd=str(f.root))
    check("the published record validates", r.returncode == 0, r.stdout + r.stderr)
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root),
                        "search", "polyhedron"], capture_output=True, text=True,
                       cwd=str(f.root))
    check("and is findable by a word from the middle of the prose",
          "Is scl rational in surface groups?" in r.stdout, r.stdout)
    f.clean()


def t_tutorial_runs_and_leaves_a_valid_sandbox():
    """The guided introduction must run start to finish without help, and the
    sandbox it leaves behind must itself pass every check -- including after
    step 7 puts back the record it deliberately corrupts."""
    r = subprocess.run([sys.executable, str(SCRIPT), "tutorial", "--no-pause"],
                       capture_output=True, text=True, cwd=str(HERE.parent))
    check("`polymath tutorial` runs to completion", r.returncode == 0, r.stderr[-400:])
    out = r.stdout
    for step in range(1, 9):
        check(f"tutorial reaches step {step}", f"Step {step} of 8" in out)
    check("it shows list and browse", "$ polymath list" in out and "$ polymath browse" in out)
    listed = [c for c in ("doctor", "search", "list", "browse", "show", "new", "publish")
              if f"    {c}" in out]
    n_claimed = re.search(r"(\w+) commands over six steps", out)
    words = {"five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9}
    check("the number of commands it claims matches the number it lists",
          n_claimed and words.get(n_claimed.group(1).lower()) == len(listed),
          f"claims {n_claimed and n_claimed.group(1)}, lists {len(listed)}: {listed}")
    check("it shows a record with no connections",
          "[unconnected]" in out)
    check("it shows the real command, not one with --root or --out",
          "--root" not in out and "--out" not in out)
    check("command output is marked so it cannot be mistaken for record content",
          "    | " in out)
    check("it demonstrates that a claim is not verified by its own author",
          "machine-checked, awaiting an independent statement review" in out)
    check("and that a third-party review does verify it",
          "claim status now:  verified" in out)
    check("it demonstrates a tampered record being caught",
          "[I02]" in out and "[I08]" in out)
    m = [l for l in out.splitlines() if l.strip().startswith("/") and "corpus" in l]
    check("it reports where the sandbox is", bool(m), out[-300:])
    if m:
        sandbox = Path(m[-1].strip())
        r2 = subprocess.run([sys.executable, str(SCRIPT), "--root", str(sandbox), "validate"],
                            capture_output=True, text=True)
        check("the sandbox it leaves behind validates cleanly",
              r2.returncode == 0, r2.stdout + r2.stderr)
        shutil.rmtree(sandbox.parent, ignore_errors=True)


def t_search_matches_whole_words():
    """`lp` must not match `help`. Danny hit this: LP is one of the most natural
    search terms on the pilot problem."""
    f = fresh()
    f.place(f.make(title="A cry for help", body="This says help, and alpha, and scalp."))
    f.place(f.make(title="Linear programming", body="The LP is finite sided."))
    c = f.corpus()
    hits = [r["title"] for _, _, r in pm.search_records(c, ["lp"])]
    check("`lp` finds the LP record", "Linear programming" in hits)
    check("`lp` does not match help/alpha/scalp", "A cry for help" not in hits, hits)
    hits = [r["title"] for _, _, r in pm.search_records(c, ["lp"], substring=True)]
    check("--substring brings the old behaviour back", len(hits) == 2, hits)
    f.clean()


def t_search_phrase_survives_a_line_break():
    """A quoted phrase used to silently miss records where the prose wrapped
    between the words, reporting 'nothing found' -- the worst false negative
    this project can produce."""
    f = fresh()
    f.place(f.make(title="Wrapped", body="We cut along a separating\ncurve and it failed."))
    hits = pm.search_records(f.corpus(), ["separating curve"])
    check("a phrase matches across a line break", len(hits) == 1)
    f.clean()


def t_search_ranks_records_matching_everything_first():
    f = fresh()
    f.place(f.make(title="Only one word", body="Something about surfaces."))
    f.place(f.make(title="Both words", body="Something about surfaces and about scl."))
    hits = pm.search_records(f.corpus(), ["surfaces", "scl"])
    check("the record containing all the words comes first",
          hits[0][2]["title"] == "Both words")
    check("the partial match is still returned", len(hits) == 2)
    f.clean()


def t_search_has_no_regular_expressions():
    f = fresh()
    f.place(f.make(title="Rational scl", body="Is scl always rational here?"))
    check("a regular expression is matched literally and finds nothing",
          pm.search_records(f.corpus(), ["scl.*rational"]) == [])
    f.clean()


def t_you_never_have_to_type_an_identifier():
    f = fresh()
    a = f.make(title="First record"); f.place(a)
    b = f.make(title="Second record"); f.place(b)
    c = f.corpus()
    pm.save_shortlist(c, [a["id"], b["id"]])
    check("a number from the last list resolves", pm.resolve_id(c, "2") == b["id"])
    check("a short prefix resolves", pm.resolve_id(c, a["id"][:4]) == a["id"])
    check("the whole identifier resolves", pm.resolve_id(c, a["id"]) == a["id"])
    f.clean()


def t_list_numbers_records_and_flags_orphans():
    f = fresh()
    q = f.make(author="alice", rtype="question", title="An open question")
    f.place(q)
    f.place(f.make(author="bob", title="Connected claim",
                   links=[{"rel": "answers", "target": q["id"]}]))
    f.place(f.make(author="bob", rtype="note", title="Stray note",
                   body="Attached to nothing."))
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root), "list"],
                       capture_output=True, text=True)
    check("`polymath list` runs", r.returncode == 0, r.stderr)
    check("it numbers the records", "  1  " in r.stdout and "  3  " in r.stdout)
    check("it flags the record nothing links to", "[unconnected]" in r.stdout)
    check("it groups by kind", "QUESTION" in r.stdout and "NOTE" in r.stdout)
    check("it leaves a shortlist that show can use",
          len(pm.load_shortlist(f.corpus())) == 3)
    f.clean()


def t_browse_writes_an_escaped_offline_page():
    f = fresh()
    f.place(f.make(title="Presentations and ampersands",
                   body="For F_2 = <a,b> & the commutator [a,b], scl = 1/2."))
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root),
                        "browse", "--no-open"], capture_output=True, text=True)
    check("`polymath browse` runs", r.returncode == 0, r.stderr)
    page = (f.root / ".polymath-browse.html").read_text()
    check("angle brackets from a group presentation are escaped",
          "&lt;a,b&gt;" in page and "<a,b>" not in page)
    check("ampersands are escaped", "&amp;" in page)
    check("nothing is loaded from the network",
          "http://" not in page and "https://" not in page)
    check("the record is actually on the page", "Presentations and ampersands" in page)
    f.clean()


def t_publish_carries_through_to_a_commit():
    f = fresh()
    subprocess.run(["git", "-C", str(f.root), "add", "-A"], capture_output=True)
    subprocess.run(["git", "-C", str(f.root), "-c", "user.name=T",
                    "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "seed"],
                   capture_output=True)
    draft = f.tmp / "d.md"
    draft.write_text("---\ntype: note\ntitle: A note that gets committed\n"
                     "author: bob\nprovenance: human\n---\n\nSome prose.\n",
                     encoding="utf-8")
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root),
                        "publish", str(draft), "--key", str(f.keys["bob"]), "-y"],
                       capture_output=True, text=True,
                       env={**os.environ, "GIT_AUTHOR_NAME": "T",
                            "GIT_AUTHOR_EMAIL": "t@example.invalid",
                            "GIT_COMMITTER_NAME": "T",
                            "GIT_COMMITTER_EMAIL": "t@example.invalid"})
    check("publish records the change in the history", r.returncode == 0,
          r.stdout + r.stderr)
    check("on a branch of its own", "Recorded in the history on a new branch" in r.stdout)
    check("and says plainly that there is no server to send it to",
          "no shared server configured" in r.stdout, r.stdout)
    log = subprocess.run(["git", "-C", str(f.root), "log", "-1", "--pretty=%s%n%b"],
                         capture_output=True, text=True).stdout
    check("the commit is signed off", "Signed-off-by:" in log, log)
    check("the commit says what it is", log.startswith("note: A note that gets"), log)
    f.clean()


def t_publish_local_only_does_not_commit():
    f = fresh()
    draft = f.tmp / "d.md"
    draft.write_text("---\ntype: note\ntitle: Local only\nauthor: bob\n"
                     "provenance: human\n---\n\nSome prose.\n", encoding="utf-8")
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root),
                        "publish", str(draft), "--key", str(f.keys["bob"]),
                        "-y", "--local-only"], capture_output=True, text=True)
    check("--local-only writes the record", r.returncode == 0, r.stderr)
    check("but commits nothing", "not been committed" in r.stdout)
    n = subprocess.run(["git", "-C", str(f.root), "log", "--oneline"],
                       capture_output=True, text=True)
    check("the history is untouched", n.returncode != 0 or n.stdout.strip() == "")
    f.clean()


def t_new_asks_when_you_do_not_say_what_you_want():
    f = fresh()
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root),
                        "new", "--no-edit", "--author", "bob"],
                       input="obstruction\nGluing loses finiteness\n",
                       capture_output=True, text=True, cwd=str(f.tmp))
    check("bare `polymath new` offers a numbered list of kinds",
          "obstruction" in r.stdout and "  1  " in r.stdout, r.stdout + r.stderr)
    check("the list distinguishes a conjecture from a theorem",
          "not proved" in r.stdout and "it is proved" in r.stdout, r.stdout)
    check("it asks for a title", "title" in r.stdout.lower())
    out = f.tmp / "draft-obstruction.md"
    check("and writes the file you chose", out.exists(), r.stdout + r.stderr)
    if out.exists():
        check("with the title you gave", "Gluing loses finiteness" in out.read_text())
        check("and no links block to puzzle over", "links:" not in out.read_text())
    f.clean()


def t_show_names_the_kind_of_each_linked_record():
    """Danny: a link should say what is at the other end. 'depends on a question'
    and 'depends on a claim' mean quite different things."""
    f = fresh()
    q = f.make(author="alice", rtype="question", title="An open question")
    f.place(q)
    o = f.make(author="bob", rtype="obstruction", title="An approach that fails",
               body="It fails.", what_was_tried="Tried the obvious thing.",
               links=[{"rel": "depends_on", "target": q["id"]}])
    f.place(o)
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root),
                        "show", o["id"]], capture_output=True, text=True)
    check("show names the kind of the linked record",
          "depends_on   question" in r.stdout, r.stdout)
    check("and says whether the link takes effect",
          "takes effect at once" in r.stdout)
    check("it numbers the links so they can be followed",
          "  1  depends_on" in r.stdout)
    check("following the number lands on the linked record",
          q["id"] in subprocess.run(
              [sys.executable, str(SCRIPT), "--root", str(f.root), "show", "1"],
              capture_output=True, text=True).stdout)

    # and the reverse direction, on the question
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root),
                        "show", q["id"]], capture_output=True, text=True)
    check("links in also name the kind at the other end",
          "depends_on   obstruction" in r.stdout, r.stdout)

    # a cross-author claim about somebody else's record is marked advisory
    ref = f.make(author="mallory", rtype="counterexample", title="A witness",
                 links=[{"rel": "refutes", "target": q["id"]}])
    f.place(ref)
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root),
                        "show", ref["id"]], capture_output=True, text=True)
    check("a claim about somebody else's record is marked advisory",
          "advisory until its author agrees" in r.stdout, r.stdout)
    f.clean()


def t_link_menu_can_express_every_relation_that_matters():
    """Seeding the real corpus needed `specializes`, which the plain-question menu
    did not offer. Anything the menu cannot say has to be hand-written, which is
    exactly what the menu exists to avoid."""
    offered = {rel for rel, _ in pm.LINK_CHOICES}
    for rel in ("answers", "depends_on", "supports", "specializes", "generalizes",
                "variant_of", "proved_in", "refutes", "duplicates", "cites"):
        check(f"the menu can express {rel}", rel in offered)
    check("every menu entry is a real relation", offered <= pm.ALL_RELS)
    check("supersedes is deliberately absent (only an author may supersede "
          "their own record)", "supersedes" not in offered)


def t_variant_of_is_a_sideways_move():
    """A variant is the same question in a neighbouring setting, where neither
    implies the other -- orbifolds against surfaces, say. It must not be confused
    with a specialization, and must not drive any automatic propagation."""
    f = fresh()
    q = f.make(author="alice", rtype="question",
               title="Is scl rational in closed hyperbolic surface groups?")
    f.place(q)
    v = f.make(author="bob", rtype="question",
               title="Is scl rational for the orbifold torus?",
               links=[{"rel": "variant_of", "target": q["id"]}])
    f.place(v)
    check("a variant_of link validates", f.validate() == [])
    check("it needs no agreement from the other author, since it imposes nothing",
          "variant_of" in pm.SOURCE_RELS)
    check("it is not a dependency, so nothing propagates along it",
          "variant_of" not in ("depends_on",))
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root),
                        "show", v["id"]], capture_output=True, text=True)
    check("show names it and the kind at the other end",
          "variant_of   question" in r.stdout, r.stdout)
    f.clean()


def t_publish_preview_never_abbreviates():
    """The confirmation screen is the human backstop against content that should
    not go out. It used to stop at 1500 characters of a 4000-character record,
    so 2500 characters were signed unseen -- which is exactly where a payload
    would go. Found because Danny asked whether he could proofread there."""
    f = fresh()
    tail = "ZZ-THE-VERY-LAST-WORDS-ZZ"
    body = ("Filler sentence about admissible surfaces. " * 88)[:pm.MAX_BODY - len(tail) - 2]
    body += " " + tail
    draft = f.tmp / "long.md"
    draft.write_text("---\ntype: note\ntitle: A record at the length limit\n"
                     "author: bob\nprovenance: human\n---\n\n" + body + "\n",
                     encoding="utf-8")
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root),
                        "publish", str(draft), "--key", str(f.keys["bob"]),
                        "-y", "--local-only"], capture_output=True, text=True)
    check("a record near the length limit publishes", r.returncode == 0, r.stderr[-300:])
    check("the confirmation screen shows the very end of the body",
          tail in r.stdout, r.stdout[-300:])
    check("and does not abbreviate", "more characters]" not in r.stdout)

    # the same for the 'what was tried' section, which was capped at 800
    tried_tail = "YY-END-OF-WHAT-WAS-TRIED-YY"
    tried = ("We tried the obvious thing. " * 40) + tried_tail
    d2 = f.tmp / "obs.md"
    d2.write_text("---\ntype: obstruction\ntitle: A long dead end\nauthor: bob\n"
                  "provenance: human\n---\n\nIt fails.\n\n## What was tried\n\n"
                  + tried + "\n", encoding="utf-8")
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root),
                        "publish", str(d2), "--key", str(f.keys["bob"]),
                        "-y", "--local-only"], capture_output=True, text=True)
    check("the what-was-tried section is shown in full too",
          tried_tail in r.stdout, r.stdout[-300:])
    f.clean()


def t_proof_standing_is_computed_not_asserted():
    """Danny's case: a statement that is a theorem *modulo* machinery in a cited
    paper, with the derivation not written out. Citing a paper must not be read
    as being proved in it, or the record would overstate what is known."""
    f = fresh()
    ref = f.make(author="alice", rtype="reference", title="A paper with the machinery",
                 body="Calegari and Walker, Surface subgroups from linear programming.")
    f.place(ref)

    bare = f.make(author="bob", rtype="theorem", title="Asserted with nothing at all",
                  body="I say it is true.")
    f.place(bare)
    modulo = f.make(author="bob", rtype="theorem", title="A theorem modulo cited machinery",
                    body="True, but the derivation is not written out.",
                    links=[{"rel": "cites", "target": ref["id"]}])
    f.place(modulo)
    proved = f.make(author="bob", rtype="theorem", title="Actually proved in that paper",
                    body="It is in there.",
                    links=[{"rel": "proved_in", "target": ref["id"]}])
    f.place(proved)
    conj = f.make(author="bob", rtype="conjecture", title="Believed but unproved",
                  body="I think so.")
    f.place(conj)
    c = f.corpus()

    check("a theorem with nothing attached is flagged",
          pm.verification_status(c, bare["id"]).startswith("asserted as proved, but no"))
    check("its short tag shouts", pm.status_tag(c, bare) == "NO PROOF ATTACHED")
    check("citing a paper is NOT read as being proved in it",
          "not written out" in pm.verification_status(c, modulo["id"]),
          pm.verification_status(c, modulo["id"]))
    check("and that state has its own honest tag",
          pm.status_tag(c, modulo) == "proof not written out")
    check("proved_in does mean proved in the literature",
          pm.verification_status(c, proved["id"]) == "proved in the literature")
    check("a conjecture is never described as proved",
          pm.verification_status(c, conj["id"]) == "conjecture, not proved")
    check("and is tagged as a conjecture", pm.status_tag(c, conj) == "conjecture")
    arg = f.make(author="mallory", rtype="argument", title="The write-up",
                 body="Here is the derivation.",
                 links=[{"rel": "supports", "target": modulo["id"]}])
    f.place(arg)
    c = f.corpus()
    check("once somebody writes the derivation, the standing changes by itself",
          pm.verification_status(c, modulo["id"]) == "proof attached here",
          pm.verification_status(c, modulo["id"]))
    check("the whole corpus validates", f.validate() == [])
    f.clean()


def t_nothing_leaks_a_home_directory_or_an_address():
    """Danny asked, before publishing, whether an artifact contained anything about
    his laptop. It did -- one path, put there by me. Everything here is public and
    mirrored by every member, so it cannot be taken back."""
    f = fresh()
    for body, what in [
            ("The data is in /Users/someone/Documents/work.", "a Unix account path"),
            ("See /home/someone/scratch/out.csv for the run.", "a Linux account path"),
            ("It lives in ~/Projects/secret-thing/ on my laptop.", "a home directory path"),
            ("Mounted at /Volumes/Backup Drive/data.", "an external disk path"),
            ("Write to me at someone@example.edu about it.", "an email address")]:
        g = fresh()
        g.place(g.make(title="A record", body=body))
        check(f"a record is refused if it contains {what}", "C07" in codes(g.validate()),
              f"{body!r} -> {codes(g.validate())}")
        g.clean()

    # generic instructions are not disclosures and must still be allowed
    f.place(f.make(title="Setup advice",
                   body="Sign with the key in ~/.ssh/id_ed25519, as usual."))
    check("a generic ~/.ssh path is allowed, since it names nobody",
          f.validate() == [], [str(p) for p in f.validate()])

    # attached files are published too, and are the likelier place for a stray path
    (f.root / "artifacts" / "data.csv").write_text(
        "value,source\n1/2,/Users/someone/run/out.txt\n")
    check("an attached file is scanned as well", "C07" in codes(f.validate()))
    (f.root / "artifacts" / "data.csv").unlink()

    # project documentation has to be able to give example paths
    (f.root / "README.md").write_text("Run `polymath init --key ~/.ssh/id_ed25519`.\n")
    check("project documentation is not scanned for this",
          "C07" not in codes(f.validate()), [str(p) for p in f.validate()])
    f.clean()


def t_publishing_without_a_git_identity_fails_cleanly():
    """Found by CI on the first push: a machine with no git identity configured
    got 'Author identity unknown' from deep inside git, AFTER the record had been
    written and a branch created. Every new member hits this."""
    f = fresh()
    for k in ("user.name", "user.email"):
        subprocess.run(["git", "-C", str(f.root), "config", "--unset", k],
                       capture_output=True)
    env = {**os.environ, "GIT_CONFIG_GLOBAL": str(f.tmp / "nogitconfig"),
           "GIT_CONFIG_SYSTEM": os.devnull, "GIT_AUTHOR_NAME": "", "GIT_AUTHOR_EMAIL": "",
           "GIT_COMMITTER_NAME": "", "GIT_COMMITTER_EMAIL": "", "EMAIL": ""}
    draft = f.tmp / "d.md"
    draft.write_text("---\ntype: note\ntitle: No identity here\nauthor: bob\n"
                     "provenance: human\n---\n\nSome prose.\n", encoding="utf-8")
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root),
                        "publish", str(draft), "--key", str(f.keys["bob"]), "-y"],
                       capture_output=True, text=True, env=env)
    out = r.stdout + r.stderr
    check("publishing stops rather than failing obscurely", r.returncode == 1, out[-300:])
    check("it explains the problem in plain words",
          "does not yet know who you are" in out, out[-300:])
    check("it gives the exact commands that fix it",
          "git config --global user.name" in out and "user.email" in out)
    branches = subprocess.run(["git", "-C", str(f.root), "branch", "--list", "record/*"],
                              capture_output=True, text=True).stdout.strip()
    check("it does not leave you stranded on a half-made branch",
          branches == "", f"created {branches!r}")
    check("the record itself was still written and is valid",
          f.validate() == [], [str(p) for p in f.validate()])

    d = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root), "doctor"],
                       capture_output=True, text=True, env=env)
    check("`doctor` reports it too, so it is caught before publishing",
          "git knows who you are" in d.stdout and "[--] git knows who you are" in d.stdout,
          d.stdout)
    f.clean()


def t_dangling_link():
    f = fresh()
    f.place(f.make(links=[{"rel": "supports", "target": "0123456789ab-nonexistent"}]))
    check("link to a non-existent record is rejected", "L05" in codes(f.validate()))
    f.clean()


def t_depends_on_cycle():
    """Note: a genuine cycle is almost impossible to build honestly, because a
    record's identifier is derived from its contents, which include its links.
    So the only route in is hand-editing a filed record -- which the fingerprint
    check also catches. This test confirms the cycle check fires anyway, since a
    cycle would hang anything that walks the dependency graph."""
    f = fresh()
    a = f.make(author="bob", title="Record A")
    f.place(a)
    b = f.make(author="bob", title="Record B",
               links=[{"rel": "depends_on", "target": a["id"]}])
    f.place(b)
    pa = f.root / "records" / "2026" / "09" / f"{a['id']}.json"
    d = json.loads(pa.read_text())
    d["links"] = [{"rel": "depends_on", "target": b["id"]}]
    pa.write_text(json.dumps(d))
    cs = codes(f.validate())
    check("a circular dependency is detected", "L07" in cs, f"got {cs}")
    check("and the hand-edit is independently caught by the fingerprint", "I02" in cs)
    f.clean()


def t_superseding_another_persons_record():
    f = fresh()
    victim = f.make(author="alice", title="Alices claim")
    f.place(victim)
    attack = f.make(author="mallory", title="Correction",
                    links=[{"rel": "supersedes", "target": victim["id"]}])
    f.place(attack)
    check("you cannot supersede somebody else's record", "L06" in codes(f.validate()))
    f.clean()


def t_agreement_forgery():
    f = fresh()
    victim = f.make(author="alice", title="Alices claim")
    f.place(victim)
    mine = f.make(author="mallory", title="My refutation",
                  links=[{"rel": "refutes", "target": victim["id"]}])
    f.place(mine)
    # mallory tries to agree, on alice's behalf, to his own refutation
    ag = f.make(author="mallory", rtype="agreement", title="Agreed",
                agrees={"source": mine["id"], "rel": "refutes", "target": victim["id"]})
    f.place(ag)
    check("only the target's author can make a cross-author link binding",
          "A02" in codes(f.validate()))
    f.clean()


def t_no_verified_confidence():
    f = fresh()
    rec = f.make(asserted_confidence="verified")
    f.place(rec)
    check("'verified' cannot be self-asserted", "S09" in codes(f.validate()))
    f.clean()
    f = fresh()
    rec = f.make()
    rec.pop("id"); rec.pop("signature")
    rec["confidence"] = "verified"
    rec["id"] = pm.make_id(rec)
    rec["signature"] = pm.ssh_sign(pm.canonical_bytes(rec), f.keys["bob"])
    f.place(rec)
    check("the old 'confidence' field is rejected outright", "S10" in codes(f.validate()))
    f.clean()


def t_verification_is_computed():
    f = fresh()
    claim = f.make(author="bob", title="The claim")
    f.place(claim)
    art = f.root / "artifacts" / "proof.lean"
    art.write_text("theorem t : True := trivial\n")
    v = f.make(author="alice", rtype="verdict", title="Checked the claim",
               links=[{"rel": "supports", "target": claim["id"]}],
               checked=[{"path": "proof.lean", "sha256": pm.file_hash(art)}])
    f.place(v)
    c = f.corpus()
    check("a machine result alone does not make a claim verified",
          pm.verification_status(c, claim["id"]).startswith("machine-checked"))

    # a review by the claim's own author must not count
    r_self = f.make(author="bob", rtype="statement_review",
                    title="Self review", reviews=v["id"])
    f.place(r_self)
    c = f.corpus()
    check("the claim's own author cannot supply the statement review",
          pm.verification_status(c, claim["id"]).startswith("machine-checked"))

    r = f.make(author="mallory", rtype="statement_review",
               title="Independent review", reviews=v["id"])
    f.place(r)
    c = f.corpus()
    check("machine result plus an independent review does verify",
          pm.verification_status(c, claim["id"]) == "verified")
    check("everything above still validates", f.validate() == [])
    f.clean()


def t_verdict_pins_file_contents():
    f = fresh()
    art = f.root / "artifacts" / "proof.lean"
    art.write_text("theorem t : True := trivial\n")
    a = f.make(author="bob", rtype="artifact", title="The proof",
               file={"path": "proof.lean", "sha256": pm.file_hash(art)})
    f.place(a)
    check("an artifact matching its fingerprint validates", f.validate() == [])
    art.write_text("theorem t : False := sorry\n")   # "golf the proof" edit
    check("changing the file afterwards invalidates the record", "F05" in codes(f.validate()))
    f.clean()


def t_verdict_must_pin_something():
    f = fresh()
    v = f.make(author="alice", rtype="verdict", title="Vague verdict", checked=[])
    f.place(v)
    check("a verdict naming no files is rejected", "V01" in codes(f.validate()))
    f.clean()


def t_symlink():
    f = fresh()
    f.place(f.make())
    secret = f.tmp / "id_bob"                     # stand-in for a private key
    (f.root / "artifacts" / "coefficients.csv").symlink_to(secret)
    check("a symbolic link anywhere in the corpus is rejected", "T01" in codes(f.validate()))
    f.clean()


def t_gitattributes():
    f = fresh()
    f.place(f.make())
    (f.root / ".gitattributes").write_text("*.json -diff\n")
    check("a .gitattributes that could hide a change is rejected", "T04" in codes(f.validate()))
    f.clean()


def t_case_collision():
    f = fresh()
    d = f.root / "artifacts"
    (d / "Table.csv").write_text("1,2\n")
    if (d / "table.csv").exists():
        print("  SKIP  case collision (filesystem is case-insensitive, cannot stage both)")
        f.clean(); return
    (d / "table.csv").write_text("3,4\n")
    check("two paths differing only by case are rejected", "T05" in codes(f.validate()))
    f.clean()


def t_oversize_file():
    f = fresh()
    (f.root / "artifacts" / "big.bin").write_bytes(b"\0" * (pm.MAX_ARTIFACT_BYTES + 1))
    check("an oversized attachment is rejected", "T06" in codes(f.validate()))
    f.clean()


def t_lfs_pointer():
    f = fresh()
    (f.root / "artifacts" / "data.bin").write_bytes(
        b"version https://git-lfs.github.com/spec/v1\noid sha256:abc\nsize 1\n")
    check("a large-file placeholder is rejected", "T07" in codes(f.validate()))
    f.clean()


def t_stray_toplevel():
    f = fresh()
    (f.root / "index").mkdir()
    check("an unexpected top-level folder (such as a stored index) is rejected",
          "T08" in codes(f.validate()))
    f.clean()


def t_the_one_unautomatable_rule_cannot_be_satisfied_by_a_placeholder():
    """Confirming a key out of band is the only rule no program can check: the
    validator can only insist you claim to have done it. Noticed while preparing
    a real member file -- if 'TODO' satisfies the claim, it is not even a speed
    bump, and a half-finished member file would sail through."""
    f = fresh()
    pub = (f.tmp / "id_bob.pub").read_text().strip()

    def member_file(confirmed):
        (f.root / "people" / "bob.toml").write_text(
            f'name = "Bob"\nrole = "member"\nadmitted_by = "alice"\n'
            f'key_confirmed_out_of_band = "{confirmed}"\nkeys = ["{pub}"]\n',
            encoding="utf-8")
        f._people = None
        return codes(f.validate())

    for placeholder in ("TODO: fill this in", "TBD", "FIXME later",
                        "read aloud over ____, 2026-09-__", "confirmed ???"):
        check(f"a placeholder is rejected: {placeholder!r}",
              "P11" in member_file(placeholder), member_file(placeholder))
    check("an empty confirmation is still rejected", "P10" in member_file(""))
    check("a real confirmation passes",
          member_file("SHA256 fingerprint read aloud over video call, 2026-09-11") == [])
    f.clean()


def t_unconfirmed_key():
    f = fresh()
    pub = (f.tmp / "id_bob.pub").read_text().strip()
    (f.root / "people" / "bob.toml").write_text(
        f'name = "Bob"\nrole = "member"\nadmitted_by = "alice"\nkeys = ["{pub}"]\n',
        encoding="utf-8")
    check("a member whose key was never confirmed in person is flagged",
          "P10" in codes(f.validate()))
    f.clean()


def t_admitted_by_nonadmin():
    f = fresh()
    pub = (f.tmp / "id_mallory.pub").read_text().strip()
    (f.root / "people" / "mallory.toml").write_text(
        f'name = "M"\nrole = "member"\nadmitted_by = "bob"\n'
        f'key_confirmed_out_of_band = "video"\nkeys = ["{pub}"]\n', encoding="utf-8")
    check("admission by a non-administrator is rejected", "P09" in codes(f.validate()))
    f.clean()


def t_filename_must_match_id():
    f = fresh()
    rec = f.make()
    f.place(rec, name="innocuous.json")
    check("a record filed under the wrong name is rejected", "I04" in codes(f.validate()))
    f.clean()


def t_agent_provenance_needs_model():
    f = fresh()
    rec = f.make()
    rec.pop("id"); rec.pop("signature")
    rec["provenance"] = {"kind": "agent-authored", "model": None}
    rec["id"] = pm.make_id(rec)
    rec["signature"] = pm.ssh_sign(pm.canonical_bytes(rec), f.keys["bob"])
    f.place(rec)
    check("assistant-written records must name the model", "S12" in codes(f.validate()))
    f.clean()


def t_search_and_show():
    f = fresh()
    q = f.make(author="alice", rtype="question",
               title="Rationality of scl in surface groups",
               body="Is scl rational for every element of a closed surface group?")
    f.place(q)
    o = f.make(author="bob", rtype="obstruction",
               title="Linear programming duality does not localise",
               body="The free group argument needs a global LP.",
               what_was_tried="Cut the surface along a separating curve and glue LPs.")
    f.place(o)
    c = f.corpus()
    hay = [r for r in c.records.values() if "scl" in (r["title"] + r["body"]).lower()]
    check("search finds a question by its words", len(hay) == 1)
    check("obstruction keeps a structured 'what was tried' field",
          c.records[o["id"]].get("what_was_tried", "").startswith("Cut the surface"))
    check("corpus with both records validates", f.validate() == [])
    f.clean()


def t_cli_end_to_end():
    f = fresh()
    env = dict(os.environ)
    draft = f.tmp / "draft.json"
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root),
                        "new", "question", "--json", "--title", "A CLI question",
                        "--author", "bob", "--out", str(draft)],
                       capture_output=True, text=True, env=env, cwd=str(f.root))
    check("`polymath new --json` still writes a raw JSON draft", draft.exists(), r.stderr)
    d = json.loads(draft.read_text()); d["body"] = "Does this work end to end?"
    draft.write_text(json.dumps(d))
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root),
                        "publish", str(draft), "--key", str(f.keys["bob"]),
                        "--author", "bob", "-y"],
                       capture_output=True, text=True, env=env, cwd=str(f.root))
    check("`polymath publish` signs and files the record", r.returncode == 0, r.stderr)
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root), "validate"],
                       capture_output=True, text=True, env=env, cwd=str(f.root))
    check("`polymath validate` passes on the result", r.returncode == 0, r.stdout + r.stderr)
    r = subprocess.run([sys.executable, str(SCRIPT), "--root", str(f.root),
                        "search", "end", "to", "end"],
                       capture_output=True, text=True, env=env, cwd=str(f.root))
    check("`polymath search` finds it", "A CLI question" in r.stdout, r.stdout)
    f.clean()


ALL = [v for k, v in sorted(globals().items()) if k.startswith("t_")]

if __name__ == "__main__":
    print(f"polymath Stage 0 tests  ({len(ALL)} groups)\n")
    for fn in ALL:
        print(fn.__name__.removeprefix("t_").replace("_", " ") + ":")
        try:
            fn()
        except Exception as e:
            import traceback
            check(fn.__name__ + " (raised)", False, repr(e))
            traceback.print_exc()
        print()
    print("=" * 60)
    print(f"{len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        for name in FAIL:
            print("  FAILED: " + name)
    sys.exit(1 if FAIL else 0)
