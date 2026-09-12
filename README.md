# polymath — Stage 0

A shared, permanently public, signed record of a mathematical collaboration.

**Stage 0 has no AI component in it at all.** It is the record format, the
signatures, the checking, and enough search to answer the one question the whole
project exists to answer:

> Has somebody already tried this?

The point of building this first, before any assistant tooling, is to find out
whether mathematicians will actually write these notes by hand. If the discipline
is too tedious to sustain, adding AI assistance does not rescue it — it just fills
the record with unread text faster. Two independent security reviews of the design
both concluded that this stage was the right thing to build first, and that nearly
every problem they found lives in machinery this stage does not include.

Design, and the reviews that shaped it, are in the folder above:
`polymath_design_v3.md`, `red_team_1.md`, `red_team_2.md`.

## What you need

Python 3.11 or newer, `git`, and `ssh-keygen`. All three are already on any Mac or
Linux machine. There is nothing to install — no libraries, no accounts, no server.

Signatures use your **SSH key**, the same one you use with GitHub, rather than the
older and much fiddlier PGP system.

## Start here

**New to the project?** Read [onboarding/README.md](onboarding/README.md) for what this is
and how it operates, and [onboarding/setup.md](onboarding/setup.md) for the practical steps.
Then:


```bash
python3 polymath tutorial
```

A guided walk through a first session, in a throwaway sandbox with throwaway
keys. It builds its own little corpus, so you can publish nonsense, break things
on purpose, and see what the checks say — nothing you do in it touches the real
record. Eight steps, a few minutes. Do this before anything else.

## Setting yourself up

```bash
git clone https://github.com/polymath-scl/corpus.git
cd corpus
git config core.symlinks false          # explained below
python3 polymath init --handle yourname --key ~/.ssh/id_ed25519
python3 polymath doctor
```

An administrator then adds `people/yourname.toml` with your public key — see
`people/TEMPLATE.toml.example`. That key must be confirmed **out of band**: in
person, over video, or against your institutional web page. This is the one step
that cannot be automated, and it is what stops somebody adding a key that is not
yours.

## Where this lives, and the settings that matter

The corpus is `github.com/polymath-scl/corpus`, in an organisation rather than
under one person's account. That is not cosmetic: several rules in the design
need more than one owner (the two-approval rule on membership and on the checks
themselves), need teams (`CODEOWNERS`), and need the project to outlive any one
person's login.

These repository settings are load-bearing, and several are **off by default**:

- **Squash merging and rebase merging switched off.** Both discard your commit and
  create a new one signed by GitHub, which would leave "signed" attesting GitHub
  rather than you. Merge commits keep your signature.
- **A pull request with one approval required**, and review from code owners
  required on the protected paths.
- **Stale approvals dismissed when new commits arrive.** Off by default. Without
  it, somebody can get approval for something harmless and then substitute
  something else.
- **The `validate` check required to pass.**
- **Administrators cannot bypass any of the above.** Also off by default, and a
  rule an administrator can step over is not a rule.
- **Two-factor authentication required** for everyone in the organisation.

Independently of all of this, every record carries its own signature over its own
contents, which `polymath validate` checks without reference to git at all. That is
what survives GitHub being compromised, an administrator going bad, or the project
moving somewhere else.

## Using it

```bash
python3 polymath search scl rational        # has this been tried?
python3 polymath list                       # or just see everything
python3 polymath browse                     # or click through it in a browser
python3 polymath show 3                     # the third thing you were shown
python3 polymath graph 3                    # what it rests on

python3 polymath new                        # asks what kind, and for a title
$EDITOR draft-obstruction.md                # it opens this for you anyway
python3 polymath publish draft-obstruction.md

python3 polymath sync                       # get everyone else's work
python3 polymath validate                   # run every rule locally
python3 polymath doctor                     # check your setup
```

**You never have to type a record's identifier.** Every command that lists
records numbers them, and the number is a handle: after a `search` or a `list`,
`polymath show 3` opens the third one. A few leading characters of an identifier
work too.

### Searching

Words are matched **whole**, so `lp` will not find "help" — pass `--substring`
if you want it to. Quote several words to search for a phrase, and the phrase
still matches when the prose happens to wrap between them. Several bare words
find records containing *any* of them, but records containing *all* of them come
first. **Regular expressions are not supported**; `scl.*rational` is matched
literally. Titles, bodies and "what was tried" sections are searched.

When nothing matches, use `list` or `browse` rather than guessing more words.

### Writing a record

`polymath new` asks what kind of record you want and what to call it, writes the
file, and opens it in your editor. You get a header that is already filled in —
ignore it — and prose sections with `REPLACE THIS` paragraphs to write over.
Plain prose is all that is needed: no formatting, nothing to escape. `publish`
refuses a draft that still contains a placeholder, so a half-finished one cannot
go out by accident.

```markdown
---
type: obstruction
title: Gluing linear programs along a separating curve loses finiteness
author: yourname
provenance: human
#
# Everything above was written for you. You can ignore it.
# Below the second line of dashes, replace each REPLACE THIS paragraph
# with your own words. Leave the ## headings alone.
#
---

## What goes wrong

The two factor polyhedra are finite-sided, but matching the boundary data is an
equality condition, and imposing it introduces infinitely many faces.

## What was tried

Split along a separating simple closed curve, set up the linear program for each
factor separately, and impose matching of boundary winding numbers.
```

The `## What was tried` heading is the one piece of formatting that matters: it
becomes a separate searchable section, and it is what stops the next person
repeating you.

Nothing in the file says how the record connects to others. You are **asked**
that when you publish, in plain questions — you never type an identifier or pick
from a list of relation names.

### Publishing

`polymath publish` does the whole thing: asks what this connects to, shows you
exactly what is about to become public and permanent under your name, waits for
you to confirm, signs it, records it in the history on its own branch, sends it
to the shared server, and opens your browser at a **pull request** — a proposal
that somebody other than you reads and agrees to before it joins the shared
record. You type no git commands.

If there is no shared server configured, it stops after recording it on your
machine and says so. `--local-only` stops even earlier.

To see the whole thing working on a worked example from the pilot problem:

```bash
python3 tests/demo.py
```

## What a record is

A short, deliberate note written at the end of a session — not a transcript. Raw
conversations are kept as attachments and are not routinely read by anything,
because forty people for a year produce more of them than anybody can read.

Twelve types: `question`, `conjecture`, `theorem`, `argument`, `obstruction`,
`counterexample`, `artifact`, `note`, `reference`, `verdict`, `statement_review`,
`vote`, plus `agreement` (below).

**There is no `claim` type, deliberately.** Whether something is proved is not a
matter of degree, so it is carried by the type: a `conjecture` is believed and
unproved, a `theorem` is proved here or in the literature. ("Claim" was rejected
as a name because in mathematical writing it is what you write immediately
*before* proving something.)

`obstruction` — an approach that fails, and why — matters more than it looks. Dead
ends are what stop forty people walking into the same wall, and they are exactly
what collaborative projects fail to write down. It carries a structured
"what was tried" field so that "several people hit this same wall" is findable.

Records are **never edited**. A correction is a new record that supersedes the old
one, and only its own author may supersede it. Everything stays in the history.

**Bodies are capped at 4000 characters.** This is deliberate: it forces the
distillation that makes the record searchable. Longer material becomes an
attachment with a record pointing at it.

## Two things that are easy to get wrong

**You cannot call your own work verified.** There is no `verified` setting. What
backs a `theorem` or `conjecture` is *computed* from what points at it — a machine
`verdict` together with a `statement_review` signed by somebody other than you, a
cited `reference`, an `argument` record, or nothing at all. A `theorem` with
nothing attached displays as `NO PROOF ATTACHED`, because at that point nothing
distinguishes it from a conjecture except your say-so.

The `statement_review` requirement exists because a flawless proof of a statement
that says nothing is still a flawless proof: define a term to mean something
trivial, or add a hypothesis that can never hold, and the machine will be
perfectly happy.

**You cannot make an assertion about somebody else's record binding on your own.**
Links like `depends_on` and `cites` live in your record and describe your record,
so they take effect immediately. Links like `refutes` and `duplicates` are
assertions about *their* record: they are visible and searchable, but nothing automatic acts
on them until that person publishes an `agreement`.

## The rules, and where they are enforced

Run `python3 polymath validate` to check your copy. **The same code runs
automatically on every proposed change, and that run is the authority** — because
using this program is optional, and a correctly signed contribution submitted with
ordinary git tools looks identical to one this program produced. Anything this
program does that the automatic check cannot re-verify afterwards is a convenience
for honest members, not a control. That includes the review screen before you
publish, so read it properly.

Every rule below exists because a security review found a specific attack.

- Identifiers are fingerprints of the contents, so any later alteration shows up.
- Every record carries its own signature over its own contents, checked without
  reference to git at all. That is the durable protection: it survives GitHub being
  compromised, an administrator going bad, or the project moving elsewhere.
- No symbolic links anywhere. A link can point at a file outside the project — your
  private key, say — and turn an innocent read into a theft.
- No invisible control characters, no text-direction overrides, no raw HTML, no
  images loaded from other people's websites. Group presentations like `<a,b | a^2>`
  are fine; that distinction is tested.
- Attachments are pinned by fingerprint, so a "tidying up" change cannot quietly
  alter a file that something already vouched for.
- `git config core.symlinks false` tells git never to create such a pointer on
  your machine even if one somehow gets into the record; it writes a harmless
  plain text file instead. You want this on, it costs you nothing, and
  `polymath doctor` checks it and explains it if it is missing.

## One thing no program can do for you

**Do not open a corpus Lean file in an editor with Lean support running.** Lean's
build configuration is itself a Lean program, so opening a file from someone else's
project runs their code on your machine. Read them as text.

And treat anything an assistant drafted as potentially influenced by text somebody
else wrote — that is the central unsolved security problem of this whole project,
and there is no filter for it. Read your own drafts as if a stranger wrote them.

## Tests

```bash
python3 tests/test_polymath.py
```

144 checks. Most are attacks drawn from the two security reviews; the rest
come from a first-time user walking through the tutorial and saying where it
lost him.
