# A shared record for a collaboration on scl

This describes what the project is and how it operates. For the practical steps to get
started, see [setup.md](setup.md).

## What this is

An experiment in running a large mathematical collaboration on a permanent, public,
cryptographically signed record, with both people and AI assistants contributing, and
everything anybody contributes kept and attributed.

The mathematics is the rationality of stable commutator length in closed surface groups,
and in hyperbolic groups more generally; with, as a side project, the scl spectrum in free
groups and the construction of explicit extremal quasimorphisms certifying particular
values.

The intended scale is roughly half a dozen senior people and twenty to forty graduate
students and postdocs.

## Why build anything at all

The original Polymath projects worked mathematically and failed navigationally: the content
ended up buried in long blog comment threads, and people repeatedly redid each other's work
because there was no way to find out what had already been tried.

So the software has one measurable goal, and everything else is subordinate to it:

> A member should be able to find out, in under a minute, whether what they are about to
> try has already been tried.

## How it works in practice

The unit of contribution is not a conversation transcript -- forty people for a year
produce more of those than anyone can read. It is a short, typed, structured note, written
deliberately at the end of a session. Run `polymath list` to see the kinds, and
`polymath tutorial` to see the whole cycle.

Three features are worth singling out, because they are what makes this different from a
wiki or a shared folder.

**Dead ends are first-class.** An `obstruction` record says what was tried and why it
failed, with "what was tried" as its own searchable section. Negative results are what stop
forty people walking into the same wall, and they are exactly what collaborations fail to
write down.

**Nobody can vouch for their own work.** There is no "verified" setting anyone can write.
Whether something is proved is carried by the record type -- `conjecture` against `theorem`
-- because being proved is categorical rather than a matter of degree. What *backs* that up
is then computed from what points at it: a machine check together with an independent human
attestation that the formal statement says what the informal claim says, a cited reference
linked with `proved_in`, an attached `argument`, or nothing at all, in which case it
displays as `NO PROOF ATTACHED`.

**Every record is signed by its author**, over its own contents, and checked without
reference to git or GitHub at all. That signature survives the host being compromised, an
administrator going bad, or the project moving elsewhere.

Contributions land through pull requests, and every one needs an approval from somebody
other than its author.

## What already exists

A command-line client (Python, needing nothing that is not already on a Mac or Linux
machine), and a seed corpus covering: the two top-level questions and their test cases; the
known reduction when a chain misses a simple essential curve; the standard cut-and-glue
approach and the winding obstruction that defeats it; the eventual-linearity idea that
might tame it; and, for the spectrum side, the conjecture that 3/4 is the first accumulation
point from either side, with the supporting computation attached as data.

There is deliberately **no AI component in what has been built so far.** The first stage is
the record format and the discipline of writing records by hand. The question it exists to
answer is whether mathematicians will actually do that. If the discipline is not bearable,
adding AI assistance does not rescue it -- it only fills the record with unread text faster.
Assisted reading, drafting, checking and cross-session synthesis are designed but unbuilt,
and should not be built until the first question is answered.

## Principles

- Everything is public, permanently, and mirrored by everyone who clones it. Nothing can be
  retracted.
- Mathematical output is public domain: CC0 for prose and records, Apache 2.0 for Lean and
  other code, with the contributor named as author -- the same licence as Mathlib, so that
  results can be contributed upstream rather than stranded. Both texts are in `LICENSES/`.
- Records say whether they were written by a person, with an assistant's help, or by an
  assistant, and which model.
- Senior participants commit to advancing the careers of junior ones in proportion to their
  contributions. The software's job is to make the evidence complete and legible -- who
  first stated what, whose work was built on -- and explicitly **not** to compute a score.
  Any single number is gamed immediately, and with AI assistance the cost of producing
  plausible volume is near zero.

## What is asked of members

Write records. Search before you work. Write down dead ends. Review other people's
proposals at whatever rate is sustainable. Say where the tooling confuses you.

**Administrators** additionally admit new members, which includes confirming their public
key out of band (see [setup.md](setup.md) step 4), and are the second approver on the things
that must not change unilaterally: the membership list, the automatic checks, and the Lean
build configuration.

## Things to weigh, stated plainly

**The central security problem is unsolved, by anyone.** The whole point of the system is
that an assistant on your machine reads text other people wrote, and there is no reliable
way for a language model to distinguish "here is the problem" from "here is an instruction
aimed at you". The design mitigates this by giving reading sessions no ability to act, by
ensuring nothing an assistant produces enters the record without a named person putting
their name to it, and by keeping everything public so that misuse is visible. That is
**detection rather than prevention**, and it is stated as such rather than glossed.

**The obscurity of the mathematics is not protection.** Forty academic laptops running AI
assistants are worth attacking regardless of what is computed on them.

**The human review steps are the weakest link**, and the design says so: two cooperating
people can produce a false "verified", and reviewers under load rubber-stamp.

**The design was adversarially reviewed twice**, by independent agents instructed to attack
it rather than approve it. They found six critical flaws each. Everything is either fixed or
labelled honestly as unfixed. Ask if you would like the reports; they are not in this
repository.

**It may not work.** The first stage is a short trial with a handful of people to find out
whether the record discipline is bearable at all. A reasonable outcome is that it is not,
and that we learn something from the attempt.

## What is not decided

The tally rule for prioritising work; limits on how much any one person may post; how the
client is distributed and updated once it is more than a single script in this repository;
and whether the corpus should eventually host more than this one project.

Views welcome, particularly on the record types -- the vocabulary has already changed
several times in response to real content, and will change again. Findings about how the
project itself runs have their own place in the corpus; search for "how this project runs".
