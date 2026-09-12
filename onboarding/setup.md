# Getting set up — four things, about fifteen minutes

They need to happen roughly in this order. The first one will bite you if you skip it.

## 1. Two-factor authentication — before you accept the invitation

The organisation requires *secure* two-factor authentication, and GitHub will not let you
accept the invitation until your account complies. If you are currently using SMS, the
invitation will simply appear not to work, without telling you why.

At **github.com/settings/security**, under Two-factor authentication:

- Add a **passkey** (Touch ID, if you are on a Mac — about ten seconds) or an
  **authenticator app** (1Password, Authy, Google Authenticator, or the Passwords app
  built into macOS and iOS).
- Ideally add **both**, so that losing one device does not lock you out.
- Then remove SMS if you have it. GitHub will not let you remove your last method, so do
  this last.
- **Download the recovery codes** and keep them somewhere durable.

SMS two-factor is defeated by SIM-swapping — persuading a phone carrier to move your
number to another SIM — which is cheap and common. This is worth doing for your own sake
regardless of the project.

## 2. Accept the invitation

At **github.com/polymath-scl** — the invitation should be waiting.

## 3. Send whoever invited you an SSH public key

This is what signs your contributions. Every record in the corpus carries a signature over
its own contents, so that anyone can check who wrote it and that nothing has been altered
since. Signatures are checked without reference to GitHub at all, which is what makes the
record survive the host being compromised or the project moving elsewhere.

Do you already have a key?

    ls ~/.ssh/id_ed25519.pub

If that prints a filename, you have one. If not:

    ssh-keygen -t ed25519 -C "your-name"

(press Enter at every prompt — the defaults are right).

Then send the contents of the **public** file, which is safe to email:

    cat ~/.ssh/id_ed25519.pub

Never send the other file, `~/.ssh/id_ed25519` with no extension. That one is private and
never leaves your machine.

## 4. A two-minute call to confirm the key

Before your key is added, it has to be checked over a channel *different* from the one that
delivered it. The attack this prevents is mundane and real: somebody intercepts the email
and substitutes their own key, and from then on everything they sign is attributed to you,
with a perfectly valid signature.

So run this, and read the result out over video or a phone call:

    ssh-keygen -lf ~/.ssh/id_ed25519.pub

It prints something like

    256 SHA256:SNE3qKzUYM6Bo1Vdq19jyyYhy8r3F1N7K8p3YdMhDI0 (ED25519)

and you compare the `SHA256:` string character by character. Read *yours* to *them* rather
than the other way round: if a key had been substituted in transit, hearing somebody read
the substituted fingerprint gives you nothing to disagree with.

Note that the trailing comment on a key is only a label and is not part of the key — the
fingerprint is identical with or without it — so do not be surprised if the comment is
changed before your key is committed. This file is published permanently, so a personal
email address in that position is usually replaced with something neutral.

This is the one rule in the entire system that no program can check. The validator can
only insist that somebody claims to have done it, and record who claimed it.

## Then

    git clone git@github.com:polymath-scl/corpus.git
    cd corpus
    git config core.symlinks false
    python3 polymath init --handle <your-handle> --key ~/.ssh/id_ed25519
    python3 polymath doctor
    python3 polymath tutorial

`doctor` tells you whether anything is misconfigured. `tutorial` is an eight-step walk
through a throwaway practice copy — nothing you do in it touches anything real.

**Please say where it confuses you.** The tutorial was rewritten substantially after the
first person went through it cold and wrote down every point at which it assumed something
they did not know. You will find more, and those are worth recording — there is a place in
the corpus for exactly that kind of finding.
