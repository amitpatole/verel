# Rollout — from shadow to enforcement

A runbook for taking Verel from "watching" to "blocking" in a media pipeline without a surprise. Every step
is reversible, and every enforcement decision is backed by evidence from **your own** assets.

## The stages

| Stage | Pipeline effect | Exit criterion |
|---|---|---|
| 1. **Shadow** | none. Verdicts are logged. | Enough labeled assets that the numbers mean something (aim for at least 100 flagged and 100 clean) |
| 2. **Advisory** | FAIL is shown as WARN. Humans see it; nothing is blocked. | Reviewers agree with it, and false alarms are tolerable to them |
| 3. **Enforce, per grader** | only promoted graders block | A grader earned it (below). Promote **one grader at a time** |

Do not skip stage 2. The system refuses to: promoting straight from shadow to enforce needs an explicit,
recorded admin override.

## Day 1: attach in shadow

```bash
# a hot folder, a worker, or `verel pilot record` in your pipeline. All default to shadow.
verel hotfolder --root /srv/qc --data-dir /var/lib/verel --tenant acme
```

Have reviewers label a sample: `{"artifact_id": "...", "defect": true|false}`. Include clean assets, or
precision means nothing. Re-run `verel pilot eval` weekly.

## What counts as evidence

Over HTTP, `POST /v1/pilot/record` takes the grader's report **from the caller**. Those decisions are *self-reported*: they show
what a client claims a grader said, not what the grader did. So by default they are **not** evidence for the readiness flag,
promotion, demotion or health checks. Evidence comes from decisions Verel produced itself: a **worker** grading a file under a
configured root, or the **hot folder** grading a file it hashed, **and** whose facts name that file's hash (`asset.sha256`).
Without that, someone who can enqueue a job could point it at any facts file and mint a "measured" decision for an asset the
grader never examined. What this does and does not guarantee: the grader really ran, on facts that claim to describe this exact
file. It does not prove the facts are *true*; that is the honesty of whoever (or whatever sensor) wrote them. The evaluation reports `self_reported_excluded` so you can see
what was left out.

A pilot with no workers can opt back in with `VEREL_EVIDENCE_ALLOW_SELF_REPORTED=1`. Do that knowingly: it means an operator's
claim about a grader is trusted. The local `verel pilot` CLI (your own machine, your own reports) is unaffected.

## What "earned it" means

A grader may be promoted to enforce when the evaluation of **your** log and labels shows all of:

- at least 30 flagged artifacts, and a precision lower bound of 0.95 or better;
- recall of at least 0.5 (it catches a real share of defects, not just a few easy ones);
- errors on at most 5% of artifacts.

The evidence is recomputed **at promotion time** from your data, so a caller cannot supply favorable numbers.
The thresholds are floors: a request can ask for stricter, never weaker. Tune the floors in code only with a
review, because they are the safety margin.

```bash
verel pilot promote --policy policy.jsonl --log pilot.jsonl --labels labels.json --grader dsp --to advisory
verel pilot promote --policy policy.jsonl --log pilot.jsonl --labels labels.json --grader dsp --to enforce
```

Over HTTP, an `admin` calls `POST /v1/pilot/promote`. Once a tenant has a policy, `mode` is not selectable per
request; the policy decides, and `record` returns `"mode": "policy"`.

If a grader cannot meet the bar but you must enforce it anyway (a regulator, a contract), an admin can pass
`--override-reason` (10+ characters). The override is recorded in the policy history and flagged, permanently.

## Watching for regressions

`verel pilot health --policy ... --log ... --labels ...` checks every enforcing grader over its most recent
flags (padding the log with clean passes cannot hide bad ones). A grader whose recent precision lower bound falls
below 0.90, or that errors on more than 10% of artifacts, is demoted to advisory with `--apply`, or by an admin
calling `POST /v1/pilot/health`. Run it from cron. It deliberately does **not** run as a side effect of someone
adding labels, because an operator's own labels must not be able to switch a control off. Re-promotion is manual
and needs fresh evidence. This catches a bad config push or a drifting model before it blocks a delivery night after night.

## Rolling back

| Need | Do |
|---|---|
| Stop everything, now | set `VEREL_PILOT_KILL_SWITCH=1` on the service, workers and hot folders. Every decision becomes a pass, still logged with a `[kill switch active]` note. No policy changes. |
| Stop one grader | `verel pilot demote --policy ... --grader dsp --reason "..."` (takes effect on the next decision) |
| Understand what happened | `verel pilot policy --policy ...` shows who changed what, when, why, and the evidence |

The policy history is keyed and hash-chained like the decision log: nobody can quietly edit it to say a grader
was enforcing, or wasn't.

## Separation of duties

The evidence is only as honest as the labels, so the service enforces some structure:

- Promotion to enforce needs **two reviewers**, meaning two different people who each labeled a meaningful share
  (at least 5 labels and 10% of the evidence) of the original labels. An admin's amendment, the promoter's own
  labels and a stray label on one artifact do not count (`reviewers` in the evaluation). With fewer, an admin needs
  an override reason, which is recorded.
- A label can only describe an artifact that already has a recorded decision, so nobody can pre-label future assets.
- **The person who recorded a decision cannot be the one whose label scores it.** Self-labeled decisions are left out of
  every evaluation, promotion and health check, so a single operator cannot fabricate both halves of the evidence, either to
  earn a promotion or to get a good grader demoted.
- **A job's decision is attributed to the person who enqueued it**, so enqueueing and then labeling your own jobs is excluded
  just like recording and labeling. **The same file counts once:** the media graders record the asset's SHA-256, and evidence
  from the same file under many artifact ids is scored a single time (`duplicate_content` in the evaluation).
- **Collusion is not prevented.** Two operators holding two tokens satisfy the two-reviewer rule. Verel can require that the
  evidence come from different principals; making them different *people* is your identity and process.
- Labels survive retention: a label that was archived cannot be flipped by a non-admin afterwards.
- **The first decision recorded for an artifact id is the one that is scored.** Recording the same id again is refused
  (HTTP 409), even after the old decision was archived out of the live log (archived ids are remembered), because re-grading a
  labeled artifact could manufacture or erase evidence. A new version of an asset gets a
  new artifact id (the hot folder derives one from the file's size and modification time).
- Labels are first-write-wins. Changing one takes an admin (`POST /v1/pilot/labels/amend`), and the amendment is a
  new record, not an edit. The latest label per artifact counts.

Verel records who labeled what, but it cannot make two accounts into two independent people.

## Checklist before turning on enforcement

- [ ] Labeled sample reflects production, including clean assets and the awkward edge cases
- [ ] Reviewers have seen advisory output for at least a few weeks
- [ ] Someone owns the kill switch and knows where it is
- [ ] The people who will be blocked know why, and who to ask
- [ ] You have exercised a demotion once, on purpose, before you need it
