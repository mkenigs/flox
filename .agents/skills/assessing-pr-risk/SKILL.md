---
name: assessing-pr-risk
description: Assess the consequences, ongoing commitments and recovery options of a Flox pull request for agent review.
---

Trace the full diff to the callers, people and systems it can affect. Identify the plausible failure that matters most. Consider system position (leaf, shared or core), contract reach, durable state, exposure, trust, failure visibility, recovery, ownership and novelty. Describe which of these drive the judgment. Cite a changed path and concrete evidence for detection and recovery. Distinguish a test you ran from one you would like to see.

Classify the whole PR by its most consequential change. For the Flox pilot:

- **Low** requires a contained effect, a familiar mechanism, a readily detectable failure and a straightforward recovery with no material residual obligation. A documentation correction or a mechanical move with verified callers can qualify.
- **Medium** fits bounded behavior changes that need domain judgment, including changes where detection or rollback lacks evidence. An opt-in CLI feature still creates a user expectation.
- **High** includes trust-boundary changes, destructive or migratory writes, incompatible external contracts, and failures that can silently damage downstream state. Reverting the writer may leave existing manifests or telemetry needing repair.

Report the consequence, commitment and control in a short rationale. Record material uncertainty and use at least medium when evidence for low is missing. Size, passing CI and commit-level review depth alone cannot establish low risk. Assess finding severity independently: even a localized change can contain an important bug.
