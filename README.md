# selinux-prolog-policy-kb

Prolog knowledge base for experimenting with SELinux-style policy extraction,
symbolic reasoning, and later OmegaClaw integration.

This repository does not reconstruct PALMS. It uses similar logic-programming
ideas with maintained SELinux tooling concepts such as SETools and
`sepolicy_analysis`.

## Current Scope

The first model layer covers:

- SELinux-shaped allow facts: `allow(Source, Target, Class, Permission)`
- type attributes: `has_attribute(Type, Attribute)`
- file-context facts: `file_context(Path, Type, Class)`
- domain transition facts: `type_transition(Source, Entrypoint, Target)`
- policy diff facts: `new_allow(PolicyVersion, Source, Target, Class, Permission)`
- provenance facts: `fact_source(Fact, SourceMetadata)`
- derived audit predicates for risky web-shell paths, path-resolved domain
  transition reachability, path-level access, high-risk policy regressions, and
  severity classification for policy diffs and findings with structured
  evidence

## Layout

- `src/selinux_facts.pl` - toy imported policy facts shaped like SETools output
- `src/selinux_rules.pl` - reusable reasoning rules over imported facts
- `scripts/export_metta.pl` - deterministic repo-local MeTTa-style export
- `scripts/export_omegaclaw_prior.pl` - generated OmegaClaw knowledge-prior
  fixture and baseline commands
- `scripts/prepare_omegaclaw_experiment.sh` - repo-local import/read experiment
  packet builder for OmegaClaw
- `fixtures/selinux_policy.metta` - generated OmegaClaw/MeTTa-style fixture
- `fixtures/omegaclaw_knowledge_prior.md` - generated import/read fixture for
  OmegaClaw baseline experiments
- `tests/selinux_rules_tests.pl` - executable Prolog tests
- `docs/model.md` - modeling notes and soundness boundaries
- `docs/omegaclaw_import_read_experiment.md` - runbook for preparing and
  recording an OmegaClaw import/read experiment without editing OmegaClaw-Core

## Run Tests

```bash
swipl -q -g run_tests -t halt tests/selinux_rules_tests.pl
swipl -q -g run_tests -t halt tests/metta_export_tests.pl
```

## Regenerate MeTTa Fixture

```bash
swipl -q -s scripts/export_metta.pl -g export_metta:export_metta -t halt > fixtures/selinux_policy.metta
swipl -q -s scripts/export_omegaclaw_prior.pl -g export_omegaclaw_prior:export_omegaclaw_prior -t halt > fixtures/omegaclaw_knowledge_prior.md
```

## Prepare OmegaClaw Import/Read Packet

```bash
sh scripts/prepare_omegaclaw_experiment.sh
```

This writes `.tmp/omegaclaw-import-read/knowledge-prior.md` and `report.md` for
an OmegaClaw experiment while leaving any OmegaClaw-Core checkout untouched.

## Boundary

The current fact set is a toy profile. It is useful for validating modeling
shape and query behavior, not for auditing a real Linux host yet.
