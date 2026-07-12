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
- domain transition facts: `type_transition(Source, Entrypoint, Target)`
- policy diff facts: `new_allow(PolicyVersion, Source, Target, Class, Permission)`
- derived audit predicates for risky web-shell paths, domain transition
  reachability, and high-risk policy regressions

## Layout

- `src/selinux_facts.pl` - toy imported policy facts shaped like SETools output
- `src/selinux_rules.pl` - reusable reasoning rules over imported facts
- `tests/selinux_rules_tests.pl` - executable Prolog tests
- `docs/model.md` - modeling notes and soundness boundaries

## Run Tests

```bash
swipl -q -g run_tests -t halt tests/selinux_rules_tests.pl
```

## Boundary

The current fact set is a toy profile. It is useful for validating modeling
shape and query behavior, not for auditing a real Linux host yet.
