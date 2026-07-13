# SELinux Prolog Model Notes

## Initial Predicate Set

The model starts with a small subset of SELinux concepts that map cleanly from
SETools-style policy analysis output:

- `allow(Source, Target, Class, Permission)`
- `boolean_state(Boolean, State)`
- `conditional_allow(Boolean, Source, Target, Class, Permission)`
- `has_attribute(Type, Attribute)`
- `type_transition(Source, Entrypoint, Target)`
- `new_allow(PolicyVersion, Source, Target, Class, Permission)`
- `file_context(Path, Type, Class)`
- `fact_source(Fact, SourceMetadata)`

These are treated as imported facts.

## Derived Predicates

Derived predicates represent local audit questions:

- `can_access/4`
- `can_access_path/4`
- `can_read_path/2`
- `can_read_web_content/1`
- `risky_web_shell_path/3`
- `risky_executable_content_path/3`
- `can_domain_transition/3`
- `can_domain_transition_via_path/3`
- `high_risk_policy_regression/5`
- `policy_regression_severity/6`
- `audit_finding/2`
- `audit_finding_with_evidence/2`

`effective_allow/4` is the access primitive used by `can_access/4`. It includes
unconditional `allow/4` facts plus `conditional_allow/5` facts whose controlling
`boolean_state/2` is `true`. Disabled boolean-gated allows are kept as imported
facts but do not become effective access.

`fixtures/omegaclaw_knowledge_prior.md` is generated from the MeTTa export and
adds a small set of OmegaClaw `metta` commands for the first import/read
experiment. It is intentionally a bridge artifact: the Prolog model remains the
source of truth, while OmegaClaw receives a stable fact block and explicit
baseline checks.

`file_context/3` intentionally uses already-expanded path facts instead of
implementing SELinux regex precedence. A real importer should normalize
`semanage fcontext`, `matchpathcon`, or SETools-derived output before facts
reach this model.

`fact_source/2` stores provenance for imported facts as structured metadata.
`audit_finding_with_evidence/2` keeps the original finding shape and adds an
`evidence` list whose entries pair each supporting fact with its source
metadata. This is intended for downstream consumers that need explainable
reasoning output without parsing Prolog proof traces.

`policy_regression_severity/6` classifies imported `new_allow/5` policy diff
facts with a small local rubric:

- `critical` for new read, write, or append access to credential-store types
- `high` for new writes from webserver domains to executable content
- `low` for other new allows

## Soundness Boundary

The model is sound only relative to the facts provided and the local rules in
`src/selinux_rules.pl`.

It does not yet model:

- nested conditional expressions beyond one controlling boolean
- constraints and MLS/MCS labels
- type bounds
- role/user mappings
- file-context path matching
- Linux DAC, capabilities, seccomp, cgroups, namespaces, or firewall policy

Those should be added in small commits with tests.
