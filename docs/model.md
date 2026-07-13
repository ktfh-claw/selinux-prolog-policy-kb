# SELinux Prolog Model Notes

## Initial Predicate Set

The model starts with a small subset of SELinux concepts that map cleanly from
SETools-style policy analysis output:

- `allow(Source, Target, Class, Permission)`
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
- `audit_finding/2`
- `audit_finding_with_evidence/2`

`file_context/3` intentionally uses already-expanded path facts instead of
implementing SELinux regex precedence. A real importer should normalize
`semanage fcontext`, `matchpathcon`, or SETools-derived output before facts
reach this model.

`fact_source/2` stores provenance for imported facts as structured metadata.
`audit_finding_with_evidence/2` keeps the original finding shape and adds an
`evidence` list whose entries pair each supporting fact with its source
metadata. This is intended for downstream consumers that need explainable
reasoning output without parsing Prolog proof traces.

## Soundness Boundary

The model is sound only relative to the facts provided and the local rules in
`src/selinux_rules.pl`.

It does not yet model:

- conditionals and booleans
- constraints and MLS/MCS labels
- type bounds
- role/user mappings
- file-context path matching
- Linux DAC, capabilities, seccomp, cgroups, namespaces, or firewall policy

Those should be added in small commits with tests.
