# SELinux Prolog Model Notes

## Initial Predicate Set

The model starts with a small subset of SELinux concepts that map cleanly from
SETools-style policy analysis output:

- `allow(Source, Target, Class, Permission)`
- `has_attribute(Type, Attribute)`
- `type_transition(Source, Entrypoint, Target)`
- `new_allow(PolicyVersion, Source, Target, Class, Permission)`

These are treated as imported facts.

## Derived Predicates

Derived predicates represent local audit questions:

- `can_access/4`
- `can_read_web_content/1`
- `risky_web_shell_path/3`
- `can_domain_transition/3`
- `high_risk_policy_regression/5`
- `audit_finding/2`

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
