# SELinux Prolog Model Notes

## Initial Predicate Set

The model starts with a small subset of SELinux concepts that map cleanly from
SETools-style policy analysis output:

- `allow(Source, Target, Class, Permission)`
- `boolean_state(Boolean, State)`
- `conditional_allow(Boolean, Source, Target, Class, Permission)`
- `constraint_denies(Source, Target, Class, Permission, Reason)`
- `sensitivity_level(Level, Rank)`
- `mls_range(Entity, LowLevel, HighLevel, Categories)`
- `type_bound(ChildType, ParentType)`
- `sensitive_capability(Capability, Reason)`
- `has_attribute(Type, Attribute)`
- `type_transition(Source, Entrypoint, Target)`
- `new_allow(PolicyVersion, Source, Target, Class, Permission)`
- `file_context(Path, Type, Class)`
- `port_context(Port, Type, Protocol)`
- `fact_source(Fact, SourceMetadata)`

These are treated as imported facts.

## Derived Predicates

Derived predicates represent local audit questions:

- `can_access/4`
- `can_access_path/4`
- `can_read_path/2`
- `can_read_web_content/1`
- `can_name_connect_port/3`
- `access_denied_by_constraint/5`
- `access_denied_by_type_bound/6`
- `sensitivity_dominates/2`
- `mls_read_allowed/2`
- `mls_read_blocked/3`
- `has_sensitive_capability/3`
- `ai_agent_sensitive_capability/3`
- `risky_web_shell_path/3`
- `risky_executable_content_path/3`
- `can_domain_transition/3`
- `can_domain_transition_via_path/3`
- `high_risk_policy_regression/5`
- `policy_regression_severity/6`
- `audit_finding/2`
- `audit_finding_with_evidence/2`

`effective_allow/4` is the access primitive used by `can_access/4`. It starts
from unconditional `allow/4` facts plus `conditional_allow/5` facts whose
controlling `boolean_state/2` is `true`, then removes any access covered by an
explicit `constraint_denies/5` fact. Disabled boolean-gated allows and
constraint-blocked allows are kept as imported facts but do not become effective
access.

`type_bound/2` represents an already-normalized SELinux typebounds relation.
For the current read/write access layer, a child type's imported allow is not
effective unless the bounded parent type has the same allow candidate. This
models the common audit question without attempting to reproduce every kernel
typebounds edge case.

`constraint_denies/5` is an already-normalized imported fact, not a full
implementation of SELinux constraint expression evaluation. This keeps the
initial model reviewable while preserving the important audit behavior: an allow
rule can be present but non-effective because another policy layer denies it.

`mls_range/4` and `sensitivity_level/2` provide a first normalized MLS/MCS
layer. `mls_read_allowed/2` checks the narrow read case where the subject high
level dominates the object high level and the subject categories include all
object categories. `mls_read_blocked/3` exposes imported read allows that fail
that range check. This is intentionally smaller than SELinux constraint
expression evaluation; it is a reviewable bridge toward richer range algebra.

SELinux capability-class grants are represented as ordinary `allow/4` facts
such as `allow(ai_agent_t, self, capability, dac_override)`.
`sensitive_capability/2` is a local audit rubric over capability permissions,
not an imported SELinux primitive. `ai_agent_sensitive_capability/3` combines
that rubric with `has_attribute(Source, ai_agent_domain)` so early AI-agent
behavior checks can flag powerful Linux capability grants without claiming to
model DAC outcomes or kernel capability semantics.

`fixtures/omegaclaw_knowledge_prior.md` is generated from the MeTTa export and
adds a small set of OmegaClaw `metta` commands for the first import/read
experiment. It is intentionally a bridge artifact: the Prolog model remains the
source of truth, while OmegaClaw receives a stable fact block and explicit
baseline checks.

`file_context/3` intentionally uses already-expanded path facts instead of
implementing SELinux regex precedence. A real importer should normalize
`semanage fcontext`, `matchpathcon`, or SETools-derived output before facts
reach this model.

`port_context/3` likewise stores already-resolved SELinux port labels. The
current `can_name_connect_port/3` rule maps TCP and UDP protocols to their
socket classes and checks effective `name_connect` permission against the
resolved port type. Firewall policy and runtime socket state are out of scope.

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
- full SELinux constraint expressions and write-side MLS/MCS range algebra
- role/user mappings
- file-context path matching
- Linux DAC outcomes, seccomp, cgroups, namespaces, or firewall policy

Those should be added in small commits with tests.
