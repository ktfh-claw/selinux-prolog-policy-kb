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
- `sensitive_process_permission(Permission, Reason)`
- `firewall_egress_rule(Source, Protocol, Port, Action, Reason)`
- `seccomp_profile(Source, Profile)`
- `seccomp_rule(Profile, Syscall, Action, Reason)`
- `cgroup_assignment(Source, Cgroup)`
- `cgroup_limit(Cgroup, Resource, Value, Unit, Reason)`
- `service_unit(Service, Login, EntrypointPath, RestartPolicy)`
- `administrator_action(Action, Source, Primitive)`
- `administrator_service_action(Action, Service, Primitive)`
- `login_mapping(Login, SelinuxUser)`
- `selinux_user_role(SelinuxUser, Role)`
- `role_type(Role, Type)`
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
- `has_sensitive_process_permission/3`
- `ai_agent_sensitive_process_permission/3`
- `runtime_name_connect_allowed/3`
- `runtime_name_connect_blocked/4`
- `ai_agent_network_exposure/4`
- `runtime_syscall_allowed/2`
- `runtime_syscall_blocked/3`
- `ai_agent_syscall_block/3`
- `runtime_resource_limited/5`
- `ai_agent_resource_limit/5`
- `login_domain/2`
- `login_can_access/4`
- `login_sensitive_capability/4`
- `login_sensitive_process_permission/4`
- `service_domain/2`
- `service_domain_mismatch/3`
- `service_ai_agent_network_exposure/5`
- `service_ai_agent_syscall_block/4`
- `service_ai_agent_resource_limit/6`
- `admin_action_allowed/3`
- `admin_action_blocked/3`
- `admin_action_risky/3`
- `service_admin_action_risky/4`
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
effective unless the bounded parent type has the same effective access after
conditionals and explicit denials are applied. This models the common audit
question without attempting to reproduce every kernel typebounds edge case.

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

SELinux process-class permissions are represented as ordinary `allow/4` facts
such as `allow(ai_agent_t, self, process, dyntransition)`.
`sensitive_process_permission/2` is a local rubric for permissions that can
change process execution or domain-transition behavior. It currently flags
`dyntransition` and `noatsecure` for AI-agent domains as an application-style
baseline; it does not model every process permission or kernel transition path.

`login_mapping/2`, `selinux_user_role/2`, and `role_type/2` form a normalized
login-to-domain chain. `login_domain/2` resolves that chain, and
`login_can_access/4` asks whether a login can reach an effective allow through
any of its mapped roles and types. The sensitive login predicates reuse the
capability and process-permission rubrics so service accounts can be audited by
login identity as well as by SELinux domain.

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
resolved port type.

`firewall_egress_rule/5` is a coarse runtime policy layer over SELinux
`name_connect` reachability. `runtime_name_connect_allowed/3` requires both
SELinux `name_connect` access and an allow firewall rule, with explicit deny
rules winning over allows for the same domain/protocol/port tuple.
`runtime_name_connect_blocked/4` exposes the useful audit edge case where
SELinux would permit a connection but a runtime firewall rule blocks it.
This is intentionally a normalized rule list, not a packet-filter language.

`seccomp_profile/2` and `seccomp_rule/4` add a second normalized runtime policy
layer. `runtime_syscall_allowed/2` requires an allow rule in the domain's
profile and no matching deny rule. `runtime_syscall_blocked/3` exposes deny
rules directly, and `ai_agent_syscall_block/3` scopes those blocks to domains
tagged with `ai_agent_domain`. These facts are intentionally profile summaries,
not raw BPF/seccomp filter evaluation.

`cgroup_assignment/2` and `cgroup_limit/5` add a third normalized runtime policy
layer for resource isolation. `runtime_resource_limited/5` joins a domain to its
cgroup and then to resource caps such as `pids.max` and `memory.max`.
`ai_agent_resource_limit/5` scopes those limits to domains tagged with
`ai_agent_domain`. These facts are summaries of already-resolved cgroup policy,
not a model of controller inheritance, delegation, pressure metrics, or systemd
unit semantics.

`service_unit/4` stores a normalized service-manager summary with the service
name, login identity, entrypoint path, and restart policy. `service_domain/2`
requires the login-to-domain mapping and the `init_t` entrypoint transition to
agree on the same domain. `service_domain_mismatch/3` exposes units where the
configured login maps to one domain but the entrypoint transition resolves to
another. Service-scoped AI-agent predicates reuse the existing network,
seccomp, and cgroup checks after the unit domain is resolved.

`administrator_action/3` and `administrator_service_action/3` map named
AI-agent Linux administrator behaviors onto normalized primitives already in
the model: SELinux access checks, port `name_connect`, seccomp syscalls,
cgroup limits, and service restart policy. The `admin_action_allowed/3`,
`admin_action_blocked/3`, and `admin_action_risky/3` predicates provide an
action-level audit vocabulary without reimplementing those lower layers.
`service_admin_action_risky/4` currently covers the narrow `Restart=always`
loop-risk case for resolved AI-agent services.

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
- role transitions and role dominance
- file-context path matching
- Linux DAC outcomes, namespaces, or full firewall/seccomp/cgroup policy
- full systemd unit semantics, restart timing, or service dependency/order behavior

Those should be added in small commits with tests.
