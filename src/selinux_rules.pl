:- module(selinux_rules, [
    effective_allow/4,
    can_access/4,
    can_access_path/4,
    can_read_web_content/1,
    can_read_path/2,
    can_name_connect_port/3,
    access_denied_by_constraint/5,
    access_denied_by_type_bound/6,
    sensitivity_dominates/2,
    mls_read_allowed/2,
    mls_read_blocked/3,
    risky_web_shell_path/3,
    risky_executable_content_path/3,
    can_domain_transition/3,
    can_domain_transition_via_path/3,
    high_risk_policy_regression/5,
    policy_regression_severity/6,
    audit_finding/2,
    audit_finding_with_evidence/2
]).

:- use_module(selinux_facts).

effective_allow(Source, Target, Class, Permission) :-
    effective_allow_candidate(Source, Target, Class, Permission),
    \+ constraint_denies(Source, Target, Class, Permission, _Reason),
    \+ access_denied_by_type_bound(
        Source,
        Target,
        Class,
        Permission,
        _Parent,
        _BoundReason
    ).

effective_allow_candidate(Source, Target, Class, Permission) :-
    allow(Source, Target, Class, Permission).
effective_allow_candidate(Source, Target, Class, Permission) :-
    conditional_allow(Boolean, Source, Target, Class, Permission),
    boolean_state(Boolean, true).

can_access(Source, Target, Class, Permission) :-
    effective_allow(Source, Target, Class, Permission).

can_access_path(Source, Path, Class, Permission) :-
    file_context(Path, Target, Class),
    effective_allow(Source, Target, Class, Permission).

can_read_web_content(Source) :-
    effective_allow(Source, httpd_sys_content_t, file, read).

can_read_path(Source, Path) :-
    can_access_path(Source, Path, file, read).

can_name_connect_port(Source, Protocol, Port) :-
    port_context(Port, PortType, Protocol),
    socket_class_for_protocol(Protocol, SocketClass),
    effective_allow(Source, PortType, SocketClass, name_connect).

socket_class_for_protocol(tcp, tcp_socket).
socket_class_for_protocol(udp, udp_socket).

access_denied_by_constraint(Source, Target, Class, Permission, Reason) :-
    effective_allow_candidate(Source, Target, Class, Permission),
    constraint_denies(Source, Target, Class, Permission, Reason).

access_denied_by_type_bound(
    Source,
    Target,
    Class,
    Permission,
    Parent,
    parent_missing_allow
) :-
    type_bound(Source, Parent),
    effective_allow_candidate(Source, Target, Class, Permission),
    \+ effective_allow_candidate(Parent, Target, Class, Permission).

sensitivity_dominates(SourceLevel, TargetLevel) :-
    sensitivity_level(SourceLevel, SourceRank),
    sensitivity_level(TargetLevel, TargetRank),
    SourceRank >= TargetRank.

mls_read_allowed(Source, Target) :-
    mls_range(Source, _SourceLow, SourceHigh, SourceCategories),
    mls_range(Target, _TargetLow, TargetHigh, TargetCategories),
    sensitivity_dominates(SourceHigh, TargetHigh),
    categories_include(SourceCategories, TargetCategories).

mls_read_blocked(Source, Target, insufficient_mls_range) :-
    allow(Source, Target, file, read),
    mls_range(Source, _SourceLow, _SourceHigh, _SourceCategories),
    mls_range(Target, _TargetLow, _TargetHigh, _TargetCategories),
    \+ mls_read_allowed(Source, Target).

categories_include(SourceCategories, TargetCategories) :-
    forall(member(Category, TargetCategories), member(Category, SourceCategories)).

risky_web_shell_path(Source, Target, write_executable_content) :-
    effective_allow(Source, Target, file, write),
    has_attribute(Source, webserver_domain),
    has_attribute(Target, executable_content).

risky_executable_content_path(Source, Path, write_executable_content) :-
    file_context(Path, Target, file),
    risky_web_shell_path(Source, Target, write_executable_content).

can_domain_transition(Source, Entrypoint, Target) :-
    type_transition(Source, Entrypoint, Target),
    effective_allow(Source, Entrypoint, file, entrypoint),
    effective_allow(Source, Target, process, transition).

can_domain_transition_via_path(Source, EntrypointPath, Target) :-
    file_context(EntrypointPath, Entrypoint, file),
    can_domain_transition(Source, Entrypoint, Target).

high_risk_policy_regression(PolicyVersion, Source, Target, Class, Permission) :-
    new_allow(PolicyVersion, Source, Target, Class, Permission),
    has_attribute(Target, credential_store),
    member(Permission, [read, write, append]).

policy_regression_severity(PolicyVersion, Source, Target, Class, Permission, Severity) :-
    new_allow(PolicyVersion, Source, Target, Class, Permission),
    policy_regression_severity_for(Source, Target, Class, Permission, Severity).

policy_regression_severity_for(_Source, Target, _Class, Permission, critical) :-
    has_attribute(Target, credential_store),
    member(Permission, [read, write, append]),
    !.
policy_regression_severity_for(Source, Target, file, write, high) :-
    has_attribute(Source, webserver_domain),
    has_attribute(Target, executable_content),
    !.
policy_regression_severity_for(_Source, _Target, _Class, _Permission, low).

audit_finding(risky_web_shell_path, finding{
    source: Source,
    target: Target,
    reason: write_executable_content
}) :-
    risky_web_shell_path(Source, Target, write_executable_content).

audit_finding(risky_executable_content_path, finding{
    source: Source,
    path: Path,
    reason: Reason
}) :-
    risky_executable_content_path(Source, Path, Reason).

audit_finding(high_risk_policy_regression, finding{
    policy_version: PolicyVersion,
    source: Source,
    target: Target,
    class: Class,
    permission: Permission
}) :-
    high_risk_policy_regression(PolicyVersion, Source, Target, Class, Permission).

audit_finding(constraint_blocked_allow, finding{
    source: Source,
    target: Target,
    class: Class,
    permission: Permission,
    reason: Reason
}) :-
    access_denied_by_constraint(Source, Target, Class, Permission, Reason).

audit_finding(type_bound_blocked_allow, finding{
    source: Source,
    parent: Parent,
    target: Target,
    class: Class,
    permission: Permission,
    reason: Reason
}) :-
    access_denied_by_type_bound(
        Source,
        Target,
        Class,
        Permission,
        Parent,
        Reason
    ).

audit_finding(mls_blocked_read, finding{
    source: Source,
    target: Target,
    reason: Reason
}) :-
    mls_read_blocked(Source, Target, Reason).

audit_finding_with_evidence(Kind, FindingWithEvidence) :-
    audit_finding(Kind, Finding),
    audit_evidence(Kind, Finding, Evidence),
    put_dict(evidence, Finding, Evidence, FindingWithEvidence).

audit_evidence(risky_web_shell_path, Finding, Evidence) :-
    Source = Finding.source,
    Target = Finding.target,
    Evidence = [
        allow(Source, Target, file, write)-AllowSource,
        has_attribute(Source, webserver_domain)-SourceAttributeSource,
        has_attribute(Target, executable_content)-TargetAttributeSource
    ],
    fact_source(allow(Source, Target, file, write), AllowSource),
    fact_source(has_attribute(Source, webserver_domain), SourceAttributeSource),
    fact_source(has_attribute(Target, executable_content), TargetAttributeSource).

audit_evidence(risky_executable_content_path, Finding, Evidence) :-
    Source = Finding.source,
    Path = Finding.path,
    file_context(Path, Target, file),
    Evidence = [
        file_context(Path, Target, file)-FileContextSource,
        allow(Source, Target, file, write)-AllowSource,
        has_attribute(Source, webserver_domain)-SourceAttributeSource,
        has_attribute(Target, executable_content)-TargetAttributeSource
    ],
    fact_source(file_context(Path, Target, file), FileContextSource),
    fact_source(allow(Source, Target, file, write), AllowSource),
    fact_source(has_attribute(Source, webserver_domain), SourceAttributeSource),
    fact_source(has_attribute(Target, executable_content), TargetAttributeSource).

audit_evidence(high_risk_policy_regression, Finding, Evidence) :-
    PolicyVersion = Finding.policy_version,
    Source = Finding.source,
    Target = Finding.target,
    Class = Finding.class,
    Permission = Finding.permission,
    Evidence = [
        new_allow(PolicyVersion, Source, Target, Class, Permission)-NewAllowSource,
        has_attribute(Target, credential_store)-TargetAttributeSource
    ],
    fact_source(
        new_allow(PolicyVersion, Source, Target, Class, Permission),
        NewAllowSource
    ),
    fact_source(has_attribute(Target, credential_store), TargetAttributeSource).

audit_evidence(constraint_blocked_allow, Finding, Evidence) :-
    Source = Finding.source,
    Target = Finding.target,
    Class = Finding.class,
    Permission = Finding.permission,
    Reason = Finding.reason,
    Evidence = [
        allow(Source, Target, Class, Permission)-AllowSource,
        constraint_denies(Source, Target, Class, Permission, Reason)-ConstraintSource
    ],
    fact_source(allow(Source, Target, Class, Permission), AllowSource),
    fact_source(
        constraint_denies(Source, Target, Class, Permission, Reason),
        ConstraintSource
    ).

audit_evidence(type_bound_blocked_allow, Finding, Evidence) :-
    Source = Finding.source,
    Parent = Finding.parent,
    Target = Finding.target,
    Class = Finding.class,
    Permission = Finding.permission,
    Evidence = [
        allow(Source, Target, Class, Permission)-AllowSource,
        type_bound(Source, Parent)-TypeBoundSource
    ],
    fact_source(allow(Source, Target, Class, Permission), AllowSource),
    fact_source(type_bound(Source, Parent), TypeBoundSource).

audit_evidence(mls_blocked_read, Finding, Evidence) :-
    Source = Finding.source,
    Target = Finding.target,
    Evidence = [
        allow(Source, Target, file, read)-AllowSource,
        mls_range(Source, SourceLow, SourceHigh, SourceCategories)-SourceRangeSource,
        mls_range(Target, TargetLow, TargetHigh, TargetCategories)-TargetRangeSource
    ],
    fact_source(allow(Source, Target, file, read), AllowSource),
    fact_source(
        mls_range(Source, SourceLow, SourceHigh, SourceCategories),
        SourceRangeSource
    ),
    fact_source(
        mls_range(Target, TargetLow, TargetHigh, TargetCategories),
        TargetRangeSource
    ).
