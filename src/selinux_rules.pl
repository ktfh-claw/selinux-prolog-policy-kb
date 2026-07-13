:- module(selinux_rules, [
    effective_allow/4,
    can_access/4,
    can_access_path/4,
    can_read_web_content/1,
    can_read_path/2,
    can_name_connect_port/3,
    runtime_name_connect_allowed/3,
    runtime_name_connect_blocked/4,
    runtime_syscall_allowed/2,
    runtime_syscall_blocked/3,
    ai_agent_syscall_block/3,
    access_denied_by_constraint/5,
    access_denied_by_type_bound/6,
    sensitivity_dominates/2,
    mls_read_allowed/2,
    mls_read_blocked/3,
    has_sensitive_capability/3,
    ai_agent_sensitive_capability/3,
    has_sensitive_process_permission/3,
    ai_agent_sensitive_process_permission/3,
    ai_agent_network_exposure/4,
    login_domain/2,
    login_can_access/4,
    login_sensitive_capability/4,
    login_sensitive_process_permission/4,
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

runtime_name_connect_allowed(Source, Protocol, Port) :-
    can_name_connect_port(Source, Protocol, Port),
    firewall_egress_rule(Source, Protocol, Port, allow, _Reason),
    \+ firewall_egress_rule(Source, Protocol, Port, deny, _DenyReason).

runtime_name_connect_blocked(Source, Protocol, Port, Reason) :-
    can_name_connect_port(Source, Protocol, Port),
    firewall_egress_rule(Source, Protocol, Port, deny, Reason).

runtime_syscall_allowed(Source, Syscall) :-
    seccomp_profile(Source, Profile),
    seccomp_rule(Profile, Syscall, allow, _Reason),
    \+ seccomp_rule(Profile, Syscall, deny, _DenyReason).

runtime_syscall_blocked(Source, Syscall, Reason) :-
    seccomp_profile(Source, Profile),
    seccomp_rule(Profile, Syscall, deny, Reason).

ai_agent_syscall_block(Source, Syscall, Reason) :-
    has_attribute(Source, ai_agent_domain),
    runtime_syscall_blocked(Source, Syscall, Reason).

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
    parent_missing_effective_allow
) :-
    type_bound(Source, Parent),
    effective_allow_candidate(Source, Target, Class, Permission),
    \+ effective_allow(Parent, Target, Class, Permission).

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

has_sensitive_capability(Source, Capability, Reason) :-
    effective_allow(Source, self, capability, Capability),
    sensitive_capability(Capability, Reason).

ai_agent_sensitive_capability(Source, Capability, Reason) :-
    has_attribute(Source, ai_agent_domain),
    has_sensitive_capability(Source, Capability, Reason).

has_sensitive_process_permission(Source, Permission, Reason) :-
    effective_allow(Source, self, process, Permission),
    sensitive_process_permission(Permission, Reason).

ai_agent_sensitive_process_permission(Source, Permission, Reason) :-
    has_attribute(Source, ai_agent_domain),
    has_sensitive_process_permission(Source, Permission, Reason).

ai_agent_network_exposure(Source, Protocol, Port, Reason) :-
    has_attribute(Source, ai_agent_domain),
    runtime_name_connect_allowed(Source, Protocol, Port),
    firewall_egress_rule(Source, Protocol, Port, allow, Reason).

login_domain(Login, Domain) :-
    login_mapping(Login, SelinuxUser),
    selinux_user_role(SelinuxUser, Role),
    role_type(Role, Domain).

login_can_access(Login, Target, Class, Permission) :-
    login_domain(Login, Domain),
    effective_allow(Domain, Target, Class, Permission).

login_sensitive_capability(Login, Domain, Capability, Reason) :-
    login_domain(Login, Domain),
    has_sensitive_capability(Domain, Capability, Reason).

login_sensitive_process_permission(Login, Domain, Permission, Reason) :-
    login_domain(Login, Domain),
    has_sensitive_process_permission(Domain, Permission, Reason).

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

audit_finding(ai_agent_sensitive_capability, finding{
    source: Source,
    capability: Capability,
    reason: Reason
}) :-
    ai_agent_sensitive_capability(Source, Capability, Reason).

audit_finding(ai_agent_sensitive_process_permission, finding{
    source: Source,
    permission: Permission,
    reason: Reason
}) :-
    ai_agent_sensitive_process_permission(Source, Permission, Reason).

audit_finding(ai_agent_network_exposure, finding{
    source: Source,
    protocol: Protocol,
    port: Port,
    reason: Reason
}) :-
    ai_agent_network_exposure(Source, Protocol, Port, Reason).

audit_finding(runtime_network_block, finding{
    source: Source,
    protocol: Protocol,
    port: Port,
    reason: Reason
}) :-
    runtime_name_connect_blocked(Source, Protocol, Port, Reason).

audit_finding(runtime_syscall_block, finding{
    source: Source,
    syscall: Syscall,
    reason: Reason
}) :-
    runtime_syscall_blocked(Source, Syscall, Reason).

audit_finding(ai_agent_syscall_block, finding{
    source: Source,
    syscall: Syscall,
    reason: Reason
}) :-
    ai_agent_syscall_block(Source, Syscall, Reason).

audit_finding(login_sensitive_capability, finding{
    login: Login,
    domain: Domain,
    capability: Capability,
    reason: Reason
}) :-
    login_sensitive_capability(Login, Domain, Capability, Reason).

audit_finding(login_sensitive_process_permission, finding{
    login: Login,
    domain: Domain,
    permission: Permission,
    reason: Reason
}) :-
    login_sensitive_process_permission(Login, Domain, Permission, Reason).

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

audit_evidence(ai_agent_sensitive_capability, Finding, Evidence) :-
    Source = Finding.source,
    Capability = Finding.capability,
    Reason = Finding.reason,
    Evidence = [
        allow(Source, self, capability, Capability)-AllowSource,
        has_attribute(Source, ai_agent_domain)-AgentAttributeSource,
        sensitive_capability(Capability, Reason)-CapabilitySource
    ],
    fact_source(allow(Source, self, capability, Capability), AllowSource),
    fact_source(has_attribute(Source, ai_agent_domain), AgentAttributeSource),
    fact_source(sensitive_capability(Capability, Reason), CapabilitySource).

audit_evidence(ai_agent_sensitive_process_permission, Finding, Evidence) :-
    Source = Finding.source,
    Permission = Finding.permission,
    Reason = Finding.reason,
    Evidence = [
        allow(Source, self, process, Permission)-AllowSource,
        has_attribute(Source, ai_agent_domain)-AgentAttributeSource,
        sensitive_process_permission(Permission, Reason)-PermissionSource
    ],
    fact_source(allow(Source, self, process, Permission), AllowSource),
    fact_source(has_attribute(Source, ai_agent_domain), AgentAttributeSource),
    fact_source(sensitive_process_permission(Permission, Reason), PermissionSource).

audit_evidence(ai_agent_network_exposure, Finding, Evidence) :-
    Source = Finding.source,
    Protocol = Finding.protocol,
    Port = Finding.port,
    Reason = Finding.reason,
    port_context(Port, PortType, Protocol),
    socket_class_for_protocol(Protocol, SocketClass),
    Evidence = [
        has_attribute(Source, ai_agent_domain)-AgentAttributeSource,
        port_context(Port, PortType, Protocol)-PortContextSource,
        allow(Source, PortType, SocketClass, name_connect)-AllowSource,
        firewall_egress_rule(Source, Protocol, Port, allow, Reason)-FirewallSource
    ],
    fact_source(has_attribute(Source, ai_agent_domain), AgentAttributeSource),
    fact_source(port_context(Port, PortType, Protocol), PortContextSource),
    fact_source(allow(Source, PortType, SocketClass, name_connect), AllowSource),
    fact_source(
        firewall_egress_rule(Source, Protocol, Port, allow, Reason),
        FirewallSource
    ).

audit_evidence(runtime_network_block, Finding, Evidence) :-
    Source = Finding.source,
    Protocol = Finding.protocol,
    Port = Finding.port,
    Reason = Finding.reason,
    port_context(Port, PortType, Protocol),
    socket_class_for_protocol(Protocol, SocketClass),
    Evidence = [
        port_context(Port, PortType, Protocol)-PortContextSource,
        allow(Source, PortType, SocketClass, name_connect)-AllowSource,
        firewall_egress_rule(Source, Protocol, Port, deny, Reason)-FirewallSource
    ],
    fact_source(port_context(Port, PortType, Protocol), PortContextSource),
    fact_source(allow(Source, PortType, SocketClass, name_connect), AllowSource),
    fact_source(
        firewall_egress_rule(Source, Protocol, Port, deny, Reason),
        FirewallSource
    ).

audit_evidence(runtime_syscall_block, Finding, Evidence) :-
    Source = Finding.source,
    Syscall = Finding.syscall,
    Reason = Finding.reason,
    seccomp_profile(Source, Profile),
    Evidence = [
        seccomp_profile(Source, Profile)-ProfileSource,
        seccomp_rule(Profile, Syscall, deny, Reason)-RuleSource
    ],
    fact_source(seccomp_profile(Source, Profile), ProfileSource),
    fact_source(seccomp_rule(Profile, Syscall, deny, Reason), RuleSource).

audit_evidence(ai_agent_syscall_block, Finding, Evidence) :-
    Source = Finding.source,
    Syscall = Finding.syscall,
    Reason = Finding.reason,
    seccomp_profile(Source, Profile),
    Evidence = [
        has_attribute(Source, ai_agent_domain)-AgentAttributeSource,
        seccomp_profile(Source, Profile)-ProfileSource,
        seccomp_rule(Profile, Syscall, deny, Reason)-RuleSource
    ],
    fact_source(has_attribute(Source, ai_agent_domain), AgentAttributeSource),
    fact_source(seccomp_profile(Source, Profile), ProfileSource),
    fact_source(seccomp_rule(Profile, Syscall, deny, Reason), RuleSource).

audit_evidence(login_sensitive_capability, Finding, Evidence) :-
    Login = Finding.login,
    Domain = Finding.domain,
    Capability = Finding.capability,
    Reason = Finding.reason,
    login_mapping(Login, SelinuxUser),
    selinux_user_role(SelinuxUser, Role),
    Evidence = [
        login_mapping(Login, SelinuxUser)-LoginSource,
        selinux_user_role(SelinuxUser, Role)-UserRoleSource,
        role_type(Role, Domain)-RoleTypeSource,
        allow(Domain, self, capability, Capability)-AllowSource,
        sensitive_capability(Capability, Reason)-CapabilitySource
    ],
    fact_source(login_mapping(Login, SelinuxUser), LoginSource),
    fact_source(selinux_user_role(SelinuxUser, Role), UserRoleSource),
    fact_source(role_type(Role, Domain), RoleTypeSource),
    fact_source(allow(Domain, self, capability, Capability), AllowSource),
    fact_source(sensitive_capability(Capability, Reason), CapabilitySource).

audit_evidence(login_sensitive_process_permission, Finding, Evidence) :-
    Login = Finding.login,
    Domain = Finding.domain,
    Permission = Finding.permission,
    Reason = Finding.reason,
    login_mapping(Login, SelinuxUser),
    selinux_user_role(SelinuxUser, Role),
    Evidence = [
        login_mapping(Login, SelinuxUser)-LoginSource,
        selinux_user_role(SelinuxUser, Role)-UserRoleSource,
        role_type(Role, Domain)-RoleTypeSource,
        allow(Domain, self, process, Permission)-AllowSource,
        sensitive_process_permission(Permission, Reason)-PermissionSource
    ],
    fact_source(login_mapping(Login, SelinuxUser), LoginSource),
    fact_source(selinux_user_role(SelinuxUser, Role), UserRoleSource),
    fact_source(role_type(Role, Domain), RoleTypeSource),
    fact_source(allow(Domain, self, process, Permission), AllowSource),
    fact_source(sensitive_process_permission(Permission, Reason), PermissionSource).
