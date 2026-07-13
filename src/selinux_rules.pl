:- module(selinux_rules, [
    can_access/4,
    can_access_path/4,
    can_read_web_content/1,
    can_read_path/2,
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

can_access(Source, Target, Class, Permission) :-
    allow(Source, Target, Class, Permission).

can_access_path(Source, Path, Class, Permission) :-
    file_context(Path, Target, Class),
    allow(Source, Target, Class, Permission).

can_read_web_content(Source) :-
    allow(Source, httpd_sys_content_t, file, read).

can_read_path(Source, Path) :-
    can_access_path(Source, Path, file, read).

risky_web_shell_path(Source, Target, write_executable_content) :-
    allow(Source, Target, file, write),
    has_attribute(Source, webserver_domain),
    has_attribute(Target, executable_content).

risky_executable_content_path(Source, Path, write_executable_content) :-
    file_context(Path, Target, file),
    risky_web_shell_path(Source, Target, write_executable_content).

can_domain_transition(Source, Entrypoint, Target) :-
    type_transition(Source, Entrypoint, Target),
    allow(Source, Entrypoint, file, entrypoint),
    allow(Source, Target, process, transition).

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
