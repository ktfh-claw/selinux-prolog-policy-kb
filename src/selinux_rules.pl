:- module(selinux_rules, [
    can_access/4,
    can_read_web_content/1,
    risky_web_shell_path/3,
    can_domain_transition/3,
    high_risk_policy_regression/5,
    audit_finding/2
]).

:- use_module(selinux_facts).

can_access(Source, Target, Class, Permission) :-
    allow(Source, Target, Class, Permission).

can_read_web_content(Source) :-
    allow(Source, httpd_sys_content_t, file, read).

risky_web_shell_path(Source, Target, write_executable_content) :-
    allow(Source, Target, file, write),
    has_attribute(Source, webserver_domain),
    has_attribute(Target, executable_content).

can_domain_transition(Source, Entrypoint, Target) :-
    type_transition(Source, Entrypoint, Target),
    allow(Source, Entrypoint, file, entrypoint),
    allow(Source, Target, process, transition).

high_risk_policy_regression(PolicyVersion, Source, Target, Class, Permission) :-
    new_allow(PolicyVersion, Source, Target, Class, Permission),
    has_attribute(Target, credential_store),
    member(Permission, [read, write, append]).

audit_finding(risky_web_shell_path, finding{
    source: Source,
    target: Target,
    reason: write_executable_content
}) :-
    risky_web_shell_path(Source, Target, write_executable_content).

audit_finding(high_risk_policy_regression, finding{
    policy_version: PolicyVersion,
    source: Source,
    target: Target,
    class: Class,
    permission: Permission
}) :-
    high_risk_policy_regression(PolicyVersion, Source, Target, Class, Permission).
