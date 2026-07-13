:- begin_tests(selinux_rules).

:- use_module('../src/selinux_rules').

test(direct_allow_read_web_content) :-
    can_access(httpd_t, httpd_sys_content_t, file, read).

test(negative_write_web_content, [fail]) :-
    can_access(httpd_t, httpd_sys_content_t, file, write).

test(derived_read_web_content) :-
    can_read_web_content(httpd_t).

test(path_read_web_content) :-
    can_access_path(httpd_t, '/var/www/html/index.html', file, read).

test(path_read_helper) :-
    can_read_path(httpd_t, '/var/www/cgi-bin/admin.cgi').

test(negative_path_write_static_content, [fail]) :-
    can_access_path(httpd_t, '/var/www/html/index.html', file, write).

test(risky_web_shell_path) :-
    once(risky_web_shell_path(
        httpd_t,
        httpd_sys_script_exec_t,
        write_executable_content
    )).

test(risky_executable_content_path) :-
    once(risky_executable_content_path(
        httpd_t,
        '/var/www/cgi-bin/admin.cgi',
        write_executable_content
    )).

test(negative_log_path_is_not_executable_content, [fail]) :-
    risky_executable_content_path(
        httpd_t,
        '/var/log/httpd/access.log',
        write_executable_content
    ).

test(domain_transition) :-
    can_domain_transition(init_t, daemon_exec_t, daemon_t).

test(domain_transition_via_path) :-
    can_domain_transition_via_path(init_t, '/usr/sbin/exampled', daemon_t).

test(negative_domain_transition_via_non_entrypoint_path, [fail]) :-
    can_domain_transition_via_path(init_t, '/var/www/html/index.html', daemon_t).

test(high_risk_policy_regression) :-
    once(high_risk_policy_regression(policy_v2, httpd_t, shadow_t, file, read)).

test(policy_regression_severity_critical) :-
    once(policy_regression_severity(
        policy_v2,
        httpd_t,
        shadow_t,
        file,
        read,
        critical
    )).

test(policy_regression_severity_high) :-
    once(policy_regression_severity(
        policy_v2,
        httpd_t,
        httpd_sys_script_exec_t,
        file,
        write,
        high
    )).

test(policy_regression_severity_low) :-
    once(policy_regression_severity(
        policy_v2,
        httpd_t,
        httpd_log_t,
        file,
        getattr,
        low
    )).

test(audit_finding_web_shell_shape) :-
    audit_finding(risky_web_shell_path, Finding),
    assertion(Finding.source == httpd_t),
    assertion(Finding.target == httpd_sys_script_exec_t).

test(audit_finding_path_shape) :-
    once(audit_finding(risky_executable_content_path, Finding)),
    assertion(Finding.source == httpd_t),
    assertion(Finding.path == '/var/www/cgi-bin/admin.cgi').

test(audit_finding_policy_regression_shape) :-
    once(audit_finding(high_risk_policy_regression, Finding)),
    assertion(Finding.policy_version == policy_v2),
    assertion(Finding.target == shadow_t).

test(audit_finding_web_shell_evidence) :-
    once(audit_finding_with_evidence(risky_web_shell_path, Finding)),
    assertion(Finding.source == httpd_t),
    assertion(Finding.target == httpd_sys_script_exec_t),
    assertion(Finding.evidence = [
        allow(httpd_t, httpd_sys_script_exec_t, file, write)-_,
        has_attribute(httpd_t, webserver_domain)-_,
        has_attribute(httpd_sys_script_exec_t, executable_content)-_
    ]).

test(audit_finding_path_evidence) :-
    once(audit_finding_with_evidence(risky_executable_content_path, Finding)),
    assertion(Finding.path == '/var/www/cgi-bin/admin.cgi'),
    assertion(Finding.evidence = [
        file_context('/var/www/cgi-bin/admin.cgi', httpd_sys_script_exec_t, file)-_,
        allow(httpd_t, httpd_sys_script_exec_t, file, write)-_,
        has_attribute(httpd_t, webserver_domain)-_,
        has_attribute(httpd_sys_script_exec_t, executable_content)-_
    ]).

test(audit_finding_policy_regression_evidence) :-
    once(audit_finding_with_evidence(high_risk_policy_regression, Finding)),
    assertion(Finding.policy_version == policy_v2),
    assertion(Finding.evidence = [
        new_allow(policy_v2, httpd_t, shadow_t, file, read)-_,
        has_attribute(shadow_t, credential_store)-_
    ]).

:- end_tests(selinux_rules).
