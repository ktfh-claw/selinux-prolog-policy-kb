:- begin_tests(selinux_rules).

:- use_module('../src/selinux_rules').

test(direct_allow_read_web_content) :-
    once(can_access(httpd_t, httpd_sys_content_t, file, read)).

test(negative_write_web_content, [fail]) :-
    can_access(httpd_t, httpd_sys_content_t, file, write).

test(effective_allow_from_enabled_boolean) :-
    once(can_access(httpd_t, http_port_t, tcp_socket, name_connect)).

test(disabled_conditional_is_not_effective, [fail]) :-
    can_access(httpd_t, user_home_t, file, read).

test(derived_read_web_content) :-
    once(can_read_web_content(httpd_t)).

test(path_read_web_content) :-
    once(can_access_path(httpd_t, '/var/www/html/index.html', file, read)).

test(path_read_helper) :-
    once(can_read_path(httpd_t, '/var/www/cgi-bin/admin.cgi')).

test(negative_path_write_static_content, [fail]) :-
    can_access_path(httpd_t, '/var/www/html/index.html', file, write).

test(disabled_conditional_path_read, [fail]) :-
    can_access_path(httpd_t, '/home/alice/public_html/index.html', file, read).

test(constrained_allow_is_not_effective, [fail]) :-
    can_access(user_t, secret_doc_t, file, read).

test(constrained_path_read_is_not_effective, [fail]) :-
    can_read_path(user_t, '/srv/secret/report.txt').

test(access_denied_by_constraint) :-
    once(access_denied_by_constraint(
        user_t,
        secret_doc_t,
        file,
        read,
        mls_range_mismatch
    )).

test(sensitivity_dominates_same_level) :-
    once(sensitivity_dominates(s0, s0)).

test(sensitivity_dominates_higher_level) :-
    once(sensitivity_dominates(s1, s0)).

test(sensitivity_does_not_dominate_higher_target, [fail]) :-
    sensitivity_dominates(s0, s1).

test(mls_read_allowed_when_range_and_categories_cover_target) :-
    once(mls_read_allowed(auditor_t, secret_doc_t)).

test(mls_read_blocked_by_sensitivity) :-
    once(mls_read_blocked(user_t, secret_doc_t, insufficient_mls_range)).

test(mls_read_blocked_by_missing_category) :-
    once(mls_read_blocked(
        auditor_limited_t,
        secret_doc_t,
        insufficient_mls_range
    )).

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
    once(can_domain_transition(init_t, daemon_exec_t, daemon_t)).

test(domain_transition_via_path) :-
    once(can_domain_transition_via_path(init_t, '/usr/sbin/exampled', daemon_t)).

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
    once(audit_finding(risky_web_shell_path, Finding)),
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

test(audit_finding_constraint_shape) :-
    once(audit_finding(constraint_blocked_allow, Finding)),
    assertion(Finding.source == user_t),
    assertion(Finding.target == secret_doc_t),
    assertion(Finding.reason == mls_range_mismatch).

test(audit_finding_mls_shape) :-
    once(audit_finding(mls_blocked_read, Finding)),
    assertion(Finding.source == user_t),
    assertion(Finding.target == secret_doc_t),
    assertion(Finding.reason == insufficient_mls_range).

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

test(audit_finding_constraint_evidence) :-
    once(audit_finding_with_evidence(constraint_blocked_allow, Finding)),
    assertion(Finding.reason == mls_range_mismatch),
    assertion(Finding.evidence = [
        allow(user_t, secret_doc_t, file, read)-_,
        constraint_denies(user_t, secret_doc_t, file, read, mls_range_mismatch)-_
    ]).

test(audit_finding_mls_evidence) :-
    once(audit_finding_with_evidence(mls_blocked_read, Finding)),
    assertion(Finding.reason == insufficient_mls_range),
    assertion(Finding.evidence = [
        allow(user_t, secret_doc_t, file, read)-_,
        mls_range(user_t, s0, s0, [c0])-_,
        mls_range(secret_doc_t, s1, s1, [c1])-_
    ]).

:- end_tests(selinux_rules).
