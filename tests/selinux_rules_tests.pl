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

test(high_risk_policy_regression) :-
    once(high_risk_policy_regression(policy_v2, httpd_t, shadow_t, file, read)).

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

:- end_tests(selinux_rules).
