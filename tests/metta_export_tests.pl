:- begin_tests(metta_export).

:- use_module(library(readutil)).
:- use_module('../scripts/export_metta').
:- use_module('../scripts/export_omegaclaw_prior').

test(export_matches_fixture) :-
    with_output_to(string(Actual), export_metta),
    read_file_to_string(
        'fixtures/selinux_policy.metta',
        Expected,
        []
    ),
    assertion(Actual == Expected).

test(omegaclaw_prior_matches_fixture) :-
    omegaclaw_prior_text(Actual),
    read_file_to_string(
        'fixtures/omegaclaw_knowledge_prior.md',
        Expected,
        []
    ),
    assertion(Actual == Expected).

test(omegaclaw_prior_contains_path_and_severity_baselines) :-
    omegaclaw_prior_text(Text),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(boolean-state httpd_can_network_connect true)'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(conditional-allow httpd_enable_homedirs httpd_t user_home_t file read)'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(constraint-denies user_t secret_doc_t file read mls_range_mismatch)'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(file-context "/var/www/cgi-bin/admin.cgi" httpd_sys_script_exec_t file)'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(mls-range user_t s0 s0 (c0))'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(mls-range auditor_t s0 s1 (c0 c1))'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(policy-regression-severity policy_v2 httpd_t shadow_t file read critical)'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        'blocked_secret_doc_read_for_user_t'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        'mls_blocked_secret_doc_read_for_user_t'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        'critical_policy_regression_policy_v2_httpd_shadow_read'
    )).

:- end_tests(metta_export).
