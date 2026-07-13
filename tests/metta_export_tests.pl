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
        '(administrator-action connect_database ai_agent_t (name_connect tcp 5432))'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(administrator-action create_namespace ai_agent_t (syscall clone3))'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(administrator-service-action restart_loop_risk ai_agent_service (restart_policy always))'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(allow ai_agent_t self capability dac_override)'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(sensitive-capability dac_override dac_bypass)'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(sensitive-process-permission dyntransition arbitrary_domain_transition)'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(firewall-egress-rule ai_agent_t tcp 5432 deny database_egress_block)'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(seccomp-profile ai_agent_t ai_agent_restricted)'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(seccomp-rule ai_agent_restricted clone3 deny no_unprivileged_namespace_creation)'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(cgroup-assignment ai_agent_t ai_agent_slice)'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(cgroup-limit ai_agent_slice pids 64 count pids_max_64)'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(service-unit ai_agent_service agent_service "/usr/local/bin/ai-agentd" always)'
    )),
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
        '(login-mapping agent_service agent_u)'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(selinux-user-role agent_u agent_r)'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(role-type agent_r ai_agent_t)'
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
        '(port-context 80 http_port_t tcp)'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        '(type-bound sandbox_web_t sandbox_web_parent_t)'
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
        'can_name_connect_http_port_80'
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
        'ai_agent_has_dac_override'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        'ai_agent_has_dyntransition'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        'ai_agent_database_egress_blocked'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        'ai_agent_clone3_blocked_by_seccomp'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        'ai_agent_pids_limited_by_cgroup'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        'agent_service_maps_to_sensitive_agent_domain'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        'service_domain_mismatch_mislabelled_agent_service'
    )),
    once(sub_string(
        Text,
        _,
        _,
        _,
        'critical_policy_regression_policy_v2_httpd_shadow_read'
    )).

:- end_tests(metta_export).
