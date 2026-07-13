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

test(port_name_connect_from_enabled_boolean) :-
    once(can_name_connect_port(httpd_t, tcp, 80)).

test(port_name_connect_denies_unallowed_database_port, [fail]) :-
    can_name_connect_port(httpd_t, tcp, 5432).

test(ai_agent_selinux_can_name_connect_database_port) :-
    once(can_name_connect_port(ai_agent_t, tcp, 5432)).

test(runtime_allows_ai_agent_web_egress) :-
    once(runtime_name_connect_allowed(ai_agent_t, tcp, 80)).

test(runtime_blocks_ai_agent_database_egress, [fail]) :-
    runtime_name_connect_allowed(ai_agent_t, tcp, 5432).

test(runtime_name_connect_blocked_reason) :-
    once(runtime_name_connect_blocked(
        ai_agent_t,
        tcp,
        5432,
        database_egress_block
    )).

test(ai_agent_network_exposure) :-
    once(ai_agent_network_exposure(
        ai_agent_t,
        tcp,
        80,
        web_api_baseline
    )).

test(runtime_syscall_allowed_by_seccomp_profile) :-
    once(runtime_syscall_allowed(ai_agent_t, read)).

test(runtime_syscall_blocked_by_seccomp_profile, [fail]) :-
    runtime_syscall_allowed(ai_agent_t, clone3).

test(runtime_syscall_blocked_reason) :-
    once(runtime_syscall_blocked(
        ai_agent_t,
        clone3,
        no_unprivileged_namespace_creation
    )).

test(ai_agent_syscall_block) :-
    once(ai_agent_syscall_block(
        ai_agent_t,
        bpf,
        block_kernel_observability
    )).

test(runtime_resource_limit_from_cgroup) :-
    once(runtime_resource_limited(
        ai_agent_t,
        pids,
        64,
        count,
        pids_max_64
    )).

test(ai_agent_resource_limit_from_cgroup) :-
    once(ai_agent_resource_limit(
        ai_agent_t,
        memory,
        512,
        mebibytes,
        memory_max_512m
    )).

test(non_ai_agent_resource_limit_is_not_agent_scoped, [fail]) :-
    ai_agent_resource_limit(
        log_shipper_t,
        memory,
        256,
        mebibytes,
        log_memory_cap
    ).

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

test(type_bound_allows_parent_permitted_access) :-
    once(can_access(sandbox_web_t, httpd_sys_content_t, file, read)).

test(type_bound_blocks_child_extra_access, [fail]) :-
    can_access(sandbox_web_t, httpd_log_t, file, append).

test(type_bound_blocks_when_parent_candidate_is_constrained, [fail]) :-
    can_access(sandbox_secret_reader_t, secret_doc_t, file, read).

test(access_denied_by_type_bound) :-
    once(access_denied_by_type_bound(
        sandbox_web_t,
        httpd_log_t,
        file,
        append,
        sandbox_web_parent_t,
        parent_missing_effective_allow
    )).

test(access_denied_by_type_bound_parent_constraint) :-
    once(access_denied_by_type_bound(
        sandbox_secret_reader_t,
        secret_doc_t,
        file,
        read,
        sandbox_secret_parent_t,
        parent_missing_effective_allow
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

test(capability_allow_is_effective) :-
    once(can_access(ai_agent_t, self, capability, sys_admin)).

test(sensitive_capability_grant) :-
    once(has_sensitive_capability(ai_agent_t, sys_admin, kernel_administration)).

test(ai_agent_sensitive_capability_grant) :-
    once(ai_agent_sensitive_capability(
        ai_agent_t,
        dac_override,
        dac_bypass
    )).

test(non_sensitive_capability_is_not_flagged, [fail]) :-
    has_sensitive_capability(log_shipper_t, audit_write, _Reason).

test(process_permission_allow_is_effective) :-
    once(can_access(ai_agent_t, self, process, dyntransition)).

test(sensitive_process_permission_grant) :-
    once(has_sensitive_process_permission(
        ai_agent_t,
        dyntransition,
        arbitrary_domain_transition
    )).

test(ai_agent_sensitive_process_permission_grant) :-
    once(ai_agent_sensitive_process_permission(
        ai_agent_t,
        noatsecure,
        unsafe_exec_environment
    )).

test(non_sensitive_process_permission_is_not_flagged, [fail]) :-
    has_sensitive_process_permission(log_shipper_t, sigchld, _Reason).

test(login_domain_resolves_role_type) :-
    once(login_domain(agent_service, ai_agent_t)).

test(login_can_access_sensitive_capability) :-
    once(login_can_access(agent_service, self, capability, sys_admin)).

test(login_can_access_respects_effective_allow, [fail]) :-
    login_can_access(alice, secret_doc_t, file, read).

test(login_sensitive_capability_grant) :-
    once(login_sensitive_capability(
        agent_service,
        ai_agent_t,
        dac_override,
        dac_bypass
    )).

test(login_sensitive_process_permission_grant) :-
    once(login_sensitive_process_permission(
        agent_service,
        ai_agent_t,
        dyntransition,
        arbitrary_domain_transition
    )).

test(login_non_sensitive_capability_is_not_flagged, [fail]) :-
    login_sensitive_capability(log_shipper, log_shipper_t, audit_write, _Reason).

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

test(audit_finding_type_bound_shape) :-
    once(audit_finding(type_bound_blocked_allow, Finding)),
    assertion(Finding.source == sandbox_web_t),
    assertion(Finding.parent == sandbox_web_parent_t),
    assertion(Finding.target == httpd_log_t),
    assertion(Finding.reason == parent_missing_effective_allow).

test(audit_finding_mls_shape) :-
    once(audit_finding(mls_blocked_read, Finding)),
    assertion(Finding.source == user_t),
    assertion(Finding.target == secret_doc_t),
    assertion(Finding.reason == insufficient_mls_range).

test(audit_finding_ai_agent_capability_shape) :-
    once(audit_finding(
        ai_agent_sensitive_capability,
        finding{
            source: ai_agent_t,
            capability: dac_override,
            reason: dac_bypass
        }
    )).

test(audit_finding_ai_agent_process_permission_shape) :-
    once(audit_finding(
        ai_agent_sensitive_process_permission,
        finding{
            source: ai_agent_t,
            permission: dyntransition,
            reason: arbitrary_domain_transition
        }
    )).

test(audit_finding_ai_agent_network_exposure_shape) :-
    once(audit_finding(
        ai_agent_network_exposure,
        finding{
            source: ai_agent_t,
            protocol: tcp,
            port: 80,
            reason: web_api_baseline
        }
    )).

test(audit_finding_runtime_network_block_shape) :-
    once(audit_finding(
        runtime_network_block,
        finding{
            source: ai_agent_t,
            protocol: tcp,
            port: 5432,
            reason: database_egress_block
        }
    )).

test(audit_finding_runtime_syscall_block_shape) :-
    once(audit_finding(
        runtime_syscall_block,
        finding{
            source: ai_agent_t,
            syscall: clone3,
            reason: no_unprivileged_namespace_creation
        }
    )).

test(audit_finding_ai_agent_syscall_block_shape) :-
    once(audit_finding(
        ai_agent_syscall_block,
        finding{
            source: ai_agent_t,
            syscall: bpf,
            reason: block_kernel_observability
        }
    )).

test(audit_finding_runtime_resource_limit_shape) :-
    once(audit_finding(
        runtime_resource_limit,
        finding{
            source: ai_agent_t,
            resource: pids,
            value: 64,
            unit: count,
            reason: pids_max_64
        }
    )).

test(audit_finding_ai_agent_resource_limit_shape) :-
    once(audit_finding(
        ai_agent_resource_limit,
        finding{
            source: ai_agent_t,
            resource: memory,
            value: 512,
            unit: mebibytes,
            reason: memory_max_512m
        }
    )).

test(audit_finding_login_capability_shape) :-
    once(audit_finding(
        login_sensitive_capability,
        finding{
            login: agent_service,
            domain: ai_agent_t,
            capability: sys_admin,
            reason: kernel_administration
        }
    )).

test(audit_finding_login_process_permission_shape) :-
    once(audit_finding(
        login_sensitive_process_permission,
        finding{
            login: agent_service,
            domain: ai_agent_t,
            permission: noatsecure,
            reason: unsafe_exec_environment
        }
    )).

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

test(audit_finding_type_bound_evidence) :-
    once(audit_finding_with_evidence(type_bound_blocked_allow, Finding)),
    assertion(Finding.reason == parent_missing_effective_allow),
    assertion(Finding.evidence = [
        allow(sandbox_web_t, httpd_log_t, file, append)-_,
        type_bound(sandbox_web_t, sandbox_web_parent_t)-_
    ]).

test(audit_finding_mls_evidence) :-
    once(audit_finding_with_evidence(mls_blocked_read, Finding)),
    assertion(Finding.reason == insufficient_mls_range),
    assertion(Finding.evidence = [
        allow(user_t, secret_doc_t, file, read)-_,
        mls_range(user_t, s0, s0, [c0])-_,
        mls_range(secret_doc_t, s1, s1, [c1])-_
    ]).

test(audit_finding_ai_agent_capability_evidence) :-
    once((
        audit_finding_with_evidence(ai_agent_sensitive_capability, Finding),
        Finding.capability == dac_override
    )),
    assertion(Finding.capability == dac_override),
    assertion(Finding.evidence = [
        allow(ai_agent_t, self, capability, dac_override)-_,
        has_attribute(ai_agent_t, ai_agent_domain)-_,
        sensitive_capability(dac_override, dac_bypass)-_
    ]).

test(audit_finding_ai_agent_process_permission_evidence) :-
    once((
        audit_finding_with_evidence(
            ai_agent_sensitive_process_permission,
            Finding
        ),
        Finding.permission == noatsecure
    )),
    assertion(Finding.permission == noatsecure),
    assertion(Finding.evidence = [
        allow(ai_agent_t, self, process, noatsecure)-_,
        has_attribute(ai_agent_t, ai_agent_domain)-_,
        sensitive_process_permission(noatsecure, unsafe_exec_environment)-_
    ]).

test(audit_finding_ai_agent_network_exposure_evidence) :-
    once(audit_finding_with_evidence(ai_agent_network_exposure, Finding)),
    assertion(Finding.source == ai_agent_t),
    assertion(Finding.port == 80),
    assertion(Finding.evidence = [
        has_attribute(ai_agent_t, ai_agent_domain)-_,
        port_context(80, http_port_t, tcp)-_,
        allow(ai_agent_t, http_port_t, tcp_socket, name_connect)-_,
        firewall_egress_rule(ai_agent_t, tcp, 80, allow, web_api_baseline)-_
    ]).

test(audit_finding_runtime_network_block_evidence) :-
    once(audit_finding_with_evidence(runtime_network_block, Finding)),
    assertion(Finding.source == ai_agent_t),
    assertion(Finding.port == 5432),
    assertion(Finding.evidence = [
        port_context(5432, postgresql_port_t, tcp)-_,
        allow(ai_agent_t, postgresql_port_t, tcp_socket, name_connect)-_,
        firewall_egress_rule(ai_agent_t, tcp, 5432, deny, database_egress_block)-_
    ]).

test(audit_finding_runtime_syscall_block_evidence) :-
    once(audit_finding_with_evidence(runtime_syscall_block, Finding)),
    assertion(Finding.source == ai_agent_t),
    assertion(Finding.syscall == clone3),
    assertion(Finding.evidence = [
        seccomp_profile(ai_agent_t, ai_agent_restricted)-_,
        seccomp_rule(ai_agent_restricted, clone3, deny, no_unprivileged_namespace_creation)-_
    ]).

test(audit_finding_ai_agent_syscall_block_evidence) :-
    once(audit_finding_with_evidence(ai_agent_syscall_block, Finding)),
    assertion(Finding.source == ai_agent_t),
    assertion(Finding.syscall == clone3),
    assertion(Finding.evidence = [
        has_attribute(ai_agent_t, ai_agent_domain)-_,
        seccomp_profile(ai_agent_t, ai_agent_restricted)-_,
        seccomp_rule(ai_agent_restricted, clone3, deny, no_unprivileged_namespace_creation)-_
    ]).

test(audit_finding_runtime_resource_limit_evidence) :-
    once((
        audit_finding_with_evidence(runtime_resource_limit, Finding),
        Finding.resource == pids
    )),
    assertion(Finding.source == ai_agent_t),
    assertion(Finding.evidence = [
        cgroup_assignment(ai_agent_t, ai_agent_slice)-_,
        cgroup_limit(ai_agent_slice, pids, 64, count, pids_max_64)-_
    ]).

test(audit_finding_ai_agent_resource_limit_evidence) :-
    once((
        audit_finding_with_evidence(ai_agent_resource_limit, Finding),
        Finding.resource == memory
    )),
    assertion(Finding.source == ai_agent_t),
    assertion(Finding.evidence = [
        has_attribute(ai_agent_t, ai_agent_domain)-_,
        cgroup_assignment(ai_agent_t, ai_agent_slice)-_,
        cgroup_limit(ai_agent_slice, memory, 512, mebibytes, memory_max_512m)-_
    ]).

test(audit_finding_login_capability_evidence) :-
    once((
        audit_finding_with_evidence(login_sensitive_capability, Finding),
        Finding.capability == dac_override
    )),
    assertion(Finding.login == agent_service),
    assertion(Finding.domain == ai_agent_t),
    assertion(Finding.evidence = [
        login_mapping(agent_service, agent_u)-_,
        selinux_user_role(agent_u, agent_r)-_,
        role_type(agent_r, ai_agent_t)-_,
        allow(ai_agent_t, self, capability, dac_override)-_,
        sensitive_capability(dac_override, dac_bypass)-_
    ]).

test(audit_finding_login_process_permission_evidence) :-
    once((
        audit_finding_with_evidence(
            login_sensitive_process_permission,
            Finding
        ),
        Finding.permission == dyntransition
    )),
    assertion(Finding.login == agent_service),
    assertion(Finding.domain == ai_agent_t),
    assertion(Finding.evidence = [
        login_mapping(agent_service, agent_u)-_,
        selinux_user_role(agent_u, agent_r)-_,
        role_type(agent_r, ai_agent_t)-_,
        allow(ai_agent_t, self, process, dyntransition)-_,
        sensitive_process_permission(dyntransition, arbitrary_domain_transition)-_
    ]).

:- end_tests(selinux_rules).
