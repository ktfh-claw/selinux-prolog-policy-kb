:- module(selinux_facts, [
    allow/4,
    boolean_state/2,
    conditional_allow/5,
    constraint_denies/5,
    sensitivity_level/2,
    mls_range/4,
    type_bound/2,
    sensitive_capability/2,
    sensitive_process_permission/2,
    firewall_egress_rule/5,
    seccomp_profile/2,
    seccomp_rule/4,
    cgroup_assignment/2,
    cgroup_limit/5,
    service_unit/4,
    login_mapping/2,
    selinux_user_role/2,
    role_type/2,
    has_attribute/2,
    type_transition/3,
    new_allow/5,
    file_context/3,
    port_context/3,
    fact_source/2
]).

% Toy imported SELinux profile shaped like a SETools/sepolicy_analysis export.

allow(httpd_t, httpd_sys_content_t, file, read).
allow(httpd_t, httpd_log_t, file, append).
allow(httpd_t, httpd_sys_script_exec_t, file, write).
allow(httpd_t, httpd_sys_script_exec_t, file, read).
allow(init_t, daemon_exec_t, file, entrypoint).
allow(init_t, daemon_t, process, transition).
allow(init_t, ai_agent_exec_t, file, entrypoint).
allow(init_t, ai_agent_t, process, transition).
allow(init_t, log_shipper_exec_t, file, entrypoint).
allow(init_t, log_shipper_t, process, transition).
allow(user_t, secret_doc_t, file, read).
allow(auditor_t, secret_doc_t, file, read).
allow(auditor_limited_t, secret_doc_t, file, read).
allow(sandbox_web_t, httpd_sys_content_t, file, read).
allow(sandbox_web_parent_t, httpd_sys_content_t, file, read).
allow(sandbox_web_t, httpd_log_t, file, append).
allow(sandbox_secret_reader_t, secret_doc_t, file, read).
allow(sandbox_secret_parent_t, secret_doc_t, file, read).
allow(ai_agent_t, self, capability, sys_admin).
allow(ai_agent_t, self, capability, dac_override).
allow(ai_agent_t, self, process, dyntransition).
allow(ai_agent_t, self, process, noatsecure).
allow(ai_agent_t, http_port_t, tcp_socket, name_connect).
allow(ai_agent_t, postgresql_port_t, tcp_socket, name_connect).
allow(log_shipper_t, self, capability, audit_write).
allow(log_shipper_t, self, process, sigchld).

boolean_state(httpd_can_network_connect, true).
boolean_state(httpd_enable_homedirs, false).

conditional_allow(httpd_can_network_connect, httpd_t, http_port_t, tcp_socket, name_connect).
conditional_allow(httpd_enable_homedirs, httpd_t, user_home_t, file, read).

constraint_denies(user_t, secret_doc_t, file, read, mls_range_mismatch).
constraint_denies(
    sandbox_secret_parent_t,
    secret_doc_t,
    file,
    read,
    parent_mls_range_mismatch
).

sensitivity_level(s0, 0).
sensitivity_level(s1, 1).

mls_range(user_t, s0, s0, [c0]).
mls_range(auditor_t, s0, s1, [c0, c1]).
mls_range(auditor_limited_t, s0, s1, [c0]).
mls_range(secret_doc_t, s1, s1, [c1]).

type_bound(sandbox_web_t, sandbox_web_parent_t).
type_bound(sandbox_secret_reader_t, sandbox_secret_parent_t).

sensitive_capability(sys_admin, kernel_administration).
sensitive_capability(dac_override, dac_bypass).

sensitive_process_permission(dyntransition, arbitrary_domain_transition).
sensitive_process_permission(noatsecure, unsafe_exec_environment).

firewall_egress_rule(ai_agent_t, tcp, 80, allow, web_api_baseline).
firewall_egress_rule(ai_agent_t, tcp, 5432, deny, database_egress_block).
firewall_egress_rule(log_shipper_t, tcp, 443, allow, log_export_baseline).

seccomp_profile(ai_agent_t, ai_agent_restricted).
seccomp_profile(log_shipper_t, log_shipper_restricted).

seccomp_rule(ai_agent_restricted, read, allow, baseline_io).
seccomp_rule(ai_agent_restricted, clone3, deny, no_unprivileged_namespace_creation).
seccomp_rule(ai_agent_restricted, bpf, deny, block_kernel_observability).
seccomp_rule(log_shipper_restricted, write, allow, baseline_io).

cgroup_assignment(ai_agent_t, ai_agent_slice).
cgroup_assignment(log_shipper_t, log_shipper_slice).

cgroup_limit(ai_agent_slice, pids, 64, count, pids_max_64).
cgroup_limit(ai_agent_slice, memory, 512, mebibytes, memory_max_512m).
cgroup_limit(log_shipper_slice, memory, 256, mebibytes, log_memory_cap).

service_unit(ai_agent_service, agent_service, '/usr/local/bin/ai-agentd', always).
service_unit(log_shipper_service, log_shipper, '/usr/local/bin/log-shipper', on_failure).
service_unit(
    mislabelled_agent_service,
    agent_service,
    '/usr/local/bin/log-shipper',
    always
).

login_mapping(alice, user_u).
login_mapping(agent_service, agent_u).
login_mapping(log_shipper, log_u).

selinux_user_role(user_u, user_r).
selinux_user_role(agent_u, agent_r).
selinux_user_role(log_u, log_r).

role_type(user_r, user_t).
role_type(agent_r, ai_agent_t).
role_type(log_r, log_shipper_t).

has_attribute(httpd_t, webserver_domain).
has_attribute(ai_agent_t, ai_agent_domain).
has_attribute(httpd_sys_script_exec_t, executable_content).
has_attribute(shadow_t, credential_store).

type_transition(init_t, daemon_exec_t, daemon_t).
type_transition(init_t, ai_agent_exec_t, ai_agent_t).
type_transition(init_t, log_shipper_exec_t, log_shipper_t).

new_allow(policy_v2, httpd_t, shadow_t, file, read).
new_allow(policy_v2, httpd_t, httpd_sys_script_exec_t, file, write).
new_allow(policy_v2, httpd_t, httpd_log_t, file, getattr).

file_context('/var/www/html/index.html', httpd_sys_content_t, file).
file_context('/var/www/cgi-bin/admin.cgi', httpd_sys_script_exec_t, file).
file_context('/var/log/httpd/access.log', httpd_log_t, file).
file_context('/etc/shadow', shadow_t, file).
file_context('/usr/sbin/exampled', daemon_exec_t, file).
file_context('/usr/local/bin/ai-agentd', ai_agent_exec_t, file).
file_context('/usr/local/bin/log-shipper', log_shipper_exec_t, file).
file_context('/home/alice/public_html/index.html', user_home_t, file).
file_context('/srv/secret/report.txt', secret_doc_t, file).

port_context(80, http_port_t, tcp).
port_context(5432, postgresql_port_t, tcp).

fact_source(
    allow(httpd_t, httpd_sys_content_t, file, read),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow httpd_t httpd_sys_content_t:file read'}
).
fact_source(
    allow(httpd_t, httpd_log_t, file, append),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow httpd_t httpd_log_t:file append'}
).
fact_source(
    allow(httpd_t, httpd_sys_script_exec_t, file, write),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow httpd_t httpd_sys_script_exec_t:file write'}
).
fact_source(
    allow(httpd_t, httpd_sys_script_exec_t, file, read),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow httpd_t httpd_sys_script_exec_t:file read'}
).
fact_source(
    allow(init_t, daemon_exec_t, file, entrypoint),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow init_t daemon_exec_t:file entrypoint'}
).
fact_source(
    allow(init_t, daemon_t, process, transition),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow init_t daemon_t:process transition'}
).
fact_source(
    allow(init_t, ai_agent_exec_t, file, entrypoint),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow init_t ai_agent_exec_t:file entrypoint'}
).
fact_source(
    allow(init_t, ai_agent_t, process, transition),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow init_t ai_agent_t:process transition'}
).
fact_source(
    allow(init_t, log_shipper_exec_t, file, entrypoint),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow init_t log_shipper_exec_t:file entrypoint'}
).
fact_source(
    allow(init_t, log_shipper_t, process, transition),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow init_t log_shipper_t:process transition'}
).
fact_source(
    allow(user_t, secret_doc_t, file, read),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow user_t secret_doc_t:file read'}
).
fact_source(
    allow(auditor_t, secret_doc_t, file, read),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow auditor_t secret_doc_t:file read'}
).
fact_source(
    allow(auditor_limited_t, secret_doc_t, file, read),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow auditor_limited_t secret_doc_t:file read'}
).
fact_source(
    allow(sandbox_web_t, httpd_sys_content_t, file, read),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow sandbox_web_t httpd_sys_content_t:file read'}
).
fact_source(
    allow(sandbox_web_parent_t, httpd_sys_content_t, file, read),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow sandbox_web_parent_t httpd_sys_content_t:file read'}
).
fact_source(
    allow(sandbox_web_t, httpd_log_t, file, append),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow sandbox_web_t httpd_log_t:file append'}
).
fact_source(
    allow(sandbox_secret_reader_t, secret_doc_t, file, read),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow sandbox_secret_reader_t secret_doc_t:file read'}
).
fact_source(
    allow(sandbox_secret_parent_t, secret_doc_t, file, read),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow sandbox_secret_parent_t secret_doc_t:file read'}
).
fact_source(
    allow(ai_agent_t, self, capability, sys_admin),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow ai_agent_t self:capability sys_admin'}
).
fact_source(
    allow(ai_agent_t, self, capability, dac_override),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow ai_agent_t self:capability dac_override'}
).
fact_source(
    allow(ai_agent_t, self, process, dyntransition),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow ai_agent_t self:process dyntransition'}
).
fact_source(
    allow(ai_agent_t, self, process, noatsecure),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow ai_agent_t self:process noatsecure'}
).
fact_source(
    allow(ai_agent_t, http_port_t, tcp_socket, name_connect),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow ai_agent_t http_port_t:tcp_socket name_connect'}
).
fact_source(
    allow(ai_agent_t, postgresql_port_t, tcp_socket, name_connect),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow ai_agent_t postgresql_port_t:tcp_socket name_connect'}
).
fact_source(
    allow(log_shipper_t, self, capability, audit_write),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow log_shipper_t self:capability audit_write'}
).
fact_source(
    allow(log_shipper_t, self, process, sigchld),
    source{tool: setools, artifact: 'toy_policy.allow', selector: 'allow log_shipper_t self:process sigchld'}
).

fact_source(
    boolean_state(httpd_can_network_connect, true),
    source{tool: sepolicy, artifact: 'toy_booleans', selector: 'httpd_can_network_connect --> on'}
).
fact_source(
    boolean_state(httpd_enable_homedirs, false),
    source{tool: sepolicy, artifact: 'toy_booleans', selector: 'httpd_enable_homedirs --> off'}
).

fact_source(
    conditional_allow(httpd_can_network_connect, httpd_t, http_port_t, tcp_socket, name_connect),
    source{tool: setools, artifact: 'toy_policy.conditional_allow', selector: 'if httpd_can_network_connect allow httpd_t http_port_t:tcp_socket name_connect'}
).
fact_source(
    conditional_allow(httpd_enable_homedirs, httpd_t, user_home_t, file, read),
    source{tool: setools, artifact: 'toy_policy.conditional_allow', selector: 'if httpd_enable_homedirs allow httpd_t user_home_t:file read'}
).

fact_source(
    constraint_denies(user_t, secret_doc_t, file, read, mls_range_mismatch),
    source{tool: setools, artifact: 'toy_policy.constraints', selector: 'constrain file read (mls range mismatch)'}
).
fact_source(
    constraint_denies(
        sandbox_secret_parent_t,
        secret_doc_t,
        file,
        read,
        parent_mls_range_mismatch
    ),
    source{tool: setools, artifact: 'toy_policy.constraints', selector: 'constrain parent bounded file read (mls range mismatch)'}
).

fact_source(
    sensitivity_level(s0, 0),
    source{tool: setools, artifact: 'toy_policy.mls', selector: 'sensitivity s0 rank 0'}
).
fact_source(
    sensitivity_level(s1, 1),
    source{tool: setools, artifact: 'toy_policy.mls', selector: 'sensitivity s1 rank 1'}
).

fact_source(
    mls_range(user_t, s0, s0, [c0]),
    source{tool: sepolicy, artifact: 'toy_policy.mls', selector: 'user_t:s0-s0:c0'}
).
fact_source(
    mls_range(auditor_t, s0, s1, [c0, c1]),
    source{tool: sepolicy, artifact: 'toy_policy.mls', selector: 'auditor_t:s0-s1:c0,c1'}
).
fact_source(
    mls_range(auditor_limited_t, s0, s1, [c0]),
    source{tool: sepolicy, artifact: 'toy_policy.mls', selector: 'auditor_limited_t:s0-s1:c0'}
).
fact_source(
    mls_range(secret_doc_t, s1, s1, [c1]),
    source{tool: sepolicy, artifact: 'toy_policy.mls', selector: 'secret_doc_t:s1-s1:c1'}
).

fact_source(
    type_bound(sandbox_web_t, sandbox_web_parent_t),
    source{tool: setools, artifact: 'toy_policy.typebounds', selector: 'typebounds sandbox_web_parent_t sandbox_web_t'}
).
fact_source(
    type_bound(sandbox_secret_reader_t, sandbox_secret_parent_t),
    source{tool: setools, artifact: 'toy_policy.typebounds', selector: 'typebounds sandbox_secret_parent_t sandbox_secret_reader_t'}
).

fact_source(
    sensitive_capability(sys_admin, kernel_administration),
    source{tool: local_rubric, artifact: 'capability_severity', selector: 'sys_admin'}
).
fact_source(
    sensitive_capability(dac_override, dac_bypass),
    source{tool: local_rubric, artifact: 'capability_severity', selector: 'dac_override'}
).

fact_source(
    sensitive_process_permission(dyntransition, arbitrary_domain_transition),
    source{tool: local_rubric, artifact: 'process_permission_severity', selector: 'dyntransition'}
).
fact_source(
    sensitive_process_permission(noatsecure, unsafe_exec_environment),
    source{tool: local_rubric, artifact: 'process_permission_severity', selector: 'noatsecure'}
).

fact_source(
    firewall_egress_rule(ai_agent_t, tcp, 80, allow, web_api_baseline),
    source{tool: local_runtime_profile, artifact: 'toy_firewall_rules', selector: 'ai_agent_t tcp/80 allow'}
).
fact_source(
    firewall_egress_rule(ai_agent_t, tcp, 5432, deny, database_egress_block),
    source{tool: local_runtime_profile, artifact: 'toy_firewall_rules', selector: 'ai_agent_t tcp/5432 deny'}
).
fact_source(
    firewall_egress_rule(log_shipper_t, tcp, 443, allow, log_export_baseline),
    source{tool: local_runtime_profile, artifact: 'toy_firewall_rules', selector: 'log_shipper_t tcp/443 allow'}
).

fact_source(
    seccomp_profile(ai_agent_t, ai_agent_restricted),
    source{tool: local_runtime_profile, artifact: 'toy_seccomp_profiles', selector: 'ai_agent_t -> ai_agent_restricted'}
).
fact_source(
    seccomp_profile(log_shipper_t, log_shipper_restricted),
    source{tool: local_runtime_profile, artifact: 'toy_seccomp_profiles', selector: 'log_shipper_t -> log_shipper_restricted'}
).

fact_source(
    seccomp_rule(ai_agent_restricted, read, allow, baseline_io),
    source{tool: local_runtime_profile, artifact: 'toy_seccomp_rules', selector: 'ai_agent_restricted read allow'}
).
fact_source(
    seccomp_rule(ai_agent_restricted, clone3, deny, no_unprivileged_namespace_creation),
    source{tool: local_runtime_profile, artifact: 'toy_seccomp_rules', selector: 'ai_agent_restricted clone3 deny'}
).
fact_source(
    seccomp_rule(ai_agent_restricted, bpf, deny, block_kernel_observability),
    source{tool: local_runtime_profile, artifact: 'toy_seccomp_rules', selector: 'ai_agent_restricted bpf deny'}
).
fact_source(
    seccomp_rule(log_shipper_restricted, write, allow, baseline_io),
    source{tool: local_runtime_profile, artifact: 'toy_seccomp_rules', selector: 'log_shipper_restricted write allow'}
).

fact_source(
    cgroup_assignment(ai_agent_t, ai_agent_slice),
    source{tool: local_runtime_profile, artifact: 'toy_cgroup_assignments', selector: 'ai_agent_t -> ai_agent_slice'}
).
fact_source(
    cgroup_assignment(log_shipper_t, log_shipper_slice),
    source{tool: local_runtime_profile, artifact: 'toy_cgroup_assignments', selector: 'log_shipper_t -> log_shipper_slice'}
).

fact_source(
    cgroup_limit(ai_agent_slice, pids, 64, count, pids_max_64),
    source{tool: local_runtime_profile, artifact: 'toy_cgroup_limits', selector: 'ai_agent_slice pids.max 64'}
).
fact_source(
    cgroup_limit(ai_agent_slice, memory, 512, mebibytes, memory_max_512m),
    source{tool: local_runtime_profile, artifact: 'toy_cgroup_limits', selector: 'ai_agent_slice memory.max 512M'}
).
fact_source(
    cgroup_limit(log_shipper_slice, memory, 256, mebibytes, log_memory_cap),
    source{tool: local_runtime_profile, artifact: 'toy_cgroup_limits', selector: 'log_shipper_slice memory.max 256M'}
).

fact_source(
    service_unit(ai_agent_service, agent_service, '/usr/local/bin/ai-agentd', always),
    source{tool: systemd, artifact: 'toy_units', selector: 'ai-agent.service User=agent_service ExecStart=/usr/local/bin/ai-agentd Restart=always'}
).
fact_source(
    service_unit(log_shipper_service, log_shipper, '/usr/local/bin/log-shipper', on_failure),
    source{tool: systemd, artifact: 'toy_units', selector: 'log-shipper.service User=log_shipper ExecStart=/usr/local/bin/log-shipper Restart=on-failure'}
).
fact_source(
    service_unit(
        mislabelled_agent_service,
        agent_service,
        '/usr/local/bin/log-shipper',
        always
    ),
    source{tool: systemd, artifact: 'toy_units', selector: 'mislabelled-agent.service User=agent_service ExecStart=/usr/local/bin/log-shipper Restart=always'}
).

fact_source(
    login_mapping(alice, user_u),
    source{tool: semanage, artifact: 'toy_login_mappings', selector: 'alice -> user_u'}
).
fact_source(
    login_mapping(agent_service, agent_u),
    source{tool: semanage, artifact: 'toy_login_mappings', selector: 'agent_service -> agent_u'}
).
fact_source(
    login_mapping(log_shipper, log_u),
    source{tool: semanage, artifact: 'toy_login_mappings', selector: 'log_shipper -> log_u'}
).

fact_source(
    selinux_user_role(user_u, user_r),
    source{tool: sepolicy, artifact: 'toy_users', selector: 'user user_u roles { user_r }'}
).
fact_source(
    selinux_user_role(agent_u, agent_r),
    source{tool: sepolicy, artifact: 'toy_users', selector: 'user agent_u roles { agent_r }'}
).
fact_source(
    selinux_user_role(log_u, log_r),
    source{tool: sepolicy, artifact: 'toy_users', selector: 'user log_u roles { log_r }'}
).

fact_source(
    role_type(user_r, user_t),
    source{tool: setools, artifact: 'toy_policy.roles', selector: 'role user_r types user_t'}
).
fact_source(
    role_type(agent_r, ai_agent_t),
    source{tool: setools, artifact: 'toy_policy.roles', selector: 'role agent_r types ai_agent_t'}
).
fact_source(
    role_type(log_r, log_shipper_t),
    source{tool: setools, artifact: 'toy_policy.roles', selector: 'role log_r types log_shipper_t'}
).

fact_source(
    has_attribute(httpd_t, webserver_domain),
    source{tool: setools, artifact: 'toy_policy.attrs', selector: 'typeattribute httpd_t webserver_domain'}
).
fact_source(
    has_attribute(ai_agent_t, ai_agent_domain),
    source{tool: setools, artifact: 'toy_policy.attrs', selector: 'typeattribute ai_agent_t ai_agent_domain'}
).
fact_source(
    has_attribute(httpd_sys_script_exec_t, executable_content),
    source{tool: setools, artifact: 'toy_policy.attrs', selector: 'typeattribute httpd_sys_script_exec_t executable_content'}
).
fact_source(
    has_attribute(shadow_t, credential_store),
    source{tool: setools, artifact: 'toy_policy.attrs', selector: 'typeattribute shadow_t credential_store'}
).

fact_source(
    type_transition(init_t, daemon_exec_t, daemon_t),
    source{tool: setools, artifact: 'toy_policy.transitions', selector: 'type_transition init_t daemon_exec_t:process daemon_t'}
).
fact_source(
    type_transition(init_t, ai_agent_exec_t, ai_agent_t),
    source{tool: setools, artifact: 'toy_policy.transitions', selector: 'type_transition init_t ai_agent_exec_t:process ai_agent_t'}
).
fact_source(
    type_transition(init_t, log_shipper_exec_t, log_shipper_t),
    source{tool: setools, artifact: 'toy_policy.transitions', selector: 'type_transition init_t log_shipper_exec_t:process log_shipper_t'}
).

fact_source(
    new_allow(policy_v2, httpd_t, shadow_t, file, read),
    source{tool: sepolicy_analysis, artifact: 'toy_policy_diff.json', selector: 'policy_v2 new allow httpd_t shadow_t:file read'}
).
fact_source(
    new_allow(policy_v2, httpd_t, httpd_sys_script_exec_t, file, write),
    source{tool: sepolicy_analysis, artifact: 'toy_policy_diff.json', selector: 'policy_v2 new allow httpd_t httpd_sys_script_exec_t:file write'}
).
fact_source(
    new_allow(policy_v2, httpd_t, httpd_log_t, file, getattr),
    source{tool: sepolicy_analysis, artifact: 'toy_policy_diff.json', selector: 'policy_v2 new allow httpd_t httpd_log_t:file getattr'}
).

fact_source(
    file_context('/var/www/html/index.html', httpd_sys_content_t, file),
    source{tool: matchpathcon, artifact: 'toy_file_contexts', selector: '/var/www/html/index.html'}
).
fact_source(
    file_context('/var/www/cgi-bin/admin.cgi', httpd_sys_script_exec_t, file),
    source{tool: matchpathcon, artifact: 'toy_file_contexts', selector: '/var/www/cgi-bin/admin.cgi'}
).
fact_source(
    file_context('/var/log/httpd/access.log', httpd_log_t, file),
    source{tool: matchpathcon, artifact: 'toy_file_contexts', selector: '/var/log/httpd/access.log'}
).
fact_source(
    file_context('/etc/shadow', shadow_t, file),
    source{tool: matchpathcon, artifact: 'toy_file_contexts', selector: '/etc/shadow'}
).
fact_source(
    file_context('/usr/sbin/exampled', daemon_exec_t, file),
    source{tool: matchpathcon, artifact: 'toy_file_contexts', selector: '/usr/sbin/exampled'}
).
fact_source(
    file_context('/usr/local/bin/ai-agentd', ai_agent_exec_t, file),
    source{tool: matchpathcon, artifact: 'toy_file_contexts', selector: '/usr/local/bin/ai-agentd'}
).
fact_source(
    file_context('/usr/local/bin/log-shipper', log_shipper_exec_t, file),
    source{tool: matchpathcon, artifact: 'toy_file_contexts', selector: '/usr/local/bin/log-shipper'}
).
fact_source(
    file_context('/home/alice/public_html/index.html', user_home_t, file),
    source{tool: matchpathcon, artifact: 'toy_file_contexts', selector: '/home/alice/public_html/index.html'}
).
fact_source(
    file_context('/srv/secret/report.txt', secret_doc_t, file),
    source{tool: matchpathcon, artifact: 'toy_file_contexts', selector: '/srv/secret/report.txt'}
).

fact_source(
    port_context(80, http_port_t, tcp),
    source{tool: sepolicy, artifact: 'toy_ports', selector: 'http_port_t tcp 80'}
).
fact_source(
    port_context(5432, postgresql_port_t, tcp),
    source{tool: sepolicy, artifact: 'toy_ports', selector: 'postgresql_port_t tcp 5432'}
).
