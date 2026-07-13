:- module(selinux_facts, [
    allow/4,
    boolean_state/2,
    conditional_allow/5,
    constraint_denies/5,
    sensitivity_level/2,
    mls_range/4,
    type_bound/2,
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
allow(user_t, secret_doc_t, file, read).
allow(auditor_t, secret_doc_t, file, read).
allow(auditor_limited_t, secret_doc_t, file, read).
allow(sandbox_web_t, httpd_sys_content_t, file, read).
allow(sandbox_web_parent_t, httpd_sys_content_t, file, read).
allow(sandbox_web_t, httpd_log_t, file, append).

boolean_state(httpd_can_network_connect, true).
boolean_state(httpd_enable_homedirs, false).

conditional_allow(httpd_can_network_connect, httpd_t, http_port_t, tcp_socket, name_connect).
conditional_allow(httpd_enable_homedirs, httpd_t, user_home_t, file, read).

constraint_denies(user_t, secret_doc_t, file, read, mls_range_mismatch).

sensitivity_level(s0, 0).
sensitivity_level(s1, 1).

mls_range(user_t, s0, s0, [c0]).
mls_range(auditor_t, s0, s1, [c0, c1]).
mls_range(auditor_limited_t, s0, s1, [c0]).
mls_range(secret_doc_t, s1, s1, [c1]).

type_bound(sandbox_web_t, sandbox_web_parent_t).

has_attribute(httpd_t, webserver_domain).
has_attribute(httpd_sys_script_exec_t, executable_content).
has_attribute(shadow_t, credential_store).

type_transition(init_t, daemon_exec_t, daemon_t).

new_allow(policy_v2, httpd_t, shadow_t, file, read).
new_allow(policy_v2, httpd_t, httpd_sys_script_exec_t, file, write).
new_allow(policy_v2, httpd_t, httpd_log_t, file, getattr).

file_context('/var/www/html/index.html', httpd_sys_content_t, file).
file_context('/var/www/cgi-bin/admin.cgi', httpd_sys_script_exec_t, file).
file_context('/var/log/httpd/access.log', httpd_log_t, file).
file_context('/etc/shadow', shadow_t, file).
file_context('/usr/sbin/exampled', daemon_exec_t, file).
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
    has_attribute(httpd_t, webserver_domain),
    source{tool: setools, artifact: 'toy_policy.attrs', selector: 'typeattribute httpd_t webserver_domain'}
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
