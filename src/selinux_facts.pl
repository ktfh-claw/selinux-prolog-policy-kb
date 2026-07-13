:- module(selinux_facts, [
    allow/4,
    has_attribute/2,
    type_transition/3,
    new_allow/5,
    file_context/3,
    fact_source/2
]).

% Toy imported SELinux profile shaped like a SETools/sepolicy_analysis export.

allow(httpd_t, httpd_sys_content_t, file, read).
allow(httpd_t, httpd_log_t, file, append).
allow(httpd_t, httpd_sys_script_exec_t, file, write).
allow(httpd_t, httpd_sys_script_exec_t, file, read).
allow(init_t, daemon_exec_t, file, entrypoint).
allow(init_t, daemon_t, process, transition).

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
