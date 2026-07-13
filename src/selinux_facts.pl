:- module(selinux_facts, [
    allow/4,
    has_attribute/2,
    type_transition/3,
    new_allow/5,
    file_context/3
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

file_context('/var/www/html/index.html', httpd_sys_content_t, file).
file_context('/var/www/cgi-bin/admin.cgi', httpd_sys_script_exec_t, file).
file_context('/var/log/httpd/access.log', httpd_log_t, file).
file_context('/etc/shadow', shadow_t, file).
file_context('/usr/sbin/exampled', daemon_exec_t, file).
