:- module(export_omegaclaw_prior, [
    export_omegaclaw_prior/0,
    omegaclaw_prior_text/1,
    omegaclaw_prior_lines/1
]).

:- use_module(export_metta, [metta_lines/1]).

export_omegaclaw_prior :-
    omegaclaw_prior_lines(Lines),
    forall(member(Line, Lines), format('~w~n', [Line])).

omegaclaw_prior_text(Text) :-
    omegaclaw_prior_lines(Lines),
    atomic_list_concat(Lines, '\n', Body),
    atom_concat(Body, '\n', TextAtom),
    atom_string(TextAtom, Text).

omegaclaw_prior_lines(Lines) :-
    metta_lines(MettaLines),
    header_lines(HeaderLines),
    metta_fact_lines(MettaLines, FactLines),
    baseline_query_lines(BaselineLines),
    boundary_lines(BoundaryLines),
    append(HeaderLines, FactLines, HeaderAndFacts),
    append(HeaderAndFacts, BaselineLines, WithoutBoundary),
    append(WithoutBoundary, BoundaryLines, Lines).

header_lines([
    '# SELinux Policy Reasoning Baseline',
    '',
    'This is a generated OmegaClaw knowledge-prior fixture for the SELinux Prolog policy KB.',
    'The source facts are toy SETools/sepolicy_analysis-shaped facts, not a real host policy extract.',
    ''
]).

metta_fact_lines(MettaLines, Lines) :-
    FactHeader = [
        '## Imported SELinux-shaped Facts',
        '',
        'Use these as structured facts for OmegaClaw MeTTa/NAL reasoning experiments.',
        ''
    ],
    bullet_lines(MettaLines, Bullets),
    append(FactHeader, Bullets, Lines).

bullet_lines([], []).
bullet_lines([Line | Lines], [Bullet | Bullets]) :-
    format(atom(Bullet), '- `~w`', [Line]),
    bullet_lines(Lines, Bullets).

baseline_query_lines([
    '',
    '## Baseline OmegaClaw Commands',
    '',
    'These commands mirror the first application-style reasoning checks to run after import.',
    'They combine imported facts with local assessment rules and should be reported with raw truth values.',
    '',
    '```text',
    'metta (|- ((==> (allow httpd_t httpd_sys_content_t file read) can_read_web_content_httpd_t) (stv 1.0 0.95)) ((allow httpd_t httpd_sys_content_t file read) (stv 1.0 0.95)))',
    'metta (|- ((==> (file-context "/var/www/cgi-bin/admin.cgi" httpd_sys_script_exec_t file) risky_executable_content_path_var_www_cgi_bin_admin_cgi) (stv 1.0 0.95)) ((file-context "/var/www/cgi-bin/admin.cgi" httpd_sys_script_exec_t file) (stv 1.0 0.95)))',
    'metta (|- ((==> (allow httpd_t httpd_sys_script_exec_t file write) risky_executable_content_path_var_www_cgi_bin_admin_cgi) (stv 1.0 0.9)) ((allow httpd_t httpd_sys_script_exec_t file write) (stv 1.0 0.95)))',
    'metta (|- ((==> (type-transition init_t daemon_exec_t daemon_t) can_transition_init_to_daemon_via_usr_sbin_exampled) (stv 1.0 0.95)) ((type-transition init_t daemon_exec_t daemon_t) (stv 1.0 0.95)))',
    'metta (|- ((==> (new-allow policy_v2 httpd_t shadow_t file read) critical_policy_regression_policy_v2_httpd_shadow_read) (stv 1.0 0.95)) ((new-allow policy_v2 httpd_t shadow_t file read) (stv 1.0 0.95)))',
    '```'
]).

boundary_lines([
    '',
    '## Expected Use',
    '',
    'For an OmegaClaw run, place this file under `knowledge-priors/` or include its fact block in the task prompt, then run the baseline commands above through the `metta` skill.',
    'The useful result is not that the toy facts are realistic; it is whether OmegaClaw preserves imported fact boundaries, local assessment rules, raw conclusions, and confidence thresholds.',
    '',
    '## Soundness Boundary',
    '',
    'This fixture models only simple boolean-gated conditionals. It does not model nested conditional expressions, constraints, MLS/MCS, roles, users, type bounds, DAC, capabilities, seccomp, namespaces, cgroups, or firewall policy.'
]).
