#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
out_dir="$repo_root/.tmp/omegaclaw-import-read"
prior="$out_dir/knowledge-prior.md"
report="$out_dir/report.md"

mkdir -p "$out_dir"

if command -v swipl >/dev/null 2>&1; then
    swipl -q \
        -s "$repo_root/scripts/export_omegaclaw_prior.pl" \
        -g export_omegaclaw_prior:export_omegaclaw_prior \
        -t halt > "$prior"
    prior_source="regenerated from Prolog source"
else
    cp "$repo_root/fixtures/omegaclaw_knowledge_prior.md" "$prior"
    prior_source="copied from checked-in fixture because swipl was not found"
fi

cat > "$report" <<EOF
# OmegaClaw SELinux Prior Import/Read Report

- Prepared: $(date -u '+%Y-%m-%dT%H:%M:%SZ')
- Prior source: $prior_source
- Knowledge prior: knowledge-prior.md
- OmegaClaw-Core commit/version:
- Import method:

## Baseline Command Results

| Command label | Raw result | Confidence | Notes |
| --- | --- | --- | --- |
| can_read_web_content_httpd_t | | | |
| risky_executable_content_path_var_www_cgi_bin_admin_cgi_from_context | | | |
| risky_executable_content_path_var_www_cgi_bin_admin_cgi_from_write | | | |
| can_transition_init_to_daemon_via_usr_sbin_exampled | | | |
| critical_policy_regression_policy_v2_httpd_shadow_read | | | |

## Boundary Checks

- Imported facts stayed separate from local assessment rules:
- No unsupported SELinux concepts were inferred:
- Parser/import errors:

## Summary

EOF

printf 'Prepared OmegaClaw import/read packet in %s\n' "$out_dir"
printf 'Prior: %s\n' "$prior"
printf 'Report: %s\n' "$report"
