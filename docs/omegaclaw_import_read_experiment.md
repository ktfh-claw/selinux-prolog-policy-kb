# OmegaClaw Import/Read Experiment

This runbook prepares a repo-local packet for testing whether OmegaClaw can
import and read the generated SELinux knowledge prior without changing an
OmegaClaw-Core checkout.

## Prepare Packet

From this repository:

```bash
sh scripts/prepare_omegaclaw_experiment.sh
```

The command writes `.tmp/omegaclaw-import-read/` with:

- `knowledge-prior.md` - the generated SELinux prior to import or paste
- `report.md` - a small results template for the import/read run

If `swipl` is available, the packet is regenerated from the Prolog source. If
not, the script copies the checked-in fixture so the experiment can still be
prepared.

## Run Experiment

Use `knowledge-prior.md` as an OmegaClaw knowledge prior or paste its fact block
into the task prompt. Run the baseline commands listed in that file through the
OmegaClaw `metta` path.

Record in `report.md`:

- the OmegaClaw-Core commit or package version used
- how the prior was loaded
- each baseline command
- raw truth values and confidence values returned
- any parser, import, or boundary-preservation failures

The useful result is whether OmegaClaw preserves imported fact boundaries, local
assessment conclusions, raw truth values, and confidence thresholds for this toy
SELinux policy profile.
