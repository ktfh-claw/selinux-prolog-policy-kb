:- begin_tests(metta_export).

:- use_module(library(readutil)).
:- use_module('../scripts/export_metta').

test(export_matches_fixture) :-
    with_output_to(string(Actual), export_metta),
    read_file_to_string(
        'fixtures/selinux_policy.metta',
        Expected,
        []
    ),
    assertion(Actual == Expected).

:- end_tests(metta_export).
