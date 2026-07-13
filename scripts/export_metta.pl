:- module(export_metta, [
    export_metta/0,
    metta_lines/1
]).

:- use_module('../src/selinux_facts').
:- use_module('../src/selinux_rules').

export_metta :-
    metta_lines(Lines),
    forall(member(Line, Lines), format('~w~n', [Line])).

metta_lines(Lines) :-
    findall(Line, metta_line(Line), UnsortedLines),
    sort(UnsortedLines, Lines).

metta_line(Line) :-
    allow(Source, Target, Class, Permission),
    sexpr_line([allow, Source, Target, Class, Permission], Line).
metta_line(Line) :-
    boolean_state(Boolean, State),
    sexpr_line(['boolean-state', Boolean, State], Line).
metta_line(Line) :-
    conditional_allow(Boolean, Source, Target, Class, Permission),
    sexpr_line(['conditional-allow', Boolean, Source, Target, Class, Permission], Line).
metta_line(Line) :-
    constraint_denies(Source, Target, Class, Permission, Reason),
    sexpr_line(['constraint-denies', Source, Target, Class, Permission, Reason], Line).
metta_line(Line) :-
    has_attribute(Type, Attribute),
    sexpr_line(['has-attribute', Type, Attribute], Line).
metta_line(Line) :-
    type_transition(Source, Entrypoint, Target),
    sexpr_line(['type-transition', Source, Entrypoint, Target], Line).
metta_line(Line) :-
    new_allow(PolicyVersion, Source, Target, Class, Permission),
    sexpr_line(['new-allow', PolicyVersion, Source, Target, Class, Permission], Line).
metta_line(Line) :-
    file_context(Path, Type, Class),
    sexpr_line(['file-context', Path, Type, Class], Line).
metta_line(Line) :-
    audit_finding(Kind, Finding),
    finding_terms(Finding, Terms),
    sexpr_line(['audit-finding', Kind | Terms], Line).
metta_line(Line) :-
    policy_regression_severity(
        PolicyVersion,
        Source,
        Target,
        Class,
        Permission,
        Severity
    ),
    sexpr_line([
        'policy-regression-severity',
        PolicyVersion,
        Source,
        Target,
        Class,
        Permission,
        Severity
    ], Line).

finding_terms(Finding, Terms) :-
    dict_pairs(Finding, _, Pairs),
    sort(Pairs, SortedPairs),
    findall([Key, Value], member(Key-Value, SortedPairs), Terms).

sexpr_line(Terms, Line) :-
    maplist(metta_token, Terms, Tokens),
    atomic_list_concat(Tokens, ' ', Body),
    format(atom(Line), '(~w)', [Body]).

metta_token(Term, Token) :-
    is_list(Term),
    !,
    sexpr_line(Term, Token).
metta_token(Term, Token) :-
    atom(Term),
    sub_atom(Term, 0, 1, _, '/'),
    !,
    quoted_string_token(Term, Token).
metta_token(Term, Term) :-
    atom(Term),
    !.
metta_token(Term, Token) :-
    format(atom(Token), '~w', [Term]).

quoted_string_token(Atom, Token) :-
    atom_chars(Atom, Chars),
    phrase(escaped_chars(Chars), EscapedChars),
    atom_chars(Escaped, EscapedChars),
    format(atom(Token), '"~w"', [Escaped]).

escaped_chars([]) --> [].
escaped_chars(['"' | Chars]) --> ['\\', '"'], escaped_chars(Chars).
escaped_chars(['\\' | Chars]) --> ['\\', '\\'], escaped_chars(Chars).
escaped_chars([Char | Chars]) --> [Char], escaped_chars(Chars).
