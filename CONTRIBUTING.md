# Contributing to ACMEd


## Project home

This project has been moved from [GitHub][acmed_github] to
[Codeberg][acmed_codeberg]. GitHub has been kept as a mirror where changes are
forced-push. Since this will erase every change made on GitHub, you should
therefore exclusively contribute on Codeberg.

An indirect way to help this project is therefore to [help
Codeberg][codeberg_help].

[acmed_github]: https://github.com/breard-r/acmed
[acmed_codeberg]: https://codeberg.org/rbd/acmed
[codeberg_help]: https://docs.codeberg.org/improving-codeberg/


## Testing and bug report

The first way to help is to actually use the software and [report any bug you
encounter][bugtracker]. Do not hesitate to test the limits. When reporting a
bug, please follow the generic [bug reporting recommendations][bug_howto].

[bugtracker]: https://codeberg.org/rbd/acmed/issues
[bug_howto]: https://www.chiark.greenend.org.uk/~sgtatham/bugs.html


## Improving the language

Since the author is not a native English speaker, some of the texts used in
this project should be fixed. This is especially true on the man pages as well
as the [wiki][wiki].

[wiki]: https://codeberg.org/rbd/acmed/wiki


## Package it for your favorite system

A great way to contribute to the project is to package it. You can check the
packages status on [Repology][repology].

[repology]: https://repology.org/project/acmed/versions


## Improving the code

As a one-man project, it has several goals already set but not explicitly
written in an issue or any other follow-up file. It will not be the case before
version 1.0 is released since everything may change at any moment. Therefore,
it is recommended to request change instead of implementing them, this way we
can discuss how things should be made. That said, there might be a few [good
first issues][good_first_issue] you might want to look into.

If you want to submit a pull request, please:

- document your changes in the man pages and the `CHANGELOG.md` file
- write as much tests as you can
- run `cargo test` and be sure every test pass
- format your code using [rustfmt][rustfmt]
- be sure not to have any warning when compiling
- run [clippy][clippy] and fix any issue
- refrain from including a new dependency
- beware of potential repercussions on the default hooks: those should remain
  usable

Notice: man pages are written using the mdoc syntax, documentation is available
in [`man 7 mdoc`][mdoc].

[good_first_issue]: https://codeberg.org/rbd/acmed/issues?q=&type=all&labels=577900&state=open
[rustfmt]: https://github.com/rust-lang/rustfmt
[clippy]: https://github.com/rust-lang/rust-clippy
[mdoc]: https://man.freebsd.org/cgi/man.cgi?query=mdoc&sektion=7
