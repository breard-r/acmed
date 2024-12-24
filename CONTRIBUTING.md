# Contributing to ACMEd


## Testing and bug report

The first way to help is to actually use the software and [report any bug you
encounter][bug_report]. Do not hesitate to test the limits.


## Improving the language

Since the author is not a native English speaker, some of the texts used in
this project should be fixed. This is especially true on the man pages as well
as the [wiki][wiki].


## Package it for your favorite system

A great way to contribute to the project is to package it. You can check the
packages status on [Repology](https://repology.org/project/acmed/versions).


## Improving the code

As a one-man project, it has several goals already set but not explicitly
written in an issue or any other follow-up file. It will not be the case before
version 1.0 is released since everything may change at any moment. Therefore,
it is recommended to request change instead of implementing them, this way we
can discuss how things should be made. That said, there might be a few [good
first issues][first_issue] you might want to look into.

If you want to submit a pull request, please:

- document your changes in the man pages and the `CHANGELOG.md` file
- write as much tests as you can
- run `cargo test` and be sure every test pass
- format your code using [rustfmt][rustfmt]
- be sure not to have any warning when compiling
- run [clippy][clippy] and fix any issue
- run [cargo-deny][cargo-deny] and fix any issue

Notice: man pages are written using the mdoc syntax, documentation is available
in [`man 7 mdoc`][mdoc].


## Work on dependencies

The dependencies may have some bugs or features waiting to be implemented.
Improving them will have a positive repercussion on ACMEd.


[bug_report]: https://github.com/breard-r/acmed/issues
[wiki]: https://github.com/breard-r/acmed-wiki
[repology]: https://repology.org/project/acmed/versions
[first_issue]: https://github.com/breard-r/acmed/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22
[rustfmt]: https://github.com/rust-lang/rustfmt
[clippy]: https://github.com/rust-lang/rust-clippy
[cargo-deny]: https://github.com/EmbarkStudios/cargo-deny
[mdoc]: https://man.freebsd.org/cgi/man.cgi?query=mdoc&sektion=7&apropos=0
