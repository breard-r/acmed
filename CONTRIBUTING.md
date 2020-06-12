# Contributing to ACMEd


## Testing and bug report

The first way to help is to actually use the software and [report any bug you encounter](https://github.com/breard-r/acmed/issues). Do not hesitate to test the limits.


## Improving the language

Since the author is not a native English speaker, some of the texts used in this project should be fixed.


## Fix issues in dependencies

### rust-openssl

The [openssl](https://crates.io/crates/openssl) crate does not expose the Asn1Time in a usable way, which requires ACMEd to parse certificates using an external library in order to get the `not after` field. This is sub-optimal.

- https://github.com/sfackler/rust-openssl/issues/687
- https://github.com/sfackler/rust-openssl/pull/673

An other improvement that would be appreciable is to add Curve 25519 support.

- https://github.com/sfackler/rust-openssl/issues/947


## Improving the code

As a one-man project, it has several goals already set but not explicitly written in an issue or any other follow-up file. It will not be the case before version 1.0 is released since everything may change at any moment. Therefore, it is recommended to request change instead of implementing them, this way we can discuss how things should be made.

If you really want to submit a pull request, please :

- document your changes in the man pages and the `CHANGELOG.md` file
- write as much tests as you can
- run `cargo test` and be sure every test pass
- format your code using [rustfmt](https://github.com/rust-lang/rustfmt)
- be sure not to have any warning when compiling
- run [clippy](https://github.com/rust-lang/rust-clippy) and fix any issue
- refrain from including a new dependency (crates having `ring` in their dependency tree are a no-go, see #2)
- beware of potential repercussions on the default hooks: those should remain usable

Not following the rules above will delay the merge since they will have to be fixed first.


## Author vs. contributor

Some people have troubles seeing the difference between an author and a contributor. Here is how it is seen withing this project.

A contributor is a person who helps the project in various ways whenever she or he wants. As such, a contributor does not have any obligation other than being respectful and open-minded. People who wrote code that have been accepted are automatically listed in the [contributors page](https://github.com/breard-r/acmed/graphs/contributors). The creation of a file with the names of people contributing outside of the code base will be studied upon request from such people.

An author is a person who has some responsibilities on the project. Authors are expected to contribute on a regular basis, decide architectural choices, enforce copyright issues and so on. One does not grant himself the author status, it is given by the others authors after having discussed the request.
