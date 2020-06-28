# Contributing to ACMEd


## Testing and bug report

The first way to help is to actually use the software and [report any bug you encounter](https://github.com/breard-r/acmed/issues). Do not hesitate to test the limits.


## Improving the language

Since the author is not a native English speaker, some of the texts used in this project should be fixed.


## Work on dependencies

### attohttpc

Although `attohttpc` is not currently a dependency, it may replace `reqwest` which is far too big and drags a lot of dependencies. But before this could be done, it needs to allow [new root certificates to be added](https://github.com/sbstp/attohttpc/issues/71).

### rust-openssl

An improvement that would be appreciable is to add Curve 25519 support to the [openssl](https://crates.io/crates/openssl) crate.

- https://github.com/sfackler/rust-openssl/issues/947
- https://github.com/sfackler/rust-openssl/pull/1275

### Find or create a good template engine

As reported in [issue #8](https://github.com/breard-r/acmed/issues/8), there is currently no perfect template engine. A good way to help improve ACMEd would be to find or create one that supports all the listed requirements.


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
